// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// +build linux

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Microsoft/confidential-sidecard-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecard-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecard-containers/pkg/skr"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Test dependencies
var (
	_azmountRun                    = azmountRun
	_containerMountAzureFilesystem = containerMountAzureFilesystem
	_cryptsetupOpen                = cryptsetupOpen
	ioutilWriteFile                = ioutil.WriteFile
	osGetenv                       = os.Getenv
	osMkdirAll                     = os.MkdirAll
	osRemoveAll                    = os.RemoveAll
	osStat                         = os.Stat
	timeSleep                      = time.Sleep
	unixMount                      = unix.Mount
)

var (
	Identity              common.Identity
	CertCache             attest.CertCache
	EncodedSecurityPolicy string
	// for testing encrypted filesystems without releasing secrets from
	// MHSM allowTestingWithRawKey needs to be set to true and a raw key
	// needs to have been provided. default mode is that such testing is
	// disabled.
	allowTestingWithRawKey = false
)

// azmountRun starts azmount with the specified arguments, and leaves it running
// in the background.
func azmountRun(imageLocalFolder string, azureImageUrl string, azureImageUrlPrivate bool, azmountLogFile string, cacheBlockSize string, numBlocks string) error {

	identityJson, err := json.Marshal(Identity)
	if err != nil {
		logrus.Debugf("failed to marshal identity...")
		return err
	}

	encodedIdentity := base64.StdEncoding.EncodeToString(identityJson)

	logrus.Debugf("Starting azmount: %s %s %s %s %s KB", imageLocalFolder, azureImageUrl, strconv.FormatBool(azureImageUrlPrivate), azmountLogFile, cacheBlockSize)
	cmd := exec.Command("/bin/azmount", "-mountpoint", imageLocalFolder, "-url", azureImageUrl, "-private", strconv.FormatBool(azureImageUrlPrivate), "-identity", encodedIdentity, "-logfile", azmountLogFile, "-blocksize", cacheBlockSize, "-numblocks", numBlocks)
	if err := cmd.Start(); err != nil {
		errorString := "azmount failed to start"
		logrus.WithError(err).Error(errorString)
		return errors.Wrapf(err, errorString)
	}
	logrus.Debugf("azmount running...")
	return nil
}

// cryptsetupCommand runs cryptsetup with the provided arguments
func cryptsetupCommand(args []string) error {
	// --debug and -v are used to increase the information printed by
	// cryptsetup. By default, it doesn't print much information, which makes it
	// hard to debug it when there are problems.
	cmd := exec.Command("cryptsetup", append([]string{"--debug", "-v"}, args...)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to execute cryptsetup: %s", string(output))
	}
	return nil
}

// cryptsetupOpen runs "cryptsetup luksOpen" with the right arguments.
func cryptsetupOpen(source string, deviceName string, keyFilePath string) error {
	openArgs := []string{
		// Open device with the key passed to luksFormat
		"luksOpen", source, deviceName, "--key-file", keyFilePath,
		// Don't use a journal to increase performance
		"--integrity-no-journal",
		"--persistent"}

	return cryptsetupCommand(openArgs)
}

func mountAzureFile(tempDir string, index int, azureImageUrl string, azureImageUrlPrivate bool, cacheBlockSize string, numBlocks string) (string, error) {

	imageLocalFolder := filepath.Join(tempDir, fmt.Sprintf("%d", index))
	if err := osMkdirAll(imageLocalFolder, 0755); err != nil {
		return "", errors.Wrapf(err, "mkdir failed: %s", imageLocalFolder)
	}

	// Location in the UVM of the encrypted filesystem image.
	imageLocalFile := filepath.Join(imageLocalFolder, "data")

	// Location of log file generated by azmount
	azmountLogFile := filepath.Join(tempDir, fmt.Sprintf("log-%d.txt", index))

	// Any program that sets up a FUSE filesystem becomes a server that listens
	// to requests from the kernel, and it gets stuck in the loop that serves
	// requests, so it is needed to run it in a different process so that the
	// execution can continue in this one.
	_azmountRun(imageLocalFolder, azureImageUrl, azureImageUrlPrivate, azmountLogFile, cacheBlockSize, numBlocks)

	// Wait until the file is available
	count := 0
	for {
		_, err := osStat(imageLocalFile)
		if err == nil {
			// Found
			break
		}
		// Timeout after 10 seconds
		count++
		if count == 1000 {
			return "", errors.New("timed out")
		}
		timeSleep(60 * time.Millisecond)
	}
	logrus.Debugf("Found file")

	return imageLocalFile, nil
}

// rawRemoteFilesystemKey sets up the key file path using the raw key passed
func rawRemoteFilesystemKey(tempDir string, rawKeyHexString string) (keyFilePath string, err error) {

	keyFilePath = filepath.Join(tempDir, "keyfile")

	keyBytes := make([]byte, 64)

	keyBytes, err = hex.DecodeString(rawKeyHexString)
	if err != nil {
		logrus.WithError(err).Debugf("failed to decode raw key: %s", rawKeyHexString)
		return "", errors.Wrapf(err, "failed to write keyfile")
	}

	// dm-crypt expects a key file, so create a key file using the key released in
	// previous step
	err = ioutilWriteFile(keyFilePath, keyBytes, 0644)
	if err != nil {
		logrus.WithError(err).Debugf("failed to delete keyfile: %s", keyFilePath)
		return "", errors.Wrapf(err, "failed to write keyfile")
	}

	return keyFilePath, nil
}

// releaseRemoteFilesystemKey releases the key identified by keyBlob from managed HSM
// azure key vault
//
// 1) Retrieve encoded  security policy by reading the environment variable
//
// 2) Perform secure key release
//
// 3) Prepare the key file path using the released key
func releaseRemoteFilesystemKey(tempDir string, keyBlob skr.KeyBlob) (keyFilePath string, err error) {

	keyFilePath = filepath.Join(tempDir, "keyfile")

	// 1) Retrieve the incoming encoded security policy
	EncodedSecurityPolicy = osGetenv("SECURITY_POLICY")

	fmt.Println("EncodedSecurityPolicy: ", EncodedSecurityPolicy)

	// 2) release key identified by keyBlob using encoded security policy and certcache
	//    certcache is required for validating the attestation report against the cert
	//    chain of the chip identified in the attestation report

	keyBytes := make([]byte, 64)

	// MHSM has limit on the request size. We do not pass the EncodedSecurityPolicy here so
	// it is not presented as fine-grained init-time claims in the MAA token, which would
	// introduce larger MAA tokens that MHSM would accept
	keyBytes, err = skr.SecureKeyRelease("", CertCache, Identity, keyBlob)
	if err != nil {
		logrus.WithError(err).Debugf("failed to release key: %v", keyBlob)
	}

	// 3) dm-crypt expects a key file, so create a key file using the key released in
	//    previous step
	err = ioutilWriteFile(keyFilePath, keyBytes, 0644)
	if err != nil {
		logrus.WithError(err).Debugf("failed to delete keyfile: %s", keyFilePath)
		return "", errors.Wrapf(err, "failed to write keyfile")
	}

	return keyFilePath, nil
}

// containerMountAzureFilesystem mounts a remote filesystems specified in the
// policy of a given container.
//
// 1) Get the actual filesystem image. This is done by starting a new azmount
//    process. The file is then exposed at ``/[tempDir]/[index]/data`` and the
//    log of azmount is saved to ``/[tempDir]/log-[index].txt``.
//
// 2) Obtain keyfile. This is hardcoded at the moment and needs to be replaced
//    by the actual code that gets the key. It is saved to a temporary file so
//    that it can be passed to cryptsetup. It can be removed afterwards.
//
// 3) Open encrypted filesystem with cryptsetup. The result is a block device in
//    ``/dev/mapper/remote-crypt-[filesystem-index]``.
//
// 4) Mount block device as a read-only filesystem.
//
// 5) Create a symlink to the filesystem in the path shared between the UVM and
//    the container.
func containerMountAzureFilesystem(tempDir string, index int, fs AzureFilesystem) (err error) {

	cacheBlockSize := "512"
	numBlocks := "32"

	// 1) Mount remote image
	imageLocalFile, err := mountAzureFile(tempDir, index, fs.AzureUrl, fs.AzureUrlPrivate, cacheBlockSize, numBlocks)
	if err != nil {
		return errors.Wrapf(err, "failed to mount remote file: %s", fs.AzureUrl)
	}

	// 2) Obtain keyfile

	var keyFilePath string
	if fs.KeyBlob.KID != "" {
		keyFilePath, err = releaseRemoteFilesystemKey(tempDir, fs.KeyBlob)
		if err != nil {
			return errors.Wrapf(err, "failed to obtain keyfile")
		}
	} else if allowTestingWithRawKey {
		keyFilePath, err = rawRemoteFilesystemKey(tempDir, fs.RawKeyHexString)
		if err != nil {
			return errors.Wrapf(err, "failed to obtain keyfile")
		}
	}

	defer func() {
		// Delete keyfile on exit
		if inErr := osRemoveAll(keyFilePath); inErr != nil {
			logrus.WithError(inErr).Debugf("failed to delete keyfile: %s", keyFilePath)
		} else {
			logrus.Debugf("Deleted keyfile: %s", keyFilePath)
		}
	}()

	// 3) Open encrypted filesystem with cryptsetup. The result is a block
	// device in /dev/mapper/remote-crypt-[filesystem-index] so that it is
	// unique from all other filesystems.
	var deviceName = fmt.Sprintf("remote-crypt-%d", index)
	var deviceNamePath = "/dev/mapper/" + deviceName

	err = _cryptsetupOpen(imageLocalFile, deviceName, keyFilePath)
	if err != nil {
		return errors.Wrapf(err, "luksOpen failed: %s", deviceName)
	}
	logrus.Debugf("Device opened: %s", deviceName)

	// 4) Mount block device as a read-only filesystem.
	tempMountFolder, err := filepath.Abs(filepath.Join(fs.MountPoint, fmt.Sprintf("../.filesystem-%d", index)))
	if err != nil {
		return errors.Wrapf(err, "failed to resolve absolute path")
	}

	logrus.Debugf("Mounting to: %s", tempMountFolder)

	var flags uintptr = unix.MS_RDONLY
	data := "noload"

	if err := osMkdirAll(tempMountFolder, 0755); err != nil {
		return errors.Wrapf(err, "mkdir failed: %s", tempMountFolder)
	}

	if err := unixMount(deviceNamePath, tempMountFolder, "ext4", flags, data); err != nil {
		return errors.Wrapf(err, "failed to mount filesystem: %s", deviceNamePath)
	}

	// 5) Create a symlink to the folder where the filesystem is mounted.
	destPath := fs.MountPoint
	logrus.Debugf("Linking to: %s", destPath)

	if err := os.Symlink(fmt.Sprintf(".filesystem-%d", index), destPath); err != nil {
		return errors.Wrapf(err, "failed to symlink filesystem: %s", destPath)
	}

	return nil
}

func MountAzureFilesystems(tempDir string, info RemoteFilesystemsInformation) (err error) {

	Identity = info.AzureInfo.Identity
	CertCache = info.AzureInfo.CertCache

	for i, fs := range info.AzureFilesystems {
		logrus.Debugf("Mounting Azure Storage blob %d...", i)

		err = _containerMountAzureFilesystem(tempDir, i, fs)
		if err != nil {
			return errors.Wrapf(err, "failed to mount filesystem index %d", i)
		}
	}

	return nil
}
