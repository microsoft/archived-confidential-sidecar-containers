// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"strconv"

	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Set to true to regenerate test files at every request.
// Also useful to debug the various steps, especially encoding
// to the correct base64url encoding.

const GenerateTestData = false

type UvmInformation struct {
	EncodedSecurityPolicy   string // customer security policy
	CertChain               string // platform certificates for the actual physical host, ascii PEM
	EncodedUvmReferenceInfo string // endorsements for the particular UVM image
	LocalThimUri            string // uri for the local THIM endpoint -- TO-DO: add method to get this value
	ThimTcbm                uint64 // TCBM for the THIM Certs
}

// format of the json provided to the UVM by hcsshim. Comes from the THIM endpoint
// and is a base64 encoded json string
type THIMCerts struct {
	VcekCert         string `json:"vcekCert"`
	Tcbm             string `json:"tcbm"`
	CertificateChain string `json:"certificateChain"`
	CacheControl     string `json:"cacheControl"`
}

func THIMtoPEM(encodedHostCertsFromTHIM string) (string, uint64, error) {
	var thimTcbm uint64
	hostCertsFromTHIM, err := base64.StdEncoding.DecodeString(encodedHostCertsFromTHIM)
	if err != nil {
		return "", thimTcbm, errors.Wrapf(err, "base64 decoding platform certs failed")
	}

	if GenerateTestData {
		ioutil.WriteFile("uvm_host_amd_certificate.json", hostCertsFromTHIM, 0644)
	}

	var certsFromTHIM THIMCerts
	err = json.Unmarshal(hostCertsFromTHIM, &certsFromTHIM)
	if err != nil {
		return "", thimTcbm, errors.Wrapf(err, "json unmarshal platform certs failed")
	}

	certsString := certsFromTHIM.VcekCert + certsFromTHIM.CertificateChain

	if GenerateTestData {
		ioutil.WriteFile("uvm_host_amd_certificate.pem", []byte(certsString), 0644)
	}

	logrus.Debugf("certsFromTHIM:\n\n%s\n\n", certsString)

	thimTcbm, err = strconv.ParseUint(certsFromTHIM.Tcbm, 10, 64)
	if err != nil {
		return "", thimTcbm, errors.Wrap(err, "Unable to convert TCBM from THIM certificates to a uint64")
	}

	return certsString, thimTcbm, nil
}

func GetUvmInformation() (UvmInformation, error) {
	var encodedUvmInformation UvmInformation

	encodedHostCertsFromTHIM := os.Getenv("UVM_HOST_AMD_CERTIFICATE")

	if GenerateTestData {
		ioutil.WriteFile("uvm_host_amd_certificate.base64", []byte(encodedHostCertsFromTHIM), 0644)
	}

	if encodedHostCertsFromTHIM != "" {
		certsFromTHIM, tcbmFromTHIM, err := THIMtoPEM(encodedHostCertsFromTHIM)
		if err != nil {
			return encodedUvmInformation, err
		}
		encodedUvmInformation.ThimTcbm = tcbmFromTHIM
		encodedUvmInformation.CertChain = certsFromTHIM
	}
	encodedUvmInformation.EncodedSecurityPolicy = os.Getenv("UVM_SECURITY_POLICY")
	encodedUvmInformation.EncodedUvmReferenceInfo = os.Getenv("UVM_REFERENCE_INFO")

	if GenerateTestData {
		ioutil.WriteFile("uvm_security_policy.base64", []byte(encodedUvmInformation.EncodedSecurityPolicy), 0644)
		ioutil.WriteFile("uvm_reference_info.base64", []byte(encodedUvmInformation.EncodedUvmReferenceInfo), 0644)
	}

	return encodedUvmInformation, nil
}
