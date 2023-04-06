// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"crypto/x509"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Set to true to regenerate test files at every request.
// Also useful to debug the various steps, especially encoding
// to the correct base64url encoding.

const GenerateTestData = false

// Information supplied by the UVM specific to running Pod

type UvmInformation struct {
	EncodedSecurityPolicy   string // customer security policy
	CertChain               string // platform certificates for the actual physical host, ascii PEM
	EncodedUvmReferenceInfo string // endorsements for the particular UVM image
	RemoteTHIMServiceURL    string `json:",omitempty"` // URL where the remote THIM service is found
}

// returns the cached VCEK certificates (CertChain)
// If the CertChain is nil, refresh the certificates from the remote service before returning
func (u *UvmInformation) GetVCEK() string {
	if u.CertChain == "" {
		err := u.RefreshVCEK()
		if err != nil {
			logrus.Errorf("Error refreshing VCEK certificates: %v", err)
		}
	}
	return u.CertChain
}

// fetches new VCEK certificates from the remote THIM endpoint
func (u *UvmInformation) RefreshVCEK() error {
	resp, err := HTTPGetRequest(u.RemoteTHIMServiceURL, false)
	if err != nil {
		logrus.Errorf("Error fetching remote VCEK cert: %v", err)
		return err
	}
	responseData, err := HTTPResponseBody(resp)
	if err != nil {
		logrus.Errorf("Error reading remote VCEK cert: %v", err)
		return err
	}
	u.CertChain = string(responseData)
	return nil
}

// parses the cached CertChain and returns the VCEK leaf certificate
// Subject of the (x509) VCEK certificate (CN=SEV-VCEK)
func (u *UvmInformation) GetParsedVCEK() (*x509.Certificate, error) {
	currChain := []byte(u.GetVCEK())
	// iterate through the certificates in the chain
	for len(currChain) > 0 {
		var block *pem.Block
		block, currChain = pem.Decode(currChain)
		if block.Type == "CERTIFICATE" {
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			// check if this is the correct certificate
			if certificate.Subject.CommonName == "SEV-VCEK" {
				return certificate, nil
			}
		}
	}
	return nil, errors.New("No UVM certificate chain found")
}

// parses the VCEK certificate to return the TCB version
// fields reprocessed back into a uint64 to compare against the `ReportedTCB` in the fetched attestation report
func (u *UvmInformation) ParseVCEK() ( /*tcbVersion*/ uint64, error) {
	vcekCert, err := u.GetParsedVCEK()
	if err != nil {
		return 0, err
	}

	tcbValues := make([]byte, 8) // TCB version is 8 bytes
	var hwid, ucode, bl, tee, snp string
	// parse extensions to update the THIM URL and get TCB Version
	for _, ext := range vcekCert.Extensions {
		// productName
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.2") {
			u.RemoteTHIMServiceURL += string(ext.Value) + "/"
		}
		// HwID
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.4") {
			hwid = hex.EncodeToString(ext.Value) + "?"
		}
		// blSPL
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.1") {
			bl = fmt.Sprintf("blSPL=%d", ext.Value[2])
			tcbValues[0] = ext.Value[2]
		}
		// teeSPL
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.2") {
			tee = fmt.Sprintf("teeSPL=%d&", ext.Value[2])
			tcbValues[1] = ext.Value[2]
		}
		// spl_4
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.4") {
			tcbValues[2] = ext.Value[2]
		}
		// spl_5
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.5") {
			tcbValues[3] = ext.Value[2]
		}
		// spl_6
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.6") {
			tcbValues[4] = ext.Value[2]
		}
		// spl_7
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.7") {
			tcbValues[5] = ext.Value[2]
		}
		// snpSPL
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.3") {
			snp = fmt.Sprintf("snpSPL=%d&", ext.Value[2])
			tcbValues[6] = ext.Value[2]
		}
		// ucodeSPL
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.8") {
			ucode = fmt.Sprintf("ucodeSPL=%d&", ext.Value[2])
			tcbValues[7] = ext.Value[2]
		}
	}
	u.RemoteTHIMServiceURL += hwid + ucode + snp + tee + bl

	return binary.LittleEndian.Uint64(tcbValues), nil
}

// format of the json provided to the UVM by hcsshim. Comes from the THIM endpoint
// and is a base64 encoded json string

type THIMCerts struct {
	VcekCert         string `json:"vcekCert"`
	Tcbm             string `json:"tcbm"`
	CertificateChain string `json:"certificateChain"`
	CacheControl     string `json:"cacheControl"`
}

func THIMtoPEM(encodedHostCertsFromTHIM string) (string, error) {
	hostCertsFromTHIM, err := base64.StdEncoding.DecodeString(encodedHostCertsFromTHIM)
	if err != nil {
		return "", errors.Wrapf(err, "base64 decoding platform certs failed")
	}

	if GenerateTestData {
		ioutil.WriteFile("uvm_host_amd_certificate.json", hostCertsFromTHIM, 0644)
	}

	var certsFromTHIM THIMCerts
	err = json.Unmarshal(hostCertsFromTHIM, &certsFromTHIM)
	if err != nil {
		return "", errors.Wrapf(err, "json unmarshal platform certs failed")
	}

	certsString := certsFromTHIM.VcekCert + certsFromTHIM.CertificateChain

	if GenerateTestData {
		ioutil.WriteFile("uvm_host_amd_certificate.pem", []byte(certsString), 0644)
	}

	logrus.Debugf("certsFromTHIM:\n\n%s\n\n", certsString)

	return certsString, nil
}

func GetUvmInformation() (UvmInformation, error) {
	var encodedUvmInformation UvmInformation
	encodedUvmInformation.RemoteTHIMServiceURL = os.Getenv("UVM_THIM_SERVICE_URL") + "/vcek/v1/"

	encodedHostCertsFromTHIM := os.Getenv("UVM_HOST_AMD_CERTIFICATE")

	if GenerateTestData {
		ioutil.WriteFile("uvm_thim_service_url.base64", []byte(encodedUvmInformation.RemoteTHIMServiceURL), 0644)
		ioutil.WriteFile("uvm_host_amd_certificate.base64", []byte(encodedHostCertsFromTHIM), 0644)
	}

	if encodedHostCertsFromTHIM != "" {
		certChain, err := THIMtoPEM(encodedHostCertsFromTHIM)
		if err != nil {
			return encodedUvmInformation, err
		}
		encodedUvmInformation.CertChain = certChain
	}
	encodedUvmInformation.EncodedSecurityPolicy = os.Getenv("UVM_SECURITY_POLICY")
	encodedUvmInformation.EncodedUvmReferenceInfo = os.Getenv("UVM_REFERENCE_INFO")

	if GenerateTestData {
		ioutil.WriteFile("uvm_security_policy.base64", []byte(encodedUvmInformation.EncodedSecurityPolicy), 0644)
		ioutil.WriteFile("uvm_reference_info.base64", []byte(encodedUvmInformation.EncodedUvmReferenceInfo), 0644)
	}

	return encodedUvmInformation, nil
}
