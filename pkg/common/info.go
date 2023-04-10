// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"

	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Set to true to regenerate test files at every request.
// Also useful to debug the various steps, especially encoding
// to the correct base64url encoding.

const GenerateTestData = false

type UvmInformation struct {
	EncodedSecurityPolicy   string    // customer security policy
	CertChain               string    // platform certificates for the actual physical host, ascii PEM
	EncodedUvmReferenceInfo string    // endorsements for the particular UVM image
	ThimCerts               THIMCerts // THIM Certs for the particular UVM image
}

// format of the json provided to the UVM by hcsshim. Comes from the THIM endpoint
// and is a base64 encoded json string
type THIMCerts struct {
	VcekCert         string `json:"vcekCert"`
	Tcbm             string `json:"tcbm"`
	CertificateChain string `json:"certificateChain"`
	CacheControl     string `json:"cacheControl"`
}

func THIMtoPEM(encodedHostCertsFromTHIM string) (THIMCerts, error) {
	var certsFromTHIM THIMCerts
	hostCertsFromTHIM, err := base64.StdEncoding.DecodeString(encodedHostCertsFromTHIM)
	if err != nil {
		return certsFromTHIM, errors.Wrapf(err, "base64 decoding platform certs failed")
	}

	if GenerateTestData {
		ioutil.WriteFile("uvm_host_amd_certificate.json", hostCertsFromTHIM, 0644)
	}

	err = json.Unmarshal(hostCertsFromTHIM, &certsFromTHIM)
	if err != nil {
		return certsFromTHIM, errors.Wrapf(err, "json unmarshal platform certs failed")
	}

	return certsFromTHIM, nil
}

func GetUvmInformation() (UvmInformation, error) {
	var encodedUvmInformation UvmInformation

	encodedHostCertsFromTHIM := os.Getenv("UVM_HOST_AMD_CERTIFICATE")

	if GenerateTestData {
		ioutil.WriteFile("uvm_host_amd_certificate.base64", []byte(encodedHostCertsFromTHIM), 0644)
	}

	if encodedHostCertsFromTHIM != "" {
		certsFromTHIM, err := THIMtoPEM(encodedHostCertsFromTHIM)
		if err != nil {
			return encodedUvmInformation, err
		}
		encodedUvmInformation.ThimCerts = certsFromTHIM
		certsString := certsFromTHIM.VcekCert + certsFromTHIM.CertificateChain

		if GenerateTestData {
			ioutil.WriteFile("uvm_host_amd_certificate.pem", []byte(certsString), 0644)
		}

		logrus.Debugf("certsFromTHIM:\n\n%s\n\n", certsString)
		encodedUvmInformation.CertChain = certsString
	}
	encodedUvmInformation.EncodedSecurityPolicy = os.Getenv("UVM_SECURITY_POLICY")
	encodedUvmInformation.EncodedUvmReferenceInfo = os.Getenv("UVM_REFERENCE_INFO")

	if GenerateTestData {
		ioutil.WriteFile("uvm_security_policy.base64", []byte(encodedUvmInformation.EncodedSecurityPolicy), 0644)
		ioutil.WriteFile("uvm_reference_info.base64", []byte(encodedUvmInformation.EncodedUvmReferenceInfo), 0644)
	}

	return encodedUvmInformation, nil
}
