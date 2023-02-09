// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"encoding/base64"
	"encoding/json"

	// "io/ioutil" needed when generating test data
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Information supplied by the UVM specific to running Pod

type UvmInformation struct {
	EncodedSecurityPolicy   string // customer security policy
	CertChain               string // platform certificates for the actual physical host, ascii PEM
	EncodedUvmReferenceInfo string // endorsements for the particular UVM image
}

// format of the json provided to the UVM by hcsshim. Comes fro the THIM endpoint
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

	// ioutil.WriteFile("uvm_host_amd_certificate.json", hostCertsFromTHIM, 0644)

	var certsFromTHIM THIMCerts
	err = json.Unmarshal(hostCertsFromTHIM, &certsFromTHIM)
	if err != nil {
		return "", errors.Wrapf(err, "json unmarshal platform certs failed")
	}

	certsString := certsFromTHIM.VcekCert + certsFromTHIM.CertificateChain

	// ioutil.WriteFile("uvm_host_amd_certificate.pem", []byte(certsString), 0644)
	logrus.Debugf("certsFromTHIM:\n\n%s\n\n", certsString)

	return certsString, nil
}

func GetUvmInfomation() (UvmInformation, error) {
	var encodedUvmInformation UvmInformation
	encodedHostCertsFromTHIM := os.Getenv("UVM_HOST_AMD_CERTIFICATE")
	// ioutil.WriteFile("uvm_host_amd_certificate.base64", []byte(encodedHostCertsFromTHIM), 0644)

	if encodedHostCertsFromTHIM != "" {
		certChain, err := THIMtoPEM(encodedHostCertsFromTHIM)
		if err != nil {
			return encodedUvmInformation, err
		}
		encodedUvmInformation.CertChain = certChain
	}
	encodedUvmInformation.EncodedSecurityPolicy = os.Getenv("UVM_SECURITY_POLICY")
	// ioutil.WriteFile("uvm_security_policy.base64", []byte(encodedUvmInformation.EncodedSecurityPolicy), 0644)
	encodedUvmInformation.EncodedUvmReferenceInfo = os.Getenv("UVM_REFERENCE_INFO")
	// ioutil.WriteFile("uvm_reference_info.base64", []byte(encodedUvmInformation.EncodedUvmReferenceInfo), 0644)

	return encodedUvmInformation, nil
}
