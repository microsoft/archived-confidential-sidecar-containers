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
	"net/url"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Set to true to regenerate test files at every request.
// Also useful to debug the various steps, especially encoding
// to the correct base64url encoding.

const GenerateTestData = false

// can't find any documentation on why the 3rd byte of the Certificate.Extensions byte array is the one that matters
// all the byte arrays for the tcb values are of length 3 and fit the format [2 1 IMPORTANT_VALUE]
const x509CertExtensionsValuePos = 2

// TCB byte array index values
const TcbBlSpl = 0
const TcbTeeSpl = 1
const TcbSpl_4 = 2
const TcbSpl_5 = 3
const TcbSpl_6 = 4
const TcbSpl_7 = 5
const TcbSnpSpl = 6
const TcbUcodeSpl = 7

// Information supplied by the UVM specific to running Pod

type UvmInformation struct {
	EncodedSecurityPolicy   string   // customer security policy
	CertChain               string   // platform certificates for the actual physical host, ascii PEM
	EncodedUvmReferenceInfo string   // endorsements for the particular UVM image
	RemoteTHIMServiceURL    *url.URL `json:",omitempty"` // URL where the remote THIM service is found
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
	resp, err := HTTPGetRequest(u.RemoteTHIMServiceURL.String(), false)
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
	v := url.Values{}
	var hwid string //, ucode, bl, tee, snp string
	// parse extensions to update the THIM URL and get TCB Version
	for _, ext := range vcekCert.Extensions {
		fmt.Println(ext.Value)
		// productName
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.2") {
			u.RemoteTHIMServiceURL.Path += string(ext.Value) + "/"
		}
		// HwID
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.4") {
			hwid = hex.EncodeToString(ext.Value) + "?"
		}
		// blSPL
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.1") {
			//bl = fmt.Sprintf("blSPL=%d", ext.Value[2])
			v.Set("blSPL", fmt.Sprintf("%d", ext.Value[x509CertExtensionsValuePos]))
			tcbValues[TcbBlSpl] = ext.Value[x509CertExtensionsValuePos]
		}
		// teeSPL
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.2") {
			//tee = fmt.Sprintf("teeSPL=%d&", ext.Value[2])
			v.Set("teeSPL", fmt.Sprintf("%d", ext.Value[x509CertExtensionsValuePos]))
			tcbValues[TcbTeeSpl] = ext.Value[x509CertExtensionsValuePos]
		}
		// spl_4
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.4") {
			tcbValues[TcbSpl_4] = ext.Value[x509CertExtensionsValuePos]
		}
		// spl_5
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.5") {
			tcbValues[TcbSpl_5] = ext.Value[x509CertExtensionsValuePos]
		}
		// spl_6
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.6") {
			tcbValues[TcbSpl_6] = ext.Value[x509CertExtensionsValuePos]
		}
		// spl_7
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.7") {
			tcbValues[TcbSpl_7] = ext.Value[x509CertExtensionsValuePos]
		}
		// snpSPL
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.3") {
			//snp = fmt.Sprintf("snpSPL=%d&", ext.Value[2])
			v.Set("snpSPL", fmt.Sprintf("%d", ext.Value[x509CertExtensionsValuePos]))
			tcbValues[TcbSnpSpl] = ext.Value[x509CertExtensionsValuePos]
		}
		// ucodeSPL
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.3704.1.3.8") {
			//ucode = fmt.Sprintf("ucodeSPL=%d&", ext.Value[2])
			v.Set("ucodeSPL", fmt.Sprintf("%d", ext.Value[x509CertExtensionsValuePos]))
			tcbValues[TcbUcodeSpl] = ext.Value[x509CertExtensionsValuePos]
		}
	}
	u.RemoteTHIMServiceURL.Path += hwid
	u.RemoteTHIMServiceURL.RawQuery = v.Encode()
	// getting the string value ends up looking like: https://americas.test.acccache.azure.net/vcek/v1/%16%08Milan-A0/e6c86796cd44b0bc6b7c0d4fdab33e2807e14b5fc4538b3750921169d97bcf4447c7d3ab2a7c25f74c1641e2885c1011d025cc536f5c9a2504713136c7877f48%3F?blSPL=0&snpSPL=0&teeSPL=0&ucodeSPL=49
	// it has the correct parameters, but the additional %16, %3F etc. addeded to the path values are not part of the path when you print it separately
	// fmt.Println(u.RemoteTHIMServiceURL.String())

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
	var err error
	encodedUvmInformation.RemoteTHIMServiceURL, err = url.Parse(os.Getenv("UVM_THIM_SERVICE_URL") + "/vcek/v1/")

	encodedHostCertsFromTHIM := os.Getenv("UVM_HOST_AMD_CERTIFICATE")

	if GenerateTestData {
		ioutil.WriteFile("uvm_thim_service_url.base64", []byte(encodedUvmInformation.RemoteTHIMServiceURL.String()), 0644)
		ioutil.WriteFile("uvm_host_amd_certificate.base64", []byte(encodedHostCertsFromTHIM), 0644)
	}

	if encodedHostCertsFromTHIM != "" {
		var certChain string
		certChain, err = THIMtoPEM(encodedHostCertsFromTHIM)
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
