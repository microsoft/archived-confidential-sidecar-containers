// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package attest

/*
	This is not currently strictly required as these platform certificates from AMD are
	now provided by GCS to containers as an environment variable UVM_HOST_AMD_CERTIFICATE

	It is required for the tests and when running outside of Azure.
*/

import (
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"strconv"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/pkg/errors"
)

// Set to true to regenerate test files at every request.
// Also useful to debug the various steps, especially encoding
// to the correct base64url encoding.
const GenerateTestData = false

const (
	AzureCertCacheRequestURITemplate = "https://%s/%s/certificates/%s/%s?%s"
	AmdVCEKRequestURITemplate        = "https://%s/%s/%s?ucodeSPL=%d&snpSPL=%d&teeSPL=%d&blSPL=%d"
	AmdCertChainRequestURITemplate   = "https://%s/%s/cert_chain"
	AmdTHIMRequestURITemplate        = "https://%s/vcek/v1/%s/%s?ucodeSPL=%d&snpSPL=%d&teeSPL=%d&blSPL=%d"
)

// CertCache contains information about the certificate cache service
// that provides access to the certificate chain required upon attestation
type CertCache struct {
	AMD        bool   `json:"amd,omitempty"`
	THIM       bool   `json:"thim,omitempty"`
	Endpoint   string `json:"endpoint"`
	TEEType    string `json:"tee_type,omitempty"`
	APIVersion string `json:"api_version,omitempty"`
}

// retrieveCertChain interacts with the cert cache service to fetch the cert chain of the
// chip identified by chipId running firmware identified by reportedTCB. These attributes
// are retrived from the attestation report.
func (certCache CertCache) retrieveCertChain(chipID string, reportedTCB uint64) ([]byte, common.THIMCerts, error) {
	// HTTP GET request to cert cache service
	var uri string

	var thimCerts common.THIMCerts

	reportedTCBBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(reportedTCBBytes, reportedTCB)

	if certCache.AMD {
		// AMD cert cache endpoint returns the VCEK certificate in DER format
		uri = fmt.Sprintf(AmdVCEKRequestURITemplate, certCache.Endpoint, certCache.TEEType, chipID, reportedTCBBytes[7], reportedTCBBytes[6], reportedTCBBytes[1], reportedTCBBytes[0])
		httpResponse, err := common.HTTPGetRequest(uri, false)
		if err != nil {
			return nil, thimCerts, errors.Wrapf(err, "certcache http get request failed")
		}
		derBytes, err := common.HTTPResponseBody(httpResponse)
		if err != nil {
			return nil, thimCerts, err
		}
		// encode the VCEK cert in PEM format
		vcekPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

		// now retrieve the cert chain
		uri = fmt.Sprintf(AmdCertChainRequestURITemplate, certCache.Endpoint, certCache.TEEType)
		httpResponse, err = common.HTTPGetRequest(uri, false)
		if err != nil {
			return nil, thimCerts, errors.Wrapf(err, "certcache http get request failed")
		}
		certChainPEMBytes, err := common.HTTPResponseBody(httpResponse)
		if err != nil {
			return nil, thimCerts, errors.Wrapf(err, "pulling certchain response from get request failed")
		}

		// constuct full chain by appending the VCEK cert to the cert chain
		var fullCertChain []byte
		fullCertChain = append(fullCertChain, vcekPEMBytes[:]...)
		fullCertChain = append(fullCertChain, certChainPEMBytes[:]...)

		return fullCertChain, thimCerts, nil
	} else if certCache.THIM {
		// AMD THIM cert cache endpoint returns THIM Certs object
		// Is TEEType the same as productName in this case or should I add a field for that?
		uri = fmt.Sprintf(AmdTHIMRequestURITemplate, certCache.Endpoint, certCache.TEEType, chipID, reportedTCBBytes[7], reportedTCBBytes[6], reportedTCBBytes[1], reportedTCBBytes[0])
		httpResponse, err := common.HTTPGetRequest(uri, false)
		if err != nil {
			return nil, thimCerts, errors.Wrapf(err, "certcache http get request failed")
		}
		THIMCertsBytes, err := common.HTTPResponseBody(httpResponse)
		if err != nil {
			return nil, thimCerts, errors.Wrapf(err, "pulling certchain response from get request failed")
		}

		thimCerts, err = common.THIMtoPEM(string(THIMCertsBytes))
		if err != nil {
			return nil, thimCerts, err
		}

		// constuct full chain by appending the VCEK cert to the cert chain
		var fullCertChain []byte
		fullCertChain = append(fullCertChain, []byte(thimCerts.VcekCert)[:]...)
		fullCertChain = append(fullCertChain, []byte(thimCerts.CertificateChain)[:]...)
		return fullCertChain, thimCerts, nil
	} else {
		uri = fmt.Sprintf(AzureCertCacheRequestURITemplate, certCache.Endpoint, certCache.TEEType, chipID, strconv.FormatUint(reportedTCB, 16), certCache.APIVersion)
		httpResponse, err := common.HTTPGetRequest(uri, false)
		if err != nil {
			return nil, thimCerts, errors.Wrapf(err, "certcache http get request failed")
		}
		certChain, err := common.HTTPResponseBody(httpResponse)
		if err != nil {
			return nil, thimCerts, errors.Wrapf(err, "certcache http read response failed")
		}
		return certChain, thimCerts, nil
	}
}

func (certCache CertCache) GetCertChain(chipID string, reportedTCB uint64) ([]byte, common.THIMCerts, error) {
	return certCache.retrieveCertChain(chipID, reportedTCB)
}
