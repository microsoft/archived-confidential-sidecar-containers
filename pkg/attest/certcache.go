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

const (
	AzureCertCacheRequestURITemplate = "https://%s/%s/certificates/%s/%s?%s"
	AmdVCEKRequestURITemplate        = "https://%s/%s/%s?ucodeSPL=%d&snpSPL=%d&teeSPL=%d&blSPL=%d"
	AmdCertChainRequestURITemplate   = "https://%s/%s/cert_chain"
)

const (
	BlSplTcbmByteIndex    = 0
	TeeSplTcbmByteIndex   = 1
	SnpSplTcbmByteIndex   = 6
	UcodeSplTcbmByteIndex = 7
)

// CertCache contains information about the certificate cache service
// that provides access to the certificate chain required upon attestation
type CertCache struct {
	AMD        bool   `json:"amd,omitempty"`
	Endpoint   string `json:"endpoint"`
	TEEType    string `json:"tee_type,omitempty"`
	APIVersion string `json:"api_version,omitempty"`
}

// retrieveCertChain interacts with the cert cache service to fetch the cert chain of the
// chip identified by chipId running firmware identified by reportedTCB. These attributes
// are retrived from the attestation report.
// Returns the cert chain as a bytes array, the TCBM from the local THIM cert cache is as a string
// (only in the case of a local THIM endpoint), and any errors encountered
func (certCache CertCache) retrieveCertChain(chipID string, reportedTCB uint64, localThimUri string) ([]byte, uint64, error) {
	// HTTP GET request to cert cache service
	var uri string
	var thimTcbm uint64

	reportedTCBBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(reportedTCBBytes, reportedTCB)

	if certCache.AMD {
		// AMD cert cache endpoint returns the VCEK certificate in DER format
		uri = fmt.Sprintf(AmdVCEKRequestURITemplate, certCache.Endpoint, certCache.TEEType, chipID, reportedTCBBytes[UcodeSplTcbmByteIndex], reportedTCBBytes[SnpSplTcbmByteIndex], reportedTCBBytes[TeeSplTcbmByteIndex], reportedTCBBytes[BlSplTcbmByteIndex])
		httpResponse, err := common.HTTPGetRequest(uri, false)
		if err != nil {
			return nil, thimTcbm, errors.Wrapf(err, "certcache http get request failed")
		}
		derBytes, err := common.HTTPResponseBody(httpResponse)
		if err != nil {
			return nil, thimTcbm, err
		}
		// encode the VCEK cert in PEM format
		vcekPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

		// now retrieve the cert chain
		uri = fmt.Sprintf(AmdCertChainRequestURITemplate, certCache.Endpoint, certCache.TEEType)
		httpResponse, err = common.HTTPGetRequest(uri, false)
		if err != nil {
			return nil, thimTcbm, errors.Wrapf(err, "certcache http get request failed")
		}
		certChainPEMBytes, err := common.HTTPResponseBody(httpResponse)
		if err != nil {
			return nil, thimTcbm, errors.Wrapf(err, "pulling certchain response from get request failed")
		}

		// constuct full chain by appending the VCEK cert to the cert chain
		fullCertChain := append(vcekPEMBytes, certChainPEMBytes[:]...)

		return fullCertChain, thimTcbm, nil
	} else if certCache.TEEType == "LocalTHIM" && localThimUri != "" {
		// local THIM cert cache endpoint returns THIM Certs object
		httpResponse, err := common.HTTPGetRequest(localThimUri, false)
		if err != nil {
			return nil, thimTcbm, errors.Wrapf(err, "certcache http get request failed")
		}
		THIMCertsBytes, err := common.HTTPResponseBody(httpResponse)
		if err != nil {
			return nil, thimTcbm, errors.Wrapf(err, "pulling certchain response from get request failed")
		}

		thimCerts, thimTcbm, err := common.THIMtoPEM(string(THIMCertsBytes))
		if err != nil {
			return nil, thimTcbm, err
		}

		return []byte(thimCerts), thimTcbm, nil
	} else {
		uri = fmt.Sprintf(AzureCertCacheRequestURITemplate, certCache.Endpoint, certCache.TEEType, chipID, strconv.FormatUint(reportedTCB, 16), certCache.APIVersion)
		httpResponse, err := common.HTTPGetRequest(uri, false)
		if err != nil {
			return nil, thimTcbm, err
		}
		certChain, err := common.HTTPResponseBody(httpResponse)
		if err != nil {
			return nil, thimTcbm, err
		}
		return certChain, thimTcbm, nil
	}
}

func (certCache CertCache) GetCertChain(chipID string, reportedTCB uint64, localThimUri string) ([]byte, uint64, error) {
	return certCache.retrieveCertChain(chipID, reportedTCB, localThimUri)
}
