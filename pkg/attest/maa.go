// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package attest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"time"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	AttestRequestURITemplate = "https://%s/attest/%s?%s"
)

// MAA contains information about the MAA service that acts as an authority
// for managed HSM service
type MAA struct {
	Endpoint   string `json:"endpoint"`
	TEEType    string `json:"tee_type,omitempty"`
	APIVersion string `json:"api_version,omitempty"`
}

// MAA SNP Request Body class
type maaReport struct {
	UvmEndorsements string `json:"Endorsements"`
	SNPReport       string `json:"SnpReport"`
	CertChain       string `json:"VcekCertChain"`
}

type attestedData struct {
	Data     string `json:"data"`
	DataType string `json:"dataType"`
}

type attestSNPRequestBody struct {
	Report       string       `json:"report"`
	RuntimeData  attestedData `json:"runtimeData"`  // lowecase t
	InittimeData attestedData `json:"initTimeData"` // upercase T
	Nonce        uint64       `json:"nonce"`
}

// newAttestSNPRequestBody constructs a MAA attest request. It contains (i) the base64
// URL encoding of a bundle containing the hardware attestation report (SNPReport)
// and the certificate chain, (ii) the  runtime data (base64 URL encoding of the public
// wrapping key), (iii) the inittime data (base64 URL encoding of the security policy),
// and (iv) a nonce
func newAttestSNPRequestBody(encodedUvmReferenceInfo string, snpAttestationReport, vcekCertChain, policyBlob, keyBlob []byte) (*attestSNPRequestBody, error) {
	var request attestSNPRequestBody

	ioutil.WriteFile("body.uvm_reference_info.base64", []byte(encodedUvmReferenceInfo), 0644)
	// MAA wants the endorsements (aka the cosesign1 reference_info.cose) as base64Url not base64
	uvmReferenceInfo, err := base64.StdEncoding.DecodeString(encodedUvmReferenceInfo)
	if err != nil {
		return nil, errors.Wrapf(err, "base64 decoding uvm reference info failed")
	}
	ioutil.WriteFile("body.uvm_reference_info.bin", uvmReferenceInfo, 0644)
	base64urlEncodedUvmReferenceInfo := base64.URLEncoding.EncodeToString(uvmReferenceInfo)
	ioutil.WriteFile("body.uvm_reference_info.base64url", []byte(base64urlEncodedUvmReferenceInfo), 0644)

	// the maa report is a bundle of the signed attestation report and
	// the cert chain that endorses the signing key
	maaReport := maaReport{
		UvmEndorsements: base64urlEncodedUvmReferenceInfo,
		SNPReport:       base64.URLEncoding.EncodeToString(snpAttestationReport),
		CertChain:       base64.URLEncoding.EncodeToString(vcekCertChain),
	}

	maaReportJSONBytes, err := json.Marshal(maaReport)
	if err != nil {
		return nil, errors.Wrapf(err, "marhalling maa Report field failed")
	}
	ioutil.WriteFile("body.maa_report.json", maaReportJSONBytes, 0644)

	request.Report = base64.URLEncoding.EncodeToString(maaReportJSONBytes)
	ioutil.WriteFile("body.report.base64url", []byte(request.Report), 0644)

	logrus.Printf("\nrequest.Report\n\n%s\n\n", request.Report)

	// the key blob is passed as runtime data
	request.RuntimeData = attestedData{
		Data:     base64.URLEncoding.EncodeToString(keyBlob),
		DataType: "binary", // could be JSON - see https://learn.microsoft.com/en-us/rest/api/attestation/attestation/attest-sev-snp-vm?tabs=HTTP#datatype
	}

	logrus.Printf("\nrequest.RuntimeData\n\n%v\n\n", request.RuntimeData)

	// the policy blob is passed as inittime data
	if policyBlob != nil {
		request.InittimeData = attestedData{
			Data:     base64.URLEncoding.EncodeToString(policyBlob),
			DataType: "binary", // rego, never JSON
		}
	}
	logrus.Printf("\nrequest.InittimeData\n\n%v\n\n", request.InittimeData)

	rand.Seed(time.Now().UnixNano())
	request.Nonce = rand.Uint64()

	return &request, nil
}

// attest interracts with MAA to fetch an MAA token. A valid MAA attest request requires a
// cert chain that endorses the signing key of the attestation report, the hardware attestation
// report, and additional evidence, including the policy blob and the key blob, whose hash have
// been included in the HOST_DATA and REPORT_DATA fields of the attestation report, respectively.
//
// MAA validates the signature of the attestation report using the public key of the leaf
// certificate of the cert chain, validates the cert chain, and finally validates the additional
// evidence against the HOST_DATA and REPORT_DATA fields of the validated attestation report.
// Upon successful attestation, MAA issues an MAA token which presents the policy blob as inittime
// claims and the key blob as runtime claims.
func (maa MAA) attest(encodedUvmReferenceInfo string, SNPReportHexBytes []byte, vcekCertChain []byte, policyBlobBytes []byte, keyBlobBytes []byte) (MAAToken string, err error) {
	// Construct attestation request that contain the four attributes
	request, err := newAttestSNPRequestBody(encodedUvmReferenceInfo, SNPReportHexBytes, vcekCertChain, policyBlobBytes, keyBlobBytes)
	if err != nil {
		return "", errors.Wrapf(err, "creating new AttestSNPRequestBody failed")
	}

	maaRequestJSONData, err := json.Marshal(request)
	if err != nil {
		return "", errors.Wrapf(err, "marshalling maa request failed")
	}
	logrus.Debugf("MAA Request: %s\n", string(maaRequestJSONData))
	ioutil.WriteFile("request.json", maaRequestJSONData, 0644)

	// HTTP POST request to MAA service
	uri := fmt.Sprintf(AttestRequestURITemplate, maa.Endpoint, maa.TEEType, maa.APIVersion)
	httpResponse, err := common.HTTPPRequest("POST", uri, maaRequestJSONData, "")
	if err != nil {
		return "", errors.Wrapf(err, "maa post request failed")
	}

	httpResponseBodyBytes, err := common.HTTPResponseBody(httpResponse)
	if err != nil {
		logrus.Debugf("MAA Response header: %v", httpResponse)
		logrus.Debugf("MAA Response body bytes: %s", string(httpResponseBodyBytes))
		return "", errors.Wrapf(err, "pulling maa post response failed")
	}

	// Retrieve MAA token from the JWT response returned by MAA
	var maaResponse struct {
		Token string
	}

	if err = json.Unmarshal(httpResponseBodyBytes, &maaResponse); err != nil {
		return "", errors.Wrapf(err, "unmarshalling maa http response body failed")
	}

	if maaResponse.Token == "" {
		return "", errors.New("empty token string in maa response")
	}

	logrus.Debugf("MAA Token: %s", maaResponse.Token)
	return maaResponse.Token, nil
}
