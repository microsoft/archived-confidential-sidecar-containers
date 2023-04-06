// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package attest

import (
	"encoding/base64"
	"encoding/hex"

	"io/ioutil"
	"os"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// RawAttest returns the raw attestation report in hex string format
func RawAttest(inittimeDataBytes []byte, runtimeDataBytes []byte) (string, error) {
	// check if sev device exists on the platform; if not fetch fake snp report
	var fetchRealSNPReport bool
	if _, err := os.Stat("/dev/sev"); os.IsNotExist(err) {
		fetchRealSNPReport = false
	} else {
		fetchRealSNPReport = true
	}

	SNPReportBytes, err := FetchSNPReport(fetchRealSNPReport, runtimeDataBytes, inittimeDataBytes)
	if err != nil {
		return "", errors.Wrapf(err, "fetching snp report failed")
	}

	logrus.Debugf("   SNPReportBytes:    %v", SNPReportBytes)

	return hex.EncodeToString(SNPReportBytes), nil
}

// Attest interacts with maa services to fetch an MAA token
// MAA expects four attributes:
// (A) the attestation report signed by the PSP signing key
// (B) a certificate chain that endorses the signing key of the attestation report
// (C) reference information that provides evidence that the UVM image is genuine.
// (D) inittime data: this is the policy blob that has been hashed by the host OS during the utility
//
//	VM bringup and has been reported by the PSP in the attestation report as HOST DATA
//
// (E) runtime data: for example it may be a wrapping key blob that has been hashed during the attestation report
//
//	retrieval and has been reported by the PSP in the attestation report as REPORT DATA
func Attest(maa MAA, runtimeDataBytes []byte, uvmInformation common.UvmInformation) (string, error) {
	// Fetch the attestation report

	// check if sev device exists on the platform; if not fetch fake snp report
	var fetchRealSNPReport bool
	if _, err := os.Stat("/dev/sev"); os.IsNotExist(err) {
		fetchRealSNPReport = false
	} else {
		fetchRealSNPReport = true
	}

	inittimeDataBytes, err := base64.StdEncoding.DecodeString(uvmInformation.EncodedSecurityPolicy)
	if err != nil {
		return "", errors.Wrap(err, "decoding policy from Base64 format failed")
	}
	logrus.Debugf("   inittimeDataBytes:    %v", inittimeDataBytes)

	SNPReportBytes, err := FetchSNPReport(fetchRealSNPReport, runtimeDataBytes, inittimeDataBytes)
	if err != nil {
		return "", errors.Wrapf(err, "fetching snp report failed")
	}

	if common.GenerateTestData {
		ioutil.WriteFile("snp_report.bin", SNPReportBytes, 0644)
	}

	logrus.Debugf("   SNPReportBytes:    %v", SNPReportBytes)

	// Retrieve the certificate chain using the chip identifier and platform version
	// fields of the attestation report
	var SNPReport SNPAttestationReport
	if err := SNPReport.DeserializeReport(SNPReportBytes); err != nil {
		return "", errors.Wrapf(err, "failed to deserialize attestation report")
	}

	// check that the TCB of the cert chain matches that reported so we fail early or
	// fetch certs again if the TCB has changed
	var vcekTCBVersion uint64
	vcekTCBVersion, err = uvmInformation.ParseVCEK()
	if err != nil {
		return "", errors.Wrap(err, "parsing VCEK failed")
	}
	// If the VCEK TCB version does not match the attestation report ReportedTCB
	if vcekTCBVersion != SNPReport.ReportedTCB {
		// Clear the cached CertChain
		uvmInformation.CertChain = ""
		// RefreshVCEK
		err = uvmInformation.RefreshVCEK()
		if err != nil {
			return "", errors.Wrap(err, "refreshing VCEK failed")
		}
		// do the comparison again
		vcekTCBVersion, err = uvmInformation.ParseVCEK()
		if err != nil {
			return "", errors.Wrap(err, "parsing VCEK failed on retry")
		}
		// If the refresh does not work, fail
		if vcekTCBVersion != SNPReport.ReportedTCB {
			return "", errors.Wrap(err, "VCEK TCB version does not match the attestation report ReportedTCB")
		}
	}

	vcekCertChain := []byte(uvmInformation.CertChain)

	/* TODO: to support use outside of Azure add code to fetch the AMD certs here */

	uvmReferenceInfoBytes, err := base64.StdEncoding.DecodeString(uvmInformation.EncodedUvmReferenceInfo)

	if err != nil {
		return "", errors.Wrap(err, "decoding policy from Base64 format failed")
	}

	// Retrieve the MAA token required by the request's MAA endpoint
	maaToken, err := maa.attest(SNPReportBytes, vcekCertChain, inittimeDataBytes, runtimeDataBytes, uvmReferenceInfoBytes)
	if err != nil || maaToken == "" {
		return "", errors.Wrapf(err, "retrieving MAA token from MAA endpoint failed")
	}

	return maaToken, nil
}
