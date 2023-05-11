// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package attest

import (
	"encoding/base64"
	"fmt"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// CertState contains information about the certificate cache service
// that provides access to the certificate chain required upon attestation
type CertState struct {
	CertFetcher CertFetcher `json:"cert_cache"`
	Tcbm        uint64      `json:"tcbm"`
}

func (certState *CertState) RefreshCertChain(SNPReport SNPAttestationReport) ([]byte, error) {
	// TCB values not the same, try refreshing cert first
	vcekCertChain, thimTcbm, err := certState.CertFetcher.GetCertChain(SNPReport.ChipID, SNPReport.ReportedTCB)
	if err != nil {
		return nil, errors.Wrap(err, "refreshing CertChain failed")
	}
	certState.Tcbm = thimTcbm
	return vcekCertChain, nil
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
func (certState *CertState) Attest(maa MAA, runtimeDataBytes []byte, uvmInformation common.UvmInformation) (string, error) {
	inittimeDataBytes, err := base64.StdEncoding.DecodeString(uvmInformation.EncodedSecurityPolicy)
	if err != nil {
		return "", errors.Wrap(err, "decoding policy from Base64 format failed")
	}
	logrus.Debugf("   inittimeDataBytes:    %v", inittimeDataBytes)

	// Fetch the attestation report
	// PR_COMMENT: I guess there is no use case to use MAA with fake attestation report, so I am hard-coding to use Real AttestationReportFetcher
	reportFetcher := NewAttestationReportFetcher()
	reportData := GenerateMAAReportData(runtimeDataBytes)
	SNPReportBytes, err := reportFetcher.FetchAttestationReportByte(reportData)
	if err != nil {
		return "", errors.Wrapf(err, "failed to retrieve attestation report")
	}

	// Retrieve the certificate chain using the chip identifier and platform version
	// fields of the attestation report
	var SNPReport SNPAttestationReport
	if err = SNPReport.DeserializeReport(SNPReportBytes); err != nil {
		return "", errors.Wrapf(err, "failed to deserialize attestation report")
	}

	logrus.Debugf("SNP Report Reported TCB: %d\nCert Chain TCBM Value: %d\n", SNPReport.ReportedTCB, certState.Tcbm)

	// At this point check that the TCB of the cert chain matches that reported so we fail early or
	// fetch fresh certs by other means.
	var vcekCertChain []byte
	if SNPReport.ReportedTCB != certState.Tcbm {
		// TCB values not the same, try refreshing cert cache first
		vcekCertChain, err = certState.RefreshCertChain(SNPReport)
		if err != nil {
			return "", err
		}

		if SNPReport.ReportedTCB != certState.Tcbm {
			// TCB values still don't match, try retrieving the SNP report again
			SNPReportBytes, err := reportFetcher.FetchAttestationReportByte(reportData)
			if err != nil {
				return "", errors.Wrapf(err, "failed to retrieve new attestation report")
			}

			if err = SNPReport.DeserializeReport(SNPReportBytes); err != nil {
				return "", errors.Wrapf(err, "failed to deserialize new attestation report")
			}

			// refresh certs again
			vcekCertChain, err = certState.RefreshCertChain(SNPReport)
			if err != nil {
				return "", err
			}

			// if no match after refreshing certs and attestation report, fail
			if SNPReport.ReportedTCB != certState.Tcbm {
				return "", errors.New(fmt.Sprintf("SNP reported TCB value: %d doesn't match Certificate TCB value: %d", SNPReport.ReportedTCB, certState.Tcbm))
			}
		}
	} else {
		certString := uvmInformation.InitialCerts.VcekCert + uvmInformation.InitialCerts.CertificateChain
		vcekCertChain = []byte(certString)
	}

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
