// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package attest

import (
	"bytes"
	_ "embed"
	"testing"

	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/pkg/errors"
)

/*
	data/ contains data logged from an instance running in production Azure instance, talking to a preprod MAA
	      thus all the certs, report etc are genuine.
*/

//go:embed test_data/uvm_security_policy.base64
var uvm_security_policy_base64 string

var uvm_security_policy_bin []byte

//go:embed test_data/body.uvm_reference_info.bin
var uvm_reference_info_bin []byte // generated by the query version

//go:embed test_data/uvm_host_amd_certificate.pem
var amd_certificate_pem string

//go:embed test_data/snp_report.bin
var snp_report_bin []byte

// the json to be passed as runtime claims.
var runtimedata_json_base64 string = "ewogICAiYWtleSIgOiAiYXZhbHVlIgp9Cg=="

// as a string presented through the api
var runtimedata_json_bin []byte

func Test_SNP(t *testing.T) {

	TestSNPReport := SNPAttestationReport{
		Version:          1,
		GuestSvn:         1,
		Policy:           196639,
		FamilyID:         "01000000000000000000000000000000",
		ImageID:          "02000000000000000000000000000000",
		VMPL:             0,
		SignatureAlgo:    1,
		PlatformVersion:  3530822107858468864,
		PlatformInfo:     1,
		AuthorKeyEn:      0,
		Reserved1:        0,
		ReportData:       "7ab000a323b3c873f5b81bbe584e7c1a26bcf40dc27e00f8e0d144b1ed2d14f10000000000000000000000000000000000000000000000000000000000000000",
		Measurement:      "b579c7d6b89f3914659abe09a004a58a1e77846b65bbdac9e29bd8f2f31b31af445a5dd40f76f71ecdd73117f1d592a3",
		HostData:         "8c19f1b6eee8658fbf8ff1b37f603c38929896b1cc813583bbfb21015b7aa66d",
		IDKeyDigest:      "d188ac79386022aec7aa4e72a7e87b0a8e0e8009183334bb0fe4f97ed89436f360b3644cd8382c7a14531a87b81a8f36",
		AuthorKeyDigest:  "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		ReportID:         "2e880add9a31077e5e8f3568b4c4451f0fea4372f66e3df3c0ca3ba26f447db2",
		ReportIDMA:       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		ReportedTCB:      3530822107858468864,
		Reserved2:        "000000000000000000000000000000000000000000000000",
		ChipID:           "e6c86796cd44b0bc6b7c0d4fdab33e2807e14b5fc4538b3750921169d97bcf4447c7d3ab2a7c25f74c1641e2885c1011d025cc536f5c9a2504713136c7877f48",
		CommittedSvn:     0,
		CommittedVersion: 0,
		LaunchSvn:        0,
		Reserved3:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		Signature:        "247c7525e84623db9868fccf00faab22229d60aaa380213108f8875011a8f456231c5371277cc706733f4a483338fb59000000000000000000000000000000000000000000000000ed8c62254022f64630ebf97d66254dee04f708ecbe22387baf8018752fadc2b763f64bded65c94a325b6b9f22ebbb0d80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	TestSNPReportBytes, _ := hex.DecodeString("01000000010000001f00030000000000010000000000000000000000000000000200000000000000000000000000000000000000010000000000000000000031010000000000000000000000000000007ab000a323b3c873f5b81bbe584e7c1a26bcf40dc27e00f8e0d144b1ed2d14f10000000000000000000000000000000000000000000000000000000000000000b579c7d6b89f3914659abe09a004a58a1e77846b65bbdac9e29bd8f2f31b31af445a5dd40f76f71ecdd73117f1d592a38c19f1b6eee8658fbf8ff1b37f603c38929896b1cc813583bbfb21015b7aa66dd188ac79386022aec7aa4e72a7e87b0a8e0e8009183334bb0fe4f97ed89436f360b3644cd8382c7a14531a87b81a8f360000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e880add9a31077e5e8f3568b4c4451f0fea4372f66e3df3c0ca3ba26f447db2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000031000000000000000000000000000000000000000000000000e6c86796cd44b0bc6b7c0d4fdab33e2807e14b5fc4538b3750921169d97bcf4447c7d3ab2a7c25f74c1641e2885c1011d025cc536f5c9a2504713136c7877f48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000247c7525e84623db9868fccf00faab22229d60aaa380213108f8875011a8f456231c5371277cc706733f4a483338fb59000000000000000000000000000000000000000000000000ed8c62254022f64630ebf97d66254dee04f708ecbe22387baf8018752fadc2b763f64bded65c94a325b6b9f22ebbb0d80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

	type testcase struct {
		name string

		SNPReport      *SNPAttestationReport
		SNPReportBytes []byte

		expectedContent interface{}
		expectedError   error
		expectErr       bool
	}

	testcases := []*testcase{
		// SerializeReport_Success passes the testing if the error returned is nil and the returned content matches the expected one
		{
			name: "SerializeReport_Success",

			SNPReport:      &TestSNPReport,
			SNPReportBytes: nil,

			expectedContent: TestSNPReportBytes,

			expectedError: nil,
			expectErr:     false,
		},
		// DeseerializeReport_Succes passes the testing if it does not receive error and the returned content matches the expected one
		{
			name: "DeserializeReport_Success",

			SNPReport:      nil,
			SNPReportBytes: TestSNPReportBytes,

			expectedContent: TestSNPReport,

			expectedError: nil,
			expectErr:     false,
		},
		// DeserializeReport_InvalidSize passes the testing if it receives the expected error
		{
			name: "DeserializeReport_InvalidSize",

			SNPReport:      nil,
			SNPReportBytes: make([]byte, 4),

			expectedError: errors.Errorf("invalid snp report size"),
			expectErr:     true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			if tc.SNPReportBytes == nil {
				// this is a Serialize Test
				mySNPReportBytes, err := tc.SNPReport.SerializeReport()

				if tc.expectErr {
					if err == nil {
						t.Fatal("expected err but got nil")
					} else if err.Error() != tc.expectedError.Error() {
						t.Fatalf("expected %q got %q", tc.expectedError.Error(), err.Error())
					}
				} else {
					if err != nil {
						t.Fatalf("did not expect err got %q", err.Error())
					} else if !bytes.Equal(tc.expectedContent.([]byte), mySNPReportBytes) {
						t.Fatalf("expected %q got %q", tc.expectedContent.([]byte), tc.SNPReportBytes)
					}
				}

			} else {
				// this is a Deserialize Test
				var mySNPReport SNPAttestationReport
				err := mySNPReport.DeserializeReport(tc.SNPReportBytes)

				if tc.expectErr {
					if err == nil {
						t.Fatal("expected err but got nil")
					} else if err.Error() != tc.expectedError.Error() {
						t.Fatalf("expected %q got %q", tc.expectedError.Error(), err.Error())
					}
				} else {
					if err != nil {
						t.Fatalf("did not expect err got %q", err.Error())
					} else if tc.expectedContent.(SNPAttestationReport) != mySNPReport {
						t.Fatalf("expected %v got %v", tc.expectedContent.(SNPAttestationReport), mySNPReport)
					}
				}
			}
		})
	}
}

func Test_CertCache(t *testing.T) {
	TestSNPReportBytes, _ := hex.DecodeString("01000000010000001f00030000000000010000000000000000000000000000000200000000000000000000000000000000000000010000000000000000000031010000000000000000000000000000007ab000a323b3c873f5b81bbe584e7c1a26bcf40dc27e00f8e0d144b1ed2d14f10000000000000000000000000000000000000000000000000000000000000000b579c7d6b89f3914659abe09a004a58a1e77846b65bbdac9e29bd8f2f31b31af445a5dd40f76f71ecdd73117f1d592a38c19f1b6eee8658fbf8ff1b37f603c38929896b1cc813583bbfb21015b7aa66dd188ac79386022aec7aa4e72a7e87b0a8e0e8009183334bb0fe4f97ed89436f360b3644cd8382c7a14531a87b81a8f360000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e880add9a31077e5e8f3568b4c4451f0fea4372f66e3df3c0ca3ba26f447db2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000031000000000000000000000000000000000000000000000000e6c86796cd44b0bc6b7c0d4fdab33e2807e14b5fc4538b3750921169d97bcf4447c7d3ab2a7c25f74c1641e2885c1011d025cc536f5c9a2504713136c7877f48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000247c7525e84623db9868fccf00faab22229d60aaa380213108f8875011a8f456231c5371277cc706733f4a483338fb59000000000000000000000000000000000000000000000000ed8c62254022f64630ebf97d66254dee04f708ecbe22387baf8018752fadc2b763f64bded65c94a325b6b9f22ebbb0d80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	var TestSNPReport SNPAttestationReport
	if err := TestSNPReport.DeserializeReport(TestSNPReportBytes); err != nil {
		t.Fatalf("failed to deserialize attestation report")
	}

	ValidEndpoint := "americas.test.acccache.azure.net"
	ValidTEEType := "SevSnpVM"
	ValidAPIVersion := "api-version=2020-10-15-preview"
	ValidChipID := TestSNPReport.ChipID
	ValidPlatformVersion := TestSNPReport.PlatformVersion

	type testcase struct {
		name string

		certCache CertCache

		chipID          string
		platformVersion uint64

		expectedError   error
		expectErr       bool
		expectedContent string
	}

	testcases := []*testcase{
		// CertCache_Success passes the testing if it does not receive an error and the certchain mathces the expected content
		{
			name: "CertCache_Success",
			certCache: CertCache{
				Endpoint:   ValidEndpoint,
				TEEType:    ValidTEEType,
				APIVersion: ValidAPIVersion,
			},
			chipID:          ValidChipID,
			platformVersion: ValidPlatformVersion,
			expectedError:   nil,
			expectErr:       false,
			expectedContent: "-----BEGIN CERTIFICATE-----\nMIIFTDCCAvugAwIBAgIBADBGBgkqhkiG9w0BAQowOaAPMA0GCWCGSAFlAwQCAgUA\noRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATCjAwIBATB7MRQwEgYD\nVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDASBgNVBAcMC1NhbnRhIENs\nYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5jZWQgTWljcm8gRGV2aWNl\nczESMBAGA1UEAwwJU0VWLU1pbGFuMB4XDTIyMDIwOTIxMDYwMFoXDTI5MDIwOTIx\nMDYwMFowejEUMBIGA1UECwwLRW5naW5lZXJpbmcxCzAJBgNVBAYTAlVTMRQwEgYD\nVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExHzAdBgNVBAoMFkFkdmFuY2Vk\nIE1pY3JvIERldmljZXMxETAPBgNVBAMMCFNFVi1WQ0VLMHYwEAYHKoZIzj0CAQYF\nK4EEACIDYgAEv8TQmmW1BdCCyeVpj9C6Y2IW3rv3swTxZJNHBYGd9hRvWAyan82O\nCrX4tPiRzxmFRzY7e1RcGWYDhgQw2p8UokXGVz9fKNJKqBMdvEQf7vGUocRHhM83\nJTJrxmq0QxBXo4IBFjCCARIwEAYJKwYBBAGceAEBBAMCAQAwFwYJKwYBBAGceAEC\nBAoWCE1pbGFuLUEwMBEGCisGAQQBnHgBAwEEAwIBADARBgorBgEEAZx4AQMCBAMC\nAQAwEQYKKwYBBAGceAEDBAQDAgEAMBEGCisGAQQBnHgBAwUEAwIBADARBgorBgEE\nAZx4AQMGBAMCAQAwEQYKKwYBBAGceAEDBwQDAgEAMBEGCisGAQQBnHgBAwMEAwIB\nADARBgorBgEEAZx4AQMIBAMCATEwTQYJKwYBBAGceAEEBEDmyGeWzUSwvGt8DU/a\nsz4oB+FLX8RTizdQkhFp2XvPREfH06sqfCX3TBZB4ohcEBHQJcxTb1yaJQRxMTbH\nh39IMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0B\nAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBA4ICAQBbwYA2balTK5o3cPAQarZT\ngIRuX4nXWJDHpDJ2YikPK2Te48O49i9r5+1Voza/JauOI+u8h3Rg3fZSCbemLutw\nDzp6vRv9LJOKhy20HcBl2xYKL1zDX2MTnxg2PrHEE++PeMVf4nbhZkbnyfOXE9Ui\nkatdAdpjpSVhIe78c+IipM1rI1weCdRckmPidZHrJvIARYDyUZjHWoqV28O0reaE\nGXPO7k4VyfRh9hBYhwaFyVsAc1yhdU8Fi1jVzXwnyh7xlGfoakIC1oTiv2OF8w8C\nTKir+JXWqndF3BVNK4vMpdCoXO76KELA+gCPOsbbOQ2LMo7ZlwrwrXElFONwyQdi\ncM56hZ7pdGeGe4DoVWQMR/0LJ3b53r90zrvK+2rT65TffeYkt9OUhn5EkCYEGwOI\nb0/f41VTcN2eyh3OUXhucuCsNGCkqSp4sT79W9TOwUHB2oCricjMoLo9nNmdjIWj\nrA0cAae74AbSMmrVEavEdm10zb2lvFshYp5L4reqOqs5DKM+ksKp1u/SsiELYu+i\n3SMDsP/+3eM+7MgJj05rRaGSoYm/mbTUtDl1zZTRVPaW7eQmJBrzClHTd47N+hzD\n/2rJ4hcJnQLVSyYeNxi6zWAv83B95elvyD35CFh8M0L8GjHu+iww3/i6d5rSPLEp\n94cYfdFPuj/5HEjXDN5eww==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n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\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIGYzCCBBKgAwIBAgIDAQAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC\nBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS\nBgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg\nQ2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp\nY2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTcyMzA1WhcNNDUxMDIy\nMTcyMzA1WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS\nBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j\nZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLU1pbGFuMIICIjANBgkqhkiG\n9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsVmD7FktuotWwX1fNg\nW41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU0V5tkKiU1EesNFta\n1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S1ju8X93+6dxDUrG2\nSzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI52Naz5m2B+O+vjsC0\n60d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3KFYXP59XmJgtcog05\ngmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd/y8KxX7jksTEzAOg\nbKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBkgnlENEWx1UcbQQrs\n+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V9TJQqnN3Q53kt5vi\nQi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnqz55I0u33wh4r0ZNQ\neTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+OgpCCoMNit2uLo9M18\nfHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXoQPHfbkH0CyPfhl1j\nWhJFZasCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSFrBrRQ/fI\nrFXUxR1BSKvVeErUUzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG\nKWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvTWlsYW4vY3JsMEYGCSqG\nSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI\nAWUDBAICBQCiAwIBMKMDAgEBA4ICAQC6m0kDp6zv4Ojfgy+zleehsx6ol0ocgVel\nETobpx+EuCsqVFRPK1jZ1sp/lyd9+0fQ0r66n7kagRk4Ca39g66WGTJMeJdqYriw\nSTjjDCKVPSesWXYPVAyDhmP5n2v+BYipZWhpvqpaiO+EGK5IBP+578QeW/sSokrK\ndHaLAxG2LhZxj9aF73fqC7OAJZ5aPonw4RE299FVarh1Tx2eT3wSgkDgutCTB1Yq\nzT5DuwvAe+co2CIVIzMDamYuSFjPN0BCgojl7V+bTou7dMsqIu/TW/rPCX9/EUcp\nKGKqPQ3P+N9r1hjEFY1plBg93t53OOo49GNI+V1zvXPLI6xIFVsh+mto2RtgEX/e\npmMKTNN6psW88qg7c1hTWtN6MbRuQ0vm+O+/2tKBF2h8THb94OvvHHoFDpbCELlq\nHnIYhxy0YKXGyaW1NjfULxrrmxVW4wcn5E8GddmvNa6yYm8scJagEi13mhGu4Jqh\n3QU3sf8iUSUr09xQDwHtOQUVIqx4maBZPBtSMf+qUDtjXSSq8lfWcd8bLr9mdsUn\nJZJ0+tuPMKmBnSH860llKk+VpVQsgqbzDIvOLvD6W1Umq25boxCYJ+TuBoa4s+HH\nCViAvgT9kf/rBq1d+ivj6skkHxuzcxbk1xv6ZGxrteJxVH7KlX7YRdZ6eARKwLe4\nAFZEAwoKCQ==\n-----END CERTIFICATE-----\n",
		},
		// CertCache_Invalid_PlatformVersion passes if the uri associated with the requested certificate was not found
		{
			name: "CertCache_Invalid_PlatformVersion",
			certCache: CertCache{
				Endpoint:   ValidEndpoint,
				TEEType:    ValidTEEType,
				APIVersion: ValidAPIVersion,
			},
			chipID:          ValidChipID,
			platformVersion: 0xdeadbeef,
			expectedError:   errors.Errorf("http response status equal to 404 Not Found"),
			expectErr:       true,
		},
		// CertCache_Invalid_ChipID passes if the uri associated with the requested certificate was not found
		{
			name: "CertCache_Invalid_ChipID",
			certCache: CertCache{
				Endpoint:   ValidEndpoint,
				TEEType:    ValidTEEType,
				APIVersion: ValidAPIVersion,
			},
			chipID:          "0xdeadbeef",
			platformVersion: ValidPlatformVersion,
			expectedError:   errors.Errorf("http response status equal to 404 Not Found"),
			expectErr:       true,
		},
		// CertCache_Invalid_TEEType passes if the uri associated with the requested tee_type and certificate was not found
		{
			name: "CertCache_Invalid_TEEType",
			certCache: CertCache{
				Endpoint:   ValidEndpoint,
				TEEType:    "InvalidTEEType",
				APIVersion: ValidAPIVersion,
			},
			chipID:          ValidChipID,
			platformVersion: ValidPlatformVersion,
			expectedError:   errors.Errorf("http response status equal to 404 Not Found"),
			expectErr:       true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			certchain, _, err := tc.certCache.retrieveCertChain(tc.chipID, tc.platformVersion)

			if tc.expectErr {
				if err == nil {
					t.Fatal("expected err got nil")
				}
				if err.Error() != tc.expectedError.Error() {
					t.Fatalf("expected %q got %q", tc.expectedError.Error(), err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("did not expect err got %q", err.Error())
				}
				if string(certchain) != tc.expectedContent {
					t.Fatalf("expected %q got %q", tc.expectedContent, certchain)
				}
			}
		})
	}
}

func Test_MAA(t *testing.T) {
	TestKeyBlobBytes, err := common.GenerateJWKSetFromPEM("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAv965SRmyp8zbG5eNFuDCmmiSeaHpujG2bC/keLSuzvDMLO1W\nyrUJveaa5bzMoO0pA46pXkmbqHisozVzpiNDLCo6d3z4TrGMeFPf2APIMu+RSrzN\n56qvHVyIr5caWfHWk+FMRDwAefyNYRHkdYYkgmFK44hhUdtlCAKEv5UQpFZjvh4i\nI9jVBdGYMyBaKQLhjI5WIh+QG6Za5sSuOCFMnmuyuvN5DflpLFz595Ss+EoBIY+N\nil6lCtvcGgR+IbjUYHAOs5ajamTzgeO8kx3VCE9HcyKmyUZsiyiF6IDRp2Bpy3NH\nTjIz7tmkpTHx7tHnRtlfE2FUv0B6i/QYl/ZA5QIDAQABAoIBAG9Ig9jFIdy3MWII\nfVmGlPgvrL0FTuWiTbbj9DSaP0VhXlq0cYFyjSrqZG7ZGSpBQ2d/x/Ya5UBKdX7X\n0rLKgvxLpcuF3RLvYZSsuQi18NiyIGfjp901Hwn9kH2fOzZt0NHGe5Cb6H7YHzvs\nv7/2RJimS2Q6xo9Om4OQymO/1n4pZ+ZMiTy56AvIYZ/ToD8lorlzkGFNQsljmTSC\nIHEqRuyttI0Tf64jNaD8K74EThlZG8AE/yNG2FiRtN37+gAgMhxNWoF64s+9D/G0\n1xL96WNP5GmxXidK4BAUwWZmLJTtgUDcGjJbmfSuEMFjpRA9wfcL717jDzB0AImO\nOnZSgWECgYEA2swHf+pU8D1vshCBCTx/wGeIMRJE1Nw3YBhvPrUCExMo8M2UAkzs\nlKq61xSnh0X7f/Ma28vj9/gT+AHOnoCSdFSFO3dxX8B3y+B3jVvbxx7P+iZrM8J+\nVgrqPaXrIpBNPCooieD6O9EGvyC0+somgvtkA3ne2jdxX1rbPaQZr5kCgYEA4H6Y\ndWb2F5Dglhby9oXfjaLslIumoTTRFTgygIXHBG0auwMQzwfhuLyzH55mBICn16Ez\nLRyqssna5NgfTF0XrZT/BIPo8dSj0hlWvDtvCnZbDMTLYrk+GdypJD2oWmsbB6gB\nFjdjU4pv8c/4WjGuuWJ8Vs47+HTBNJlJlr6fWy0CgYBapPJqdRtxWBKBM8Mxn2XR\nwVKz+byYbw9l+VmFIhpU6rgoYxLxjQrqYHz9hCoPqdeS35V9/89XOOiU87K1CdEi\n7q0vwMEwiR1YUotU/fxkVwiUuvvouqf6X5VBqw5qCFxnE5Qt4w3oYCWqYxN3Xu5r\nj1iU9BV2VEfc2FhCBk056QKBgQDChm/tKy6K9QrmgzQ80XwI6ug9P1U/0thpnqyE\nGWd+OlwzOFDUVGwO+9PqzgJwXFsTyabirDhte+Ok8HEOZowh6T2g1/x9sFfTsgkq\nSgXJ9wymX9As138sQbx+nr7GupBNbhKjAZObzBV8X01AOlTAZsp/HW1xuRnBTiIp\n8Tt8cQKBgQDUv6Jpe1/kO0YJ6KlqVcMIZa+aQFamoMavlCNxxBvjoPnVdWB9PtWi\narzVMyAVvTjnT1QvGPJj1dffE+GSrAf3mssdp/tGfMGcgSB0DRcE1jz/JlzEc81F\no9Ki1lCw8ljoaNfJ8K+7wdiQ1V/H+rgL691P/2ZGc4vdOXJvy/hGZA==\n-----END RSA PRIVATE KEY-----")
	if err != nil {
		t.Fatal("generating key blob failed")
	}

	TestSNPPolicyBlobBytes, err := base64.StdEncoding.DecodeString(uvm_security_policy_base64)
	if err != nil {
		t.Fatal("decoding policy base64 failed")
	}

	// generate a different rsa key pair
	privateWrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("tampered rsa key pair generation failed")
	}

	TestKeyBlobBytesTampered, err := common.GenerateJWKSet(privateWrappingKey)
	if err != nil {
		t.Fatal("generating tampered key blob failed")
	}

	// Use a non-matching policy
	TestSNPPolicyBlobBytesTampered, err := base64.StdEncoding.DecodeString("ewoJImFsbG93X2FsbCI6IGZhbHNlLAoJImNvbnRhaW5lcnMiOiB7CgkJIm51bSI6IDIsCgkJInBhdXNlIjogewoJCQkiY29tbWFuZCI6ICIvcGF1c2UiLAoJCQkibGF5ZXJzIjogewoJCQkJIm51bSI6IDEsCgkJCQkibDAiOiAiMTZiNTE0MDU3YTA2YWQ2NjVmOTJjMDI4NjNhY2EwNzRmZDU5NzZjNzU1ZDI2YmZmMTYzNjUyOTkxNjllODQxNSIKCQkJfQoJCX0sCgkJImMwIjogewoJCQkiY29tbWFuZCI6ICJydXN0YyAtLWhlbHAiLAoJCQkibGF5ZXJzIjogewoJCQkJIm51bSI6IDYsCgkJCQkibDAiOiAiZmU4NGM5ZDViZmRkZDA3YTI2MjRkMDAzMzNjZjEzYzFhOWM5NDFmM2EyNjFmMTNlYWQ0NGZjNmE5M2JjMGU3YSIsCgkJCQkibDEiOiAiNGRlZGFlNDI4NDdjNzA0ZGE4OTFhMjhjMjVkMzIyMDFhMWFlNDQwYmNlMmFlY2NjZmE4ZTZmMDNiOTdhNmE2YyIsCgkJCQkibDIiOiAiNDFkNjRjZGViMzQ3YmYyMzZiNGMxM2I3NDAzYjYzM2ZmMTFmMWNmOTRkYmM3Y2Y4ODFhNDRkNmRhODhjNTE1NiIsCgkJCQkibDMiOiAiZWIzNjkyMWUxZjgyYWY0NmRmZTI0OGVmOGYxYjNhZmI2YTUyMzBhNjQxODFkOTYwZDEwMjM3YTA4Y2Q3M2M3OSIsCgkJCQkibDQiOiAiZTc2OWQ3NDg3Y2MzMTRkM2VlNzQ4YTQ0NDA4MDUzMTdjMTkyNjJjN2FjZDJmZGJkYjBkNDdkMmU0NjEzYTE1YyIsCgkJCQkibDUiOiAiMWI4MGYxMjBkYmQ4OGU0MzU1ZDYyNDFiNTE5YzNlMjUyOTAyMTVjNDY5NTE2YjQ5ZGVjZTljZjA3MTc1YTc2NiIKCQkJfQoJCX0KCX0sCgkic2VydmljZXMiOiB7CgkJImNlcnRjYWNoZSI6IHsKCQkJImVuZHBvaW50IjogImFtZXJpY2FzLnRlc3QuYWNjY2FjaGUuYXp1cmUubmV0IiwKCQkJInRlZV90eXBlIjogIlNldlNucFZNIiwKCQkJImFwaV92ZXJzaW9uIjogImFwaS12ZXJzaW9uPTIwMjAtMTAtMTUtcHJldmlldyIKCQl9LAoJCSJtYWEiOiB7IAoJCQkiZW5kcG9pbnQiOiAic2hhcmVkbmV1Lm5ldS5hdHRlc3QuYXp1cmUubmV0IiwKCQkJInRlZV90eXBlIjogIlNldlNucFZNIiwKCQkJImFwaV92ZXJzaW9uIjogImFwaS12ZXJzaW9uPTIwMjAtMTAtMDEiCgkJfSwgCgkJIm1oc20iOiBbIHsgCQoJCQkiZW5kcG9pbnQiOiAic3ZvbG9zLWhzbS5tYW5hZ2VkaHNtLmF6dXJlLm5ldCIsCgkJCSJhcGlfdmVyc2lvbiI6ICJhcGktdmVyc2lvbj03LjMtcHJldmlldyIsCgkJCSJraWQiOiBbCgkJCQkiTXlSdXN0Y0tleSIKCQkJXQoJCX0gXQkKCX0KfQ==")
	if err != nil {
		t.Fatal("decoding tampered policy base64 failed")
	}

	TestSNPReportBytes := snp_report_bin
	var TestSNPReport SNPAttestationReport
	if err := TestSNPReport.DeserializeReport(TestSNPReportBytes); err != nil {
		t.Fatalf("failed to deserialize attestation report")
	}

	ProductionTestSNPReportBytes := snp_report_bin
	var ProductionTestSNPReport SNPAttestationReport
	if err := ProductionTestSNPReport.DeserializeReport(ProductionTestSNPReportBytes); err != nil {
		t.Fatalf("failed to deserialize attestation report")
	}

	ValidMAAEndpoint := "sharedeus2.eus2.test.attest.azure.net"
	ValidTEEType := "SevSnpVM"
	ValidMAAAPIVersion := "api-version=2020-10-01"

	certCache := CertCache{
		Endpoint:   "americas.test.acccache.azure.net",
		TEEType:    "SevSnpVM",
		APIVersion: "api-version=2020-10-15-preview",
	}

	ValidCertChain, _, err := certCache.retrieveCertChain(TestSNPReport.ChipID, TestSNPReport.PlatformVersion)
	if err != nil {
		t.Fatalf("retrieving cert chain failed")
	}

	ProductionCertCache := CertCache{
		Endpoint:   "americas.acccache.azure.net",
		TEEType:    "SevSnpVM",
		APIVersion: "api-version=2020-10-15-preview",
	}

	ProductionValidCertChain, _, err := ProductionCertCache.retrieveCertChain(ProductionTestSNPReport.ChipID, ProductionTestSNPReport.PlatformVersion)
	if err != nil {
		t.Fatalf("retrieving cert chain failed")
	}

	ProductionTestKeyBlobBytes, err := base64.StdEncoding.DecodeString(
		"eyJrZXlzIjpbeyJlIjoiQVFBQiIsImtleV9vcHMiOlsiZW5jcnlwdCJdLCJraWQiOiJOdmhmdXEyY0NJT0FCOFhSNFhpOVByME5QXzlDZU16V1FHdFdfSEFMel93Iiwia3R5IjoiUlNBIiwibiI6InY5NjVTUm15cDh6Ykc1ZU5GdURDbW1pU2VhSHB1akcyYkNfa2VMU3V6dkRNTE8xV3lyVUp2ZWFhNWJ6TW9PMHBBNDZwWGttYnFIaXNvelZ6cGlORExDbzZkM3o0VHJHTWVGUGYyQVBJTXUtUlNyek41NnF2SFZ5SXI1Y2FXZkhXay1GTVJEd0FlZnlOWVJIa2RZWWtnbUZLNDRoaFVkdGxDQUtFdjVVUXBGWmp2aDRpSTlqVkJkR1lNeUJhS1FMaGpJNVdJaC1RRzZaYTVzU3VPQ0ZNbm11eXV2TjVEZmxwTEZ6NTk1U3MtRW9CSVktTmlsNmxDdHZjR2dSLUlialVZSEFPczVhamFtVHpnZU84a3gzVkNFOUhjeUtteVVac2l5aUY2SURScDJCcHkzTkhUakl6N3Rta3BUSHg3dEhuUnRsZkUyRlV2MEI2aV9RWWxfWkE1USJ9XX0=")

	if err != nil {
		t.Fatal("decoding policy base64 failed")
	}

	ProductionTestSNPPolicyBlobBytes, err := base64.StdEncoding.DecodeString(uvm_security_policy_base64)

	if err != nil {
		t.Fatal("decoding policy base64 failed")
	}

	InvalidCertChain := make([]byte, len(ValidCertChain))
	copy(InvalidCertChain, ValidCertChain)
	// modify one byte
	InvalidCertChain[len(InvalidCertChain)/2] = 0x00

	CorruptedProductionSNPReportBytes, _ := hex.DecodeString("00000000020000001f0003000000000001000000000000000000000000000000020000000000000000000000000000000000000001000000020000000000065d010000000000000000000000000000007ab000a323b3c873f5b81bbe584e7c1a26bcf40dc27e00f8e0d144b1ed2d14f10000000000000000000000000000000000000000000000000000000000000000deac3d39f12ba5f45e4bdd7a3686134c0b7b6883381210a87d6b8015e60a6bad5b264d5c2725e6b6ef8b9e3f376160b4dff51dbeac6096960223d54e5bee6a7df6a131c109b34d8043da5874d56bb78d70eed5b3693ebb29d964f7ae295f49cb0554b4cc33ced533c7a6f9aeb4c563c68bece465756389dfa5f527bcb65c74ea0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e29a02183df412e5c69c3d7b0beedfc8eff96bc16c0020b1cd06d9718ae37d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff020000000000065d0000000000000000000000000000000000000000000000005c6095e0748b55eaca503f2a020ade6a9151d6a62a292c6c7af3c935e3a3f8f401770cd189b7f666141930e3461573301a635e7fb0898de062241ea0da9a85d3020000000000065d0133010001330100020000000000065d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008961c43fca3e22bb3e4ecd99e70bc1027fe43b32cc955077528c02249de74e1ececc6bbb91a6e2899fec6c54fab5653700000000000000000000000000000000000000000000000089c9797445d305380c5595ccc2f4e61b2c1fe5596b9ed5dc842c3d0dece0bf9aab9fc0d7c34e1315d5e143bb374303a30000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

	CorruptedProductionSigSNPReportBytes, _ := hex.DecodeString("02000000020000001f0003000000000001000000000000000000000000000000020000000000000000000000000000000000000001000000020000000000065d010000000000000000000000000000007ab000a323b3c873f5b81bbe584e7c1a26bcf40dc27e00f8e0d144b1ed2d14f10000000000000000000000000000000000000000000000000000000000000000deac3d39f12ba5f45e4bdd7a3686134c0b7b6883381210a87d6b8015e60a6bad5b264d5c2725e6b6ef8b9e3f376160b4dff51dbeac6096960223d54e5bee6a7df6a131c109b34d8043da5874d56bb78d70eed5b3693ebb29d964f7ae295f49cb0554b4cc33ced533c7a6f9aeb4c563c68bece465756389dfa5f527bcb65c74ea0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e29a02183df412e5c69c3d7b0beedfc8eff96bc16c0020b1cd06d9718ae37d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff020000000000065d0000000000000000000000000000000000000000000000005c6095e0748b55eaca503f2a020ade6a9151d6a62a292c6c7af3c935e3a3f8f401770cd189b7f666141930e3461573301a635e7fb0898de062241ea0da9a85d3020000000000065d0133010001330100020000000000065d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008961c43fca3e22bb3e4ecd99e70bc1027fe43b32cc955077528c02249de74e1ececc6bbb91a6e2899fec6c54fab5653700000000000000000000000000000000000000000000000089c9797445d305380c5595ccc2f4e61b2c1fe5596b9ed5dc842c3d0dece0bf9aab9fc0d7c34e1315d5e143bb374303000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

	type testcase struct {
		name string

		maa MAA

		snpAttestationReport []byte
		vcekCertChain        []byte
		policyBlob           []byte
		keyBlob              []byte
		uvmReferenceInfo     []byte

		expectedError error
		expectErr     bool
	}

	testcases := []*testcase{
		// MAA_Success passes testing if the error is nil

		{
			name: "MAA_Success_Production",

			maa: MAA{
				Endpoint:   ValidMAAEndpoint,
				TEEType:    ValidTEEType,
				APIVersion: ValidMAAAPIVersion,
			},

			snpAttestationReport: snp_report_bin,
			vcekCertChain:        []byte(amd_certificate_pem),
			policyBlob:           uvm_security_policy_bin,
			keyBlob:              runtimedata_json_bin,
			uvmReferenceInfo:     uvm_reference_info_bin,

			expectedError: nil,
			expectErr:     false,
		},
		// MAA_InvalidCertChain testing passes if the MAA responds with Bad Request
		{
			name: "MAA_InvalidCertChain",

			maa: MAA{
				Endpoint:   ValidMAAEndpoint,
				TEEType:    ValidTEEType,
				APIVersion: ValidMAAAPIVersion,
			},

			snpAttestationReport: TestSNPReportBytes,
			vcekCertChain:        InvalidCertChain,
			policyBlob:           TestSNPPolicyBlobBytes,
			keyBlob:              TestKeyBlobBytes,
			uvmReferenceInfo:     uvm_reference_info_bin,

			expectedError: errors.New("pulling maa post response failed: http response status equal to 400 Bad Request"),
			expectErr:     true,
		},
		// MAA_InvalidKeyBlob testing passes if the MAA responds with Bad Request as the key blob does not match the one in the attestation report
		{
			name: "MAA_InvalidKeyBlob",

			maa: MAA{
				Endpoint:   ValidMAAEndpoint,
				TEEType:    ValidTEEType,
				APIVersion: ValidMAAAPIVersion,
			},

			snpAttestationReport: TestSNPReportBytes,
			vcekCertChain:        ValidCertChain,
			policyBlob:           TestSNPPolicyBlobBytes,
			keyBlob:              make([]byte, 4),
			uvmReferenceInfo:     uvm_reference_info_bin,

			expectedError: errors.New("pulling maa post response failed: http response status equal to 400 Bad Request"),
			expectErr:     true,
		},
		// MAA_TamperedKeyBlob testing passes if the MAA responds with Bad Request as the key blob does not match the one in the attestation report
		{
			name: "MAA_TamperedKeyBlob",

			maa: MAA{
				Endpoint:   ValidMAAEndpoint,
				TEEType:    ValidTEEType,
				APIVersion: ValidMAAAPIVersion,
			},

			snpAttestationReport: TestSNPReportBytes,
			vcekCertChain:        ValidCertChain,
			policyBlob:           TestSNPPolicyBlobBytes,
			keyBlob:              TestKeyBlobBytesTampered,
			uvmReferenceInfo:     uvm_reference_info_bin,

			expectedError: errors.New("pulling maa post response failed: http response status equal to 400 Bad Request"),
			expectErr:     true,
		},
		// MAA_InvalidPolicyBlob testing passes if the MAA responds with Bad Request as the policy does not match the one in the attestation report
		{
			name: "MAA_InvalidPolicyBlob",

			maa: MAA{
				Endpoint:   ValidMAAEndpoint,
				TEEType:    ValidTEEType,
				APIVersion: ValidMAAAPIVersion,
			},

			snpAttestationReport: TestSNPReportBytes,
			vcekCertChain:        ValidCertChain,
			policyBlob:           make([]byte, 4),
			keyBlob:              TestKeyBlobBytes,
			uvmReferenceInfo:     uvm_reference_info_bin,

			expectedError: errors.New("pulling maa post response failed: http response status equal to 400 Bad Request"),
			expectErr:     true,
		},

		// MAA_TamperedPolicyBlob testing passes if the MAA responds with Bad Request as the policy does not match the one in the attestation report
		{
			name: "MAA_TamperedPolicyBlob",

			maa: MAA{
				Endpoint:   ValidMAAEndpoint,
				TEEType:    ValidTEEType,
				APIVersion: ValidMAAAPIVersion,
			},

			snpAttestationReport: TestSNPReportBytes,
			vcekCertChain:        ValidCertChain,
			policyBlob:           TestSNPPolicyBlobBytesTampered,
			keyBlob:              TestKeyBlobBytes,
			uvmReferenceInfo:     uvm_reference_info_bin,

			expectedError: errors.New("pulling maa post response failed: http response status equal to 400 Bad Request"),
			expectErr:     true,
		},
		{
			name: "MAA_CorruptedSNPReport",

			maa: MAA{
				Endpoint:   ValidMAAEndpoint,
				TEEType:    ValidTEEType,
				APIVersion: ValidMAAAPIVersion,
			},

			snpAttestationReport: CorruptedProductionSNPReportBytes,
			vcekCertChain:        ProductionValidCertChain,
			policyBlob:           ProductionTestSNPPolicyBlobBytes,
			keyBlob:              ProductionTestKeyBlobBytes,
			uvmReferenceInfo:     uvm_reference_info_bin,

			expectedError: errors.New("pulling maa post response failed: http response status equal to 400 Bad Request"),
			expectErr:     true,
		},
		{
			name: "MAA_CorruptedSigSNPReport",

			maa: MAA{
				Endpoint:   ValidMAAEndpoint,
				TEEType:    ValidTEEType,
				APIVersion: ValidMAAAPIVersion,
			},

			snpAttestationReport: CorruptedProductionSigSNPReportBytes,
			vcekCertChain:        ProductionValidCertChain,
			policyBlob:           ProductionTestSNPPolicyBlobBytes,
			keyBlob:              ProductionTestKeyBlobBytes,
			uvmReferenceInfo:     uvm_reference_info_bin,

			expectedError: errors.New("pulling maa post response failed: http response status equal to 400 Bad Request"),
			expectErr:     true,
		},
		{
			name: "MAA_NotMatchingCertChain",

			maa: MAA{
				Endpoint:   ValidMAAEndpoint,
				TEEType:    ValidTEEType,
				APIVersion: ValidMAAAPIVersion,
			},

			snpAttestationReport: ProductionTestSNPReportBytes,
			vcekCertChain:        ValidCertChain,
			policyBlob:           ProductionTestSNPPolicyBlobBytes,
			keyBlob:              ProductionTestKeyBlobBytes,
			uvmReferenceInfo:     uvm_reference_info_bin,

			expectedError: errors.New("pulling maa post response failed: http response status equal to 400 Bad Request"),
			expectErr:     true,
		},
	}

	uvm_security_policy_bin, _ = base64.StdEncoding.DecodeString(uvm_security_policy_base64)
	runtimedata_json_bin, _ = base64.StdEncoding.DecodeString(runtimedata_json_base64)

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tc.maa.attest(tc.snpAttestationReport, tc.vcekCertChain, tc.policyBlob, tc.keyBlob, tc.uvmReferenceInfo)

			if tc.expectErr && err == nil {
				fmt.Printf("token: %v\n", resp)
				t.Fatal("expected err got nil")
			} else if tc.expectErr && err.Error() != tc.expectedError.Error() {
				t.Fatalf("expected %q got %q", tc.expectedError.Error(), err.Error())
			} else if !tc.expectErr && err != nil {
				t.Fatalf("did not expect err got %q", err.Error())
			}
		})
	}
}
