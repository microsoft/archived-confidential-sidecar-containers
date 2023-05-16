package server

import (
	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/skr"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/sirupsen/logrus"
)

type Server struct {
	tokenRelease TokenKeyRelease
	ready        bool
}

func NewServer(tr TokenKeyRelease) *Server {
	return &Server{
		tokenRelease: tr,
		ready:        false,
	}
}

type MAAAttestData struct {
	// MAA endpoint which authors the MAA token
	MAAEndpoint string `json:"maa_endpoint" binding:"required"`
	// Base64 encoded representation of runtime data to be encoded
	// as runtime claim in the MAA token
	RuntimeData string `json:"runtime_data" binding:"required"`
}

type RawAttestData struct {
	// Base64 encoded representation of runtime data whose hash digest
	// will be encoded as ReportData in the hardware attestation repport
	RuntimeData string `json:"runtime_data" binding:"required"`
}

type KeyReleaseData struct {
	// MAA endpoint which acts as authority to the key that needs to be released
	MAAEndpoint string `json:"maa_endpoint" binding:"required"`
	// AKV endpoint from which the key is released
	AKVEndpoint string `json:"akv_endpoint" binding:"required"`
	// key identifier for key to be released
	KID string `json:"kid" binding:"required"`
	// In the absence of managed identity assignment to the container group
	// an AAD token issued for authentication with AKV resource may be included
	// in the request to release the key.
	AccessToken string `json:"access_token"`
}

// postMAAAttest retrieves an attestation token issued by Microsoft Azure Attestation
// service which encodes the request's RuntimeData as a runtime claim
//
//   - RuntimeData is expected to be a base64-standard-encoded string
//   - MAAEndpoint is the uri to the Microsoft Azure Attestation service endpoint which
//     will author and sign the attestation token

func (s *Server) postMAAAttest(maa *attest.MAA, runtimeDataBytes []byte) (string, error) {
	maaToken, err := attest.ServerCertState.Attest(*maa, runtimeDataBytes, *common.EncodedUvmInformation)
	if err != nil {
		return "", err
	}
	return maaToken, nil

}

// postKeyRelease retrieves a secret previously imported to Azure Key Vault
//
//   - AKVEndpoint is the uri to the key vault from which the secret will be retrieved
//   - MAAEndpoint is the uri to the Microsoft Azure Attestation service endpoint which
//     will author and sign the attestation claims presented to the MSHM during secure
//     key release operation. It needs to be the same as the authority defined in the
//     SKR policy when the secret was imported to the AKV.
//   - KID is the key identifier of the secret to be retrieved.

func (s *Server) postKeyRelease(skrKeyBlob *skr.KeyBlob) (_ jwk.Key, err error) {
	jwKey, err := skr.SecureKeyRelease(*common.WorkloadIdentity, *attest.ServerCertState, *skrKeyBlob, *common.EncodedUvmInformation)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("Key released of type %s", jwKey.KeyType())

	return jwKey, nil
}

// postRawAttest retrieves a hardware attestation report signed by the
// Platform Security Processor and which encodes the hash digest of
// the request's RuntimeData in the attestation's ReportData
//
// - RuntimeData is expected to be a base64-standard-encoded string

func (s *Server) postRawAttest(inittimeDataBytes []byte, runtimeDataBytes []byte) (string, error) {
	rawReport, err := attest.RawAttest(inittimeDataBytes, runtimeDataBytes)
	if err != nil {
		return "", err
	}
	return rawReport, nil
}

func (s *Server) pollStatus() bool {
	return s.ready
}

func SetupServer(certState *attest.CertState, identity *common.Identity, uvmInfo *common.UvmInformation, url string) {
	attest.ServerCertState = certState
	common.WorkloadIdentity = identity
	common.EncodedUvmInformation = uvmInfo
	certString := uvmInfo.InitialCerts.VcekCert + uvmInfo.InitialCerts.CertificateChain
	logrus.Debugf("Setting security policy to %s", uvmInfo.EncodedSecurityPolicy)
	logrus.Debugf("Setting uvm reference to %s", uvmInfo.EncodedUvmReferenceInfo)
	logrus.Debugf("Setting platform certs to %s", certString)

	ginServer := NewGinServer()
	server := NewServer(ginServer)
	ginServer.skrServer = server
	ginServer.server.GET("/status", ginServer.GetStatus)
	ginServer.server.POST("/attest/raw", ginServer.RawAttestInfo)
	ginServer.server.POST("/attest/maa", ginServer.MaaAttest)
	ginServer.server.POST("/key/release", ginServer.KeyReleaseInfo)
	server.ready = true

	ginServer.server.Run(url)
}
