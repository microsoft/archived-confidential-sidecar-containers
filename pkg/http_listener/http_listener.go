package http_listener

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/skr"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Due to protocol differences, context info for key/maa token release such as
// AKV or MAA endpoint can be passed in various format. This interface allows
// different protocols to implement its own logic for extracting these info
type TokenKeyRelease interface {
	GetMAAInfo(c *gin.Context) (*attest.MAA, []byte, error)
	GetKeyReleaseInfo(c *gin.Context) *skr.KeyBlob
	GetRawAttestInfo(c *gin.Context) ([]byte, []byte)
}

type GinServer struct {
	server *gin.Engine
	ready  bool
}

func NewGinServer() *GinServer {
	server := gin.Default()

	return &GinServer{
		server: server,
		ready:  true,
	}
}

type Server struct {
	tokenRelease TokenKeyRelease
}

func NewServer(tr TokenKeyRelease) *Server {
	return &Server{
		tokenRelease: tr,
	}
}

// postRawAttest retrieves a hardware attestation report signed by the
// Platform Security Processor and which encodes the hash digest of
// the request's RuntimeData in the attestation's ReportData
//
// - RuntimeData is expected to be a base64-standard-encoded string

func (s *Server) postRawAttest(c *gin.Context) {
	inittimeDataBytes, runtimeDataBytes := s.tokenRelease.GetRawAttestInfo(c)

	rawReport, err := attest.RawAttest(inittimeDataBytes, runtimeDataBytes)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusOK, gin.H{"report": rawReport})
}

func (gs *GinServer) GetRawAttestInfo(c *gin.Context) ([]byte, []byte) {
	var attestData RawAttestData

	// Call BindJSON to bind the received JSON to AttestData
	if err := c.ShouldBindJSON(&attestData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "invalid request format").Error()})
		return nil, nil
	}

	// base64 decode the incoming encoded security policy
	inittimeDataBytes, err := base64.StdEncoding.DecodeString(common.EncodedUvmInformation.EncodedSecurityPolicy)

	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errors.Wrap(err, "decoding policy from Base64 format failed").Error()})
		return nil, nil
	}

	// standard base64 decode the incoming runtime data
	runtimeDataBytes, err := base64.StdEncoding.DecodeString(attestData.RuntimeData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "decoding base64-encoded runtime data of request failed").Error()})
		return nil, nil
	}

	return inittimeDataBytes, runtimeDataBytes
}

// postMAAAttest retrieves an attestation token issued by Microsoft Azure Attestation
// service which encodes the request's RuntimeData as a runtime claim
//
//   - RuntimeData is expected to be a base64-standard-encoded string
//   - MAAEndpoint is the uri to the Microsoft Azure Attestation service endpoint which
//     will author and sign the attestation token

func (gs *GinServer) GetMAAInfo(c *gin.Context) (*attest.MAA, []byte, error) {
	var attestData MAAAttestData

	// call BindJSON to bind the received JSON to AttestData
	if err := c.ShouldBindJSON(&attestData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "invalid request format").Error()})
		return nil, nil, nil
	}

	// base64 decode the incoming runtime data
	runtimeDataBytes, err := base64.StdEncoding.DecodeString(attestData.RuntimeData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "decoding base64-encoded runtime data of request failed").Error()})
		return nil, nil, nil
	}

	maa := attest.MAA{
		Endpoint:   attestData.MAAEndpoint,
		TEEType:    "SevSnpVM",
		APIVersion: "api-version=2020-10-01",
	}

	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	}
	return &maa, runtimeDataBytes, nil
}

func (s *Server) postMAAAttest(c *gin.Context) {
	maa, runtimeDataBytes, _ := s.tokenRelease.GetMAAInfo(c)

	maaToken, err := attest.ServerCertState.Attest(*maa, runtimeDataBytes, *common.EncodedUvmInformation)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusOK, gin.H{"token": maaToken})
}

// postKeyRelease retrieves a secret previously imported to Azure Key Vault
//
//   - AKVEndpoint is the uri to the key vault from which the secret will be retrieved
//   - MAAEndpoint is the uri to the Microsoft Azure Attestation service endpoint which
//     will author and sign the attestation claims presented to the MSHM during secure
//     key release operation. It needs to be the same as the authority defined in the
//     SKR policy when the secret was imported to the AKV.
//   - KID is the key identifier of the secret to be retrieved.
func (gs *GinServer) GetKeyReleaseInfo(c *gin.Context) *skr.KeyBlob {
	var newKeyReleaseData KeyReleaseData

	// Call BindJSON to bind the received JSON to KeyReleaseData
	if err := c.ShouldBindJSON(&newKeyReleaseData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "invalid request format")})
		return nil
	}

	akv := skr.AKV{
		Endpoint:    newKeyReleaseData.AKVEndpoint,
		APIVersion:  "api-version=7.3-preview",
		BearerToken: newKeyReleaseData.AccessToken,
	}

	maa := attest.MAA{
		Endpoint:   newKeyReleaseData.MAAEndpoint,
		TEEType:    "SevSnpVM",
		APIVersion: "api-version=2020-10-01",
	}

	skrKeyBlob := skr.KeyBlob{
		KID:       newKeyReleaseData.KID,
		Authority: maa,
		AKV:       akv,
	}
	return &skrKeyBlob
}

func (s *Server) postKeyRelease(c *gin.Context) {
	skrKeyBlob := s.tokenRelease.GetKeyReleaseInfo(c)

	jwKey, err := skr.SecureKeyRelease(*common.WorkloadIdentity, *attest.ServerCertState, *skrKeyBlob, *common.EncodedUvmInformation)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	logrus.Debugf("Key released of type %s", jwKey.KeyType())

	jwkJSONBytes, err := json.Marshal(jwKey)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"key": string(jwkJSONBytes)})
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
	ginServer.server.POST("/attest/raw", server.postRawAttest)
	ginServer.server.POST("/key/release", server.postKeyRelease)
	ginServer.server.POST("/attest/maa", server.postMAAAttest)
	ginServer.server.Run(url)
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
