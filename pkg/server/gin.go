package server

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

type GinServer struct {
	server    *gin.Engine
	skrServer *Server
}

func NewGinServer() *GinServer {
	server := gin.Default()
	return &GinServer{
		server: server,
	}
}

func (gs *GinServer) GetStatus(c *gin.Context) {
	if gs.skrServer.pollStatus() {
		c.JSON(http.StatusOK, gin.H{"message": "Status OK"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Status NOT OK"})
}

func (gs *GinServer) RawAttestInfo(c *gin.Context) {
	inittimeDataBytes, runtimeDataBytes := gs.GetRawAttestInfo(c)
	rawReport, err := gs.skrServer.postRawAttest(inittimeDataBytes, runtimeDataBytes)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusOK, gin.H{"report": rawReport})
}

func (gs *GinServer) RegisterCertStatePostMaaAttest(certState *attest.CertState) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		maa, runtimeDataBytes, _ := gs.GetMAAInfo(c)
		maaToken, err := gs.skrServer.postMAAAttest(maa, certState, runtimeDataBytes)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		}
		c.JSON(http.StatusOK, gin.H{"token": maaToken})
	}

	return fn
}

func (gs *GinServer) RegisterCertStatePostKeyRelease(certState *attest.CertState) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		skrKeyBlob := gs.GetKeyReleaseInfo(c)
		jwKey, err := gs.skrServer.postKeyRelease(skrKeyBlob, certState)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		}

		jwkJSONBytes, err := json.Marshal(jwKey)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"key": string(jwkJSONBytes)})
	}

	return fn
}

func (gs *GinServer) GetKeyReleaseInfo(ctx interface{}) *skr.KeyBlob {
	var newKeyReleaseData KeyReleaseData

	c := ctx.(*gin.Context)
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

func (gs *GinServer) GetMAAInfo(ctx interface{}) (*attest.MAA, []byte, error) {
	var attestData MAAAttestData
	c := ctx.(*gin.Context)
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

func (gs *GinServer) GetRawAttestInfo(ctx interface{}) ([]byte, []byte) {
	var attestData RawAttestData

	c := ctx.(*gin.Context)
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

func SetupGinServer(certState *attest.CertState, identity *common.Identity, uvmInfo *common.UvmInformation, url string) {
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
	ginServer.server.POST("/attest/maa", ginServer.RegisterCertStatePostMaaAttest(certState))
	ginServer.server.POST("/key/release", ginServer.RegisterCertStatePostKeyRelease(certState))

	server.ready = true

	ginServer.server.Run(url)
}
