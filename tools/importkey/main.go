// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/hkdf"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/skr"
	"github.com/lestrrat-go/jwx/jwk"
)

type importKeyConfig struct {
	Key      skr.KeyBlob         `json:"key"`
	Claims   [][]skr.ClaimStruct `json:"claims"`
	Identity common.Identity     `json:"identity, omitempty"`
}

type RSAKey struct {
	KTY    string   `json:"kty"`
	KeyOps []string `json:"key_ops"`
	D      string   `json:"d"`
	DP     string   `json:"dp"`
	DQ     string   `json:"dq"`
	E      string   `json:"e"`
	N      string   `json:"n"`
	P      string   `json:"p"`
	Q      string   `json:"q"`
	QI     string   `json:"qi"`
}

type OctKey struct {
	KTY     string   `json:"kty"`
	KeyOps  []string `json:"key_ops,omitempty"`
	K       string   `json:"k"`
	KeySize int      `json:"key_size"`
}

func main() {
	// variables declaration
	var configFile string
	var runInsideAzure bool
	var keyHexString string

	// flags declaration using flag package
	flag.StringVar(&configFile, "c", "", "Specify config file to process")
	flag.StringVar(&keyHexString, "kh", "", "Specify oct key bytes in hexstring [optional]")
	flag.BoolVar(&runInsideAzure, "a", false, "Run within Azure VM [optional]")
	flag.Parse() // after declaring flags we need to call it

	flag.Parse()
	if flag.NArg() != 0 || len(configFile) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	importKeyCfg := new(importKeyConfig)
	if configBytes, err := ioutil.ReadFile(configFile); err != nil {
		fmt.Println("Error reading Azure services configuration")
		os.Exit(1)
	} else if err = json.Unmarshal(configBytes, importKeyCfg); err != nil {
		fmt.Println("Error unmarshalling import key configuration " + string(configBytes))
		os.Exit(1)
	}

	// retrieve a token from managed hsm. this requires to be run within a VM that has been assigned a managed identity associated with the managed hsm
	if runInsideAzure {
		var ResourceIDTemplate string
		if strings.Contains(importKeyCfg.Key.MHSM.Endpoint, "managedhsm") {
			ResourceIDTemplate = "https%3A%2F%2Fmanagedhsm.azure.net"
		} else {
			ResourceIDTemplate = "https%3A%2F%2Fvault.azure.net"
		}

		token, err := common.GetToken(ResourceIDTemplate, importKeyCfg.Identity)
		if err != nil {
			fmt.Println("Error retrieving the authentication token")
			os.Exit(1)
		}

		importKeyCfg.Key.MHSM.BearerToken = token.AccessToken
	}

	// create release policy
	var releasePolicy skr.ReleasePolicy

	releasePolicy.Version = "0.2"

	for _, allOfStatement := range importKeyCfg.Claims {
		// authority denotes authorized MAA endpoint that can present MAA tokens to the AKV MHSM
		releasePolicy.AnyOf = append(
			releasePolicy.AnyOf,
			skr.OuterClaimStruct{
				Authority: "https://" + importKeyCfg.Key.Authority.Endpoint,
				AllOf:     allOfStatement,
			},
		)
	}

	var key interface{}

	if importKeyCfg.Key.KTY == "RSA-HSM" {
		privateRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Println(err)
			return
		}

		// convert to JSON Web Key (JWK) format
		jwKey := jwk.NewRSAPrivateKey()
		err = jwKey.FromRaw(privateRSAKey)

		if err != nil {
			fmt.Println(err)
			return
		}

		// Underlying hash function for HMAC.
		hash := sha256.New

		// public salt and label
		salt := make([]byte, hash().Size())
		if _, err := rand.Read(salt); err != nil {
			fmt.Println(err)
			return
		}
		label := []byte("Symmetric Encryption Key")

		// Generate three 128-bit derived keys.
		hkdf := hkdf.New(hash, jwKey.D(), salt, label)

		octKey := make([]byte, 32)
		if _, err := io.ReadFull(hkdf, octKey); err != nil {
			fmt.Println(err)
			return
		}

		fmt.Printf("Symmetric key %s (salt: %s label: %s)", hex.EncodeToString(octKey), hex.EncodeToString(salt), label)
		jwKey.Set("key_ops", "encrypt")
		key = jwKey
	} else if importKeyCfg.Key.KTY == "" {
		// if not specified, default is to generate an OCT key
		var octKey []byte
		var err error

		if keyHexString == "" {
			octKey = make([]byte, 32)
			rand.Read(octKey)
		} else {
			octKey, err = hex.DecodeString(keyHexString)
			if err != nil {
				fmt.Println(err)
				return
			}
		}

		fmt.Printf("Symmetric key %s", hex.EncodeToString(octKey))

		key = OctKey{
			KTY:     "oct-HSM",
			KeyOps:  []string{"encrypt", "decrypt"},
			K:       base64.RawURLEncoding.EncodeToString(octKey),
			KeySize: len(octKey) * 8,
		}
	} else {
		fmt.Println("Key not supported")
		return
	}

	if mHSMResponse, err := importKeyCfg.Key.MHSM.ImportPlaintextKey(key, releasePolicy, importKeyCfg.Key.KID); err == nil {
		fmt.Println(mHSMResponse.Key.KID)
		releasePolicyJSON, err := json.Marshal(releasePolicy)
		if err != nil {
			fmt.Println("marshalling releasy policy failed")
		} else {
			fmt.Println(string(releasePolicyJSON))
		}
	} else {
		fmt.Println(err)
	}
}
