// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/skr"
	"github.com/lestrrat-go/jwx/jwk"
)

type importKeyConfig struct {
	Key      skr.KeyBlob         `json:"key"`
	Claims   [][]skr.ClaimStruct `json:"claims"`
	Identity common.Identity     `json:"identity, omitempty"`
}

func main() {
	// variables declaration
	var configFile string
	var runInsideAzure bool
	var keyHexString string
	var keyRSAPEMFile string

	// flags declaration using flag package
	flag.StringVar(&configFile, "c", "", "Specify config file to process")
	flag.StringVar(&keyHexString, "kh", "", "Specify oct key bytes in hexstring [optional]")
	flag.StringVar(&keyRSAPEMFile, "kp", "", "Specify RSA key PEM file [optional]")
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
		token, err := common.GetToken("https%3A%2F%2Fmanagedhsm.azure.net", importKeyCfg.Identity)
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
		var privateRSAKey *rsa.PrivateKey
		var err error
		if keyRSAPEMFile == "" {
			privateRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				fmt.Println(err)
				return
			}
		} else {
			privateRSAPEMBytes, err := ioutil.ReadFile(keyRSAPEMFile)
			if err != nil {
				fmt.Println(err)
				return
			}
			privateRSAKey, err = x509.ParsePKCS1PrivateKey(privateRSAPEMBytes)
			if err != nil {
				fmt.Println(err)
				return
			}
		}

		jwKey := jwk.NewRSAPrivateKey()
		err = jwKey.FromRaw(privateRSAKey)

		if err != nil {
			fmt.Println(err)
			return
		}

		//jwKey.Set("key_ops", "encrypt")
		//		jwkJSONBytes, err := json.Marshal(jwKey)
		//		if err != nil {
		//			fmt.Println(err)
		//			return
		//		}

		//		var jwkVol skr.RSAKey
		//		json.Unmarshal(jwkJSONBytes, &jwkVol)

		//		jwkVol.KTY = importKeyCfg.Key.KTY

		key = jwKey
	} else {
		// create a new random key
		var secretKey []byte
		var err error

		if keyHexString == "" {
			secretKey = make([]byte, 32)
			rand.Read(secretKey)
		} else {
			secretKey, err = hex.DecodeString(keyHexString)
			if err != nil {
				fmt.Println(err)
				return
			}
		}

		fmt.Println(secretKey)

		key = skr.OctKey{
			KTY:     "oct-HSM",
			KeyOps:  []string{"encrypt", "decrypt"},
			K:       base64.RawURLEncoding.EncodeToString(secretKey),
			KeySize: len(secretKey) * 8,
		}
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
