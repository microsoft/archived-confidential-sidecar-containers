// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package skr

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	ResourceIdManagedHSM = "https%3A%2F%2Fmanagedhsm.azure.net"
	ResourceIdVault      = "https%3A%2F%2Fvault.azure.net"
)

// KeyDerivationBlob contains information about the key that needs to be derived
// from a secret that has been released
//
// Safe use of this is to ensure that the secret has enough entropy. Examples
// include RSA private keys.
type KeyDerivationBlob struct {
	Salt  string `json:"salt,omitempty`
	Label string `json:"label,omitemtpy`
}

// KeyBlob contains information about the managed hsm service that holds the secret
// to be released.
//
// Authority lists the valid MAA that can issue tokens that the managed hsm service
// will accept. The key imported to this managed hsm needs to have included the
// authority's endpoint as the authority in the SKR.

type KeyBlob struct {
	KID       string     `json:"kid"`
	KTY       string     `json:"kty,omitempty"`
	KeyOps    []string   `json:"key_ops,omitempty"`
	Authority attest.MAA `json:"authority"`
	MHSM      MHSM       `json:"mhsm"`
}

// SecureKeyRelease releases a secret identified by the KID and MHSM in the keyblob
//  1. Retrieve an MAA token using the attestation package. This token can be presented to a Azure Key
//     Vault managed HSM to release a secret.
//  2. Present the MAA token to the managed HSM for each secret that will be released. The managed HSM
//     uses the public key presented as runtime-claims in the MAA token to wrap the released secret. This
//     ensures that only the utility VM in posession of the private wrapping key can decrypt the material
//
// The method requires serveral attributes including the security policy, the keyblob that contains
// information about the mhsm, authority and the key to be released.
func SecureKeyRelease(identity common.Identity, SKRKeyBlob KeyBlob, uvmInformation common.UvmInformation) (_ []byte, _ string, err error) {

	logrus.Debugf("Releasing key blob: %v", SKRKeyBlob)

	// Retrieve an MAA token

	var maaToken string

	// Generate an RSA pair that will be used for wrapping material released from a keyvault. MAA
	// expects the public wrapping key to be formatted as a JSON Web Key (JWK).

	// generate rsa key pair
	privateWrappingKey, err := rsa.GenerateKey(rand.Reader, RSASize)
	if err != nil {
		return nil, "", errors.Wrapf(err, "rsa key pair generation failed")
	}

	// construct the key blob
	jwkSetBytes, err := common.GenerateJWKSet(privateWrappingKey)
	if err != nil {
		return nil, "", errors.Wrapf(err, "generating key blob failed")
	}

	// Attest
	maaToken, err = attest.Attest(SKRKeyBlob.Authority, jwkSetBytes, uvmInformation)
	if err != nil {
		return nil, "", errors.Wrapf(err, "attestation failed")
	}

	// 2. Interact with Azure Key Vault. The REST API of AKV requires
	//     authentication using an Azure authentication token.

	// retrieve an Azure authentication token for authenticating with AKV
	if SKRKeyBlob.MHSM.BearerToken == "" {
		var ResourceIDTemplate string
		// If endpoint contains managedhsm, request a token for managedhsm
		// resource; otherwise for a vault
		if strings.Contains(SKRKeyBlob.MHSM.Endpoint, "managedhsm") {
			ResourceIDTemplate = ResourceIdManagedHSM
		} else {
			ResourceIDTemplate = ResourceIdVault
		}

		token, err := common.GetToken(ResourceIDTemplate, identity)
		if err != nil {
			return nil, "", errors.Wrapf(err, "retrieving authentication token failed")
		}

		// set the azure authentication token to the MHSM instance
		SKRKeyBlob.MHSM.BearerToken = token.AccessToken
		logrus.Debugf("AAD Token: %s ", token.AccessToken)
	}

	// use the MAA token obtained from the mhsm's authority to retrieve the key identified by kid. The ReleaseKey
	// operation requires the private wrapping key to unwrap the encrypted key material released from
	// the managed HSM.

	key, kty, err := SKRKeyBlob.MHSM.ReleaseKey(maaToken, SKRKeyBlob.KID, privateWrappingKey)
	if err != nil {
		return nil, "", errors.Wrapf(err, "releasing the key %s failed", SKRKeyBlob.KID)
	}

	logrus.Debugf("Key Type: %s Key %v", kty, key)

	return key, kty, nil
}
