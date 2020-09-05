// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package piv_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"

	"github.com/go-piv/piv-go/piv"
)

func ExampleECDSAPrivateKey_SharedKey_epheremalEncrypt() {
	// Add code here to either load the hardware slot's ECDSA public
	// key from a file, or open a PIV card, call Attest, get the
	// certificate's PublicKey field, and type assert that.
	var hardwarePublicKey *ecdsa.PublicKey

	ephemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("cannot generate ephemeral key: %v", err)
	}
	// Obtain public key of the hardware slot, e.g.
	mult, _ := hardwarePublicKey.Curve.ScalarMult(hardwarePublicKey.X, hardwarePublicKey.Y, ephemeral.D.Bytes())
	secret := mult.Bytes()
	ephemeralPublicKey := &ephemeral.PublicKey

	// Add code here to derive an encryption key from secret, and
	// encrypt something with it. Store ephemeralPublicKey with the
	// encrypted data, see crypto/elliptic.MarshalCompressed.
	_ = secret
	_ = ephemeralPublicKey
}

func ExampleECDSAPrivateKey_SharedKey_ephemeralDecrypt() {
	// Add code here to open a PIV card, and load ephemeralPublicKey
	// from where you stored it with the encrypted data.
	var card *piv.YubiKey
	var hardwarePublicKey *ecdsa.PublicKey
	var ephemeralPublicKey *ecdsa.PublicKey

	priv, err := card.PrivateKey(piv.SlotAuthentication, hardwarePublicKey, piv.KeyAuth{})
	if err != nil {
		log.Fatalf("error accessing hardware key: %v", err)
	}
	privECDSA, ok := priv.(*piv.ECDSAPrivateKey)
	if !ok {
		log.Fatalf("not an ECDSA key: %T", priv)
	}
	secret, err := privECDSA.SharedKey(ephemeralPublicKey)
	if err != nil {
		log.Fatalf("key agreement failed: %v", err)
	}

	// Add code here to derive an encryption key from secret, and
	// decrypt the data with it.
	_ = secret
}
