package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/encoding/protojson"
)

type PQKeypair struct {
	pubKey  *mldsa65.PublicKey
	privKey *mldsa65.PrivateKey
}

func (pqk PQKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return protocommon.HashAlgorithm_SHA3_256
}

func (pqk PQKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return protocommon.PublicKeyDetails_ML_DSA_65
}

func (pqk PQKeypair) GetHint() []byte {
	digest := sha3.Sum256(pqk.pubKey.Bytes())
	return []byte(base64.StdEncoding.EncodeToString(digest[:]))
}

func (pqk PQKeypair) GetKeyAlgorithm() string {
	return "" // Not using with Fulcio for now
}

func (pqk PQKeypair) GetPublicKey() crypto.PublicKey {
	return pqk.pubKey
}

func (pqk PQKeypair) GetPublicKeyPem() (string, error) {
	return string(pqk.pubKey.Bytes()), nil
}

func (pqk PQKeypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	digest := sha3.Sum256(data)
	var sig [mldsa65.SignatureSize]byte
	err := mldsa65.SignTo(pqk.privKey, digest[:], nil, false, sig[:])
	return sig[:], digest[:], err
}

func main() {
	pubKey, privKey, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	keypair := PQKeypair{
		pubKey:  pubKey,
		privKey: privKey,
	}
	content := sign.PlainData{
		Data: []byte("hello world!"),
	}

	bundle, err := sign.Bundle(&content, keypair, sign.BundleOptions{})
	if err != nil {
		log.Fatal(err)
	}

	bundleJSON, err := protojson.Marshal(bundle)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(bundleJSON))
}
