package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
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

type PQVerifier struct {
	pubKey *mldsa65.PublicKey
}

func (pqv PQVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return pqv.pubKey, nil
}

func (pqv PQVerifier) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	messageBytes, err := io.ReadAll(message)
	if err != nil {
		return errors.New("unable to read message")
	}
	sigBytes, err := io.ReadAll(signature)
	if err != nil {
		return errors.New("unable to read signature")
	}
	digest := sha3.Sum256(messageBytes)
	if mldsa65.Verify(pqv.pubKey, digest[:], nil, sigBytes) {
		return nil
	} else {
		return errors.New("failed to verify")
	}
}

func (pqv PQVerifier) ValidAtTime(_ time.Time) bool {
	return true
}

func trustedPublicKeyMaterial(pqv PQVerifier) *root.TrustedPublicKeyMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		return &pqv, nil
	})
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

	protobundle, err := sign.Bundle(&content, keypair, sign.BundleOptions{})
	if err != nil {
		log.Fatal(err)
	}

	bundleJSON, err := protojson.Marshal(protobundle)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("bundle:")
	fmt.Println(string(bundleJSON))
	fmt.Println("public key:")
	var buf [mldsa65.PublicKeySize]byte
	keypair.pubKey.Pack(&buf)
	fmt.Println(base64.StdEncoding.EncodeToString(buf[:]))

	// Perform verification
	pubKey.Unpack(&buf)
	verifier := PQVerifier{
		pubKey: pubKey,
	}
	var trustedMaterial = make(root.TrustedMaterialCollection, 0)
	trustedMaterial = append(trustedMaterial, trustedPublicKeyMaterial(verifier))
	b, err := bundle.NewBundle(protobundle)
	if err != nil {
		log.Fatal(err)
	}
	verifierConfig := []verify.VerifierOption{}
	verifierConfig = append(verifierConfig, verify.WithNoObserverTimestamps())
	identityPolicies := []verify.PolicyOption{}
	identityPolicies = append(identityPolicies, verify.WithKey())
	artifactPolicy := verify.WithArtifact(strings.NewReader("hello world!"))

	sev, err := verify.NewVerifier(trustedMaterial, verifierConfig...)
	if err != nil {
		log.Fatal(err)
	}
	_, err = sev.Verify(b, verify.NewPolicy(artifactPolicy, identityPolicies...))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("verification success!")
}
