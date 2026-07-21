package attestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
)

var (
	ErrMalformedReceipt   = errors.New("malformed receipt")
	ErrUnsupportedVersion = errors.New("unsupported receipt version")
	ErrUntrustedSigner    = errors.New("untrusted signer")
	ErrInvalidSignature   = errors.New("invalid signature")
)

func GenerateKeyPair(privatePath, publicPath string) (string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if err := writeExclusive(privatePath, privatePEM, 0o600); err != nil {
		return "", err
	}
	if err := writeExclusive(publicPath, publicPEM, 0o644); err != nil {
		_ = os.Remove(privatePath)
		return "", err
	}
	return KeyID(publicKey), nil
}

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("decode private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not Ed25519")
	}
	return key, nil
}

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("decode public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not Ed25519")
	}
	return key, nil
}

func KeyID(publicKey ed25519.PublicKey) string {
	return Digest(publicKey)
}

func Sign(statement Statement, privateKey ed25519.PrivateKey) (Envelope, error) {
	payload, err := json.Marshal(statement)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal statement: %w", err)
	}
	return SignPayload(PayloadType, payload, privateKey)
}

func SignPayload(payloadType string, payload []byte, privateKey ed25519.PrivateKey) (Envelope, error) {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, preAuthenticationEncoding(payloadType, payload))
	return Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{
			KeyID: KeyID(publicKey),
			Sig:   base64.StdEncoding.EncodeToString(signature),
		}},
	}, nil
}

func AddSignature(envelope Envelope, privateKey ed25519.PrivateKey) (Envelope, error) {
	if envelope.PayloadType != PayloadType {
		return Envelope{}, fmt.Errorf("%w: payload type %q", ErrUnsupportedVersion, envelope.PayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: decode payload: %v", ErrMalformedReceipt, err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	message := preAuthenticationEncoding(envelope.PayloadType, payload)
	for _, existing := range envelope.Signatures {
		signatureBytes, err := base64.StdEncoding.DecodeString(existing.Sig)
		if err != nil {
			return Envelope{}, fmt.Errorf("%w: decode signature: %v", ErrMalformedReceipt, err)
		}
		if ed25519.Verify(publicKey, message, signatureBytes) {
			return Envelope{}, fmt.Errorf("%w: signer already signed envelope", ErrMalformedReceipt)
		}
	}
	envelope.Signatures = append([]Signature(nil), envelope.Signatures...)
	envelope.Signatures = append(envelope.Signatures, Signature{
		KeyID: KeyID(publicKey),
		Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, message)),
	})
	return envelope, nil
}

func VerifySignature(envelope Envelope, publicKey ed25519.PublicKey) (Statement, error) {
	if envelope.PayloadType != PayloadType {
		return Statement{}, fmt.Errorf("%w: payload type %q", ErrUnsupportedVersion, envelope.PayloadType)
	}
	if len(envelope.Signatures) != 1 {
		return Statement{}, fmt.Errorf("%w: expected one signature", ErrMalformedReceipt)
	}
	if envelope.Signatures[0].KeyID != KeyID(publicKey) {
		return Statement{}, fmt.Errorf("%w: key id %q", ErrUntrustedSigner, envelope.Signatures[0].KeyID)
	}
	payload, err := VerifyThresholdPayload(envelope, []ed25519.PublicKey{publicKey}, 1)
	if err != nil {
		if errors.Is(err, ErrUntrustedSigner) {
			return Statement{}, ErrInvalidSignature
		}
		return Statement{}, err
	}
	return decodeStatement(payload)
}

func VerifyThresholdSignatures(envelope Envelope, publicKeys []ed25519.PublicKey, threshold int) (Statement, error) {
	if envelope.PayloadType != PayloadType {
		return Statement{}, fmt.Errorf("%w: payload type %q", ErrUnsupportedVersion, envelope.PayloadType)
	}
	payload, err := VerifyThresholdPayload(envelope, publicKeys, threshold)
	if err != nil {
		return Statement{}, err
	}
	return decodeStatement(payload)
}

func VerifyThresholdPayload(envelope Envelope, publicKeys []ed25519.PublicKey, threshold int) ([]byte, error) {
	if threshold <= 0 {
		return nil, fmt.Errorf("%w: signature threshold must be positive", ErrMalformedReceipt)
	}
	trustedKeys := make([]ed25519.PublicKey, 0, len(publicKeys))
	seenKeys := make(map[string]struct{}, len(publicKeys))
	for _, publicKey := range publicKeys {
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: trusted public key is invalid", ErrUntrustedSigner)
		}
		key := string(publicKey)
		if _, duplicate := seenKeys[key]; duplicate {
			continue
		}
		seenKeys[key] = struct{}{}
		trustedKeys = append(trustedKeys, publicKey)
	}
	if threshold > len(trustedKeys) {
		return nil, fmt.Errorf("%w: signature threshold exceeds unique trusted keys", ErrUntrustedSigner)
	}
	if len(envelope.Signatures) < threshold {
		return nil, fmt.Errorf("%w: signature threshold not met", ErrUntrustedSigner)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: decode payload: %v", ErrMalformedReceipt, err)
	}
	signatures := make([][]byte, len(envelope.Signatures))
	for index, signature := range envelope.Signatures {
		signatures[index], err = base64.StdEncoding.DecodeString(signature.Sig)
		if err != nil {
			return nil, fmt.Errorf("%w: decode signature: %v", ErrMalformedReceipt, err)
		}
	}
	message := preAuthenticationEncoding(envelope.PayloadType, payload)
	validSigners := 0
	for _, publicKey := range trustedKeys {
		for _, signature := range signatures {
			if ed25519.Verify(publicKey, message, signature) {
				validSigners++
				break
			}
		}
	}
	if validSigners < threshold {
		return nil, fmt.Errorf("%w: signature threshold not met: got %d, need %d", ErrUntrustedSigner, validSigners, threshold)
	}
	return payload, nil
}

func decodeStatement(payload []byte) (Statement, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var statement Statement
	if err := decoder.Decode(&statement); err != nil {
		return Statement{}, fmt.Errorf("%w: decode statement: %v", ErrMalformedReceipt, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Statement{}, fmt.Errorf("%w: trailing statement data", ErrMalformedReceipt)
	}
	return statement, nil
}

func MarshalEnvelope(envelope Envelope) ([]byte, error) {
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return append(data, '\n'), nil
}

func UnmarshalEnvelope(data []byte) (Envelope, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var envelope Envelope
	if err := decoder.Decode(&envelope); err != nil {
		return Envelope{}, fmt.Errorf("%w: decode envelope: %v", ErrMalformedReceipt, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Envelope{}, fmt.Errorf("%w: trailing envelope data", ErrMalformedReceipt)
	}
	return envelope, nil
}

func preAuthenticationEncoding(payloadType string, payload []byte) []byte {
	prefix := "DSSEv1 " + strconv.Itoa(len(payloadType)) + " " + payloadType + " " + strconv.Itoa(len(payload)) + " "
	encoded := make([]byte, 0, len(prefix)+len(payload))
	encoded = append(encoded, prefix...)
	return append(encoded, payload...)
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}
