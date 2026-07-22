package acceptance

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/verifier"
)

// Ed25519Key separates planned signing windows from emergency revocation.
// ValidFrom and ValidUntil are evaluated against the signed receipt time.
// RevokedAt is evaluated against verifier decision time and invalidates every
// receipt from that key because a compromised key can backdate a signature.
type Ed25519Key struct {
	PublicKey  ed25519.PublicKey
	ValidFrom  time.Time
	ValidUntil time.Time
	RevokedAt  time.Time
}

type Ed25519KeyringEvaluator struct {
	Keys      []Ed25519Key
	Threshold int
}

func (evaluator Ed25519KeyringEvaluator) Verify(envelope attestation.Envelope, expected verifier.Expected) verifier.Decision {
	if expected.Now.IsZero() {
		return keyringRejection("keyring_invalid", "verification time is required for key lifecycle evaluation")
	}
	decisionKeys, err := evaluator.keysAtDecision(expected.Now)
	if err != nil {
		return keyringRejection("keyring_invalid", err.Error())
	}
	if len(decisionKeys) < evaluator.Threshold {
		return keyringRejection("untrusted_signer", "too few non-revoked signing keys remain at decision time")
	}
	decision := verifier.VerifyThreshold(envelope, decisionKeys, evaluator.Threshold, expected)
	if !decision.Accepted {
		return decision
	}
	receiptKeys := evaluator.keysAtReceipt(decision.Statement.Predicate.IssuedAt, decisionKeys)
	if len(receiptKeys) < evaluator.Threshold {
		return keyringRejection("untrusted_signer", "receipt was not signed by enough keys active at issuance time")
	}
	return verifier.VerifyThreshold(envelope, receiptKeys, evaluator.Threshold, expected)
}

func (evaluator Ed25519KeyringEvaluator) keysAtDecision(now time.Time) ([]ed25519.PublicKey, error) {
	if evaluator.Threshold < 1 || evaluator.Threshold > len(evaluator.Keys) {
		return nil, fmt.Errorf("key threshold must be between one and the configured key count")
	}
	seen := make(map[string]struct{}, len(evaluator.Keys))
	keys := make([]ed25519.PublicKey, 0, len(evaluator.Keys))
	for _, configured := range evaluator.Keys {
		if len(configured.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("keyring contains an invalid Ed25519 public key")
		}
		if !configured.ValidFrom.IsZero() && !configured.ValidUntil.IsZero() && !configured.ValidUntil.After(configured.ValidFrom) {
			return nil, fmt.Errorf("key validity window is invalid")
		}
		keyID := attestation.KeyID(configured.PublicKey)
		if _, exists := seen[keyID]; exists {
			return nil, fmt.Errorf("keyring contains duplicate signer %s", keyID)
		}
		seen[keyID] = struct{}{}
		if configured.RevokedAt.IsZero() || now.Before(configured.RevokedAt) {
			keys = append(keys, configured.PublicKey)
		}
	}
	return keys, nil
}

func (evaluator Ed25519KeyringEvaluator) keysAtReceipt(issuedAt time.Time, decisionKeys []ed25519.PublicKey) []ed25519.PublicKey {
	trusted := make(map[string]struct{}, len(decisionKeys))
	for _, key := range decisionKeys {
		trusted[attestation.KeyID(key)] = struct{}{}
	}
	keys := make([]ed25519.PublicKey, 0, len(decisionKeys))
	for _, configured := range evaluator.Keys {
		if _, ok := trusted[attestation.KeyID(configured.PublicKey)]; !ok {
			continue
		}
		if !configured.ValidFrom.IsZero() && issuedAt.Before(configured.ValidFrom) {
			continue
		}
		if !configured.ValidUntil.IsZero() && !issuedAt.Before(configured.ValidUntil) {
			continue
		}
		keys = append(keys, configured.PublicKey)
	}
	return keys
}

func keyringRejection(code, message string) verifier.Decision {
	return verifier.Decision{Code: code, Message: message}
}
