package acceptance

import (
	"crypto/ed25519"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/store"
	"github.com/wolfiesch/cihash/internal/verifier"
)

// ProofSource resolves proof evidence for an exact required identity.
type ProofSource interface {
	Lookup(store.Identity) (attestation.Envelope, string, bool, error)
}

// TrustEvaluator decides whether an envelope satisfies one trust model and the
// required proof claims. It is the only acceptance authority after lookup.
type TrustEvaluator interface {
	Verify(attestation.Envelope, verifier.Expected) verifier.Decision
}

type Ed25519Evaluator struct {
	PublicKey ed25519.PublicKey
}

func (evaluator Ed25519Evaluator) Verify(envelope attestation.Envelope, expected verifier.Expected) verifier.Decision {
	return verifier.Verify(envelope, evaluator.PublicKey, expected)
}

type Ed25519ThresholdEvaluator struct {
	PublicKeys []ed25519.PublicKey
	Threshold  int
}

func (evaluator Ed25519ThresholdEvaluator) Verify(envelope attestation.Envelope, expected verifier.Expected) verifier.Decision {
	return verifier.VerifyThreshold(envelope, evaluator.PublicKeys, evaluator.Threshold, expected)
}

type Result struct {
	Accepted    bool
	Code        string
	Message     string
	ReceiptPath string
	Identity    store.Identity
}

func Evaluate(source ProofSource, evaluator TrustEvaluator, expected verifier.Expected) Result {
	identity := IdentityFromExpected(expected)
	envelope, receiptPath, found, err := source.Lookup(identity)
	if err != nil {
		return rejected(identity, receiptPath, "malformed_receipt", err.Error())
	}
	if !found {
		return rejected(identity, receiptPath, "proof_missing", "no proof matches the required identity")
	}
	decision := evaluator.Verify(envelope, expected)
	if !decision.Accepted {
		if decision.Code == "" {
			return rejected(identity, receiptPath, "malformed_receipt", "trust evaluator returned no rejection code")
		}
		return rejected(identity, receiptPath, decision.Code, decision.Message)
	}
	return Result{
		Accepted:    true,
		Code:        decision.Code,
		Message:     decision.Message,
		ReceiptPath: receiptPath,
		Identity:    identity,
	}
}

func IdentityFromExpected(expected verifier.Expected) store.Identity {
	return store.Identity{
		Repository:        expected.Repository,
		HeadSHA:           expected.HeadSHA,
		BaseSHA:           expected.BaseSHA,
		Profile:           expected.Profile,
		PolicyDigest:      expected.PolicyDigest,
		WorkflowDigest:    expected.WorkflowDigest,
		EnvironmentDigest: expected.EnvironmentDigest,
	}
}

func rejected(identity store.Identity, receiptPath, code, message string) Result {
	return Result{
		Code:        code,
		Message:     message,
		ReceiptPath: receiptPath,
		Identity:    identity,
	}
}
