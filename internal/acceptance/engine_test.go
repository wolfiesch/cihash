package acceptance_test

import (
	"errors"
	"testing"

	"github.com/wolfiesch/cihash/internal/acceptance"
	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/store"
	"github.com/wolfiesch/cihash/internal/verifier"
)

type proofSource struct {
	envelope attestation.Envelope
	path     string
	found    bool
	err      error
	identity store.Identity
}

func (source *proofSource) Lookup(identity store.Identity) (attestation.Envelope, string, bool, error) {
	source.identity = identity
	return source.envelope, source.path, source.found, source.err
}

type trustEvaluator struct {
	decision verifier.Decision
	calls    int
}

func (evaluator *trustEvaluator) Verify(attestation.Envelope, verifier.Expected) verifier.Decision {
	evaluator.calls++
	return evaluator.decision
}

func TestEvaluateFailClosedScenarios(t *testing.T) {
	expected := verifier.Expected{
		Repository:        "github.com/example/project",
		HeadSHA:           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BaseSHA:           "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Profile:           "verify",
		PolicyDigest:      "sha256:policy",
		WorkflowDigest:    "sha256:workflow",
		EnvironmentDigest: "sha256:environment",
	}
	wantIdentity := store.Identity{
		Repository:        expected.Repository,
		HeadSHA:           expected.HeadSHA,
		BaseSHA:           expected.BaseSHA,
		Profile:           expected.Profile,
		PolicyDigest:      expected.PolicyDigest,
		WorkflowDigest:    expected.WorkflowDigest,
		EnvironmentDigest: expected.EnvironmentDigest,
	}
	tests := []struct {
		name           string
		source         proofSource
		decision       verifier.Decision
		wantAccepted   bool
		wantCode       string
		wantTrustCalls int
	}{
		{
			name:           "lookup error",
			source:         proofSource{path: "broken.json", err: errors.New("corrupt index")},
			wantCode:       "malformed_receipt",
			wantTrustCalls: 0,
		},
		{
			name:           "missing proof",
			source:         proofSource{},
			wantCode:       "proof_missing",
			wantTrustCalls: 0,
		},
		{
			name:           "trust rejection",
			source:         proofSource{path: "proof.json", found: true},
			decision:       verifier.Decision{Code: "expired", Message: "proof has expired"},
			wantCode:       "expired",
			wantTrustCalls: 1,
		},
		{
			name:           "invalid evaluator result",
			source:         proofSource{path: "proof.json", found: true},
			wantCode:       "malformed_receipt",
			wantTrustCalls: 1,
		},
		{
			name:           "accepted proof",
			source:         proofSource{path: "proof.json", found: true},
			decision:       verifier.Decision{Accepted: true, Code: "accepted", Message: "proof accepted"},
			wantAccepted:   true,
			wantCode:       "accepted",
			wantTrustCalls: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluator := &trustEvaluator{decision: test.decision}
			result := acceptance.Evaluate(&test.source, evaluator, expected)
			if result.Accepted != test.wantAccepted || result.Code != test.wantCode {
				t.Fatalf("result = %+v, want accepted=%v code=%q", result, test.wantAccepted, test.wantCode)
			}
			if test.source.identity != wantIdentity || result.Identity != wantIdentity {
				t.Fatalf("identity = %+v / %+v, want %+v", test.source.identity, result.Identity, wantIdentity)
			}
			if evaluator.calls != test.wantTrustCalls {
				t.Fatalf("trust calls = %d, want %d", evaluator.calls, test.wantTrustCalls)
			}
		})
	}
}
