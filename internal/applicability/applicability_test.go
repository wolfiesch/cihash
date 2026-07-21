package applicability

import (
	"strings"
	"testing"

	"github.com/wolfiesch/cihash/internal/attestation"
)

func TestEvaluate(t *testing.T) {
	claim := testClaim()
	movedBase := claim
	movedBase.BaseSHA = strings.Repeat("d", 40)
	changedTree := claim
	changedTree.MergeTreeSHA = strings.Repeat("d", 40)
	mergeGroup := claim
	mergeGroup.Context = MergeGroupContext
	policyMismatch := claim
	policyMismatch.PolicyDigest = attestation.Digest([]byte("other-policy"))
	workflowMismatch := claim
	workflowMismatch.WorkflowDigest = attestation.Digest([]byte("other-workflow"))
	environmentMismatch := claim
	environmentMismatch.EnvironmentDigest = attestation.Digest([]byte("other-environment"))
	repositoryMismatch := claim
	repositoryMismatch.Repository = "github.com/other/project"
	malformedRepository := claim
	malformedRepository.Repository = "github.com/owner/"
	malformedHead := claim
	malformedHead.HeadSHA = "not-a-git-object"
	malformedDigest := claim
	malformedDigest.PolicyDigest = "sha256:not-hex"
	malformedContext := claim
	malformedContext.Context = Context("workflow_run")
	malformedTreeAndPolicy := claim
	malformedTreeAndPolicy.MergeTreeSHA = "invalid"
	malformedTreeAndPolicy.PolicyDigest = policyMismatch.PolicyDigest

	tests := []struct {
		name         string
		claim        Claim
		current      Claim
		mode         ReuseMode
		accepted     bool
		expectedCode string
	}{
		{
			name:         "strict exact pull request accepts",
			claim:        claim,
			current:      claim,
			mode:         StrictCommits,
			accepted:     true,
			expectedCode: "accepted",
		},
		{
			name:         "strict moved base rejects",
			claim:        claim,
			current:      movedBase,
			mode:         StrictCommits,
			expectedCode: "base_mismatch",
		},
		{
			name:         "merge tree moved base accepts equivalence",
			claim:        claim,
			current:      movedBase,
			mode:         MergeTree,
			accepted:     true,
			expectedCode: "tree_equivalent",
		},
		{
			name:         "merge tree changed tree rejects",
			claim:        claim,
			current:      changedTree,
			mode:         MergeTree,
			expectedCode: "merge_tree_mismatch",
		},
		{
			name:         "strict context change rejects",
			claim:        claim,
			current:      mergeGroup,
			mode:         StrictCommits,
			expectedCode: "context_mismatch",
		},
		{
			name:         "merge tree context change accepts equivalence",
			claim:        claim,
			current:      mergeGroup,
			mode:         MergeTree,
			accepted:     true,
			expectedCode: "tree_equivalent",
		},
		{
			name:         "policy mismatch rejects before reuse",
			claim:        claim,
			current:      policyMismatch,
			mode:         MergeTree,
			expectedCode: "policy_mismatch",
		},
		{
			name:         "workflow mismatch rejects before reuse",
			claim:        claim,
			current:      workflowMismatch,
			mode:         MergeTree,
			expectedCode: "workflow_mismatch",
		},
		{
			name:         "environment mismatch rejects before reuse",
			claim:        claim,
			current:      environmentMismatch,
			mode:         MergeTree,
			expectedCode: "environment_mismatch",
		},
		{
			name:         "repository mismatch rejects before tree reuse",
			claim:        claim,
			current:      repositoryMismatch,
			mode:         MergeTree,
			expectedCode: "repository_mismatch",
		},
		{
			name:         "invalid mode fails closed",
			claim:        claim,
			current:      claim,
			mode:         ReuseMode("anything_else"),
			expectedCode: "invalid_reuse_mode",
		},
		{
			name:         "malformed repository fails closed",
			claim:        claim,
			current:      malformedRepository,
			mode:         StrictCommits,
			expectedCode: "invalid_repository",
		},
		{
			name:         "malformed git object fails closed",
			claim:        malformedHead,
			current:      claim,
			mode:         StrictCommits,
			expectedCode: "invalid_head_sha",
		},
		{
			name:         "malformed digest fails closed",
			claim:        claim,
			current:      malformedDigest,
			mode:         StrictCommits,
			expectedCode: "invalid_policy_digest",
		},
		{
			name:         "malformed context fails closed",
			claim:        claim,
			current:      malformedContext,
			mode:         StrictCommits,
			expectedCode: "invalid_context",
		},
		{
			name:         "validation precedes comparison",
			claim:        claim,
			current:      malformedTreeAndPolicy,
			mode:         MergeTree,
			expectedCode: "invalid_merge_tree_sha",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := Evaluate(test.claim, test.current, test.mode)
			if decision.Accepted != test.accepted || decision.Code != test.expectedCode {
				t.Fatalf("Evaluate() = (%t, %q), want (%t, %q)", decision.Accepted, decision.Code, test.accepted, test.expectedCode)
			}
		})
	}
}

func testClaim() Claim {
	return Claim{
		Repository:        "github.com/cihash/lab",
		HeadSHA:           strings.Repeat("a", 40),
		BaseSHA:           strings.Repeat("b", 40),
		MergeTreeSHA:      strings.Repeat("c", 40),
		PolicyDigest:      attestation.Digest([]byte("policy")),
		WorkflowDigest:    attestation.Digest([]byte("workflow")),
		EnvironmentDigest: attestation.Digest([]byte("environment")),
		Context:           PullRequestContext,
	}
}
