package lab

import (
	"strings"

	"github.com/wolfiesch/cihash/internal/applicability"
	"github.com/wolfiesch/cihash/internal/attestation"
)

type applicabilityScenario struct {
	name         string
	claim        applicability.Claim
	current      applicability.Claim
	mode         applicability.ReuseMode
	expectedCode string
}

// RunApplicability exercises the lab-only merge-tree reuse experiment. A
// tree_equivalent result is not evidence that the hosted runner may reuse a
// receipt: it requires a tree-only execution mode and an administrator-approved
// policy binding that the current clone-based runner does not provide.
func RunApplicability() (Report, error) {
	claim := applicability.Claim{
		Repository:        "github.com/cihash/lab",
		HeadSHA:           strings.Repeat("a", 40),
		BaseSHA:           strings.Repeat("b", 40),
		MergeTreeSHA:      strings.Repeat("c", 40),
		PolicyDigest:      attestation.Digest([]byte("lab-policy")),
		WorkflowDigest:    attestation.Digest([]byte("lab-workflow")),
		EnvironmentDigest: attestation.Digest([]byte("lab-environment")),
		Context:           applicability.PullRequestContext,
	}
	movedBase := claim
	movedBase.BaseSHA = strings.Repeat("d", 40)
	changedTree := claim
	changedTree.MergeTreeSHA = strings.Repeat("d", 40)
	mergeGroup := claim
	mergeGroup.Context = applicability.MergeGroupContext
	policyMismatch := claim
	policyMismatch.PolicyDigest = attestation.Digest([]byte("changed-policy"))
	malformedIdentity := claim
	malformedIdentity.Repository = "github.com/cihash/"

	scenarios := []applicabilityScenario{
		{
			name:         "exact pull request acceptance",
			claim:        claim,
			current:      claim,
			mode:         applicability.StrictCommits,
			expectedCode: "accepted",
		},
		{
			name:         "moved base strict rejection",
			claim:        claim,
			current:      movedBase,
			mode:         applicability.StrictCommits,
			expectedCode: "base_mismatch",
		},
		{
			name:         "same tree moved base tree equivalence",
			claim:        claim,
			current:      movedBase,
			mode:         applicability.MergeTree,
			expectedCode: "tree_equivalent",
		},
		{
			name:         "changed tree rejection",
			claim:        claim,
			current:      changedTree,
			mode:         applicability.MergeTree,
			expectedCode: "merge_tree_mismatch",
		},
		{
			name:         "strict pull request to merge group rejection",
			claim:        claim,
			current:      mergeGroup,
			mode:         applicability.StrictCommits,
			expectedCode: "context_mismatch",
		},
		{
			name:         "same tree pull request to merge group equivalence",
			claim:        claim,
			current:      mergeGroup,
			mode:         applicability.MergeTree,
			expectedCode: "tree_equivalent",
		},
		{
			name:         "policy mismatch",
			claim:        claim,
			current:      policyMismatch,
			mode:         applicability.MergeTree,
			expectedCode: "policy_mismatch",
		},
		{
			name:         "malformed identity",
			claim:        claim,
			current:      malformedIdentity,
			mode:         applicability.StrictCommits,
			expectedCode: "invalid_repository",
		},
	}

	report := Report{
		SchemaVersion: ReportSchema,
		Experiment:    "github-state-applicability",
		Passed:        true,
		Scenarios:     make([]ScenarioResult, 0, len(scenarios)),
	}
	for _, scenario := range scenarios {
		decision := applicability.Evaluate(scenario.claim, scenario.current, scenario.mode)
		result := ScenarioResult{
			Name:         scenario.name,
			Accepted:     decision.Accepted,
			Code:         decision.Code,
			ExpectedCode: scenario.expectedCode,
			Passed:       decision.Code == scenario.expectedCode && decision.Accepted == acceptedApplicabilityCode(scenario.expectedCode),
		}
		report.Passed = report.Passed && result.Passed
		report.Scenarios = append(report.Scenarios, result)
	}
	return report, nil
}

func acceptedApplicabilityCode(code string) bool {
	return code == "accepted" || code == "tree_equivalent"
}
