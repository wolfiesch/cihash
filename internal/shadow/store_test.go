package shadow_test

import (
	"strings"
	"testing"
	"time"

	"github.com/wolfiesch/cihash/internal/shadow"
)

func TestStoreCorrelatesDecisionAndWorkflowInEitherOrder(t *testing.T) {
	for _, workflowFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "decision-first", true: "workflow-first"}[workflowFirst], func(t *testing.T) {
			store := shadow.New(t.TempDir())
			decision, workflow := fixture()
			if workflowFirst {
				if _, found, err := store.RecordWorkflow(decision.Repository, workflow); err != nil || found {
					t.Fatalf("RecordWorkflow before decision = found %t, err %v", found, err)
				}
			}
			observation, err := store.RecordDecision(decision)
			if err != nil {
				t.Fatal(err)
			}
			if !workflowFirst {
				observation, _, err = store.RecordWorkflow(decision.Repository, workflow)
				if err != nil {
					t.Fatal(err)
				}
			}
			if observation.Parity != shadow.ParityMatch || observation.Workflow == nil {
				t.Fatalf("observation = %+v, want correlated match", observation)
			}
		})
	}
}

func TestStoreClassifiesMismatchAndNonComparable(t *testing.T) {
	decision, workflow := fixture()
	workflow.Conclusion = "failure"
	store := shadow.New(t.TempDir())
	if _, err := store.RecordDecision(decision); err != nil {
		t.Fatal(err)
	}
	observation, found, err := store.RecordWorkflow(decision.Repository, workflow)
	if err != nil || !found {
		t.Fatalf("RecordWorkflow = found %t, err %v", found, err)
	}
	if observation.Parity != shadow.ParityMismatch {
		t.Fatalf("parity = %q, want mismatch", observation.Parity)
	}

	decision.HeadSHA = strings.Repeat("d", 40)
	decision.CheckRunID++
	decision.TreeSHA = strings.Repeat("e", 40)
	decision.ProofAccepted = false
	decision.ProofCode = "proof_missing"
	decision.Comparable = false
	workflow.HeadSHA = decision.HeadSHA
	workflow.RunID++
	if _, err := store.RecordDecision(decision); err != nil {
		t.Fatal(err)
	}
	observation, _, err = store.RecordWorkflow(decision.Repository, workflow)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Parity != shadow.ParityNotComparable {
		t.Fatalf("parity = %q, want not_comparable", observation.Parity)
	}
}

func TestReportRequiresComparableCompleteZeroMismatchEvidence(t *testing.T) {
	store := shadow.New(t.TempDir())
	decision, workflow := fixture()
	if _, err := store.RecordDecision(decision); err != nil {
		t.Fatal(err)
	}
	report, err := store.Report(workflow.CompletedAt)
	if err != nil {
		t.Fatal(err)
	}
	if report.EnforcementReady || report.Pending != 1 {
		t.Fatalf("pending report = %+v", report)
	}
	if _, _, err := store.RecordWorkflow(decision.Repository, workflow); err != nil {
		t.Fatal(err)
	}
	report, err = store.Report(workflow.CompletedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !report.EnforcementReady || report.Matches != 1 || report.Mismatches != 0 {
		t.Fatalf("completed report = %+v", report)
	}
}

func TestStoreKeepsDistinctEvaluationsForSameCodeIdentity(t *testing.T) {
	store := shadow.New(t.TempDir())
	decision, workflow := fixture()
	first, err := store.RecordDecision(decision)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RecordWorkflow(decision.Repository, workflow); err != nil {
		t.Fatal(err)
	}
	decision.CheckRunID++
	decision.EvaluatedAt = decision.EvaluatedAt.Add(time.Second)
	second, err := store.RecordDecision(decision)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatal("distinct check evaluations share an observation identity")
	}
	report, err := store.Report(workflow.CompletedAt)
	if err != nil {
		t.Fatal(err)
	}
	if report.Total != 2 || report.Matches != 2 {
		t.Fatalf("report = %+v, want both evaluations correlated", report)
	}
}

func TestStoreRejectsDifferentWorkflowRunForBoundEvaluation(t *testing.T) {
	store := shadow.New(t.TempDir())
	decision, workflow := fixture()
	if _, err := store.RecordDecision(decision); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RecordWorkflow(decision.Repository, workflow); err != nil {
		t.Fatal(err)
	}
	workflow.RunID++
	workflow.CompletedAt = workflow.CompletedAt.Add(time.Minute)
	if _, _, err := store.RecordWorkflow(decision.Repository, workflow); err == nil {
		t.Fatal("RecordWorkflow replaced exact workflow evidence")
	}
}

func fixture() (shadow.Decision, shadow.Workflow) {
	now := time.Date(2026, time.July, 20, 20, 0, 0, 0, time.UTC)
	return shadow.Decision{
			Repository:            "owner/repository",
			PullRequestNumber:     7,
			HeadSHA:               strings.Repeat("a", 40),
			BaseSHA:               strings.Repeat("b", 40),
			TreeSHA:               strings.Repeat("c", 40),
			PolicyDigest:          "sha256:" + strings.Repeat("d", 64),
			ProofAccepted:         true,
			ProofCode:             "accepted",
			Comparable:            true,
			CheckRunID:            42,
			EvaluatedAt:           now,
			VerificationMillis:    5,
			AppDecisionMillis:     9,
			ServiceSourceRevision: strings.Repeat("e", 40),
			ServiceBinaryDigest:   "sha256:" + strings.Repeat("f", 64),
			ServiceBuildMode:      "production",
			ServiceStartedAt:      now.Add(-time.Hour),
			PolicyTimeoutSeconds:  1800,
		}, shadow.Workflow{
			Name:              "Tooling",
			RunID:             99,
			PullRequestNumber: 7,
			HeadSHA:           strings.Repeat("a", 40),
			BaseSHA:           strings.Repeat("b", 40),
			Event:             "pull_request",
			RunAttempt:        1,
			Conclusion:        "success",
			StartedAt:         now.Add(time.Second),
			CompletedAt:       now.Add(time.Minute),
		}
}
