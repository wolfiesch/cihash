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

func TestReportWindowExcludesStalePendingFromReadiness(t *testing.T) {
	store := shadow.New(t.TempDir())
	stalePending, _ := fixture()
	stalePending.CheckRunID = 101
	stalePending.HeadSHA = strings.Repeat("1", 40)
	stalePending.TreeSHA = strings.Repeat("9", 40)
	stalePending.EvaluatedAt = stalePending.EvaluatedAt.Add(-48 * time.Hour)
	stalePending.ServiceStartedAt = stalePending.EvaluatedAt.Add(-time.Hour)
	stalePending.ProofAccepted = false
	stalePending.ProofCode = "proof_missing"
	stalePending.Comparable = false
	if _, err := store.RecordDecision(stalePending); err != nil {
		t.Fatal(err)
	}
	freshDecision, freshWorkflow := fixture()
	freshDecision.CheckRunID = 200
	freshWorkflow.RunID = 200
	if _, err := store.RecordDecision(freshDecision); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RecordWorkflow(freshDecision.Repository, freshWorkflow); err != nil {
		t.Fatal(err)
	}
	report, err := store.Report(freshDecision.EvaluatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if report.Pending != 1 || report.Matches != 1 {
		t.Fatalf("all-time counts = pending %d matches %d, want 1/1", report.Pending, report.Matches)
	}
	if report.WindowPending != 0 || report.WindowMatches != 1 {
		t.Fatalf("window counts = pending %d matches %d, want 0/1", report.WindowPending, report.WindowMatches)
	}
	if !report.EnforcementReady {
		t.Fatalf("enforcementReady = false with stale pending outside window and fresh match inside; report = %+v", report)
	}
}

func TestReportWindowRequiresFreshComparableAndBlocksOnStaleAllTimeMatch(t *testing.T) {
	store := shadow.New(t.TempDir())
	staleDecision, staleWorkflow := fixture()
	staleDecision.CheckRunID = 300
	staleDecision.HeadSHA = strings.Repeat("2", 40)
	staleDecision.TreeSHA = strings.Repeat("8", 40)
	staleDecision.EvaluatedAt = staleDecision.EvaluatedAt.Add(-48 * time.Hour)
	staleDecision.ServiceStartedAt = staleDecision.EvaluatedAt.Add(-time.Hour)
	staleWorkflow.RunID = 300
	staleWorkflow.HeadSHA = staleDecision.HeadSHA
	if _, err := store.RecordDecision(staleDecision); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RecordWorkflow(staleDecision.Repository, staleWorkflow); err != nil {
		t.Fatal(err)
	}
	report, err := store.Report(staleDecision.EvaluatedAt.Add(48 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if report.Matches != 1 {
		t.Fatalf("all-time matches = %d, want 1", report.Matches)
	}
	if report.WindowComparable != 0 {
		t.Fatalf("window comparable = %d, want 0 (no fresh comparable)", report.WindowComparable)
	}
	if report.EnforcementReady {
		t.Fatalf("enforcementReady = true with only a stale match and no fresh comparable; report = %+v", report)
	}
}

func TestReportWindowBuildEvidenceBlocksOnNonProductionNotComparable(t *testing.T) {
	store := shadow.New(t.TempDir())
	freshMatch, freshWorkflow := fixture()
	freshMatch.CheckRunID = 400
	freshWorkflow.RunID = 400
	if _, err := store.RecordDecision(freshMatch); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RecordWorkflow(freshMatch.Repository, freshWorkflow); err != nil {
		t.Fatal(err)
	}
	nonProduction, _ := fixture()
	nonProduction.CheckRunID = 401
	nonProduction.ProofAccepted = false
	nonProduction.ProofCode = "proof_missing"
	nonProduction.Comparable = false
	nonProduction.ServiceBuildMode = "development"
	if _, err := store.RecordDecision(nonProduction); err != nil {
		t.Fatal(err)
	}
	report, err := store.Report(freshMatch.EvaluatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if report.WindowMatches != 1 {
		t.Fatalf("window matches = %d, want 1", report.WindowMatches)
	}
	if report.WindowBuildEvidenceComplete {
		t.Fatalf("windowBuildEvidenceComplete = true despite non-production not_comparable inside window")
	}
	if report.EnforcementReady {
		t.Fatalf("enforcementReady = true with non-production not_comparable inside window; report = %+v", report)
	}
}

func TestReportWindowExcludesFutureDatedEvidence(t *testing.T) {
	store := shadow.New(t.TempDir())
	futureMatch, futureWorkflow := fixture()
	futureMatch.CheckRunID = 500
	futureMatch.EvaluatedAt = futureMatch.EvaluatedAt.Add(2 * time.Hour)
	futureMatch.ServiceStartedAt = futureMatch.EvaluatedAt.Add(-time.Hour)
	futureWorkflow.RunID = 500
	if _, err := store.RecordDecision(futureMatch); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RecordWorkflow(futureMatch.Repository, futureWorkflow); err != nil {
		t.Fatal(err)
	}
	report, err := store.Report(futureMatch.EvaluatedAt.Add(-1 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if report.Matches != 1 {
		t.Fatalf("all-time matches = %d, want 1", report.Matches)
	}
	if report.WindowMatches != 0 || report.WindowComparable != 0 {
		t.Fatalf("window counts = matches %d comparable %d, want 0/0 (future evidence excluded)", report.WindowMatches, report.WindowComparable)
	}
	if report.EnforcementReady {
		t.Fatalf("enforcementReady = true with only future-dated evidence; report = %+v", report)
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
