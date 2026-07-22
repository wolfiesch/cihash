package lab

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/verifier"
)

func RunJobSet() (Report, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Report{}, fmt.Errorf("generate job-set signer: %w", err)
	}
	now := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	jobs := []verifier.ExpectedJob{
		{Name: "unit", Command: []string{"go", "test", "./..."}},
		{Name: "lint", Command: []string{"go", "vet", "./..."}},
	}
	result := attestation.TestResult{
		SchemaVersion:     attestation.SchemaVersion,
		Repository:        "github.com/cihash/job-set-lab",
		HeadSHA:           strings.Repeat("a", 40),
		BaseSHA:           strings.Repeat("b", 40),
		TreeSHA:           strings.Repeat("c", 40),
		Profile:           "required",
		PolicyDigest:      attestation.Digest([]byte("job-set-policy")),
		WorkflowDigest:    attestation.Digest([]byte("job-set-workflow")),
		EnvironmentDigest: attestation.Digest([]byte("job-set-environment")),
		Architecture:      "linux/amd64",
		Jobs: []attestation.JobResult{
			jobResult(jobs[0], now.Add(-2*time.Minute), now.Add(-90*time.Second), "unit log"),
			jobResult(jobs[1], now.Add(-90*time.Second), now.Add(-time.Second), "lint log"),
		},
		Conclusion: "success",
		Nonce:      "job-set-nonce",
		IssuedAt:   now,
		ExpiresAt:  now.Add(time.Hour),
	}
	expected := verifier.Expected{
		Repository:        result.Repository,
		HeadSHA:           result.HeadSHA,
		BaseSHA:           result.BaseSHA,
		TreeSHA:           result.TreeSHA,
		Profile:           result.Profile,
		PolicyDigest:      result.PolicyDigest,
		WorkflowDigest:    result.WorkflowDigest,
		EnvironmentDigest: result.EnvironmentDigest,
		Architecture:      result.Architecture,
		Jobs:              cloneExpectedJobs(jobs),
		Nonce:             result.Nonce,
		MaxAge:            time.Hour,
		Now:               now,
	}

	scenarios := []struct {
		name         string
		expectedCode string
		mutate       func(*attestation.TestResult)
	}{
		{name: "complete-job-set", expectedCode: "accepted"},
		{name: "missing-required-job", expectedCode: "job_set_mismatch", mutate: func(result *attestation.TestResult) {
			result.Jobs = result.Jobs[:1]
		}},
		{name: "duplicate-required-job", expectedCode: "job_set_mismatch", mutate: func(result *attestation.TestResult) {
			result.Jobs[1] = cloneJobResult(result.Jobs[0])
		}},
		{name: "unapproved-job", expectedCode: "job_set_mismatch", mutate: func(result *attestation.TestResult) {
			result.Jobs[1].Name = "build"
		}},
		{name: "changed-job-command", expectedCode: "workflow_mismatch", mutate: func(result *attestation.TestResult) {
			result.Jobs[1].Command = []string{"go", "vet", "./internal/..."}
		}},
		{name: "failed-required-job", expectedCode: "job_failed", mutate: func(result *attestation.TestResult) {
			result.Jobs[1].ExitCode = 1
			result.Jobs[1].Conclusion = "failure"
			result.Conclusion = "failure"
		}},
	}

	report := Report{SchemaVersion: ReportSchema, Experiment: "complete-job-set", Passed: true}
	for _, scenario := range scenarios {
		candidate := cloneTestResult(result)
		if scenario.mutate != nil {
			scenario.mutate(&candidate)
		}
		envelope, signErr := attestation.Sign(attestation.NewStatement(candidate), privateKey)
		if signErr != nil {
			return Report{}, fmt.Errorf("sign %s receipt: %w", scenario.name, signErr)
		}
		decision := verifier.Verify(envelope, publicKey, expected)
		actualCode := decision.Code
		if decision.Accepted {
			actualCode = "accepted"
		}
		passed := actualCode == scenario.expectedCode
		report.Passed = report.Passed && passed
		report.Scenarios = append(report.Scenarios, ScenarioResult{
			Name:         scenario.name,
			Accepted:     decision.Accepted,
			Code:         actualCode,
			ExpectedCode: scenario.expectedCode,
			Passed:       passed,
		})
	}
	return report, nil
}

func jobResult(job verifier.ExpectedJob, startedAt, completedAt time.Time, log string) attestation.JobResult {
	return attestation.JobResult{
		Name:        job.Name,
		Command:     append([]string(nil), job.Command...),
		Conclusion:  "success",
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		LogDigest:   attestation.Digest([]byte(log)),
	}
}

func cloneExpectedJobs(jobs []verifier.ExpectedJob) []verifier.ExpectedJob {
	cloned := make([]verifier.ExpectedJob, len(jobs))
	for index, job := range jobs {
		cloned[index] = verifier.ExpectedJob{Name: job.Name, Command: append([]string(nil), job.Command...)}
	}
	return cloned
}

func cloneTestResult(result attestation.TestResult) attestation.TestResult {
	cloned := result
	cloned.Jobs = make([]attestation.JobResult, len(result.Jobs))
	for index, job := range result.Jobs {
		cloned.Jobs[index] = cloneJobResult(job)
	}
	return cloned
}

func cloneJobResult(job attestation.JobResult) attestation.JobResult {
	job.Command = append([]string(nil), job.Command...)
	return job
}
