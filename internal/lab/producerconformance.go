package lab

import (
	"strings"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/conformance"
	"github.com/wolfiesch/cihash/internal/policy"
	"github.com/wolfiesch/cihash/internal/rungrant"
)

const ProducerConformanceReportSchema = "https://cihash.dev/lab/producer-conformance-report/v0.1"

type ProducerConformanceScenario struct {
	Name            string `json:"name"`
	Conformant      bool   `json:"conformant"`
	SigningEligible bool   `json:"signingEligible"`
	ResultSucceeded bool   `json:"resultSucceeded"`
	Code            string `json:"code"`
	ExpectedCode    string `json:"expectedCode"`
	Passed          bool   `json:"passed"`
}

type ProducerConformanceReport struct {
	SchemaVersion string                        `json:"schemaVersion"`
	Experiment    string                        `json:"experiment"`
	Passed        bool                          `json:"passed"`
	Scenarios     []ProducerConformanceScenario `json:"scenarios"`
}

func RunProducerConformance() (ProducerConformanceReport, error) {
	now := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	configured := policy.Policy{
		Version:    policy.Version,
		Repository: "github.com/cihash/producer-lab",
		Profile:    "verify",
		Command:    []string{"go", "test", "./..."},
		Environment: policy.Environment{
			Image:          "sha256:" + strings.Repeat("a", 64),
			Platform:       "linux/amd64",
			Network:        "none",
			Memory:         "1g",
			CPUs:           "1",
			PIDsLimit:      256,
			MaxOutputBytes: 1 << 20,
		},
		MaxAgeSeconds:  3600,
		TimeoutSeconds: 300,
	}
	grant, err := rungrant.Issue(configured, strings.Repeat("b", 40), strings.Repeat("c", 40), strings.Repeat("d", 40), now)
	if err != nil {
		return ProducerConformanceReport{}, err
	}
	result := attestation.TestResult{
		SchemaVersion:     attestation.SchemaVersion,
		Repository:        configured.Repository,
		HeadSHA:           grant.HeadSHA,
		BaseSHA:           grant.BaseSHA,
		TreeSHA:           grant.TreeSHA,
		Profile:           configured.Profile,
		PolicyDigest:      grant.PolicyDigest,
		WorkflowDigest:    grant.WorkflowDigest,
		EnvironmentDigest: grant.EnvironmentDigest,
		Architecture:      grant.Architecture,
		Jobs: []attestation.JobResult{{
			Name:        configured.Profile,
			Command:     append([]string(nil), configured.Command...),
			Conclusion:  "success",
			StartedAt:   now.Add(time.Second),
			CompletedAt: now.Add(2 * time.Second),
			LogDigest:   attestation.Digest([]byte("producer log")),
		}},
		Conclusion: "success",
		Nonce:      grant.Nonce,
		IssuedAt:   now.Add(3 * time.Second),
		ExpiresAt:  grant.ExpiresAt,
	}

	scenarios := []struct {
		name         string
		expectedCode string
		conformant   bool
		successful   bool
		mutate       func(*attestation.TestResult)
	}{
		{name: "complete successful result", expectedCode: "conformant", conformant: true, successful: true},
		{name: "complete failed result", expectedCode: "job_failed", conformant: true, mutate: func(result *attestation.TestResult) {
			result.Jobs[0].ExitCode = 1
			result.Jobs[0].Conclusion = "failure"
			result.Conclusion = "failure"
		}},
		{name: "missing tree identity", expectedCode: "tree_mismatch", mutate: func(result *attestation.TestResult) {
			result.TreeSHA = ""
		}},
		{name: "missing nonce", expectedCode: "nonce_invalid", mutate: func(result *attestation.TestResult) {
			result.Nonce = ""
		}},
		{name: "missing required job", expectedCode: "job_set_mismatch", mutate: func(result *attestation.TestResult) {
			result.Jobs = nil
		}},
		{name: "changed command", expectedCode: "workflow_mismatch", mutate: func(result *attestation.TestResult) {
			result.Jobs[0].Command = []string{"go", "test", "./internal/..."}
		}},
	}

	report := ProducerConformanceReport{SchemaVersion: ProducerConformanceReportSchema, Experiment: "producer-conformance", Passed: true}
	for _, scenario := range scenarios {
		candidate := cloneTestResult(result)
		if scenario.mutate != nil {
			scenario.mutate(&candidate)
		}
		checked := conformance.Check(grant, candidate, now.Add(4*time.Second))
		passed := checked.Code == scenario.expectedCode && checked.Conformant == scenario.conformant && checked.SigningEligible == scenario.conformant && checked.ResultSucceeded == scenario.successful
		report.Passed = report.Passed && passed
		report.Scenarios = append(report.Scenarios, ProducerConformanceScenario{
			Name:            scenario.name,
			Conformant:      checked.Conformant,
			SigningEligible: checked.SigningEligible,
			ResultSucceeded: checked.ResultSucceeded,
			Code:            checked.Code,
			ExpectedCode:    scenario.expectedCode,
			Passed:          passed,
		})
	}
	return report, nil
}
