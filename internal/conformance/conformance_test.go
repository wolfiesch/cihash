package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/policy"
	"github.com/wolfiesch/cihash/internal/rungrant"
)

func TestCheckAcceptsSuccessfulAndFailedCompleteResults(t *testing.T) {
	grant, result, now := conformanceFixture(t)
	report := Check(grant, result, now)
	if !report.Conformant || !report.SigningEligible || !report.ResultSucceeded || report.Code != "conformant" {
		t.Fatalf("successful report = %+v", report)
	}
	result.Jobs[0].ExitCode = 1
	result.Jobs[0].Conclusion = "failure"
	result.Conclusion = "failure"
	report = Check(grant, result, now)
	if !report.Conformant || !report.SigningEligible || report.ResultSucceeded || report.Code != "job_failed" {
		t.Fatalf("failed report = %+v", report)
	}
}
func TestCheckRejectsContradictoryResultAsNonconformant(t *testing.T) {
	grant, result, now := conformanceFixture(t)
	result.Conclusion = "failure"
	report := Check(grant, result, now)
	if report.Conformant || report.SigningEligible || report.ResultSucceeded || report.Code != "malformed_receipt" {
		t.Fatalf("contradictory report = %+v", report)
	}
}

func TestReportJSONDoesNotClaimAuthorization(t *testing.T) {
	grant, result, now := conformanceFixture(t)
	report := Check(grant, result, now)
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if !strings.Contains(text, `"signingEligible":true`) || !strings.Contains(text, `"resultSucceeded":true`) || strings.Contains(text, "authoriz") {
		t.Fatalf("report JSON = %s", text)
	}
}

func TestLoadRejectsUnknownAndTrailingJSON(t *testing.T) {
	for name, content := range map[string]string{
		"unknown":  `{"schemaVersion":"0.1","unknown":true}`,
		"trailing": `{} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			var result attestation.TestResult
			if err := Load(path, &result); err == nil {
				t.Fatal("Load succeeded, want error")
			}
		})
	}
}

func conformanceFixture(t *testing.T) (rungrant.Grant, attestation.TestResult, time.Time) {
	t.Helper()
	now := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	configured := policy.Policy{
		Version: policy.Version, Repository: "github.com/example/project", Profile: "verify", Command: []string{"true"},
		Environment:   policy.Environment{Image: "sha256:" + strings.Repeat("a", 64), Platform: "linux/amd64", Network: "none", Memory: "1g", CPUs: "1", PIDsLimit: 64, MaxOutputBytes: 1024},
		MaxAgeSeconds: 60, TimeoutSeconds: 30,
	}
	grant, err := rungrant.Issue(configured, strings.Repeat("b", 40), strings.Repeat("c", 40), strings.Repeat("d", 40), now)
	if err != nil {
		t.Fatal(err)
	}
	result := attestation.TestResult{
		SchemaVersion: attestation.SchemaVersion, Repository: configured.Repository, HeadSHA: grant.HeadSHA, BaseSHA: grant.BaseSHA, TreeSHA: grant.TreeSHA,
		Profile: configured.Profile, PolicyDigest: grant.PolicyDigest, WorkflowDigest: grant.WorkflowDigest, EnvironmentDigest: grant.EnvironmentDigest, Architecture: grant.Architecture,
		Jobs:       []attestation.JobResult{{Name: configured.Profile, Command: configured.Command, Conclusion: "success", StartedAt: now, CompletedAt: now.Add(time.Second), LogDigest: attestation.Digest([]byte("log"))}},
		Conclusion: "success", Nonce: grant.Nonce, IssuedAt: now.Add(2 * time.Second), ExpiresAt: grant.ExpiresAt,
	}
	return grant, result, now.Add(3 * time.Second)
}
