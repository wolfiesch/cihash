package runner_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wolfiesch/cihash/internal/policy"
	"github.com/wolfiesch/cihash/internal/runner"
)

func TestRunExecutesCleanCommittedMergeTree(t *testing.T) {
	repository, baseSHA, headSHA := createRepository(t)
	configured := policy.Policy{
		Version:        policy.Version,
		Repository:     "github.com/example/fixture",
		Profile:        "verify",
		Command:        []string{"sh", "-c", `test "$(cat result.txt)" = passed && printf verified`},
		Environment:    "local://test",
		MaxAgeSeconds:  3600,
		TimeoutSeconds: 30,
	}
	outcome, err := runner.Run(context.Background(), runner.Request{
		RepositoryPath: repository,
		HeadRevision:   headSHA,
		BaseRevision:   baseSHA,
		Policy:         configured,
		Nonce:          "server-issued-nonce",
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result.Conclusion != "success" {
		t.Fatalf("conclusion = %q, want success; log: %s", outcome.Result.Conclusion, outcome.Log)
	}
	if outcome.Result.HeadSHA != headSHA || outcome.Result.BaseSHA != baseSHA {
		t.Fatalf("receipt identity = %s/%s, want %s/%s", outcome.Result.HeadSHA, outcome.Result.BaseSHA, headSHA, baseSHA)
	}
	if strings.TrimSpace(string(outcome.Log)) != "verified" {
		t.Fatalf("log = %q, want verified", outcome.Log)
	}
}

func TestRunRejectsDirtyRepository(t *testing.T) {
	repository, baseSHA, headSHA := createRepository(t)
	if err := os.WriteFile(filepath.Join(repository, "uncommitted.txt"), []byte("dirty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runner.Run(context.Background(), runner.Request{
		RepositoryPath: repository,
		HeadRevision:   headSHA,
		BaseRevision:   baseSHA,
		Policy: policy.Policy{
			Version:        policy.Version,
			Repository:     "github.com/example/fixture",
			Profile:        "verify",
			Command:        []string{"true"},
			Environment:    "local://test",
			MaxAgeSeconds:  60,
			TimeoutSeconds: 30,
		},
		Nonce: "server-issued-nonce",
	})
	if err == nil || !strings.Contains(err.Error(), "uncommitted or untracked") {
		t.Fatalf("Run error = %v, want dirty-repository rejection", err)
	}
}

func createRepository(t *testing.T) (string, string, string) {
	t.Helper()
	repository := filepath.Join(t.TempDir(), "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, repository, "init", "-b", "main")
	git(t, repository, "config", "user.name", "CIHash Test")
	git(t, repository, "config", "user.email", "cihash@example.invalid")
	if err := os.WriteFile(filepath.Join(repository, "base.txt"), []byte("base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, repository, "add", "base.txt")
	git(t, repository, "commit", "-m", "initial fixture")
	baseSHA := git(t, repository, "rev-parse", "HEAD")
	git(t, repository, "switch", "-c", "feature")
	if err := os.WriteFile(filepath.Join(repository, "result.txt"), []byte("passed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, repository, "add", "result.txt")
	git(t, repository, "commit", "-m", "add passing result")
	headSHA := git(t, repository, "rev-parse", "HEAD")
	return repository, baseSHA, headSHA
}

func git(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
	return strings.TrimSpace(string(output))
}
