package runner_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wolfiesch/cihash/internal/policy"
	"github.com/wolfiesch/cihash/internal/rungrant"
	"github.com/wolfiesch/cihash/internal/runner"
)

func TestRunExecutesAuthoritativeMetadataFreeMergeTree(t *testing.T) {
	repository, baseSHA, headSHA := createRepository(t)
	if err := os.WriteFile(filepath.Join(repository, "uncommitted.txt"), []byte("must not enter proof input\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	docker := fakeDocker(t, `
+[ "$platform" = "linux/amd64" ]
	[ "$image" = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ]
+[ "$(cat "$source/common.txt")" = common ]
+[ "$(cat "$source/result.txt")" = passed ]
+[ "$(cat "$source/base-advanced.txt")" = advanced ]
+[ ! -e "$source/.git" ]
+[ ! -e "$source/uncommitted.txt" ]
+printf verified
+`)
	grant := issueGrant(t, repository, baseSHA, headSHA, 3600, 30)
	outcome, err := runner.Run(context.Background(), runner.Request{
		RepositoryPath: repository,
		Grant:          grant,
		Container:      runner.ContainerConfig{DockerBinary: docker},
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
	expectedTree := git(t, repository, "merge-tree", "--write-tree", "--no-messages", baseSHA, headSHA)
	if outcome.Result.TreeSHA != expectedTree {
		t.Fatalf("tree = %s, want authoritative merge tree %s", outcome.Result.TreeSHA, expectedTree)
	}
	if len(outcome.Result.Jobs) != 1 || !slices.Equal(outcome.Result.Jobs[0].Command, grant.Policy.Command) {
		t.Fatalf("receipt job command = %v, want %v", outcome.Result.Jobs, grant.Policy.Command)
	}
	if outcome.Result.Nonce != grant.Nonce || outcome.Result.Architecture != grant.Architecture || !outcome.Result.ExpiresAt.Equal(grant.ExpiresAt) {
		t.Fatalf("receipt does not retain grant identity: %+v", outcome.Result)
	}
	if strings.TrimSpace(string(outcome.Log)) != "verified" {
		t.Fatalf("log = %q, want verified", outcome.Log)
	}
}

func TestResolveMergeTreeIgnoresRepositoryReplacementRefs(t *testing.T) {
	repository, baseSHA, headSHA := createRepository(t)
	expected, err := runner.ResolveMergeTree(context.Background(), repository, baseSHA, headSHA)
	if err != nil {
		t.Fatal(err)
	}
	git(t, repository, "replace", headSHA, baseSHA)
	actual, err := runner.ResolveMergeTree(context.Background(), repository, baseSHA, headSHA)
	if err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("merge tree with replacement ref = %s, want %s", actual, expected)
	}
}

func TestResolveMergeTreeDoesNotExecuteRepositoryMergeDriver(t *testing.T) {
	repository, baseSHA, headSHA := createConflictedRepository(t)
	attributesPath := git(t, repository, "rev-parse", "--git-path", "info/attributes")
	if !filepath.IsAbs(attributesPath) {
		attributesPath = filepath.Join(repository, attributesPath)
	}
	if err := os.WriteFile(attributesPath, []byte("conflict.txt merge=host-command\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	driverDirectory := t.TempDir()
	driver := filepath.Join(driverDirectory, "merge-driver")
	marker := filepath.Join(driverDirectory, "executed")
	if err := os.WriteFile(driver, []byte("#!/bin/sh\ntouch \"$(dirname \"$0\")/executed\"\ncp \"$3\" \"$2\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, repository, "config", "merge.host-command.driver", driver+" %O %A %B")

	_, _ = runner.ResolveMergeTree(context.Background(), repository, baseSHA, headSHA)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("repository merge driver executed on host: %v", err)
	}
}

func TestRunRejectsConflictedMergeBeforeExecution(t *testing.T) {
	repository, baseSHA, headSHA := createConflictedRepository(t)
	_, err := runner.Run(context.Background(), runner.Request{
		RepositoryPath: repository,
		Grant:          issueGrant(t, repository, baseSHA, headSHA, 3600, 30),
		Container:      runner.ContainerConfig{DockerBinary: filepath.Join(t.TempDir(), "missing-docker")},
	})
	if err == nil || !strings.Contains(err.Error(), "compute base-plus-head merge tree") {
		t.Fatalf("Run error = %v, want merge conflict rejection", err)
	}
}

func TestRunRejectsMutableEnvironmentBeforeExecution(t *testing.T) {
	repository, baseSHA, headSHA := createRepository(t)
	grant := issueGrant(t, repository, baseSHA, headSHA, 3600, 30)
	grant.Policy.Environment.Image = "node:24"
	_, err := runner.Run(context.Background(), runner.Request{
		RepositoryPath: repository,
		Grant:          grant,
		Container:      runner.ContainerConfig{DockerBinary: filepath.Join(t.TempDir(), "missing-docker")},
	})
	if err == nil || !strings.Contains(err.Error(), "pinned by sha256") {
		t.Fatalf("Run error = %v, want mutable image rejection", err)
	}
}

func TestRunBoundsTimeoutAndRemovesContainer(t *testing.T) {
	repository, baseSHA, headSHA := createRepository(t)
	calls := filepath.Join(t.TempDir(), "docker-calls")
	t.Setenv("CIHASH_FAKE_DOCKER_CALLS", calls)
	docker := fakeDocker(t, `
+printf fake-container > "$cidfile"
+exec sleep 5
+`)
	outcome, err := runner.Run(context.Background(), runner.Request{
		RepositoryPath: repository,
		Grant:          issueGrant(t, repository, baseSHA, headSHA, 3600, 1),
		Container:      runner.ContainerConfig{DockerBinary: docker},
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result.Conclusion != "failure" || outcome.Result.Jobs[0].ExitCode != -1 || !strings.Contains(string(outcome.Log), "approved timeout") {
		t.Fatalf("timeout outcome = %+v, log %q", outcome.Result, outcome.Log)
	}
	callsData, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(callsData), "rm --force fake-container") {
		t.Fatalf("Docker calls = %q, want forced cleanup", callsData)
	}
}

func TestRunRejectsExpiredGrant(t *testing.T) {
	repository, baseSHA, headSHA := createRepository(t)
	grant := issueGrant(t, repository, baseSHA, headSHA, 1, 1)
	grant.IssuedAt = grant.IssuedAt.Add(-2 * time.Second)
	grant.ExpiresAt = grant.ExpiresAt.Add(-2 * time.Second)
	_, err := runner.Run(context.Background(), runner.Request{
		RepositoryPath: repository,
		Grant:          grant,
		Container:      runner.ContainerConfig{DockerBinary: filepath.Join(t.TempDir(), "missing-docker")},
	})
	if !errors.Is(err, rungrant.ErrGrantExpired) {
		t.Fatalf("Run error = %v, want ErrGrantExpired", err)
	}
}

func fakeDocker(t *testing.T, runBody string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "docker")
	script := strings.ReplaceAll(`#!/bin/sh
+set -eu
+if [ "${1:-}" = rm ]; then
+  printf '%s\n' "$*" >> "${CIHASH_FAKE_DOCKER_CALLS:?}"
+  exit 0
+fi
+source=
+platform=
+cidfile=
image=
+previous=
+for argument in "$@"; do
+  case "$argument" in
+    --platform=*) platform=${argument#--platform=} ;;
    sha256:*) image=$argument ;;
+    type=bind,src=*,dst=/input,readonly)
+      source=${argument#type=bind,src=}
+      source=${source%,dst=/input,readonly}
+      ;;
+  esac
+  if [ "$previous" = --cidfile ]; then cidfile=$argument; fi
+  previous=$argument
+done
`+runBody, "\n+", "\n")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func issueGrant(t *testing.T, repository, baseSHA, headSHA string, maxAgeSeconds, timeoutSeconds int64) rungrant.Grant {
	t.Helper()
	treeSHA, err := runner.ResolveMergeTree(context.Background(), repository, baseSHA, headSHA)
	if err != nil {
		treeSHA = strings.Repeat("c", len(headSHA))
	}
	grant, err := rungrant.Issue(testPolicy(maxAgeSeconds, timeoutSeconds), headSHA, baseSHA, treeSHA, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func testPolicy(maxAgeSeconds, timeoutSeconds int64) policy.Policy {
	return policy.Policy{
		Version:    policy.Version,
		Repository: "github.com/example/fixture",
		Profile:    "verify",
		Command:    []string{"verify"},
		Environment: policy.Environment{
			Image:          "sha256:" + strings.Repeat("a", 64),
			Platform:       "linux/amd64",
			Network:        "none",
			Memory:         "8g",
			CPUs:           "6",
			PIDsLimit:      1024,
			MaxOutputBytes: 16 << 20,
		},
		MaxAgeSeconds:  maxAgeSeconds,
		TimeoutSeconds: timeoutSeconds,
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
	if err := os.WriteFile(filepath.Join(repository, "common.txt"), []byte("common\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, repository, "add", "common.txt")
	git(t, repository, "commit", "-m", "initial fixture")
	git(t, repository, "switch", "-c", "feature")
	if err := os.WriteFile(filepath.Join(repository, "result.txt"), []byte("passed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, repository, "add", "result.txt")
	git(t, repository, "commit", "-m", "add passing result")
	headSHA := git(t, repository, "rev-parse", "HEAD")
	git(t, repository, "switch", "main")
	if err := os.WriteFile(filepath.Join(repository, "base-advanced.txt"), []byte("advanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, repository, "add", "base-advanced.txt")
	git(t, repository, "commit", "-m", "advance base")
	baseSHA := git(t, repository, "rev-parse", "HEAD")
	return repository, baseSHA, headSHA
}

func createConflictedRepository(t *testing.T) (string, string, string) {
	t.Helper()
	repository := filepath.Join(t.TempDir(), "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, repository, "init", "-b", "main")
	git(t, repository, "config", "user.name", "CIHash Test")
	git(t, repository, "config", "user.email", "cihash@example.invalid")
	if err := os.WriteFile(filepath.Join(repository, "value.txt"), []byte("common\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, repository, "add", "value.txt")
	git(t, repository, "commit", "-m", "common")
	git(t, repository, "switch", "-c", "feature")
	if err := os.WriteFile(filepath.Join(repository, "value.txt"), []byte("feature\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, repository, "commit", "-am", "feature")
	headSHA := git(t, repository, "rev-parse", "HEAD")
	git(t, repository, "switch", "main")
	if err := os.WriteFile(filepath.Join(repository, "value.txt"), []byte("base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, repository, "commit", "-am", "base")
	baseSHA := git(t, repository, "rev-parse", "HEAD")
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
