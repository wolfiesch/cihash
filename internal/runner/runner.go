package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/policy"
)

type Request struct {
	RepositoryPath string
	HeadRevision   string
	BaseRevision   string
	Policy         policy.Policy
	Nonce          string
}

type Outcome struct {
	Result attestation.TestResult
	Log    []byte
}

func Run(ctx context.Context, request Request) (Outcome, error) {
	if strings.TrimSpace(request.Nonce) == "" {
		return Outcome{}, fmt.Errorf("runner nonce is required")
	}
	if err := request.Policy.Validate(); err != nil {
		return Outcome{}, err
	}
	repositoryPath, err := filepath.Abs(request.RepositoryPath)
	if err != nil {
		return Outcome{}, fmt.Errorf("resolve repository path: %w", err)
	}
	if err := requireCleanRepository(ctx, repositoryPath); err != nil {
		return Outcome{}, err
	}
	headSHA, err := resolveCommit(ctx, repositoryPath, request.HeadRevision)
	if err != nil {
		return Outcome{}, fmt.Errorf("resolve head: %w", err)
	}
	baseSHA, err := resolveCommit(ctx, repositoryPath, request.BaseRevision)
	if err != nil {
		return Outcome{}, fmt.Errorf("resolve base: %w", err)
	}

	temporaryRoot, err := os.MkdirTemp("", "cihash-run-*")
	if err != nil {
		return Outcome{}, fmt.Errorf("create runner workspace: %w", err)
	}
	defer os.RemoveAll(temporaryRoot)
	workspace := filepath.Join(temporaryRoot, "repository")
	if output, err := runGit(ctx, "", "clone", "--no-checkout", "--local", repositoryPath, workspace); err != nil {
		return Outcome{}, fmt.Errorf("clone committed repository: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if output, err := runGit(ctx, workspace, "checkout", "--detach", "--force", headSHA); err != nil {
		return Outcome{}, fmt.Errorf("checkout head: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if output, err := runGit(ctx, workspace, "-c", "user.name=CIHash", "-c", "user.email=cihash@example.invalid", "merge", "--no-commit", "--no-ff", "--no-verify", baseSHA); err != nil {
		return Outcome{}, fmt.Errorf("prepare tested merge tree: %w: %s", err, strings.TrimSpace(string(output)))
	}
	treeOutput, err := runGit(ctx, workspace, "write-tree")
	if err != nil {
		return Outcome{}, fmt.Errorf("resolve tested tree: %w", err)
	}
	treeSHA := strings.TrimSpace(string(treeOutput))
	if output, err := runGit(ctx, workspace, "remote", "remove", "origin"); err != nil {
		return Outcome{}, fmt.Errorf("remove cloned remote: %w: %s", err, strings.TrimSpace(string(output)))
	}

	home := filepath.Join(temporaryRoot, "home")
	temporaryDirectory := filepath.Join(temporaryRoot, "tmp")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return Outcome{}, fmt.Errorf("create runner home: %w", err)
	}
	if err := os.MkdirAll(temporaryDirectory, 0o700); err != nil {
		return Outcome{}, fmt.Errorf("create runner temporary directory: %w", err)
	}

	commandContext, cancel := context.WithTimeout(ctx, time.Duration(request.Policy.TimeoutSeconds)*time.Second)
	defer cancel()
	command := exec.CommandContext(commandContext, request.Policy.Command[0], request.Policy.Command[1:]...)
	command.Dir = workspace
	command.Env = workloadEnvironment(home, temporaryDirectory)
	startedAt := time.Now().UTC()
	log, runError := command.CombinedOutput()
	completedAt := time.Now().UTC()
	exitCode := 0
	conclusion := "success"
	if runError != nil {
		conclusion = "failure"
		exitCode = exitCodeFor(runError)
	}
	if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
		conclusion = "failure"
		exitCode = -1
		log = append(log, []byte("\n[cihash] command exceeded the approved timeout\n")...)
	}

	policyDigest, err := request.Policy.Digest()
	if err != nil {
		return Outcome{}, err
	}
	workflowDigest, err := request.Policy.WorkflowDigest()
	if err != nil {
		return Outcome{}, err
	}
	issuedAt := time.Now().UTC()
	result := attestation.TestResult{
		SchemaVersion:     attestation.SchemaVersion,
		Repository:        request.Policy.Repository,
		HeadSHA:           headSHA,
		BaseSHA:           baseSHA,
		TreeSHA:           treeSHA,
		Profile:           request.Policy.Profile,
		PolicyDigest:      policyDigest,
		WorkflowDigest:    workflowDigest,
		EnvironmentDigest: request.Policy.EnvironmentDigest(),
		Architecture:      runtime.GOOS + "/" + runtime.GOARCH,
		Jobs: []attestation.JobResult{{
			Name:        request.Policy.Profile,
			Command:     append([]string(nil), request.Policy.Command...),
			ExitCode:    exitCode,
			Conclusion:  conclusion,
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			LogDigest:   attestation.Digest(log),
		}},
		Conclusion: conclusion,
		Nonce:      request.Nonce,
		IssuedAt:   issuedAt,
		ExpiresAt:  issuedAt.Add(time.Duration(request.Policy.MaxAgeSeconds) * time.Second),
	}
	return Outcome{Result: result, Log: log}, nil
}

func requireCleanRepository(ctx context.Context, repositoryPath string) error {
	output, err := runGit(ctx, repositoryPath, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return fmt.Errorf("inspect repository state: %w", err)
	}
	if len(bytes.TrimSpace(output)) != 0 {
		return fmt.Errorf("repository has uncommitted or untracked changes; commit the exact tree before running CIHash")
	}
	return nil
}

func resolveCommit(ctx context.Context, repositoryPath, revision string) (string, error) {
	if strings.TrimSpace(revision) == "" {
		return "", fmt.Errorf("revision is required")
	}
	output, err := runGit(ctx, repositoryPath, "rev-parse", "--verify", "--end-of-options", revision+"^{commit}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func runGit(ctx context.Context, directory string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "git", arguments...)
	if directory != "" {
		command.Dir = directory
	}
	return command.CombinedOutput()
}

func workloadEnvironment(home, temporaryDirectory string) []string {
	environment := []string{
		"CI=1",
		"CIHASH=1",
		"HOME=" + home,
		"TMPDIR=" + temporaryDirectory,
	}
	for _, name := range []string{"PATH", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if value, ok := os.LookupEnv(name); ok {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

func exitCodeFor(err error) int {
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}
