package runner

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/containerexec"
	"github.com/wolfiesch/cihash/internal/gitexec"
	"github.com/wolfiesch/cihash/internal/rungrant"
	"github.com/wolfiesch/cihash/internal/treesource"
)

type ContainerConfig struct {
	DockerBinary   string
	MaxTreeEntries int
	MaxTreeBytes   int64
}

type Request struct {
	RepositoryPath string
	Grant          rungrant.Grant
	Container      ContainerConfig
}

type Outcome struct {
	Result attestation.TestResult
	Log    []byte
}

func Run(ctx context.Context, request Request) (Outcome, error) {
	if err := request.Grant.Validate(); err != nil {
		return Outcome{}, err
	}
	repositoryPath, err := repositoryPath(request.RepositoryPath)
	if err != nil {
		return Outcome{}, err
	}
	headSHA, baseSHA, err := ResolveRevisions(ctx, repositoryPath, request.Grant.HeadSHA, request.Grant.BaseSHA)
	if err != nil {
		return Outcome{}, err
	}
	if !strings.EqualFold(headSHA, request.Grant.HeadSHA) || !strings.EqualFold(baseSHA, request.Grant.BaseSHA) {
		return Outcome{}, fmt.Errorf("repository revisions do not match the run grant")
	}
	treeSHA, err := ResolveMergeTree(ctx, repositoryPath, baseSHA, headSHA)
	if err != nil {
		return Outcome{}, err
	}
	if !strings.EqualFold(treeSHA, request.Grant.TreeSHA) {
		return Outcome{}, fmt.Errorf("repository merge tree does not match the run grant")
	}

	temporaryRoot, err := os.MkdirTemp("", "cihash-run-*")
	if err != nil {
		return Outcome{}, fmt.Errorf("create runner workspace: %w", err)
	}
	defer os.RemoveAll(temporaryRoot)
	workspace := filepath.Join(temporaryRoot, "source")
	if _, err := treesource.Materialize(ctx, treesource.Options{
		RepositoryPath: repositoryPath,
		TreeSHA:        treeSHA,
		Destination:    workspace,
		MaxEntries:     request.Container.MaxTreeEntries,
		MaxBytes:       request.Container.MaxTreeBytes,
	}); err != nil {
		return Outcome{}, fmt.Errorf("materialize tested tree: %w", err)
	}

	now := time.Now().UTC()
	if !now.Before(request.Grant.ExpiresAt) {
		return Outcome{}, rungrant.ErrGrantExpired
	}
	timeout := time.Duration(request.Grant.Policy.TimeoutSeconds) * time.Second
	if remaining := request.Grant.ExpiresAt.Sub(now); remaining < timeout {
		timeout = remaining
	}
	executionContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	environment := request.Grant.Policy.Environment
	startedAt := time.Now().UTC()
	log, runError := containerexec.Run(executionContext, containerexec.Options{
		Image:          environment.Image,
		Platform:       environment.Platform,
		Network:        environment.Network,
		Memory:         environment.Memory,
		CPUs:           environment.CPUs,
		PIDsLimit:      environment.PIDsLimit,
		MaxOutputBytes: environment.MaxOutputBytes,
		Command:        request.Grant.Policy.Command,
		Directory:      workspace,
		DockerBinary:   request.Container.DockerBinary,
	})
	completedAt := time.Now().UTC()
	if ctx.Err() != nil {
		return Outcome{}, ctx.Err()
	}
	if !completedAt.Before(request.Grant.ExpiresAt) {
		return Outcome{}, rungrant.ErrGrantExpired
	}
	timedOut := errors.Is(executionContext.Err(), context.DeadlineExceeded)
	if errors.Is(runError, containerexec.ErrInvalidOptions) {
		return Outcome{}, runError
	}
	if runError != nil && !timedOut {
		exitCode := exitCodeFor(runError)
		if exitCode == -1 || exitCode == 125 || exitCode == 126 || exitCode == 127 {
			return Outcome{}, runError
		}
	}

	exitCode := 0
	conclusion := "success"
	if runError != nil {
		conclusion = "failure"
		exitCode = exitCodeFor(runError)
	}
	if timedOut {
		conclusion = "failure"
		exitCode = -1
		log = append(log, []byte("\n[cihash] command exceeded the approved timeout\n")...)
	}
	result := attestation.TestResult{
		SchemaVersion:     attestation.SchemaVersion,
		Repository:        request.Grant.Policy.Repository,
		HeadSHA:           headSHA,
		BaseSHA:           baseSHA,
		TreeSHA:           treeSHA,
		Profile:           request.Grant.Policy.Profile,
		PolicyDigest:      request.Grant.PolicyDigest,
		WorkflowDigest:    request.Grant.WorkflowDigest,
		EnvironmentDigest: request.Grant.EnvironmentDigest,
		Architecture:      request.Grant.Architecture,
		Jobs: []attestation.JobResult{{
			Name:        request.Grant.Policy.Profile,
			Command:     append([]string(nil), request.Grant.Policy.Command...),
			ExitCode:    exitCode,
			Conclusion:  conclusion,
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			LogDigest:   attestation.Digest(log),
		}},
		Conclusion: conclusion,
		Nonce:      request.Grant.Nonce,
		IssuedAt:   completedAt,
		ExpiresAt:  request.Grant.ExpiresAt,
	}
	return Outcome{Result: result, Log: log}, nil
}

func ResolveRevisions(ctx context.Context, repository, headRevision, baseRevision string) (string, string, error) {
	repository, err := repositoryPath(repository)
	if err != nil {
		return "", "", err
	}
	headSHA, err := resolveCommit(ctx, repository, headRevision)
	if err != nil {
		return "", "", fmt.Errorf("resolve head: %w", err)
	}
	baseSHA, err := resolveCommit(ctx, repository, baseRevision)
	if err != nil {
		return "", "", fmt.Errorf("resolve base: %w", err)
	}
	return headSHA, baseSHA, nil
}

func repositoryPath(value string) (string, error) {
	resolved, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("resolve repository path: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect repository path: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("repository path must be a directory")
	}
	return resolved, nil
}

func resolveCommit(ctx context.Context, repository, revision string) (string, error) {
	if strings.TrimSpace(revision) == "" {
		return "", fmt.Errorf("revision is required")
	}
	output, err := runGit(ctx, repository, "rev-parse", "--verify", "--end-of-options", revision+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	resolved := strings.TrimSpace(string(output))
	if !validGitObjectID(resolved) {
		return "", fmt.Errorf("Git returned an invalid commit identity")
	}
	return resolved, nil
}

func ResolveMergeTree(ctx context.Context, repository, baseSHA, headSHA string) (string, error) {
	output, err := runGit(ctx, repository, "merge-tree", "--write-tree", "--no-messages", baseSHA, headSHA)
	if err != nil {
		return "", fmt.Errorf("compute base-plus-head merge tree: %w: %s", err, strings.TrimSpace(string(output)))
	}
	treeSHA := strings.TrimSpace(string(output))
	if !validGitObjectID(treeSHA) || len(treeSHA) != len(headSHA) {
		return "", fmt.Errorf("Git returned an invalid merge tree identity")
	}
	objectType, err := runGit(ctx, repository, "cat-file", "-t", treeSHA)
	if err != nil || strings.TrimSpace(string(objectType)) != "tree" {
		return "", fmt.Errorf("computed merge object is not a tree")
	}
	return treeSHA, nil
}

func runGit(ctx context.Context, directory string, arguments ...string) ([]byte, error) {
	return gitexec.Command(ctx, "git", directory, arguments...).CombinedOutput()
}

func gitEnvironment() []string {
	blocked := map[string]struct{}{
		"GIT_ALTERNATE_OBJECT_DIRECTORIES": {},
		"GIT_CONFIG_COUNT":                 {},
		"GIT_CONFIG_GLOBAL":                {},
		"GIT_CONFIG_KEY_0":                 {},
		"GIT_CONFIG_SYSTEM":                {},
		"GIT_CONFIG_VALUE_0":               {},
		"GIT_DIR":                          {},
		"GIT_INDEX_FILE":                   {},
		"GIT_OBJECT_DIRECTORY":             {},
		"GIT_REPLACE_REF_BASE":             {},
		"GIT_SHALLOW_FILE":                 {},
		"GIT_WORK_TREE":                    {},
	}
	current := os.Environ()
	environment := make([]string, 0, len(current)+2)
	for _, variable := range current {
		name, _, _ := strings.Cut(variable, "=")
		if _, excluded := blocked[name]; !excluded && !strings.HasPrefix(name, "GIT_CONFIG_KEY_") && !strings.HasPrefix(name, "GIT_CONFIG_VALUE_") {
			environment = append(environment, variable)
		}
	}
	return append(environment, "GIT_NO_REPLACE_OBJECTS=1", "GIT_CONFIG_NOSYSTEM=1")
}

func validGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func exitCodeFor(err error) int {
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}
