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
	treeView, err := resolveMergeTreeView(ctx, repositoryPath, baseSHA, headSHA)
	if err != nil {
		return Outcome{}, err
	}
	defer os.RemoveAll(treeView.workspace)
	if !strings.EqualFold(treeView.treeSHA, request.Grant.TreeSHA) {
		return Outcome{}, fmt.Errorf("repository merge tree does not match the run grant")
	}

	temporaryRoot, err := os.MkdirTemp("", "cihash-run-*")
	if err != nil {
		return Outcome{}, fmt.Errorf("create runner workspace: %w", err)
	}
	defer os.RemoveAll(temporaryRoot)
	workspace := filepath.Join(temporaryRoot, "source")
	if _, err := treesource.Materialize(ctx, treesource.Options{
		RepositoryPath:           repositoryPath,
		TreeSHA:                  treeView.treeSHA,
		GitDirectory:             treeView.gitDirectory,
		ObjectDirectory:          treeView.objectDirectory,
		AlternateObjectDirectory: treeView.alternateObjectDirectory,
		Destination:              workspace,
		MaxEntries:               request.Container.MaxTreeEntries,
		MaxBytes:                 request.Container.MaxTreeBytes,
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
		TreeSHA:           treeView.treeSHA,
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

type mergeTreeView struct {
	treeSHA                  string
	workspace                string
	gitDirectory             string
	objectDirectory          string
	alternateObjectDirectory string
}

func ResolveMergeTree(ctx context.Context, repository, baseSHA, headSHA string) (string, error) {
	view, err := resolveMergeTreeView(ctx, repository, baseSHA, headSHA)
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(view.workspace)
	return view.treeSHA, nil
}

func resolveMergeTreeView(ctx context.Context, repository, baseSHA, headSHA string) (view mergeTreeView, err error) {
	commonDirectoryOutput, err := runGit(ctx, repository, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return mergeTreeView{}, fmt.Errorf("resolve repository object directory: %w: %s", err, strings.TrimSpace(string(commonDirectoryOutput)))
	}
	sourceObjects := filepath.Join(strings.TrimSpace(string(commonDirectoryOutput)), "objects")
	if strings.ContainsAny(sourceObjects, "\n\r"+string(filepath.ListSeparator)) {
		return mergeTreeView{}, fmt.Errorf("repository object directory cannot be represented safely")
	}
	if info, err := os.Stat(sourceObjects); err != nil || !info.IsDir() {
		return mergeTreeView{}, fmt.Errorf("repository object directory is unavailable")
	}

	workspace, err := os.MkdirTemp("", "cihash-merge-tree-*")
	if err != nil {
		return mergeTreeView{}, fmt.Errorf("create isolated merge workspace: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(workspace)
		}
	}()
	templateDirectory := filepath.Join(workspace, "template")
	if err := os.Mkdir(templateDirectory, 0o700); err != nil {
		return mergeTreeView{}, fmt.Errorf("create empty Git template: %w", err)
	}
	gitDirectory := filepath.Join(workspace, "repository.git")
	if output, err := gitexec.Command(ctx, "git", "", "init", "--bare", "--template="+templateDirectory, gitDirectory).CombinedOutput(); err != nil {
		return mergeTreeView{}, fmt.Errorf("initialize isolated merge repository: %w: %s", err, strings.TrimSpace(string(output)))
	}
	objectDirectory := filepath.Join(gitDirectory, "objects")
	output, err := gitexec.ObjectCommand(ctx, "git", gitDirectory, objectDirectory, sourceObjects, "merge-tree", "--write-tree", "--no-messages", baseSHA, headSHA).CombinedOutput()
	if err != nil {
		return mergeTreeView{}, fmt.Errorf("compute base-plus-head merge tree: %w: %s", err, strings.TrimSpace(string(output)))
	}
	treeSHA := strings.TrimSpace(string(output))
	if !validGitObjectID(treeSHA) || len(treeSHA) != len(headSHA) {
		return mergeTreeView{}, fmt.Errorf("Git returned an invalid merge tree identity")
	}
	objectType, err := gitexec.ObjectCommand(ctx, "git", gitDirectory, objectDirectory, sourceObjects, "cat-file", "-t", treeSHA).CombinedOutput()
	if err != nil || strings.TrimSpace(string(objectType)) != "tree" {
		return mergeTreeView{}, fmt.Errorf("computed merge object is not a tree")
	}
	return mergeTreeView{
		treeSHA:                  treeSHA,
		workspace:                workspace,
		gitDirectory:             gitDirectory,
		objectDirectory:          objectDirectory,
		alternateObjectDirectory: sourceObjects,
	}, nil
}

func runGit(ctx context.Context, directory string, arguments ...string) ([]byte, error) {
	return gitexec.Command(ctx, "git", directory, arguments...).CombinedOutput()
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
