package lab

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wolfiesch/cihash/internal/applicability"
	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/treesource"
)

func RunTreeReuse() (Report, error) {
	root, err := os.MkdirTemp("", "cihash-tree-reuse-*")
	if err != nil {
		return Report{}, fmt.Errorf("create tree-reuse lab root: %w", err)
	}
	defer os.RemoveAll(root)

	repository := filepath.Join(root, "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		return Report{}, fmt.Errorf("create tree-reuse repository: %w", err)
	}
	if _, err := runLabGit(repository, "init", "--quiet"); err != nil {
		return Report{}, err
	}
	if err := os.WriteFile(filepath.Join(repository, "base.txt"), []byte("base content\n"), 0o644); err != nil {
		return Report{}, fmt.Errorf("write base content: %w", err)
	}
	if _, err := runLabGit(repository, "add", "--", "base.txt"); err != nil {
		return Report{}, err
	}
	baseTree, err := runLabGit(repository, "write-tree")
	if err != nil {
		return Report{}, err
	}
	baseCommit, err := commitLabTree(repository, baseTree, "base")
	if err != nil {
		return Report{}, err
	}

	if err := os.WriteFile(filepath.Join(repository, "feature.txt"), []byte("feature content\n"), 0o644); err != nil {
		return Report{}, fmt.Errorf("write feature content: %w", err)
	}
	if _, err := runLabGit(repository, "add", "--", "feature.txt"); err != nil {
		return Report{}, err
	}
	featureTree, err := runLabGit(repository, "write-tree")
	if err != nil {
		return Report{}, err
	}
	headCommit, err := commitLabTree(repository, featureTree, "feature", baseCommit)
	if err != nil {
		return Report{}, err
	}
	originalMergeTree, err := runLabGit(repository, "merge-tree", "--write-tree", baseCommit, headCommit)
	if err != nil {
		return Report{}, err
	}

	movedBaseCommit, err := commitLabTree(repository, baseTree, "metadata-only base advance", baseCommit)
	if err != nil {
		return Report{}, err
	}
	movedMergeTree, err := runLabGit(repository, "merge-tree", "--write-tree", movedBaseCommit, headCommit)
	if err != nil {
		return Report{}, err
	}
	if movedMergeTree != originalMergeTree {
		return Report{}, fmt.Errorf("metadata-only base advance changed merge tree: %s != %s", movedMergeTree, originalMergeTree)
	}
	mergeGroupCommit, err := commitLabTree(repository, movedMergeTree, "merge group", movedBaseCommit, headCommit)
	if err != nil {
		return Report{}, err
	}

	if _, err := runLabGit(repository, "read-tree", baseTree); err != nil {
		return Report{}, err
	}
	if err := os.WriteFile(filepath.Join(repository, "base.txt"), []byte("changed base content\n"), 0o644); err != nil {
		return Report{}, fmt.Errorf("write changed base content: %w", err)
	}
	if _, err := runLabGit(repository, "add", "--", "base.txt"); err != nil {
		return Report{}, err
	}
	changedBaseTree, err := runLabGit(repository, "write-tree")
	if err != nil {
		return Report{}, err
	}
	changedBaseCommit, err := commitLabTree(repository, changedBaseTree, "content base advance", movedBaseCommit)
	if err != nil {
		return Report{}, err
	}
	changedMergeTree, err := runLabGit(repository, "merge-tree", "--write-tree", changedBaseCommit, headCommit)
	if err != nil {
		return Report{}, err
	}
	if changedMergeTree == originalMergeTree {
		return Report{}, fmt.Errorf("content-changing base advance retained merge tree")
	}

	materializedPath := filepath.Join(root, "merge-tree")
	materialized, err := treesource.Materialize(context.Background(), treesource.Options{
		RepositoryPath: repository,
		TreeSHA:        originalMergeTree,
		Destination:    materializedPath,
	})
	if err != nil {
		return Report{}, fmt.Errorf("materialize merge tree: %w", err)
	}
	metadataHidden := materialized.TreeSHA == originalMergeTree
	if _, statErr := os.Lstat(filepath.Join(materializedPath, ".git")); !os.IsNotExist(statErr) {
		metadataHidden = false
	}
	for path, want := range map[string]string{"base.txt": "base content\n", "feature.txt": "feature content\n"} {
		content, readErr := os.ReadFile(filepath.Join(materializedPath, path))
		if readErr != nil || string(content) != want {
			metadataHidden = false
		}
	}

	claim := applicability.Claim{
		Repository:        "github.com/cihash/tree-reuse-lab",
		HeadSHA:           headCommit,
		BaseSHA:           baseCommit,
		MergeTreeSHA:      originalMergeTree,
		PolicyDigest:      attestation.Digest([]byte("tree-only-policy")),
		WorkflowDigest:    attestation.Digest([]byte("tree-only-workflow")),
		EnvironmentDigest: attestation.Digest([]byte("tree-only-environment")),
		Context:           applicability.PullRequestContext,
	}
	mergeGroup := claim
	mergeGroup.HeadSHA = mergeGroupCommit
	mergeGroup.BaseSHA = movedBaseCommit
	mergeGroup.Context = applicability.MergeGroupContext
	changedMergeGroup := mergeGroup
	changedMergeGroup.BaseSHA = changedBaseCommit
	changedMergeGroup.MergeTreeSHA = changedMergeTree
	policyMismatch := mergeGroup
	policyMismatch.PolicyDigest = attestation.Digest([]byte("changed-policy"))

	type reuseScenario struct {
		name         string
		current      applicability.Claim
		mode         applicability.ReuseMode
		expectedCode string
	}
	scenarios := []reuseScenario{
		{name: "exact pull request", current: claim, mode: applicability.StrictCommits, expectedCode: "accepted"},
		{name: "strict merge queue identity", current: mergeGroup, mode: applicability.StrictCommits, expectedCode: "context_mismatch"},
		{name: "tree-equivalent merge queue", current: mergeGroup, mode: applicability.MergeTree, expectedCode: "tree_equivalent"},
		{name: "content-changing base advance", current: changedMergeGroup, mode: applicability.MergeTree, expectedCode: "merge_tree_mismatch"},
		{name: "changed policy", current: policyMismatch, mode: applicability.MergeTree, expectedCode: "policy_mismatch"},
	}

	report := Report{SchemaVersion: ReportSchema, Experiment: "merge-queue-tree-reuse", Passed: metadataHidden}
	report.Scenarios = append(report.Scenarios, ScenarioResult{
		Name:         "tree-only execution input",
		Accepted:     metadataHidden,
		Code:         acceptedOrRejected(metadataHidden),
		ExpectedCode: "accepted",
		Passed:       metadataHidden,
	})
	for _, scenario := range scenarios {
		decision := applicability.Evaluate(claim, scenario.current, scenario.mode)
		passed := decision.Code == scenario.expectedCode && decision.Accepted == acceptedApplicabilityCode(scenario.expectedCode)
		report.Passed = report.Passed && passed
		report.Scenarios = append(report.Scenarios, ScenarioResult{
			Name:         scenario.name,
			Accepted:     decision.Accepted,
			Code:         decision.Code,
			ExpectedCode: scenario.expectedCode,
			Passed:       passed,
		})
	}
	return report, nil
}

func commitLabTree(repository, tree, message string, parents ...string) (string, error) {
	arguments := []string{"-c", "user.name=CIHash Lab", "-c", "user.email=cihash@example.invalid", "commit-tree", tree}
	for _, parent := range parents {
		arguments = append(arguments, "-p", parent)
	}
	arguments = append(arguments, "-m", message)
	return runLabGit(repository, arguments...)
}

func acceptedOrRejected(accepted bool) string {
	if accepted {
		return "accepted"
	}
	return "rejected"
}
