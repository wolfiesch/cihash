package lab

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/wolfiesch/cihash/internal/treesource"
)

func RunTreeIsolation() (Report, error) {
	root, err := os.MkdirTemp("", "cihash-tree-isolation-*")
	if err != nil {
		return Report{}, fmt.Errorf("create tree-isolation lab root: %w", err)
	}
	defer os.RemoveAll(root)

	repository := filepath.Join(root, "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		return Report{}, fmt.Errorf("create lab repository: %w", err)
	}
	if _, err := runLabGit(repository, "init", "--quiet"); err != nil {
		return Report{}, err
	}
	if err := os.MkdirAll(filepath.Join(repository, "cmd"), 0o755); err != nil {
		return Report{}, fmt.Errorf("create lab source directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(repository, "README.txt"), []byte("exact tree content\n"), 0o644); err != nil {
		return Report{}, fmt.Errorf("write lab content: %w", err)
	}
	if err := os.WriteFile(filepath.Join(repository, "cmd", "verify.sh"), []byte("#!/bin/sh\nset -eu\ntest ! -e .git\ntest \"$(cat README.txt)\" = \"exact tree content\"\n"), 0o755); err != nil {
		return Report{}, fmt.Errorf("write lab executable: %w", err)
	}
	if _, err := runLabGit(repository, "add", "--", "README.txt", "cmd/verify.sh"); err != nil {
		return Report{}, err
	}
	treeSHA, err := runLabGit(repository, "write-tree")
	if err != nil {
		return Report{}, err
	}
	commitSHA, err := runLabGit(repository,
		"-c", "user.name=CIHash Lab",
		"-c", "user.email=cihash@example.invalid",
		"commit-tree", treeSHA,
		"-m", "tree isolation fixture",
	)
	if err != nil {
		return Report{}, err
	}

	destination := filepath.Join(root, "tree")
	materialized, err := treesource.Materialize(context.Background(), treesource.Options{
		RepositoryPath: repository,
		TreeSHA:        treeSHA,
		Destination:    destination,
	})
	if err != nil {
		return Report{}, fmt.Errorf("materialize lab tree: %w", err)
	}

	cases := []struct {
		name     string
		accepted bool
		run      func() error
	}{
		{
			name:     "exact tree content materialized",
			accepted: true,
			run: func() error {
				content, err := os.ReadFile(filepath.Join(destination, "README.txt"))
				if err != nil {
					return err
				}
				if string(content) != "exact tree content\n" || materialized.TreeSHA != treeSHA {
					return fmt.Errorf("materialized content or tree identity differs")
				}
				return nil
			},
		},
		{
			name:     "executable bit preserved",
			accepted: true,
			run: func() error {
				info, err := os.Stat(filepath.Join(destination, "cmd", "verify.sh"))
				if err != nil {
					return err
				}
				if info.Mode()&0o111 == 0 {
					return fmt.Errorf("executable bit was not preserved")
				}
				return nil
			},
		},
		{
			name:     "metadata-free tree command executes",
			accepted: true,
			run: func() error {
				command := exec.CommandContext(context.Background(), "./cmd/verify.sh")
				command.Dir = destination
				command.Env = []string{"PATH=/usr/bin:/bin"}
				output, err := command.CombinedOutput()
				if err != nil {
					return fmt.Errorf("execute materialized tree command: %w: %s", err, strings.TrimSpace(string(output)))
				}
				return nil
			},
		},
		{
			name:     "repository metadata absent",
			accepted: true,
			run: func() error {
				if _, err := os.Lstat(filepath.Join(destination, ".git")); !os.IsNotExist(err) {
					return fmt.Errorf("materialized tree contains .git metadata")
				}
				command := exec.Command("git", "-C", destination, "rev-parse", "--is-inside-work-tree")
				if err := command.Run(); err == nil {
					return fmt.Errorf("materialized tree is still a Git worktree")
				}
				return nil
			},
		},
		{
			name:     "commit object rejected as tree identity",
			accepted: false,
			run: func() error {
				_, err := treesource.Materialize(context.Background(), treesource.Options{
					RepositoryPath: repository,
					TreeSHA:        commitSHA,
					Destination:    filepath.Join(root, "commit-object"),
				})
				return err
			},
		},
		{
			name:     "byte limit rejects and cleans partial tree",
			accepted: false,
			run: func() error {
				limitedDestination := filepath.Join(root, "limited")
				_, err := treesource.Materialize(context.Background(), treesource.Options{
					RepositoryPath: repository,
					TreeSHA:        treeSHA,
					Destination:    limitedDestination,
					MaxBytes:       1,
				})
				if err == nil {
					return nil
				}
				if _, statErr := os.Lstat(limitedDestination); !os.IsNotExist(statErr) {
					return fmt.Errorf("partial destination survived rejection")
				}
				return err
			},
		},
	}

	report := Report{
		SchemaVersion: ReportSchema,
		Experiment:    "tree-only-source-isolation",
		Passed:        true,
		Scenarios:     make([]ScenarioResult, 0, len(cases)),
	}
	for _, candidate := range cases {
		err := candidate.run()
		accepted := err == nil
		code := "rejected"
		if accepted {
			code = "accepted"
		}
		expectedCode := "rejected"
		if candidate.accepted {
			expectedCode = "accepted"
		}
		result := ScenarioResult{
			Name:         candidate.name,
			Accepted:     accepted,
			Code:         code,
			ExpectedCode: expectedCode,
			Passed:       accepted == candidate.accepted,
		}
		report.Passed = report.Passed && result.Passed
		report.Scenarios = append(report.Scenarios, result)
	}
	return report, nil
}

func runLabGit(repository string, arguments ...string) (string, error) {
	command := exec.Command("git", append([]string{"-C", repository}, arguments...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run git %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}
