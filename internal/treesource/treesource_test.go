package treesource

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaterializeCreatesMetadataFreeExactTree(t *testing.T) {
	repository, treeSHA, _ := testGitTree(t)
	destination := filepath.Join(t.TempDir(), "materialized")
	result, err := Materialize(context.Background(), Options{
		RepositoryPath: repository,
		TreeSHA:        treeSHA,
		Destination:    destination,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TreeSHA != treeSHA || result.Entries < 2 || result.Bytes == 0 {
		t.Fatalf("Materialize result = %#v, want populated exact tree result", result)
	}
	content, err := os.ReadFile(filepath.Join(destination, "README.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "tree fixture\n" {
		t.Fatalf("README content = %q", content)
	}
	info, err := os.Stat(filepath.Join(destination, "bin", "verify.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatal("executable bit was not preserved")
	}
	if _, err := os.Lstat(filepath.Join(destination, ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".git metadata check error = %v, want not exist", err)
	}
	if err := exec.Command("git", "-C", destination, "rev-parse", "--is-inside-work-tree").Run(); err == nil {
		t.Fatal("materialized tree remained a Git worktree")
	}
}

func TestMaterializeSupportsSHA256ObjectStores(t *testing.T) {
	repository, treeSHA, _ := testGitTreeWithFormat(t, "sha256")
	objectDirectory := filepath.Join(repository, ".git", "objects")
	alternateObjectDirectory := filepath.Join(t.TempDir(), "alternate-objects")
	if err := os.Mkdir(alternateObjectDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	tests := map[string]Options{
		"ordinary repository": {},
		"isolated object view": {
			GitDirectory:             filepath.Join(repository, ".git"),
			ObjectDirectory:          objectDirectory,
			AlternateObjectDirectory: alternateObjectDirectory,
		},
	}
	for name, options := range tests {
		t.Run(name, func(t *testing.T) {
			options.RepositoryPath = repository
			options.TreeSHA = treeSHA
			options.Destination = filepath.Join(t.TempDir(), "materialized")
			result, err := Materialize(context.Background(), options)
			if err != nil {
				t.Fatal(err)
			}
			if result.TreeSHA != treeSHA {
				t.Fatalf("Materialize tree SHA = %q, want %q", result.TreeSHA, treeSHA)
			}
		})
	}
}

func TestMaterializeRejectsCommitAndCleansLimitedExtraction(t *testing.T) {
	repository, treeSHA, commitSHA := testGitTree(t)
	if _, err := Materialize(context.Background(), Options{
		RepositoryPath: repository,
		TreeSHA:        commitSHA,
		Destination:    filepath.Join(t.TempDir(), "commit"),
	}); err == nil || !strings.Contains(err.Error(), "is not a tree") {
		t.Fatalf("commit materialization error = %v, want not-a-tree rejection", err)
	}

	destination := filepath.Join(t.TempDir(), "limited")
	if _, err := Materialize(context.Background(), Options{
		RepositoryPath: repository,
		TreeSHA:        treeSHA,
		Destination:    destination,
		MaxBytes:       1,
	}); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("limited materialization error = %v, want byte-limit rejection", err)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial destination check error = %v, want not exist", err)
	}
}

func TestMaterializePreservesBlobBytesDespiteArchiveAttributes(t *testing.T) {
	repository, _, commitSHA := testGitTree(t)
	attributes := "README.txt export-ignore text eol=crlf\nVERSION.txt export-subst\n"
	if err := os.WriteFile(filepath.Join(repository, ".gitattributes"), []byte(attributes), 0o644); err != nil {
		t.Fatal(err)
	}
	const version = "$Format:%H$\n"
	if err := os.WriteFile(filepath.Join(repository, "VERSION.txt"), []byte(version), 0o644); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, repository, "add", "--", ".gitattributes", "VERSION.txt")
	attributedTree := runTestGit(t, repository, "write-tree")
	destination := filepath.Join(t.TempDir(), "archive-attributes")
	if _, err := Materialize(context.Background(), Options{
		RepositoryPath: repository,
		TreeSHA:        attributedTree,
		Destination:    destination,
	}); err != nil {
		t.Fatalf("materialize attributed tree: %v", err)
	}
	for name, want := range map[string]string{
		"README.txt":  "tree fixture\n",
		"VERSION.txt": version,
	} {
		content, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != want {
			t.Fatalf("%s content = %q, want exact blob bytes %q", name, content, want)
		}
	}

	runTestGit(t, repository, "update-index", "--add", "--cacheinfo", "160000,"+commitSHA+",vendor/submodule")
	gitlinkTree := runTestGit(t, repository, "write-tree")
	if _, err := Materialize(context.Background(), Options{
		RepositoryPath: repository,
		TreeSHA:        gitlinkTree,
		Destination:    filepath.Join(t.TempDir(), "gitlink"),
	}); err == nil || !strings.Contains(err.Error(), "unsupported commit entry") {
		t.Fatalf("gitlink materialization error = %v, want unsupported-entry rejection", err)
	}
}

func TestExtractTarRejectsBoundaryViolations(t *testing.T) {
	tests := []struct {
		name       string
		headers    []tarFixture
		maxEntries int
		maxBytes   int64
		want       string
	}{
		{
			name:    "path traversal",
			headers: []tarFixture{{header: tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644}, body: "x"}},
			want:    "unsafe path",
		},
		{
			name:    "repository metadata",
			headers: []tarFixture{{header: tar.Header{Name: ".git/config", Typeflag: tar.TypeReg, Mode: 0o644}, body: "x"}},
			want:    "forbidden repository metadata",
		},
		{
			name:    "case folded repository metadata",
			headers: []tarFixture{{header: tar.Header{Name: "nested/.GIT/config", Typeflag: tar.TypeReg, Mode: 0o644}, body: "x"}},
			want:    "forbidden repository metadata",
		},
		{
			name:    "escaping symlink",
			headers: []tarFixture{{header: tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../outside", Mode: 0o777}}},
			want:    "escapes the tree-only source boundary",
		},
		{
			name:    "unsupported hard link",
			headers: []tarFixture{{header: tar.Header{Name: "hard", Typeflag: tar.TypeLink, Linkname: "target", Mode: 0o644}}},
			want:    "unsupported archive entry",
		},
		{
			name: "entry limit",
			headers: []tarFixture{
				{header: tar.Header{Name: "one", Typeflag: tar.TypeReg, Mode: 0o644}, body: "1"},
				{header: tar.Header{Name: "two", Typeflag: tar.TypeReg, Mode: 0o644}, body: "2"},
			},
			maxEntries: 1,
			want:       "entry limit",
		},
		{
			name:       "byte limit",
			headers:    []tarFixture{{header: tar.Header{Name: "large", Typeflag: tar.TypeReg, Mode: 0o644}, body: "large"}},
			maxEntries: 10,
			maxBytes:   1,
			want:       "byte limit",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			maxEntries := test.maxEntries
			if maxEntries == 0 {
				maxEntries = 10
			}
			maxBytes := test.maxBytes
			if maxBytes == 0 {
				maxBytes = 1024
			}
			_, _, err := extractTar(bytes.NewReader(testTar(t, test.headers)), t.TempDir(), maxEntries, maxBytes)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("extractTar error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestExtractTarPreservesSafeRelativeSymlink(t *testing.T) {
	destination := t.TempDir()
	archive := testTar(t, []tarFixture{
		{header: tar.Header{Name: "target.txt", Typeflag: tar.TypeReg, Mode: 0o644}, body: "target"},
		{header: tar.Header{Name: "links/", Typeflag: tar.TypeDir, Mode: 0o755}},
		{header: tar.Header{Name: "links/target", Typeflag: tar.TypeSymlink, Linkname: "../target.txt", Mode: 0o777}},
	})
	if _, _, err := extractTar(bytes.NewReader(archive), destination, 10, 1024); err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(filepath.Join(destination, "links", "target"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "../target.txt" {
		t.Fatalf("symlink target = %q", target)
	}
}

type tarFixture struct {
	header tar.Header
	body   string
}

func testTar(t *testing.T, fixtures []tarFixture) []byte {
	t.Helper()
	var data bytes.Buffer
	writer := tar.NewWriter(&data)
	for _, fixture := range fixtures {
		header := fixture.header
		header.Size = int64(len(fixture.body))
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if fixture.body != "" {
			if _, err := writer.Write([]byte(fixture.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func testGitTree(t *testing.T) (string, string, string) {
	t.Helper()
	return testGitTreeWithFormat(t, "sha1")
}

func testGitTreeWithFormat(t *testing.T, objectFormat string) (string, string, string) {
	t.Helper()
	repository := filepath.Join(t.TempDir(), "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, repository, "init", "--quiet", "--object-format="+objectFormat)
	if err := os.Mkdir(filepath.Join(repository, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "README.txt"), []byte("tree fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "bin", "verify.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, repository, "add", "--", "README.txt", "bin/verify.sh")
	treeSHA := runTestGit(t, repository, "write-tree")
	commitSHA := runTestGit(t, repository,
		"-c", "user.name=CIHash Test",
		"-c", "user.email=cihash@example.invalid",
		"commit-tree", treeSHA,
		"-m", "tree source fixture",
	)
	return repository, treeSHA, commitSHA
}

func runTestGit(t *testing.T, repository string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", repository}, arguments...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output))
}
