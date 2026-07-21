// Package treesource materializes an exact Git tree without repository metadata.
package treesource

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wolfiesch/cihash/internal/gitexec"
)

const (
	DefaultMaxEntries      = 100_000
	DefaultMaxBytes        = int64(1 << 30)
	maxManifestRecordBytes = 1 << 20
)

type Options struct {
	RepositoryPath string
	TreeSHA        string
	Destination    string
	GitBinary      string
	MaxEntries     int
	MaxBytes       int64
}

type Result struct {
	TreeSHA string `json:"treeSha"`
	Entries int    `json:"entries"`
	Bytes   int64  `json:"bytes"`
}

// Materialize extracts one exact Git tree into a newly created destination.
// Commit identity, refs, remotes, hooks, and all .git paths are excluded.
func Materialize(ctx context.Context, options Options) (result Result, err error) {
	if !validGitObjectID(options.TreeSHA) {
		return Result{}, fmt.Errorf("tree SHA must be a 40- or 64-character hexadecimal Git object ID")
	}
	repository, err := filepath.Abs(options.RepositoryPath)
	if err != nil {
		return Result{}, fmt.Errorf("resolve repository path: %w", err)
	}
	info, err := os.Stat(repository)
	if err != nil {
		return Result{}, fmt.Errorf("inspect repository path: %w", err)
	}
	if !info.IsDir() {
		return Result{}, fmt.Errorf("repository path must be a directory")
	}
	destination, err := filepath.Abs(options.Destination)
	if err != nil {
		return Result{}, fmt.Errorf("resolve destination: %w", err)
	}
	if _, err := os.Lstat(destination); err == nil {
		return Result{}, fmt.Errorf("destination must not already exist")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, fmt.Errorf("inspect destination: %w", err)
	}

	git := options.GitBinary
	if git == "" {
		git = "git"
	}
	objectType, commandErr := gitexec.Command(ctx, git, repository, "cat-file", "-t", options.TreeSHA).CombinedOutput()
	if commandErr != nil {
		return Result{}, fmt.Errorf("inspect Git object: %w: %s", commandErr, strings.TrimSpace(string(objectType)))
	}
	if strings.TrimSpace(string(objectType)) != "tree" {
		return Result{}, fmt.Errorf("Git object %s is not a tree", options.TreeSHA)
	}

	maxEntries := options.MaxEntries
	if maxEntries == 0 {
		maxEntries = DefaultMaxEntries
	}
	maxBytes := options.MaxBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxBytes
	}
	if maxEntries < 1 || maxBytes < 1 {
		return Result{}, fmt.Errorf("tree extraction limits must be positive")
	}
	manifest, err := readTreeManifest(ctx, git, repository, options.TreeSHA, maxEntries, maxBytes)
	if err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return Result{}, fmt.Errorf("create destination parent: %w", err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return Result{}, fmt.Errorf("create destination: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(destination)
		}
	}()

	archive := gitexec.Command(ctx, git, repository, "archive", "--format=tar", options.TreeSHA)
	var stderr bytes.Buffer
	archive.Stderr = &stderr
	stdout, err := archive.StdoutPipe()
	if err != nil {
		return Result{}, fmt.Errorf("open Git archive stream: %w", err)
	}
	if err := archive.Start(); err != nil {
		return Result{}, fmt.Errorf("start Git archive: %w", err)
	}
	_, bytesWritten, extractErr := extractTar(stdout, destination, maxEntries, maxBytes)
	if extractErr != nil {
		_ = archive.Process.Kill()
	}
	waitErr := archive.Wait()
	if extractErr != nil {
		return Result{}, extractErr
	}
	if waitErr != nil {
		return Result{}, fmt.Errorf("create Git archive: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	if err := validateMaterializedTree(destination, manifest); err != nil {
		return Result{}, err
	}

	complete = true
	return Result{TreeSHA: options.TreeSHA, Entries: len(manifest), Bytes: bytesWritten}, nil
}

type manifestEntry struct {
	mode     string
	objectID string
	size     int64
}

func readTreeManifest(ctx context.Context, git, repository, treeSHA string, maxEntries int, maxBytes int64) (map[string]manifestEntry, error) {
	command := gitexec.Command(ctx, git, repository, "ls-tree", "-r", "-l", "-z", "--full-tree", treeSHA)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("open Git tree manifest stream: %w", err)
	}
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start Git tree manifest: %w", err)
	}

	manifest := make(map[string]manifestEntry)
	reader := bufio.NewReaderSize(stdout, maxManifestRecordBytes)
	var manifestBytes int64
	var manifestErr error
	for {
		recordBytes, readErr := reader.ReadSlice(0)
		if errors.Is(readErr, io.EOF) && len(recordBytes) == 0 {
			break
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			manifestErr = fmt.Errorf("Git tree manifest entry exceeds the %d-byte limit", maxManifestRecordBytes)
			break
		}
		if readErr != nil {
			manifestErr = fmt.Errorf("read Git tree manifest: %w", readErr)
			break
		}
		record := strings.TrimSuffix(string(recordBytes), "\x00")
		separator := strings.IndexByte(record, '\t')
		if separator < 0 {
			manifestErr = fmt.Errorf("Git tree manifest contains malformed entry")
			break
		}
		fields := strings.Fields(record[:separator])
		if len(fields) != 4 {
			manifestErr = fmt.Errorf("Git tree manifest contains malformed metadata")
			break
		}
		name, pathErr := safeArchivePath(record[separator+1:])
		if pathErr != nil {
			manifestErr = pathErr
			break
		}
		if containsGitMetadata(name) {
			manifestErr = fmt.Errorf("Git tree contains forbidden repository metadata path %q", name)
			break
		}
		if fields[1] != "blob" {
			manifestErr = fmt.Errorf("Git tree contains unsupported %s entry %q", fields[1], name)
			break
		}
		if fields[0] != "100644" && fields[0] != "100755" && fields[0] != "120000" {
			manifestErr = fmt.Errorf("Git tree contains unsupported mode %s for %q", fields[0], name)
			break
		}
		if !validGitObjectID(fields[2]) || len(fields[2]) != len(treeSHA) {
			manifestErr = fmt.Errorf("Git tree contains invalid blob identity for %q", name)
			break
		}
		size, sizeErr := strconv.ParseInt(fields[3], 10, 64)
		if sizeErr != nil || size < 0 {
			manifestErr = fmt.Errorf("Git tree contains invalid blob size for %q", name)
			break
		}
		if len(manifest) >= maxEntries {
			manifestErr = fmt.Errorf("Git tree exceeds the %d-entry limit", maxEntries)
			break
		}
		if size > maxBytes-manifestBytes {
			manifestErr = fmt.Errorf("Git tree exceeds the %d-byte limit", maxBytes)
			break
		}
		if _, duplicate := manifest[name]; duplicate {
			manifestErr = fmt.Errorf("Git tree contains duplicate path %q", name)
			break
		}
		manifest[name] = manifestEntry{mode: fields[0], objectID: fields[2], size: size}
		manifestBytes += size
	}
	if manifestErr != nil {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if manifestErr != nil {
		return nil, manifestErr
	}
	if waitErr != nil {
		return nil, fmt.Errorf("read Git tree manifest: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	return manifest, nil
}

func validateMaterializedTree(destination string, manifest map[string]manifestEntry) error {
	expectedDirectories := make(map[string]struct{})
	for name := range manifest {
		for directory := path.Dir(name); directory != "."; directory = path.Dir(directory) {
			expectedDirectories[directory] = struct{}{}
		}
	}
	seen := make(map[string]struct{}, len(manifest))
	err := filepath.WalkDir(destination, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == destination {
			return nil
		}
		relative, err := filepath.Rel(destination, current)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if entry.IsDir() {
			if _, expected := expectedDirectories[name]; !expected {
				return fmt.Errorf("materialized archive contains unexpected directory %q", name)
			}
			return nil
		}
		expected, ok := manifest[name]
		if !ok {
			return fmt.Errorf("materialized archive contains unexpected entry %q", name)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("materialized archive contains duplicate entry %q", name)
		}
		seen[name] = struct{}{}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		objectID, err := materializedEntryID(current, name, info, expected)
		if err != nil {
			return err
		}
		if objectID != expected.objectID {
			return fmt.Errorf("materialized entry %q does not match its Git blob", name)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("validate materialized Git tree: %w", err)
	}
	if len(seen) != len(manifest) {
		return fmt.Errorf("validate materialized Git tree: archive omitted %d tracked entries", len(manifest)-len(seen))
	}
	return nil
}

func materializedEntryID(current, name string, info os.FileInfo, expected manifestEntry) (string, error) {
	if expected.mode == "120000" {
		if info.Mode()&os.ModeSymlink == 0 {
			return "", fmt.Errorf("materialized entry %q is not the expected symlink", name)
		}
		target, err := os.Readlink(current)
		if err != nil {
			return "", err
		}
		if int64(len(target)) != expected.size {
			return "", fmt.Errorf("materialized entry %q has the wrong size", name)
		}
		return gitBlobID(strings.NewReader(target), expected.size, len(expected.objectID))
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("materialized entry %q is not a regular file", name)
	}
	executable := info.Mode()&0o111 != 0
	if executable != (expected.mode == "100755") {
		return "", fmt.Errorf("materialized entry %q has the wrong executable mode", name)
	}
	if info.Size() != expected.size {
		return "", fmt.Errorf("materialized entry %q has the wrong size", name)
	}
	file, err := os.Open(current)
	if err != nil {
		return "", err
	}
	objectID, hashErr := gitBlobID(file, expected.size, len(expected.objectID))
	closeErr := file.Close()
	if hashErr != nil {
		return "", hashErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return objectID, nil
}

func gitBlobID(source io.Reader, size int64, objectIDLength int) (string, error) {
	var digest hash.Hash
	switch objectIDLength {
	case sha1.Size * 2:
		digest = sha1.New()
	case sha256.Size * 2:
		digest = sha256.New()
	default:
		return "", fmt.Errorf("unsupported Git object ID length %d", objectIDLength)
	}
	if _, err := fmt.Fprintf(digest, "blob %d\x00", size); err != nil {
		return "", err
	}
	if _, err := io.Copy(digest, source); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func extractTar(source io.Reader, destination string, maxEntries int, maxBytes int64) (int, int64, error) {
	reader := tar.NewReader(source)
	entries := 0
	var bytesWritten int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return entries, bytesWritten, nil
		}
		if err != nil {
			return 0, 0, fmt.Errorf("read Git archive: %w", err)
		}
		entries++
		if entries > maxEntries {
			return 0, 0, fmt.Errorf("Git tree exceeds the %d-entry limit", maxEntries)
		}
		name, err := safeArchivePath(header.Name)
		if err != nil {
			return 0, 0, err
		}
		if containsGitMetadata(name) {
			return 0, 0, fmt.Errorf("Git tree contains forbidden repository metadata path %q", header.Name)
		}
		target := filepath.Join(destination, filepath.FromSlash(name))
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return 0, 0, fmt.Errorf("create tree directory %q: %w", name, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > maxBytes-bytesWritten {
				return 0, 0, fmt.Errorf("Git tree exceeds the %d-byte limit", maxBytes)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return 0, 0, fmt.Errorf("create parent for %q: %w", name, err)
			}
			mode := os.FileMode(0o644)
			if header.Mode&0o111 != 0 {
				mode = 0o755
			}
			file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return 0, 0, fmt.Errorf("create tree file %q: %w", name, err)
			}
			written, copyErr := io.Copy(file, reader)
			closeErr := file.Close()
			if copyErr != nil {
				return 0, 0, fmt.Errorf("extract tree file %q: %w", name, copyErr)
			}
			if closeErr != nil {
				return 0, 0, fmt.Errorf("close tree file %q: %w", name, closeErr)
			}
			if written != header.Size {
				return 0, 0, fmt.Errorf("tree file %q size mismatch", name)
			}
			if err := os.Chmod(target, mode); err != nil {
				return 0, 0, fmt.Errorf("set tree file mode %q: %w", name, err)
			}
			bytesWritten += written
		case tar.TypeSymlink:
			if err := validateSymlink(name, header.Linkname); err != nil {
				return 0, 0, err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return 0, 0, fmt.Errorf("create symlink parent for %q: %w", name, err)
			}
			if err := os.Symlink(header.Linkname, target); err != nil {
				return 0, 0, fmt.Errorf("create tree symlink %q: %w", name, err)
			}
		default:
			return 0, 0, fmt.Errorf("Git tree contains unsupported archive entry %q of type %d", name, header.Typeflag)
		}
	}
}

func safeArchivePath(name string) (string, error) {
	if name == "" || path.IsAbs(name) {
		return "", fmt.Errorf("Git archive contains invalid path %q", name)
	}
	trimmed := strings.TrimSuffix(name, "/")
	cleaned := path.Clean(trimmed)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned != trimmed {
		return "", fmt.Errorf("Git archive contains unsafe path %q", name)
	}
	return cleaned, nil
}

func validateSymlink(name, target string) error {
	if target == "" || path.IsAbs(target) {
		return fmt.Errorf("Git tree symlink %q has unsafe target %q", name, target)
	}
	resolved := path.Clean(path.Join(path.Dir(name), target))
	if resolved == ".." || strings.HasPrefix(resolved, "../") || containsGitMetadata(resolved) {
		return fmt.Errorf("Git tree symlink %q escapes the tree-only source boundary", name)
	}
	return nil
}

func containsGitMetadata(name string) bool {
	for _, segment := range strings.Split(name, "/") {
		if strings.EqualFold(segment, ".git") {
			return true
		}
	}
	return false
}

func validGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}
