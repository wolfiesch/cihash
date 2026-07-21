package containerexec

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDockerArgumentsConstrainWorkload(t *testing.T) {
	workspace := t.TempDir()
	image := "sha256:" + strings.Repeat("a", 64)
	arguments, cidFile, err := dockerArguments(Options{
		Image:     image,
		Network:   "none",
		Memory:    "8g",
		CPUs:      "6",
		PIDsLimit: 512,
		Command:   []string{"pnpm", "test:tooling"},
		Directory: workspace,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cidFile)

	for _, required := range []string{
		"--read-only",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--pids-limit=512",
		"--memory=8g",
		"--cpus=6",
		"--network=none",
		"--pull=never",
		"type=bind,src=" + workspace + ",dst=/input,readonly",
		image,
		"pnpm",
		"test:tooling",
	} {
		if !slices.Contains(arguments, required) {
			t.Fatalf("arguments do not contain %q: %v", required, arguments)
		}
	}
	joined := strings.Join(arguments, " ")
	if !strings.Contains(joined, "--tmpfs /work:rw,nosuid,nodev,size=8g") {
		t.Fatalf("arguments do not provide a writable bounded work tmpfs: %v", arguments)
	}
	for _, forbidden := range []string{"--privileged", "docker.sock", "CIHASH_GITHUB", "PRIVATE_KEY", "WEBHOOK_SECRET"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("arguments contain forbidden value %q: %v", forbidden, arguments)
		}
	}
}

func TestRunBoundsUntrustedOutput(t *testing.T) {
	docker := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(docker, []byte("#!/bin/sh\nprintf 'abcdefghijklmnop'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	output, err := Run(context.Background(), Options{
		Image:          "sha256:" + strings.Repeat("a", 64),
		Network:        "none",
		Memory:         "8g",
		CPUs:           "6",
		MaxOutputBytes: 8,
		Command:        []string{"true"},
		Directory:      t.TempDir(),
		DockerBinary:   docker,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(output), "abcdefgh\n[cihash] output truncated after 8 bytes\n"; got != want {
		t.Fatalf("bounded output = %q, want %q", got, want)
	}
}

func TestDockerArgumentsRejectMutableImageAndUnknownNetwork(t *testing.T) {
	base := Options{
		Image:     "node:24",
		Network:   "none",
		Memory:    "8g",
		CPUs:      "6",
		Command:   []string{"true"},
		Directory: t.TempDir(),
	}
	if _, _, err := dockerArguments(base); err == nil {
		t.Fatal("mutable image tag was accepted")
	}
	base.Image = "sha256:" + strings.Repeat("a", 64)
	base.Network = "host"
	if _, _, err := dockerArguments(base); err == nil {
		t.Fatal("host network was accepted")
	}
	base.Network = "none"
	base.PIDsLimit = -1
	if _, _, err := dockerArguments(base); err == nil || !strings.Contains(err.Error(), "PID limit must be positive") {
		t.Fatalf("negative PID limit error = %v, want positive-limit rejection", err)
	}
}
