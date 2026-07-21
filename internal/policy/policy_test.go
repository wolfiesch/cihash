package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCanonicalizesEquivalentPolicies(t *testing.T) {
	directory := t.TempDir()
	first := filepath.Join(directory, "first.json")
	second := filepath.Join(directory, "second.json")
	image := "sha256:" + strings.Repeat("a", 64)
	compact := `{"version":"0.1","repository":"github.com/example/project","profile":"verify","command":["go","test","./..."],"environment":{"image":"` + image + `","platform":"linux/amd64","network":"none","memory":"8g","cpus":"6","pidsLimit":1024,"maxOutputBytes":16777216},"maxAgeSeconds":3600,"timeoutSeconds":300}`
	formatted := "{\n  \"timeoutSeconds\": 300,\n  \"maxAgeSeconds\": 3600,\n  \"environment\": {\n    \"maxOutputBytes\": 16777216,\n    \"pidsLimit\": 1024,\n    \"cpus\": \"6\",\n    \"memory\": \"8g\",\n    \"network\": \"none\",\n    \"platform\": \"linux/amd64\",\n    \"image\": \"" + image + "\"\n  },\n  \"command\": [\"go\", \"test\", \"./...\"],\n  \"profile\": \"verify\",\n  \"repository\": \"github.com/example/project\",\n  \"version\": \"0.1\"\n}\n"
	if err := os.WriteFile(first, []byte(compact), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte(formatted), 0o600); err != nil {
		t.Fatal(err)
	}
	firstPolicy, _, err := Load(first)
	if err != nil {
		t.Fatal(err)
	}
	secondPolicy, _, err := Load(second)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := firstPolicy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := secondPolicy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("equivalent policy digests differ: %s != %s", firstDigest, secondDigest)
	}
}

func TestLoadRejectsTrailingDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	data := `{"version":"0.1","repository":"github.com/example/project","profile":"verify","command":["true"],"environment":{"image":"sha256:` + strings.Repeat("a", 64) + `","platform":"linux/amd64","network":"none","memory":"8g","cpus":"6","pidsLimit":1024,"maxOutputBytes":16777216},"maxAgeSeconds":60,"timeoutSeconds":30} {}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil {
		t.Fatal("Load accepted a trailing JSON document")
	}
}

func TestValidateRejectsUnboundedTimeout(t *testing.T) {
	configured := testPolicy()
	configured.TimeoutSeconds = 7201
	if err := configured.Validate(); err == nil {
		t.Fatal("Validate accepted timeout above the limit")
	}
}

func TestValidateRejectsMutableOrUnboundedEnvironment(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Environment)
	}{
		{name: "mutable image", mutate: func(environment *Environment) { environment.Image = "runner:latest" }},
		{name: "host platform", mutate: func(environment *Environment) { environment.Platform = "darwin/arm64" }},
		{name: "network access", mutate: func(environment *Environment) { environment.Network = "bridge" }},
		{name: "zero cpus", mutate: func(environment *Environment) { environment.CPUs = "0" }},
		{name: "zero pids", mutate: func(environment *Environment) { environment.PIDsLimit = 0 }},
		{name: "unbounded output", mutate: func(environment *Environment) { environment.MaxOutputBytes = MaxOutputBytes + 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			configured := testPolicy()
			test.mutate(&configured.Environment)
			if err := configured.Validate(); err == nil {
				t.Fatal("Validate accepted an unsafe execution environment")
			}
		})
	}
}

func testPolicy() Policy {
	return Policy{
		Version:    Version,
		Repository: "github.com/example/project",
		Profile:    "verify",
		Command:    []string{"true"},
		Environment: Environment{
			Image:          "sha256:" + strings.Repeat("a", 64),
			Platform:       "linux/amd64",
			Network:        "none",
			Memory:         "8g",
			CPUs:           "6",
			PIDsLimit:      1024,
			MaxOutputBytes: 16 << 20,
		},
		MaxAgeSeconds:  60,
		TimeoutSeconds: 30,
	}
}
