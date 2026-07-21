package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCanonicalizesEquivalentPolicies(t *testing.T) {
	directory := t.TempDir()
	first := filepath.Join(directory, "first.json")
	second := filepath.Join(directory, "second.json")
	compact := `{"version":"0.1","repository":"github.com/example/project","profile":"verify","command":["go","test","./..."],"environment":"oci://runner@sha256:abc","maxAgeSeconds":3600,"timeoutSeconds":300}`
	formatted := "{\n  \"timeoutSeconds\": 300,\n  \"maxAgeSeconds\": 3600,\n  \"environment\": \"oci://runner@sha256:abc\",\n  \"command\": [\"go\", \"test\", \"./...\"],\n  \"profile\": \"verify\",\n  \"repository\": \"github.com/example/project\",\n  \"version\": \"0.1\"\n}\n"
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
	data := `{"version":"0.1","repository":"github.com/example/project","profile":"verify","command":["true"],"environment":"local://test","maxAgeSeconds":60,"timeoutSeconds":30} {}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil {
		t.Fatal("Load accepted a trailing JSON document")
	}
}

func TestValidateRejectsUnboundedTimeout(t *testing.T) {
	configured := Policy{
		Version:        Version,
		Repository:     "github.com/example/project",
		Profile:        "verify",
		Command:        []string{"true"},
		Environment:    "local://test",
		MaxAgeSeconds:  60,
		TimeoutSeconds: 7201,
	}
	if err := configured.Validate(); err == nil {
		t.Fatal("Validate accepted timeout above the limit")
	}
}
