package producer_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/policy"
	"github.com/wolfiesch/cihash/internal/producer"
	"github.com/wolfiesch/cihash/internal/rungrant"
)

func TestClientIssuesGrantAndSubmitsReceipt(t *testing.T) {
	configured := testPolicy()
	grant, err := rungrant.Issue(configured, strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result := attestation.TestResult{
		SchemaVersion:     attestation.SchemaVersion,
		Repository:        configured.Repository,
		HeadSHA:           grant.HeadSHA,
		BaseSHA:           grant.BaseSHA,
		TreeSHA:           grant.TreeSHA,
		Profile:           configured.Profile,
		PolicyDigest:      grant.PolicyDigest,
		WorkflowDigest:    grant.WorkflowDigest,
		EnvironmentDigest: grant.EnvironmentDigest,
		Architecture:      grant.Architecture,
		Jobs: []attestation.JobResult{{
			Name:        configured.Profile,
			Command:     configured.Command,
			Conclusion:  "success",
			StartedAt:   grant.IssuedAt,
			CompletedAt: grant.IssuedAt.Add(time.Second),
			LogDigest:   attestation.Digest([]byte("log")),
		}},
		Conclusion: "success",
		Nonce:      grant.Nonce,
		IssuedAt:   grant.IssuedAt,
		ExpiresAt:  grant.ExpiresAt,
	}
	envelope, err := attestation.Sign(attestation.NewStatement(result), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	const token = "producer-token-with-at-least-thirty-two-bytes"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("request headers = %v", request.Header)
		}
		switch request.URL.Path {
		case "/api/v1/runs":
			response.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(response).Encode(grant)
		case "/api/v1/runs/" + grant.ID + "/receipt":
			response.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(response).Encode(map[string]string{"receiptDigest": attestation.Digest([]byte("receipt"))})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	client, err := producer.New(server.URL, []byte(token), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	issued, err := client.Issue(context.Background(), 123, 7)
	if err != nil || issued.ID != grant.ID {
		t.Fatalf("Issue = %+v, %v", issued, err)
	}
	if _, err := client.Submit(context.Background(), issued.ID, envelope, []byte("log")); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestClientRejectsInsecureRemoteURL(t *testing.T) {
	if _, err := producer.New("http://example.com", []byte(strings.Repeat("x", 32)), nil); err == nil {
		t.Fatal("New accepted insecure remote URL")
	}
}

func testPolicy() policy.Policy {
	return policy.Policy{
		Version:    policy.Version,
		Repository: "github.com/owner/repository",
		Profile:    "verify",
		Command:    []string{"go", "test", "./..."},
		Environment: policy.Environment{
			Image:          "sha256:" + strings.Repeat("d", 64),
			Platform:       "linux/amd64",
			Network:        "none",
			Memory:         "8g",
			CPUs:           "6",
			PIDsLimit:      1024,
			MaxOutputBytes: 1 << 20,
		},
		MaxAgeSeconds:  3600,
		TimeoutSeconds: 300,
	}
}
