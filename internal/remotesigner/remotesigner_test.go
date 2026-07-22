package remotesigner

import (
	"bytes"
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
	"github.com/wolfiesch/cihash/internal/rungrant"
	"github.com/wolfiesch/cihash/internal/verifier"
)

func TestClientSignsMatchingAuthenticatedResult(t *testing.T) {
	server, publicKey, token, grant, result := fixture(t)
	httpServer := httptest.NewTLSServer(server.Handler())
	defer httpServer.Close()
	client, err := New(httpServer.URL, token, httpServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := client.Sign(context.Background(), grant, result)
	if err != nil {
		t.Fatal(err)
	}
	decision := verifier.Verify(envelope, publicKey, expected(grant, server.now()))
	if !decision.Accepted {
		t.Fatalf("decision = %+v, want accepted", decision)
	}
}

func TestServerRejectsUnauthorizedAndMismatchedResults(t *testing.T) {
	server, _, token, grant, result := fixture(t)
	requestBody, err := json.Marshal(SignRequest{Grant: grant, Result: result})
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := httptest.NewRequest(http.MethodPost, SignPath, bytes.NewReader(requestBody))
	unauthorized.Header.Set("Content-Type", "application/json")
	unauthorizedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorizedResponse, unauthorized)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", unauthorizedResponse.Code, http.StatusUnauthorized)
	}

	result.HeadSHA = strings.Repeat("d", 40)
	requestBody, err = json.Marshal(SignRequest{Grant: grant, Result: result})
	if err != nil {
		t.Fatal(err)
	}
	mismatched := httptest.NewRequest(http.MethodPost, SignPath, bytes.NewReader(requestBody))
	mismatched.Header.Set("Authorization", "Bearer "+string(token))
	mismatched.Header.Set("Content-Type", "application/json")
	mismatchedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(mismatchedResponse, mismatched)
	if mismatchedResponse.Code != http.StatusUnprocessableEntity {
		t.Fatalf("mismatched status = %d, want %d", mismatchedResponse.Code, http.StatusUnprocessableEntity)
	}
}

func TestServerRejectsExpiredGrant(t *testing.T) {
	server, _, token, grant, result := fixture(t)
	server.now = func() time.Time { return grant.ExpiresAt }
	requestBody, err := json.Marshal(SignRequest{Grant: grant, Result: result})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, SignPath, bytes.NewReader(requestBody))
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusGone)
	}
}

func fixture(t *testing.T) (*Server, ed25519.PublicKey, []byte, rungrant.Grant, attestation.TestResult) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := []byte(strings.Repeat("s", 32))
	server, err := NewServer(token, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	configuredPolicy := policy.Policy{
		Version:    "0.1",
		Repository: "github.com/owner/project",
		Profile:    "verify",
		Command:    []string{"go", "test", "./..."},
		Environment: policy.Environment{
			Image:          "sha256:" + strings.Repeat("a", 64),
			Platform:       "linux/amd64",
			Network:        "none",
			Memory:         "1g",
			CPUs:           "1",
			PIDsLimit:      128,
			MaxOutputBytes: 1 << 20,
		},
		MaxAgeSeconds:  3600,
		TimeoutSeconds: 300,
	}
	grant, err := rungrant.Issue(configuredPolicy, strings.Repeat("b", 40), strings.Repeat("c", 40), strings.Repeat("e", 40), now)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := now.Add(time.Second)
	completedAt := now.Add(2 * time.Second)
	result := attestation.TestResult{
		SchemaVersion:     attestation.SchemaVersion,
		Repository:        grant.Policy.Repository,
		HeadSHA:           grant.HeadSHA,
		BaseSHA:           grant.BaseSHA,
		TreeSHA:           grant.TreeSHA,
		Profile:           grant.Policy.Profile,
		PolicyDigest:      grant.PolicyDigest,
		WorkflowDigest:    grant.WorkflowDigest,
		EnvironmentDigest: grant.EnvironmentDigest,
		Architecture:      grant.Architecture,
		Jobs: []attestation.JobResult{{
			Name:        grant.Policy.Profile,
			Command:     append([]string(nil), grant.Policy.Command...),
			Conclusion:  "success",
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			LogDigest:   attestation.Digest(nil),
		}},
		Conclusion: "success",
		Nonce:      grant.Nonce,
		IssuedAt:   completedAt,
		ExpiresAt:  grant.ExpiresAt,
	}
	server.now = func() time.Time { return now.Add(3 * time.Second) }
	return server, publicKey, token, grant, result
}
