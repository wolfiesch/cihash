package hosted

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/githubapi"
	"github.com/wolfiesch/cihash/internal/githubapp"
	"github.com/wolfiesch/cihash/internal/policy"
	"github.com/wolfiesch/cihash/internal/rungrant"
)

func TestRunIssueAuthenticationAndAuthoritativePullRequest(t *testing.T) {
	server, client, _, token := ingestionFixture(t)
	request := httptest.NewRequest(http.MethodPost, runsEndpoint, strings.NewReader(`{"installationId":123,"pullRequestNumber":7}`))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated issuance = %d, want %d", response.Code, http.StatusUnauthorized)
	}

	client.pullRequest = githubapi.PullRequestState{HeadSHA: strings.Repeat("d", 40), BaseSHA: strings.Repeat("e", 40), TreeSHA: strings.Repeat("f", 40), HeadRepository: "fork/project", BaseRef: "main"}
	response = issueRun(t, server, token)
	if response.Code != http.StatusConflict {
		t.Fatalf("fork issuance = %d, want %d", response.Code, http.StatusConflict)
	}

	client.pullRequest = githubapi.PullRequestState{HeadSHA: strings.Repeat("d", 40), BaseSHA: strings.Repeat("e", 40), TreeSHA: strings.Repeat("f", 40), HeadRepository: "owner/project", BaseRef: "main"}
	response = issueRun(t, server, token)
	if response.Code != http.StatusCreated {
		t.Fatalf("issuance = %d, body=%s", response.Code, response.Body.String())
	}
	var grant rungrant.Grant
	if err := json.NewDecoder(response.Body).Decode(&grant); err != nil {
		t.Fatal(err)
	}
	if grant.HeadSHA != client.pullRequest.HeadSHA || grant.BaseSHA != client.pullRequest.BaseSHA || grant.TreeSHA != client.pullRequest.TreeSHA || grant.Architecture != "linux/amd64" {
		t.Fatalf("grant did not use authoritative PR state: %+v", grant)
	}
	if record, found, err := server.grantStore.Lookup(grant.ID, server.now()); err != nil || !found || record.Status != rungrant.StatusIssued {
		t.Fatalf("persisted grant = %+v, %v, %v", record, found, err)
	}

	malformed := httptest.NewRequest(http.MethodPost, runsEndpoint, strings.NewReader(`{"installationId":123,"unknown":true}`))
	malformed.Header.Set("Authorization", "Bearer "+string(token))
	malformed.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, malformed)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed issuance = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestReceiptSubmissionAcceptsExecutionAfterGrantIssuance(t *testing.T) {
	server, _, private, token := ingestionFixture(t)
	grant := issuedGrant(t, server, token)
	completedAt := grant.IssuedAt.Add(5 * time.Minute)
	server.now = func() time.Time { return completedAt }
	logBytes := []byte("verified output")
	envelope := signedReceiptAt(t, grant, private, logBytes, completedAt)
	response := submitReceipt(t, server, token, grant.ID, envelope, logBytes)
	if response.Code != http.StatusCreated {
		t.Fatalf("receipt = %d, want %d; body=%s", response.Code, http.StatusCreated, response.Body.String())
	}
}

func TestReceiptSubmissionStoresSignedFailureDiagnostics(t *testing.T) {
	server, _, private, token := ingestionFixture(t)
	grant := issuedGrant(t, server, token)
	logBytes := []byte("failing output")
	envelope := signedReceiptConclusion(t, grant, private, logBytes, "failure", 1)
	response := submitReceipt(t, server, token, grant.ID, envelope, logBytes)
	if response.Code != http.StatusCreated {
		t.Fatalf("failure receipt = %d, want %d; body=%s", response.Code, http.StatusCreated, response.Body.String())
	}
}

func TestReceiptSubmissionRejectsAdversarialInput(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*rungrant.Grant, *attestation.Envelope, *[]byte)
		advance  bool
		wantCode int
	}{
		{name: "oversized", mutate: func(_ *rungrant.Grant, _ *attestation.Envelope, log *[]byte) {
			*log = bytes.Repeat([]byte("x"), maxReceiptLog+1)
		}, wantCode: http.StatusRequestEntityTooLarge},
		{name: "bad signature", mutate: func(_ *rungrant.Grant, envelope *attestation.Envelope, _ *[]byte) {
			envelope.Signatures[0].Sig = "not-a-signature"
		}, wantCode: http.StatusUnprocessableEntity},
		{name: "stale revision", mutate: func(grant *rungrant.Grant, _ *attestation.Envelope, _ *[]byte) {
			grant.HeadSHA = strings.Repeat("f", 40)
		}, wantCode: http.StatusUnprocessableEntity},
		{name: "wrong nonce", mutate: func(grant *rungrant.Grant, _ *attestation.Envelope, _ *[]byte) {
			grant.Nonce = strings.Repeat("x", len(grant.Nonce))
		}, wantCode: http.StatusUnprocessableEntity},
		{name: "wrong policy", mutate: func(grant *rungrant.Grant, _ *attestation.Envelope, _ *[]byte) {
			grant.PolicyDigest = attestation.Digest([]byte("other"))
		}, wantCode: http.StatusUnprocessableEntity},
		{name: "wrong architecture", mutate: func(grant *rungrant.Grant, _ *attestation.Envelope, _ *[]byte) { grant.Architecture = "linux/arm64" }, wantCode: http.StatusUnprocessableEntity},
		{name: "wrong expiry", mutate: func(grant *rungrant.Grant, _ *attestation.Envelope, _ *[]byte) {
			grant.ExpiresAt = grant.ExpiresAt.Add(-time.Second)
		}, wantCode: http.StatusUnprocessableEntity},
		{name: "wrong log", mutate: func(_ *rungrant.Grant, _ *attestation.Envelope, log *[]byte) { *log = []byte("different output") }, wantCode: http.StatusUnprocessableEntity},
		{name: "expired grant", advance: true, wantCode: http.StatusGone},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, _, private, token := ingestionFixture(t)
			grant := issuedGrant(t, server, token)
			logBytes := []byte("verified output")
			proofGrant := grant
			envelope := signedReceipt(t, proofGrant, private, logBytes)
			if test.mutate != nil {
				test.mutate(&proofGrant, &envelope, &logBytes)
				if test.name != "bad signature" && test.name != "wrong log" {
					envelope = signedReceipt(t, proofGrant, private, []byte("verified output"))
				}
			}
			if test.advance {
				server.now = func() time.Time { return grant.ExpiresAt }
			}
			response := submitReceipt(t, server, token, grant.ID, envelope, logBytes)
			if response.Code != test.wantCode {
				t.Fatalf("receipt = %d, want %d; body=%s", response.Code, test.wantCode, response.Body.String())
			}
		})
	}
}
func TestReceiptSubmissionRequiresStrictJSON(t *testing.T) {
	server, _, _, token := ingestionFixture(t)
	for _, body := range []string{
		`{"envelope":{},"log":"","extra":true}`,
		`{"envelope":{},"log":""} trailing`,
	} {
		request := httptest.NewRequest(http.MethodPost, runsEndpoint+"/unknown/receipt", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+string(token))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("strict receipt JSON = %d, want %d; body=%s", response.Code, http.StatusBadRequest, response.Body.String())
		}
	}
}

func TestReceiptSubmissionFirstVerifiedEvidenceWins(t *testing.T) {
	server, _, private, token := ingestionFixture(t)
	grant := issuedGrant(t, server, token)
	logBytes := []byte("verified output")
	envelope := signedReceipt(t, grant, private, logBytes)
	if response := submitReceipt(t, server, token, grant.ID, envelope, logBytes); response.Code != http.StatusCreated {
		t.Fatalf("initial submission = %d, body=%s", response.Code, response.Body.String())
	}
	if response := submitReceipt(t, server, token, grant.ID, envelope, logBytes); response.Code != http.StatusOK {
		t.Fatalf("duplicate submission = %d, body=%s", response.Code, response.Body.String())
	}

	replacementLog := []byte("different verified output")
	replacement := signedReceipt(t, grant, private, replacementLog)
	if response := submitReceipt(t, server, token, grant.ID, replacement, replacementLog); response.Code != http.StatusConflict {
		t.Fatalf("replacement submission = %d, want %d; body=%s", response.Code, http.StatusConflict, response.Body.String())
	}
}

func TestNewServerRejectsShortProducerToken(t *testing.T) {
	server, client, _, _ := ingestionFixture(t)
	_, err := NewServer(server.config, bytes.Repeat([]byte("w"), 32), []byte("short"), server.policy, server.publicKey, client, log.New(io.Discard, "", 0))
	if err == nil {
		t.Fatal("NewServer accepted a short producer token")
	}
}

func ingestionFixture(t *testing.T) (*Server, *fakeGitHubClient, ed25519.PrivateKey, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	configuredPolicy := policy.Policy{Version: policy.Version, Repository: "github.com/owner/project", Profile: "verify", Command: []string{"go", "test", "./..."}, Environment: hostedTestEnvironment(), MaxAgeSeconds: 3600, TimeoutSeconds: 900}
	config := Config{Listen: "127.0.0.1:0", WebhookPath: "/webhooks/github", Repository: "owner/project", CheckName: "cihash/tooling", PolicyFile: root + "/policy.json", ReceiptPublicKeyFile: root + "/receipt.pub", ReceiptStore: root + "/receipts", StateDirectory: root + "/state", Mode: githubapp.ShadowMode}
	client := &fakeGitHubClient{}
	token := []byte("producer-token-with-at-least-thirty-two-bytes")
	server, err := NewServer(config, bytes.Repeat([]byte("w"), 32), token, configuredPolicy, publicKey, client, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	fixedNow := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return fixedNow }
	return server, client, privateKey, token
}

func issueRun(t *testing.T, server *Server, token []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, runsEndpoint, strings.NewReader(`{"installationId":123,"pullRequestNumber":7}`))
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func issuedGrant(t *testing.T, server *Server, token []byte) rungrant.Grant {
	t.Helper()
	response := issueRun(t, server, token)
	if response.Code != http.StatusCreated {
		t.Fatalf("issue run = %d, body=%s", response.Code, response.Body.String())
	}
	var grant rungrant.Grant
	if err := json.NewDecoder(response.Body).Decode(&grant); err != nil {
		t.Fatal(err)
	}
	return grant
}

func submitReceipt(t *testing.T, server *Server, token []byte, runID string, envelope attestation.Envelope, logBytes []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(receiptSubmission{Envelope: envelope, Log: logBytes})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, runsEndpoint+"/"+runID+"/receipt", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func signedReceipt(t *testing.T, grant rungrant.Grant, private ed25519.PrivateKey, logBytes []byte) attestation.Envelope {
	t.Helper()
	return signedReceiptWithTree(t, grant, private, logBytes, grant.TreeSHA)
}

func signedReceiptAt(t *testing.T, grant rungrant.Grant, private ed25519.PrivateKey, logBytes []byte, issuedAt time.Time) attestation.Envelope {
	t.Helper()
	return signedReceiptWindow(t, grant, private, logBytes, grant.TreeSHA, grant.IssuedAt, issuedAt)
}
func signedReceiptWithTree(t *testing.T, grant rungrant.Grant, private ed25519.PrivateKey, logBytes []byte, tree string) attestation.Envelope {
	t.Helper()
	return signedReceiptWindow(t, grant, private, logBytes, tree, grant.IssuedAt.Add(-time.Second), grant.IssuedAt)
}

func signedReceiptConclusion(t *testing.T, grant rungrant.Grant, private ed25519.PrivateKey, logBytes []byte, conclusion string, exitCode int) attestation.Envelope {
	t.Helper()
	startedAt := grant.IssuedAt.Add(-time.Second)
	result := attestation.TestResult{SchemaVersion: attestation.SchemaVersion, Repository: grant.Policy.Repository, HeadSHA: grant.HeadSHA, BaseSHA: grant.BaseSHA, TreeSHA: grant.TreeSHA, Profile: grant.Policy.Profile, PolicyDigest: grant.PolicyDigest, WorkflowDigest: grant.WorkflowDigest, EnvironmentDigest: grant.EnvironmentDigest, Architecture: grant.Architecture, Jobs: []attestation.JobResult{{Name: grant.Policy.Profile, Command: grant.Policy.Command, ExitCode: exitCode, Conclusion: conclusion, StartedAt: startedAt, CompletedAt: grant.IssuedAt, LogDigest: attestation.Digest(logBytes)}}, Conclusion: conclusion, Nonce: grant.Nonce, IssuedAt: grant.IssuedAt, ExpiresAt: grant.ExpiresAt}
	envelope, err := attestation.Sign(attestation.NewStatement(result), private)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func signedReceiptWindow(t *testing.T, grant rungrant.Grant, private ed25519.PrivateKey, logBytes []byte, tree string, startedAt, issuedAt time.Time) attestation.Envelope {
	t.Helper()
	result := attestation.TestResult{SchemaVersion: attestation.SchemaVersion, Repository: grant.Policy.Repository, HeadSHA: grant.HeadSHA, BaseSHA: grant.BaseSHA, TreeSHA: tree, Profile: grant.Policy.Profile, PolicyDigest: grant.PolicyDigest, WorkflowDigest: grant.WorkflowDigest, EnvironmentDigest: grant.EnvironmentDigest, Architecture: grant.Architecture, Jobs: []attestation.JobResult{{Name: grant.Policy.Profile, Command: grant.Policy.Command, ExitCode: 0, Conclusion: "success", StartedAt: startedAt, CompletedAt: issuedAt, LogDigest: attestation.Digest(logBytes)}}, Conclusion: "success", Nonce: grant.Nonce, IssuedAt: issuedAt, ExpiresAt: grant.ExpiresAt}
	envelope, err := attestation.Sign(attestation.NewStatement(result), private)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}
