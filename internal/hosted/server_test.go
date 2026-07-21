package hosted

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/wolfiesch/cihash/internal/store"
)

func TestWebhookRejectsInvalidSignature(t *testing.T) {
	server, client, _, _, _ := hostedFixture(t, githubapp.ShadowMode, false)
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(`{"zen":"test"}`))
	request.Header.Set("X-GitHub-Event", "ping")
	request.Header.Set("X-GitHub-Delivery", "delivery-invalid")
	request.Header.Set("X-Hub-Signature-256", "sha256="+strings.Repeat("0", 64))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
	if client.tokenCalls != 0 {
		t.Fatal("invalid signature reached GitHub client")
	}
}

func TestPullRequestAcceptsExactProof(t *testing.T) {
	server, client, secret, headSHA, _ := hostedFixture(t, githubapp.EnforceMode, true)
	response := sendWebhook(t, server, secret, "pull_request", "delivery-accepted", pullRequestBody(strings.Repeat("d", 40), strings.Repeat("e", 40)))
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(client.createdChecks) != 1 {
		t.Fatalf("created checks = %d, want 1", len(client.createdChecks))
	}
	check := client.createdChecks[0]
	if check.Status != "completed" || check.Conclusion != "success" || check.HeadSHA != headSHA {
		t.Fatalf("check = %+v, want completed success", check)
	}
	if len(client.dispatches) != 0 {
		t.Fatal("accepted proof dispatched fallback")
	}
}

func TestMissingProofDispatchesAndCompletesFallback(t *testing.T) {
	server, client, secret, headSHA, baseSHA := hostedFixture(t, githubapp.EnforceMode, false)
	response := sendWebhook(t, server, secret, "pull_request", "delivery-fallback", pullRequestBody(headSHA, baseSHA))
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(client.createdChecks) != 1 || client.createdChecks[0].Status != "queued" {
		t.Fatalf("created checks = %+v, want one queued check", client.createdChecks)
	}
	if len(client.dispatches) != 1 {
		t.Fatalf("dispatches = %d, want 1", len(client.dispatches))
	}
	dispatch := client.dispatches[0]
	if dispatch.request.Ref != "main" || dispatch.request.Inputs["cihash_head_sha"] != headSHA || dispatch.request.Inputs["cihash_base_sha"] != baseSHA {
		t.Fatalf("dispatch = %+v", dispatch.request)
	}
	state, found, err := server.stateStore.LookupWorkflowRun(99)
	if err != nil || !found {
		t.Fatalf("LookupWorkflowRun = %+v, %v, %v", state, found, err)
	}
	policyDigest, err := server.policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if state.PolicyDigest != policyDigest {
		t.Fatalf("state policy digest = %q, want %q", state.PolicyDigest, policyDigest)
	}

	workflowBody := map[string]any{
		"action":       "completed",
		"repository":   map[string]any{"full_name": "owner/project"},
		"installation": map[string]any{"id": 123},
		"workflow_run": map[string]any{
			"id":          99,
			"event":       "workflow_dispatch",
			"status":      "completed",
			"conclusion":  "success",
			"head_branch": "main",
			"head_sha":    baseSHA,
			"updated_at":  server.now().Add(time.Minute),
		},
	}
	response = sendWebhook(t, server, secret, "workflow_run", "delivery-workflow-complete", workflowBody)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(client.updatedChecks) != 1 {
		t.Fatalf("updated checks = %d, want 1", len(client.updatedChecks))
	}
	update := client.updatedChecks[0]
	if update.Status != "completed" || update.Conclusion != "success" || update.checkRunID != 42 {
		t.Fatalf("update = %+v, want completed success for check 42", update)
	}
	state, found, err = server.stateStore.LookupWorkflowRun(99)
	if err != nil || !found || state.CompletedAt == nil || state.Conclusion != "success" {
		t.Fatalf("completed state = %+v, %v, %v", state, found, err)
	}
}

type fakeGitHubClient struct {
	tokenCalls    int
	createdChecks []githubapp.CheckRunRequest
	updatedChecks []recordedUpdate
	dispatches    []recordedDispatch
}

type recordedUpdate struct {
	checkRunID int64
	githubapi.CheckRunUpdate
}

type recordedDispatch struct {
	workflow string
	request  githubapi.WorkflowDispatch
}

func (client *fakeGitHubClient) InstallationToken(_ context.Context, installationID int64, repository string) (string, error) {
	client.tokenCalls++
	if installationID != 123 || repository != "owner/project" {
		return "", io.ErrUnexpectedEOF
	}
	return "installation-token", nil
}

func (client *fakeGitHubClient) GetPullRequest(_ context.Context, token, repository string, number int64) (githubapi.PullRequestState, error) {
	if token != "installation-token" || repository != "owner/project" || number != 7 {
		return githubapi.PullRequestState{}, io.ErrUnexpectedEOF
	}
	return githubapi.PullRequestState{
		HeadSHA:        strings.Repeat("a", 40),
		HeadRepository: "owner/project",
		BaseSHA:        strings.Repeat("b", 40),
		BaseRef:        "main",
	}, nil
}

func (client *fakeGitHubClient) CreateCheckRun(_ context.Context, token, repository string, request githubapp.CheckRunRequest) (int64, error) {
	if token != "installation-token" || repository != "owner/project" {
		return 0, io.ErrUnexpectedEOF
	}
	client.createdChecks = append(client.createdChecks, request)
	return 42, nil
}

func (client *fakeGitHubClient) UpdateCheckRun(_ context.Context, token, repository string, checkRunID int64, update githubapi.CheckRunUpdate) error {
	if token != "installation-token" || repository != "owner/project" {
		return io.ErrUnexpectedEOF
	}
	client.updatedChecks = append(client.updatedChecks, recordedUpdate{checkRunID: checkRunID, CheckRunUpdate: update})
	return nil
}

func (client *fakeGitHubClient) DispatchWorkflow(_ context.Context, token, repository, workflow string, request githubapi.WorkflowDispatch) (int64, error) {
	if token != "installation-token" || repository != "owner/project" {
		return 0, io.ErrUnexpectedEOF
	}
	client.dispatches = append(client.dispatches, recordedDispatch{workflow: workflow, request: request})
	return 99, nil
}

func hostedFixture(t *testing.T, mode githubapp.Mode, withProof bool) (*Server, *fakeGitHubClient, []byte, string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	configuredPolicy := policy.Policy{
		Version:        policy.Version,
		Repository:     "github.com/owner/project",
		Profile:        "verify",
		Command:        []string{"go", "test", "./..."},
		Environment:    "oci://runner@sha256:approved",
		MaxAgeSeconds:  3600,
		TimeoutSeconds: 900,
	}
	config := Config{
		Listen:               "127.0.0.1:0",
		WebhookPath:          "/webhooks/github",
		Repository:           "owner/project",
		PolicyFile:           root + "/policy.json",
		ReceiptPublicKeyFile: root + "/receipt.pub",
		ReceiptStore:         root + "/receipts",
		StateDirectory:       root + "/state",
		Mode:                 mode,
		FallbackWorkflow:     "cihash-fallback.yml",
		GitHubAPIBaseURL:     "https://api.github.invalid",
	}
	client := &fakeGitHubClient{}
	secret := []byte("0123456789abcdef0123456789abcdef")
	server, err := NewServer(config, secret, configuredPolicy, publicKey, client, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	fixedNow := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return fixedNow }
	headSHA := strings.Repeat("a", 40)
	baseSHA := strings.Repeat("b", 40)
	if withProof {
		policyDigest, err := configuredPolicy.Digest()
		if err != nil {
			t.Fatal(err)
		}
		workflowDigest, err := configuredPolicy.WorkflowDigest()
		if err != nil {
			t.Fatal(err)
		}
		result := attestation.TestResult{
			SchemaVersion:     attestation.SchemaVersion,
			Repository:        configuredPolicy.Repository,
			HeadSHA:           headSHA,
			BaseSHA:           baseSHA,
			TreeSHA:           strings.Repeat("c", 40),
			Profile:           configuredPolicy.Profile,
			PolicyDigest:      policyDigest,
			WorkflowDigest:    workflowDigest,
			EnvironmentDigest: configuredPolicy.EnvironmentDigest(),
			Architecture:      "linux/amd64",
			Jobs: []attestation.JobResult{{
				Name:        configuredPolicy.Profile,
				Command:     configuredPolicy.Command,
				Conclusion:  "success",
				StartedAt:   fixedNow.Add(-time.Minute),
				CompletedAt: fixedNow.Add(-time.Second),
				LogDigest:   attestation.Digest([]byte("passed")),
			}},
			Conclusion: "success",
			Nonce:      "server-issued-nonce",
			IssuedAt:   fixedNow,
			ExpiresAt:  fixedNow.Add(time.Hour),
		}
		envelope, err := attestation.Sign(attestation.NewStatement(result), privateKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.New(config.ReceiptStore).Save(store.IdentityFromResult(result), envelope, []byte("passed")); err != nil {
			t.Fatal(err)
		}
	}
	return server, client, secret, headSHA, baseSHA
}

func pullRequestBody(headSHA, baseSHA string) map[string]any {
	return map[string]any{
		"action":       "opened",
		"number":       7,
		"repository":   map[string]any{"full_name": "owner/project"},
		"installation": map[string]any{"id": 123},
		"pull_request": map[string]any{
			"draft": false,
			"head":  map[string]any{"sha": headSHA, "ref": "feature"},
			"base":  map[string]any{"sha": baseSHA, "ref": "main"},
		},
	}
}

func sendWebhook(t *testing.T, server *Server, secret []byte, event, delivery string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(string(body)))
	request.Header.Set("X-GitHub-Event", event)
	request.Header.Set("X-GitHub-Delivery", delivery)
	request.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}
