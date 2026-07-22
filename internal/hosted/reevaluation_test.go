package hosted

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wolfiesch/cihash/internal/githubapi"
	"github.com/wolfiesch/cihash/internal/githubapp"
	"github.com/wolfiesch/cihash/internal/rungrant"
)

// A verified successful receipt submitted after enforcement already queued a
// check and dispatched fallback must conclude that same check as success,
// consume the run, and strip the fallback run of its authority to finish the
// check later.
func TestLateReceiptSupersedesPendingFallback(t *testing.T) {
	server, client, secret, private := newHostedServer(t, githubapp.EnforceMode)
	headSHA := strings.Repeat("a", 40)
	baseSHA := strings.Repeat("b", 40)

	if response := sendWebhook(t, server, secret, "pull_request", "delivery-open", pullRequestBody(headSHA, baseSHA)); response.Code != http.StatusAccepted {
		t.Fatalf("pull request status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(client.createdChecks) != 1 || client.createdChecks[0].Status != "queued" {
		t.Fatalf("created checks = %+v, want one queued check", client.createdChecks)
	}
	if len(client.dispatches) != 1 {
		t.Fatalf("dispatches = %d, want 1", len(client.dispatches))
	}

	grant := issuedGrant(t, server, secret)
	envelope := signedReceipt(t, grant, private, []byte("passed"))
	if response := submitReceipt(t, server, secret, grant.ID, envelope, []byte("passed")); response.Code != http.StatusCreated {
		t.Fatalf("submit receipt status = %d, body = %s", response.Code, response.Body.String())
	}

	if len(client.updatedChecks) != 1 {
		t.Fatalf("updated checks = %d, want the queued check concluded", len(client.updatedChecks))
	}
	update := client.updatedChecks[0]
	if update.checkRunID != 42 || update.Status != "completed" || update.Conclusion != "success" {
		t.Fatalf("update = %+v, want completed success for check 42", update)
	}
	record, found, err := server.grantStore.Lookup(grant.ID, server.now())
	if err != nil || !found || record.Status != rungrant.StatusConsumed {
		t.Fatalf("run record = %+v, %v, %v; want consumed", record, found, err)
	}
	state, found, err := server.stateStore.LookupWorkflowRun(99)
	if err != nil || !found || state.CompletedAt == nil || state.Conclusion != "superseded" {
		t.Fatalf("fallback state = %+v, %v, %v; want superseded", state, found, err)
	}

	workflowBody := map[string]any{
		"action":       "completed",
		"repository":   map[string]any{"full_name": "owner/project"},
		"installation": map[string]any{"id": 123},
		"workflow_run": map[string]any{
			"id":          99,
			"path":        ".github/workflows/cihash-fallback.yml",
			"event":       "workflow_dispatch",
			"status":      "completed",
			"conclusion":  "failure",
			"head_branch": "main",
			"head_sha":    baseSHA,
			"updated_at":  server.now().Add(time.Minute),
		},
	}
	if response := sendWebhook(t, server, secret, "workflow_run", "delivery-late-fallback", workflowBody); response.Code != http.StatusAccepted {
		t.Fatalf("workflow_run status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(client.updatedChecks) != 1 {
		t.Fatalf("updated checks = %d, want the superseded fallback completion ignored", len(client.updatedChecks))
	}
}

// A receipt for revisions GitHub has moved past must store diagnostics without
// touching any check; the pending fallback stays authoritative.
func TestLateReceiptIgnoresMovedGitHubState(t *testing.T) {
	server, client, secret, private := newHostedServer(t, githubapp.EnforceMode)
	headSHA := strings.Repeat("a", 40)
	baseSHA := strings.Repeat("b", 40)

	if response := sendWebhook(t, server, secret, "pull_request", "delivery-open", pullRequestBody(headSHA, baseSHA)); response.Code != http.StatusAccepted {
		t.Fatalf("pull request status = %d, body = %s", response.Code, response.Body.String())
	}
	grant := issuedGrant(t, server, secret)
	client.pullRequest = githubapi.PullRequestState{
		HeadSHA:        strings.Repeat("d", 40),
		HeadRepository: "owner/project",
		BaseSHA:        baseSHA,
		BaseRef:        "main",
		TreeSHA:        strings.Repeat("c", 40),
	}
	envelope := signedReceipt(t, grant, private, []byte("passed"))
	if response := submitReceipt(t, server, secret, grant.ID, envelope, []byte("passed")); response.Code != http.StatusCreated {
		t.Fatalf("submit receipt status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(client.updatedChecks) != 0 {
		t.Fatalf("updated checks = %+v, want none for moved GitHub state", client.updatedChecks)
	}
	if len(client.createdChecks) != 1 {
		t.Fatalf("created checks = %d, want only the original queued check", len(client.createdChecks))
	}
	state, found, err := server.stateStore.LookupWorkflowRun(99)
	if err != nil || !found || state.CompletedAt != nil {
		t.Fatalf("fallback state = %+v, %v, %v; want still pending", state, found, err)
	}
}

// In shadow mode, a verified successful receipt publishes a completed success
// check for the still-matching pull request without waiting for the next
// webhook event.
func TestLateReceiptPublishesShadowSuccess(t *testing.T) {
	server, client, secret, private := newHostedServer(t, githubapp.ShadowMode)
	grant := issuedGrant(t, server, secret)
	envelope := signedReceipt(t, grant, private, []byte("passed"))
	if response := submitReceipt(t, server, secret, grant.ID, envelope, []byte("passed")); response.Code != http.StatusCreated {
		t.Fatalf("submit receipt status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(client.createdChecks) != 1 {
		t.Fatalf("created checks = %d, want 1", len(client.createdChecks))
	}
	check := client.createdChecks[0]
	if check.Status != "completed" || check.Conclusion != "success" || check.HeadSHA != strings.Repeat("a", 40) {
		t.Fatalf("check = %+v, want completed success", check)
	}
	if len(client.updatedChecks) != 0 || len(client.dispatches) != 0 {
		t.Fatal("shadow re-evaluation touched enforcement surfaces")
	}
}

// Re-evaluation runs on a server-owned context: a producer that disconnects
// immediately after its receipt is stored must not abort the check update.
func TestLateReceiptSurvivesProducerCancellation(t *testing.T) {
	server, client, secret, private := newHostedServer(t, githubapp.EnforceMode)
	headSHA := strings.Repeat("a", 40)
	baseSHA := strings.Repeat("b", 40)
	if response := sendWebhook(t, server, secret, "pull_request", "delivery-open", pullRequestBody(headSHA, baseSHA)); response.Code != http.StatusAccepted {
		t.Fatalf("pull request status = %d, body = %s", response.Code, response.Body.String())
	}
	grant := issuedGrant(t, server, secret)
	envelope := signedReceipt(t, grant, private, []byte("passed"))

	body, err := json.Marshal(receiptSubmission{Envelope: envelope, Log: []byte("passed")})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, runsEndpoint+"/"+grant.ID+"/receipt", bytes.NewReader(body)).WithContext(cancelled)
	request.Header.Set("Authorization", "Bearer "+string(secret))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("submit receipt status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(client.updatedChecks) != 1 || client.updatedChecks[0].Conclusion != "success" {
		t.Fatalf("updated checks = %+v, want the queued check concluded despite cancellation", client.updatedChecks)
	}
}
