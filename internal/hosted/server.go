package hosted

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/wolfiesch/cihash/internal/githubapi"
	"github.com/wolfiesch/cihash/internal/githubapp"
	"github.com/wolfiesch/cihash/internal/policy"
	"github.com/wolfiesch/cihash/internal/store"
	"github.com/wolfiesch/cihash/internal/verifier"
)

const maxWebhookBody = 1 << 20

type GitHubClient interface {
	InstallationToken(context.Context, int64, string) (string, error)
	GetPullRequest(context.Context, string, string, int64) (githubapi.PullRequestState, error)
	CreateCheckRun(context.Context, string, string, githubapp.CheckRunRequest) (int64, error)
	UpdateCheckRun(context.Context, string, string, int64, githubapi.CheckRunUpdate) error
	DispatchWorkflow(context.Context, string, string, string, githubapi.WorkflowDispatch) (int64, error)
}

type Server struct {
	config        Config
	webhookSecret []byte
	policy        policy.Policy
	publicKey     ed25519.PublicKey
	receiptStore  store.Store
	stateStore    StateStore
	github        GitHubClient
	logger        *log.Logger
	now           func() time.Time
}

type pullRequestPayload struct {
	Action       string              `json:"action"`
	Number       int64               `json:"number"`
	Repository   repositoryPayload   `json:"repository"`
	Installation installationPayload `json:"installation"`
	PullRequest  struct {
		Draft bool `json:"draft"`
		Head  struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"head"`
		Base struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"base"`
	} `json:"pull_request"`
}

type workflowRunPayload struct {
	Action       string              `json:"action"`
	Repository   repositoryPayload   `json:"repository"`
	Installation installationPayload `json:"installation"`
	WorkflowRun  struct {
		ID         int64     `json:"id"`
		Event      string    `json:"event"`
		Status     string    `json:"status"`
		Conclusion string    `json:"conclusion"`
		HeadBranch string    `json:"head_branch"`
		HeadSHA    string    `json:"head_sha"`
		UpdatedAt  time.Time `json:"updated_at"`
	} `json:"workflow_run"`
}

type repositoryPayload struct {
	FullName string `json:"full_name"`
}

type installationPayload struct {
	ID int64 `json:"id"`
}

func NewServer(config Config, webhookSecret []byte, configuredPolicy policy.Policy, publicKey ed25519.PublicKey, github GitHubClient, logger *log.Logger) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if len(webhookSecret) < 32 {
		return nil, fmt.Errorf("GitHub webhook secret must contain at least 32 bytes")
	}
	if err := configuredPolicy.Validate(); err != nil {
		return nil, err
	}
	if configuredPolicy.Repository != "github.com/"+config.Repository {
		return nil, fmt.Errorf("policy repository must equal github.com/%s", config.Repository)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trusted receipt public key is invalid")
	}
	if github == nil {
		return nil, fmt.Errorf("GitHub client is required")
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Server{
		config:        config,
		webhookSecret: append([]byte(nil), webhookSecret...),
		policy:        configuredPolicy,
		publicKey:     append(ed25519.PublicKey(nil), publicKey...),
		receiptStore:  store.New(config.ReceiptStore),
		stateStore:    NewStateStore(config.StateDirectory),
		github:        github,
		logger:        logger,
		now:           func() time.Time { return time.Now().UTC() },
	}, nil
}

func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(server.config.WebhookPath, server.handleWebhook)
	mux.HandleFunc("/health", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"status":"ok"}`+"\n")
	})
	return mux
}

func (server *Server) handleWebhook(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maxWebhookBody))
	if err != nil {
		http.Error(response, "invalid webhook body", http.StatusBadRequest)
		return
	}
	if !verifyWebhookSignature(server.webhookSecret, body, request.Header.Get("X-Hub-Signature-256")) {
		http.Error(response, "invalid webhook signature", http.StatusUnauthorized)
		return
	}
	deliveryID := request.Header.Get("X-GitHub-Delivery")
	started, err := server.stateStore.BeginDelivery(deliveryID)
	if err != nil {
		server.logger.Printf("begin GitHub delivery: %v", err)
		http.Error(response, "delivery state unavailable", http.StatusInternalServerError)
		return
	}
	if !started {
		response.WriteHeader(http.StatusAccepted)
		return
	}
	completed := false
	defer func() {
		if !completed {
			server.stateStore.FailDelivery(deliveryID)
		}
	}()

	event := request.Header.Get("X-GitHub-Event")
	switch event {
	case "ping":
		err = nil
	case "pull_request":
		err = server.handlePullRequest(request.Context(), body)
	case "workflow_run":
		err = server.handleWorkflowRun(request.Context(), body)
	default:
		err = nil
	}
	if err != nil {
		server.logger.Printf("process GitHub %s delivery: %v", event, err)
		http.Error(response, "webhook processing failed", http.StatusInternalServerError)
		return
	}
	if err := server.stateStore.CompleteDelivery(deliveryID); err != nil {
		server.logger.Printf("complete GitHub delivery: %v", err)
		http.Error(response, "delivery state unavailable", http.StatusInternalServerError)
		return
	}
	completed = true
	response.WriteHeader(http.StatusAccepted)
}

func (server *Server) handlePullRequest(ctx context.Context, body []byte) error {
	var payload pullRequestPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("decode pull_request webhook: %w", err)
	}
	if !supportedPullRequestAction(payload.Action) {
		return nil
	}
	if payload.Repository.FullName != server.config.Repository {
		return nil
	}
	if payload.Installation.ID <= 0 || payload.Number <= 0 {
		return fmt.Errorf("pull_request webhook is missing installation or pull request identity")
	}
	token, err := server.github.InstallationToken(ctx, payload.Installation.ID, server.config.Repository)
	if err != nil {
		return err
	}
	current, err := server.github.GetPullRequest(ctx, token, server.config.Repository, payload.Number)
	if err != nil {
		return err
	}
	if current.HeadRepository != server.config.Repository {
		server.logger.Printf("ignoring unsupported fork pull request %d", payload.Number)
		return nil
	}
	payload.PullRequest.Head.SHA = current.HeadSHA
	payload.PullRequest.Base.SHA = current.BaseSHA
	payload.PullRequest.Base.Ref = current.BaseRef
	expected, err := verifier.ExpectedFromPolicy(server.policy, payload.PullRequest.Head.SHA, payload.PullRequest.Base.SHA, "", server.now())
	if err != nil {
		return err
	}
	decision := githubapp.Evaluate(server.receiptStore, server.publicKey, expected, server.config.Mode)
	decision.CheckRun.Name = server.config.CheckName
	if server.config.DetailsURL != "" {
		decision.CheckRun.DetailsURL = server.config.DetailsURL
	}
	checkRunID, err := server.github.CreateCheckRun(ctx, token, server.config.Repository, decision.CheckRun)
	if err != nil {
		return err
	}
	if !decision.FallbackRequired {
		return nil
	}
	return server.dispatchFallback(ctx, token, payload, decision, checkRunID)
}

func (server *Server) dispatchFallback(ctx context.Context, token string, payload pullRequestPayload, decision githubapp.Result, checkRunID int64) error {
	fallbackID, err := randomID()
	if err != nil {
		return err
	}
	policyDigest, err := server.policy.Digest()
	if err != nil {
		return err
	}
	now := server.now()
	state := FallbackState{
		ID:             fallbackID,
		Repository:     server.config.Repository,
		InstallationID: payload.Installation.ID,
		CheckRunID:     checkRunID,
		HeadSHA:        payload.PullRequest.Head.SHA,
		BaseSHA:        payload.PullRequest.Base.SHA,
		BaseRef:        payload.PullRequest.Base.Ref,
		PolicyDigest:   policyDigest,
		ExternalID:     decision.CheckRun.ExternalID,
		CreatedAt:      now,
		ExpiresAt:      now.Add(2 * time.Hour),
	}
	if err := server.stateStore.CreateFallback(state); err != nil {
		return err
	}
	workflowRunID, dispatchErr := server.github.DispatchWorkflow(ctx, token, server.config.Repository, server.config.FallbackWorkflow, githubapi.WorkflowDispatch{
		Ref: payload.PullRequest.Base.Ref,
		Inputs: map[string]string{
			"cihash_fallback_id":   fallbackID,
			"cihash_head_sha":      state.HeadSHA,
			"cihash_base_sha":      state.BaseSHA,
			"cihash_external_id":   state.ExternalID,
			"cihash_policy_digest": state.PolicyDigest,
		},
	})
	if dispatchErr != nil {
		return server.failFallbackDispatch(ctx, token, state, dispatchErr)
	}
	if err := server.stateStore.BindWorkflowRun(fallbackID, workflowRunID); err != nil {
		return server.failFallbackDispatch(ctx, token, state, err)
	}
	return nil
}

func (server *Server) failFallbackDispatch(ctx context.Context, token string, state FallbackState, cause error) error {
	now := server.now()
	update := githubapi.CheckRunUpdate{
		Name:        server.config.CheckName,
		Status:      "completed",
		Conclusion:  "action_required",
		ExternalID:  state.ExternalID,
		CompletedAt: now.Format(time.RFC3339),
		Output: githubapp.CheckRunOutput{
			Title:   "CIHash fallback could not start",
			Summary: "The trusted fallback workflow could not be dispatched. Re-run the check after correcting the integration.",
		},
	}
	if err := server.github.UpdateCheckRun(ctx, token, state.Repository, state.CheckRunID, update); err != nil {
		return fmt.Errorf("fallback dispatch failed (%v) and check update failed: %w", cause, err)
	}
	if err := server.stateStore.CompleteFallback(state.ID, "action_required", now); err != nil {
		return err
	}
	server.logger.Printf("fallback dispatch failed for check %d: %v", state.CheckRunID, cause)
	return nil
}

func (server *Server) handleWorkflowRun(ctx context.Context, body []byte) error {
	var payload workflowRunPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("decode workflow_run webhook: %w", err)
	}
	if payload.Action != "completed" || payload.WorkflowRun.ID <= 0 {
		return nil
	}
	state, found, err := server.stateStore.LookupWorkflowRun(payload.WorkflowRun.ID)
	if err != nil {
		return err
	}
	if !found || state.CompletedAt != nil {
		return nil
	}
	if payload.Repository.FullName != state.Repository || payload.Installation.ID != state.InstallationID {
		return fmt.Errorf("workflow_run identity does not match pending fallback")
	}
	conclusion, title, summary := fallbackConclusion(payload, state, server.now())
	token, err := server.github.InstallationToken(ctx, state.InstallationID, state.Repository)
	if err != nil {
		return err
	}
	completedAt := payload.WorkflowRun.UpdatedAt.UTC()
	if completedAt.IsZero() {
		completedAt = server.now()
	}
	update := githubapi.CheckRunUpdate{
		Name:        server.config.CheckName,
		Status:      "completed",
		Conclusion:  conclusion,
		ExternalID:  state.ExternalID,
		CompletedAt: completedAt.Format(time.RFC3339),
		Output: githubapp.CheckRunOutput{
			Title:   title,
			Summary: summary,
		},
	}
	if err := server.github.UpdateCheckRun(ctx, token, state.Repository, state.CheckRunID, update); err != nil {
		return err
	}
	return server.stateStore.CompleteFallback(state.ID, conclusion, completedAt)
}

func fallbackConclusion(payload workflowRunPayload, state FallbackState, now time.Time) (string, string, string) {
	if !now.Before(state.ExpiresAt) {
		return "stale", "CIHash fallback expired", "The fallback completed after its authorization window expired."
	}
	if payload.WorkflowRun.Event != "workflow_dispatch" || payload.WorkflowRun.HeadSHA != state.BaseSHA || payload.WorkflowRun.HeadBranch != state.BaseRef {
		return "stale", "CIHash fallback identity changed", "The fallback did not run from the exact trusted base revision and branch."
	}
	switch payload.WorkflowRun.Conclusion {
	case "success":
		return "success", "CIHash fallback passed", fmt.Sprintf("Trusted fallback workflow run %d succeeded.", payload.WorkflowRun.ID)
	case "cancelled":
		return "cancelled", "CIHash fallback cancelled", fmt.Sprintf("Trusted fallback workflow run %d was cancelled.", payload.WorkflowRun.ID)
	case "timed_out":
		return "timed_out", "CIHash fallback timed out", fmt.Sprintf("Trusted fallback workflow run %d timed out.", payload.WorkflowRun.ID)
	default:
		return "failure", "CIHash fallback failed", fmt.Sprintf("Trusted fallback workflow run %d concluded with %q.", payload.WorkflowRun.ID, payload.WorkflowRun.Conclusion)
	}
}

func supportedPullRequestAction(action string) bool {
	switch action {
	case "opened", "reopened", "synchronize", "ready_for_review":
		return true
	default:
		return false
	}
}

func verifyWebhookSignature(secret, body []byte, header string) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil || len(provided) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return hmac.Equal(provided, mac.Sum(nil))
}

func randomID() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate fallback ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
