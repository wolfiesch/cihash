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
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/githubapi"
	"github.com/wolfiesch/cihash/internal/githubapp"
	"github.com/wolfiesch/cihash/internal/policy"
	"github.com/wolfiesch/cihash/internal/rungrant"
	"github.com/wolfiesch/cihash/internal/shadow"
	"github.com/wolfiesch/cihash/internal/store"
	"github.com/wolfiesch/cihash/internal/verifier"
)

const (
	maxWebhookBody = 1 << 20
	maxReceiptBody = 8 << 20
	maxReceiptLog  = 4 << 20
	runsEndpoint   = "/api/v1/runs"
)

type GitHubClient interface {
	InstallationToken(context.Context, int64, string) (string, error)
	GetPullRequest(context.Context, string, string, int64) (githubapi.PullRequestState, error)
	GetWorkflowJob(context.Context, string, string, int64, int, string) (githubapi.WorkflowJob, error)
	CreateCheckRun(context.Context, string, string, githubapp.CheckRunRequest) (int64, error)
	UpdateCheckRun(context.Context, string, string, int64, githubapi.CheckRunUpdate) error
	DispatchWorkflow(context.Context, string, string, string, githubapi.WorkflowDispatch) (int64, error)
}

type Server struct {
	config        Config
	webhookSecret []byte
	producerToken []byte
	policy        policy.Policy
	publicKey     ed25519.PublicKey
	receiptStore  store.Store
	grantStore    rungrant.Store
	stateStore    StateStore
	shadowStore   shadow.Store
	serviceBuild  serviceBuild
	startedAt     time.Time
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
		ID           int64     `json:"id"`
		Event        string    `json:"event"`
		RunAttempt   int       `json:"run_attempt"`
		Status       string    `json:"status"`
		Conclusion   string    `json:"conclusion"`
		HeadBranch   string    `json:"head_branch"`
		HeadSHA      string    `json:"head_sha"`
		Name         string    `json:"name"`
		RunStartedAt time.Time `json:"run_started_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		PullRequests []struct {
			Number int64 `json:"number"`
			Head   struct {
				SHA string `json:"sha"`
			} `json:"head"`
			Base struct {
				SHA string `json:"sha"`
			} `json:"base"`
		} `json:"pull_requests"`
	} `json:"workflow_run"`
}

type repositoryPayload struct {
	FullName string `json:"full_name"`
}

type installationPayload struct {
	ID int64 `json:"id"`
}

func NewServer(config Config, webhookSecret, producerToken []byte, configuredPolicy policy.Policy, publicKey ed25519.PublicKey, github GitHubClient, logger *log.Logger) (*Server, error) {
	config.applyDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if len(webhookSecret) < 32 {
		return nil, fmt.Errorf("GitHub webhook secret must contain at least 32 bytes")
	}
	if len(producerToken) < 32 {
		return nil, fmt.Errorf("producer bearer token must contain at least 32 bytes")
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
	if err := os.MkdirAll(config.StateDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create hosted state directory: %w", err)
	}
	build, err := inspectServiceBuild()
	if err != nil {
		return nil, err
	}
	if config.BuildMode == "production" {
		if err := build.validateProduction(); err != nil {
			return nil, err
		}
	}
	startedAt := time.Now().UTC()
	return &Server{
		config:        config,
		webhookSecret: append([]byte(nil), webhookSecret...),
		policy:        configuredPolicy,
		publicKey:     append(ed25519.PublicKey(nil), publicKey...),
		producerToken: append([]byte(nil), producerToken...),
		receiptStore:  store.New(config.ReceiptStore),
		stateStore:    NewStateStore(config.StateDirectory),
		grantStore:    rungrant.NewStore(config.StateDirectory),
		shadowStore:   shadow.New(config.StateDirectory),
		serviceBuild:  build,
		startedAt:     startedAt,
		github:        github,
		logger:        logger,
		now:           func() time.Time { return time.Now().UTC() },
	}, nil
}

func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(server.config.WebhookPath, server.handleWebhook)
	mux.HandleFunc(runsEndpoint, server.handleRuns)
	mux.HandleFunc(runsEndpoint+"/", server.handleReceipt)
	mux.HandleFunc("/health", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"status":"ok"}`+"\n")
	})
	return mux
}

type runIssueRequest struct {
	InstallationID    int64 `json:"installationId"`
	PullRequestNumber int64 `json:"pullRequestNumber"`
}

type receiptSubmission struct {
	Envelope attestation.Envelope `json:"envelope"`
	Log      []byte               `json:"log"`
}

func (server *Server) handleRuns(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !server.authorizedProducer(request) {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !isJSONRequest(request) {
		http.Error(response, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	var issue runIssueRequest
	if status := decodeJSONBody(response, request, maxWebhookBody, &issue); status != 0 {
		http.Error(response, "invalid request", status)
		return
	}
	if issue.InstallationID <= 0 || issue.PullRequestNumber <= 0 {
		http.Error(response, "invalid request", http.StatusBadRequest)
		return
	}
	token, err := server.github.InstallationToken(request.Context(), issue.InstallationID, server.config.Repository)
	if err != nil {
		server.logger.Printf("issue run installation token: %v", err)
		http.Error(response, "GitHub state unavailable", http.StatusBadGateway)
		return
	}
	current, err := server.github.GetPullRequest(request.Context(), token, server.config.Repository, issue.PullRequestNumber)
	if err != nil {
		server.logger.Printf("issue run pull request: %v", err)
		http.Error(response, "GitHub state unavailable", http.StatusBadGateway)
		return
	}
	if current.HeadRepository != server.config.Repository {
		http.Error(response, "pull request is not eligible", http.StatusConflict)
		return
	}
	grant, err := rungrant.Issue(server.policy, current.HeadSHA, current.BaseSHA, current.TreeSHA, server.now())
	if err != nil {
		server.logger.Printf("issue run grant: %v", err)
		http.Error(response, "run issuance unavailable", http.StatusInternalServerError)
		return
	}
	if _, err := server.grantStore.Create(grant); err != nil {
		server.logger.Printf("persist run grant: %v", err)
		http.Error(response, "run issuance unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(response, http.StatusCreated, grant)
}

func (server *Server) handleReceipt(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !server.authorizedProducer(request) {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !isJSONRequest(request) {
		http.Error(response, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	runID, ok := receiptRunID(request.URL.Path)
	if !ok {
		http.NotFound(response, request)
		return
	}
	var submission receiptSubmission
	if status := decodeJSONBody(response, request, maxReceiptBody, &submission); status != 0 {
		http.Error(response, "invalid receipt submission", status)
		return
	}
	if len(submission.Log) > maxReceiptLog {
		http.Error(response, "receipt log too large", http.StatusRequestEntityTooLarge)
		return
	}
	now := server.now()
	record, found, err := server.grantStore.Lookup(runID, now)
	if err != nil {
		server.logger.Printf("lookup run grant: %v", err)
		http.Error(response, "run state unavailable", http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(response, request)
		return
	}
	if record.Status == rungrant.StatusExpired {
		http.Error(response, "run grant expired", http.StatusGone)
		return
	}
	if !now.Before(record.Grant.ExpiresAt) {
		http.Error(response, "run grant expired", http.StatusGone)
		return
	}
	expected := verifier.Expected{
		Repository:        record.Grant.Policy.Repository,
		HeadSHA:           record.Grant.HeadSHA,
		TreeSHA:           record.Grant.TreeSHA,
		BaseSHA:           record.Grant.BaseSHA,
		Profile:           record.Grant.Policy.Profile,
		PolicyDigest:      record.Grant.PolicyDigest,
		WorkflowDigest:    record.Grant.WorkflowDigest,
		EnvironmentDigest: record.Grant.EnvironmentDigest,
		Architecture:      record.Grant.Architecture,
		Command:           append([]string(nil), record.Grant.Policy.Command...),
		RequiredJobs:      []string{record.Grant.Policy.Profile},
		Nonce:             record.Grant.Nonce,
		MaxAge:            record.Grant.ExpiresAt.Sub(record.Grant.IssuedAt),
		NotBefore:         record.Grant.IssuedAt,
		ExpiresAt:         record.Grant.ExpiresAt,
		Now:               now,
	}
	decision := verifier.Verify(submission.Envelope, server.publicKey, expected)
	if !decision.Accepted && decision.Code != "job_failed" && decision.Code != "proof_failed" {
		server.logger.Printf("reject run %s receipt: %s: %s", runID, decision.Code, decision.Message)
		http.Error(response, "receipt verification failed", http.StatusUnprocessableEntity)
		return
	}
	logDigest := attestation.Digest(submission.Log)
	for _, job := range decision.Statement.Predicate.Jobs {
		if job.LogDigest != logDigest {
			http.Error(response, "receipt log does not match", http.StatusUnprocessableEntity)
			return
		}
	}
	envelopeData, err := attestation.MarshalEnvelope(submission.Envelope)
	if err != nil {
		http.Error(response, "invalid receipt submission", http.StatusBadRequest)
		return
	}
	receiptDigest := attestation.Digest(envelopeData)
	if _, err := server.grantStore.MarkSubmitted(runID, receiptDigest, now); err != nil {
		switch {
		case errors.Is(err, rungrant.ErrGrantExpired):
			http.Error(response, "run grant expired", http.StatusGone)
		case errors.Is(err, rungrant.ErrLifecycleConflict):
			http.Error(response, "receipt conflicts with run state", http.StatusConflict)
		default:
			server.logger.Printf("bind receipt to run: %v", err)
			http.Error(response, "run state unavailable", http.StatusInternalServerError)
		}
		return
	}
	if _, _, err := server.receiptStore.SaveForRun(runID, store.IdentityFromResult(decision.Statement.Predicate), submission.Envelope, submission.Log); err != nil {
		if errors.Is(err, store.ErrConflict) {
			http.Error(response, "receipt conflicts with existing evidence", http.StatusConflict)
			return
		}
		server.logger.Printf("persist receipt evidence: %v", err)
		http.Error(response, "receipt persistence unavailable", http.StatusInternalServerError)
		return
	}
	status := http.StatusOK
	if record.Status == rungrant.StatusIssued {
		status = http.StatusCreated
	}
	writeJSON(response, status, map[string]string{"receiptDigest": receiptDigest})
}

func (server *Server) authorizedProducer(request *http.Request) bool {
	const prefix = "Bearer "
	value := request.Header.Get("Authorization")
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	candidate := sha256.Sum256([]byte(value[len(prefix):]))
	expected := sha256.Sum256(server.producerToken)
	return hmac.Equal(candidate[:], expected[:])
}

func receiptRunID(path string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, runsEndpoint+"/"), "/")
	return parts[0], len(parts) == 2 && parts[0] != "" && parts[1] == "receipt"
}

func decodeJSONBody(response http.ResponseWriter, request *http.Request, limit int64, destination any) int {
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return http.StatusRequestEntityTooLarge
		}
		return http.StatusBadRequest
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return http.StatusBadRequest
	}
	return 0
}
func isJSONRequest(request *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/json"
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
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
	expected.TreeSHA = current.TreeSHA
	operationStarted := time.Now()
	verificationStarted := time.Now()
	decision := server.evaluateBoundProof(expected)
	verificationMillis := time.Since(verificationStarted).Milliseconds()
	decision.CheckRun.Name = server.config.CheckName
	if server.config.DetailsURL != "" {
		decision.CheckRun.DetailsURL = server.config.DetailsURL
	}
	checkRunID, err := server.github.CreateCheckRun(ctx, token, server.config.Repository, decision.CheckRun)
	if err != nil {
		return err
	}
	if server.config.Mode == githubapp.ShadowMode {
		evaluatedAt := server.now()
		serviceStartedAt := server.startedAt
		if serviceStartedAt.After(evaluatedAt) {
			serviceStartedAt = evaluatedAt
		}
		if _, err := server.shadowStore.RecordDecision(shadow.Decision{
			Repository:            server.config.Repository,
			PullRequestNumber:     payload.Number,
			HeadSHA:               current.HeadSHA,
			BaseSHA:               current.BaseSHA,
			TreeSHA:               current.TreeSHA,
			PolicyDigest:          expected.PolicyDigest,
			ProofAccepted:         decision.Accepted,
			ProofCode:             decision.Code,
			Comparable:            comparableProofDecision(decision),
			CheckRunID:            checkRunID,
			EvaluatedAt:           evaluatedAt,
			VerificationMillis:    verificationMillis,
			AppDecisionMillis:     time.Since(operationStarted).Milliseconds(),
			ServiceSourceRevision: server.serviceBuild.sourceRevision,
			ServiceBinaryDigest:   server.serviceBuild.binaryDigest,
			ServiceBuildMode:      server.config.BuildMode,
			ServiceSourceModified: server.serviceBuild.sourceModified,
			ServiceStartedAt:      serviceStartedAt,
			PolicyTimeoutSeconds:  server.policy.TimeoutSeconds,
		}); err != nil {
			return fmt.Errorf("record shadow decision: %w", err)
		}
	}
	if !decision.FallbackRequired {
		return nil
	}
	return server.dispatchFallback(ctx, token, payload, decision, checkRunID)
}

func (server *Server) evaluateBoundProof(identityExpected verifier.Expected) githubapp.Result {
	identity := store.Identity{
		Repository:        identityExpected.Repository,
		HeadSHA:           identityExpected.HeadSHA,
		BaseSHA:           identityExpected.BaseSHA,
		Profile:           identityExpected.Profile,
		PolicyDigest:      identityExpected.PolicyDigest,
		WorkflowDigest:    identityExpected.WorkflowDigest,
		EnvironmentDigest: identityExpected.EnvironmentDigest,
	}
	evidence, found, err := server.receiptStore.LookupEvidence(identity)
	if err != nil {
		return githubapp.Rejected(server.config.Mode, identityExpected, "malformed_receipt", err.Error(), evidence.ReceiptPath)
	}
	if !found {
		return githubapp.Rejected(server.config.Mode, identityExpected, "proof_missing", "no proof matches the required identity", evidence.ReceiptPath)
	}
	if evidence.RunID == "" {
		return githubapp.Rejected(server.config.Mode, identityExpected, "run_unbound", "proof is not bound to a server-issued run", evidence.ReceiptPath)
	}

	now := server.now()
	record, found, err := server.grantStore.Lookup(evidence.RunID, now)
	if err != nil {
		return githubapp.Rejected(server.config.Mode, identityExpected, "run_state_invalid", err.Error(), evidence.ReceiptPath)
	}
	if !found {
		return githubapp.Rejected(server.config.Mode, identityExpected, "run_unbound", "proof run binding does not exist", evidence.ReceiptPath)
	}
	if record.Status != rungrant.StatusSubmitted && record.Status != rungrant.StatusConsumed {
		code := "run_unsubmitted"
		if record.Status == rungrant.StatusExpired {
			code = "expired"
		}
		return githubapp.Rejected(server.config.Mode, identityExpected, code, "proof run is not submitted and valid", evidence.ReceiptPath)
	}
	if record.ReceiptDigest != evidence.ReceiptDigest {
		return githubapp.Rejected(server.config.Mode, identityExpected, "receipt_digest_mismatch", "proof digest does not match its submitted run", evidence.ReceiptPath)
	}
	if record.Grant.TreeSHA != identityExpected.TreeSHA {
		return githubapp.Rejected(server.config.Mode, identityExpected, "tree_mismatch", "run grant tree does not match the current GitHub merge tree", evidence.ReceiptPath)
	}
	expected := expectedFromGrant(record.Grant, identityExpected.TreeSHA, now)
	decision := githubapp.EvaluateEnvelope(evidence.Envelope, evidence.ReceiptPath, server.publicKey, expected, server.config.Mode)
	if !decision.Accepted {
		return decision
	}
	if _, err := server.grantStore.MarkConsumed(evidence.RunID, now); err != nil {
		code := "run_state_invalid"
		if errors.Is(err, rungrant.ErrGrantExpired) {
			code = "expired"
		} else if errors.Is(err, rungrant.ErrLifecycleConflict) {
			code = "nonce_invalid"
		}
		return githubapp.Rejected(server.config.Mode, expected, code, err.Error(), evidence.ReceiptPath)
	}
	return decision
}

func expectedFromGrant(grant rungrant.Grant, treeSHA string, now time.Time) verifier.Expected {
	return verifier.Expected{
		Repository:        grant.Policy.Repository,
		HeadSHA:           grant.HeadSHA,
		BaseSHA:           grant.BaseSHA,
		TreeSHA:           treeSHA,
		Profile:           grant.Policy.Profile,
		PolicyDigest:      grant.PolicyDigest,
		WorkflowDigest:    grant.WorkflowDigest,
		EnvironmentDigest: grant.EnvironmentDigest,
		Architecture:      grant.Architecture,
		Command:           append([]string(nil), grant.Policy.Command...),
		RequiredJobs:      []string{grant.Policy.Profile},
		Nonce:             grant.Nonce,
		MaxAge:            grant.ExpiresAt.Sub(grant.IssuedAt),
		NotBefore:         grant.IssuedAt,
		ExpiresAt:         grant.ExpiresAt,
		Now:               now,
	}
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
	if server.config.Mode == githubapp.ShadowMode {
		if server.config.ShadowWorkflow == "" || payload.WorkflowRun.Name != server.config.ShadowWorkflow {
			return nil
		}
		if payload.WorkflowRun.Event != "pull_request" || payload.WorkflowRun.RunAttempt != 1 {
			return nil
		}
		if payload.Repository.FullName != server.config.Repository {
			return nil
		}
		if payload.Installation.ID <= 0 {
			return fmt.Errorf("workflow_run webhook is missing installation identity")
		}
		var pullRequestNumber int64
		var baseSHA string
		for _, pullRequest := range payload.WorkflowRun.PullRequests {
			if pullRequest.Number > 0 && pullRequest.Head.SHA == payload.WorkflowRun.HeadSHA && pullRequest.Base.SHA != "" {
				if pullRequestNumber != 0 {
					return nil
				}
				pullRequestNumber = pullRequest.Number
				baseSHA = pullRequest.Base.SHA
			}
		}
		if pullRequestNumber == 0 {
			return nil
		}
		token, err := server.github.InstallationToken(ctx, payload.Installation.ID, server.config.Repository)
		if err != nil {
			return err
		}
		job, err := server.github.GetWorkflowJob(ctx, token, server.config.Repository, payload.WorkflowRun.ID, payload.WorkflowRun.RunAttempt, server.config.ShadowJob)
		if err != nil {
			return err
		}
		_, _, err = server.shadowStore.RecordWorkflow(server.config.Repository, shadow.Workflow{
			Name:              job.Name,
			RunID:             payload.WorkflowRun.ID,
			HeadSHA:           payload.WorkflowRun.HeadSHA,
			PullRequestNumber: pullRequestNumber,
			BaseSHA:           baseSHA,
			Event:             payload.WorkflowRun.Event,
			RunAttempt:        payload.WorkflowRun.RunAttempt,
			Conclusion:        job.Conclusion,
			StartedAt:         job.StartedAt,
			CompletedAt:       job.CompletedAt,
		})
		if err != nil {
			return fmt.Errorf("record shadow workflow: %w", err)
		}
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
func comparableProofDecision(decision githubapp.Result) bool {
	return decision.Accepted || decision.Code == "job_failed" || decision.Code == "proof_failed"
}

func supportedPullRequestAction(action string) bool {
	switch action {
	case "opened", "reopened", "synchronize", "ready_for_review", "edited":
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
