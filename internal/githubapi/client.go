package githubapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/wolfiesch/cihash/internal/githubapp"
)

const apiVersion = "2026-03-10"

type Client struct {
	baseURL    string
	clientID   string
	privateKey *rsa.PrivateKey
	httpClient *http.Client
	now        func() time.Time
}

type CheckRunUpdate struct {
	Name        string                   `json:"name,omitempty"`
	Status      string                   `json:"status"`
	Conclusion  string                   `json:"conclusion,omitempty"`
	ExternalID  string                   `json:"external_id,omitempty"`
	CompletedAt string                   `json:"completed_at,omitempty"`
	Output      githubapp.CheckRunOutput `json:"output"`
}

type WorkflowDispatch struct {
	Ref    string            `json:"ref"`
	Inputs map[string]string `json:"inputs"`
}

type PullRequestState struct {
	HeadSHA        string
	HeadRepository string
	BaseSHA        string
	BaseRef        string
	TreeSHA        string
}
type WorkflowJob struct {
	ID          int64
	Name        string
	Conclusion  string
	StartedAt   time.Time
	CompletedAt time.Time
}

func New(baseURL, clientID string, privateKey *rsa.PrivateKey, httpClient *http.Client) (*Client, error) {
	if strings.TrimSpace(clientID) == "" {
		return nil, fmt.Errorf("GitHub App client ID is required")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("GitHub App private key is required")
	}
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "https://api.github.com"
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid GitHub API base URL: %w", err)
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		clientID:   clientID,
		privateKey: privateKey,
		httpClient: httpClient,
		now:        func() time.Time { return time.Now().UTC() },
	}, nil
}

func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read GitHub App private key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("decode GitHub App private key PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse GitHub App private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("GitHub App private key is not RSA")
	}
	return key, nil
}

func (client *Client) InstallationToken(ctx context.Context, installationID int64, repository string) (string, error) {
	if installationID <= 0 {
		return "", fmt.Errorf("GitHub App installation ID is required")
	}
	_, repositoryName, err := splitRepository(repository)
	if err != nil {
		return "", err
	}
	jwt, err := client.appJWT()
	if err != nil {
		return "", err
	}
	request := struct {
		Repositories []string          `json:"repositories"`
		Permissions  map[string]string `json:"permissions"`
	}{
		Repositories: []string{repositoryName},
		Permissions: map[string]string{
			"contents":      "read",
			"actions":       "write",
			"checks":        "write",
			"pull_requests": "read",
		},
	}
	var response struct {
		Token string `json:"token"`
	}
	path := "/app/installations/" + strconv.FormatInt(installationID, 10) + "/access_tokens"
	if err := client.do(ctx, http.MethodPost, path, jwt, request, http.StatusCreated, &response); err != nil {
		return "", err
	}
	if response.Token == "" {
		return "", fmt.Errorf("GitHub returned an empty installation token")
	}
	return response.Token, nil
}

func (client *Client) GetPullRequest(ctx context.Context, token, repository string, number int64) (PullRequestState, error) {
	owner, name, err := splitRepository(repository)
	if err != nil {
		return PullRequestState{}, err
	}
	if number <= 0 {
		return PullRequestState{}, fmt.Errorf("pull request number is required")
	}
	var response struct {
		Head struct {
			SHA  string `json:"sha"`
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
		Base struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"base"`
		MergeCommitSHA string `json:"merge_commit_sha"`
	}
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/pulls/" + strconv.FormatInt(number, 10)
	if err := client.do(ctx, http.MethodGet, path, token, nil, http.StatusOK, &response); err != nil {
		return PullRequestState{}, err
	}
	if response.Head.SHA == "" || response.Head.Repo.FullName == "" || response.Base.SHA == "" || response.Base.Ref == "" {
		return PullRequestState{}, fmt.Errorf("GitHub returned incomplete pull request identity")
	}
	if !validGitObjectID(response.Head.SHA) || !validGitObjectID(response.Base.SHA) {
		return PullRequestState{}, fmt.Errorf("GitHub returned malformed pull request identity")
	}
	if response.MergeCommitSHA == "" {
		return PullRequestState{}, fmt.Errorf("GitHub has no merge commit for pull request")
	}
	if !validGitObjectID(response.MergeCommitSHA) {
		return PullRequestState{}, fmt.Errorf("GitHub returned malformed pull request merge commit SHA")
	}
	var mergeCommit struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	mergeCommitPath := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/git/commits/" + url.PathEscape(response.MergeCommitSHA)
	if err := client.do(ctx, http.MethodGet, mergeCommitPath, token, nil, http.StatusOK, &mergeCommit); err != nil {
		return PullRequestState{}, fmt.Errorf("fetch GitHub pull request merge commit: %w", err)
	}
	if mergeCommit.Tree.SHA == "" {
		return PullRequestState{}, fmt.Errorf("GitHub returned no tree SHA for pull request merge commit")
	}
	if !validGitObjectID(mergeCommit.Tree.SHA) {
		return PullRequestState{}, fmt.Errorf("GitHub returned malformed pull request merge tree SHA")
	}
	return PullRequestState{
		HeadSHA:        response.Head.SHA,
		HeadRepository: response.Head.Repo.FullName,
		BaseSHA:        response.Base.SHA,
		BaseRef:        response.Base.Ref,
		TreeSHA:        mergeCommit.Tree.SHA,
	}, nil
}

func (client *Client) CreateCheckRun(ctx context.Context, token, repository string, request githubapp.CheckRunRequest) (int64, error) {
	owner, name, err := splitRepository(repository)
	if err != nil {
		return 0, err
	}
	var response struct {
		ID int64 `json:"id"`
	}
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/check-runs"
	if err := client.do(ctx, http.MethodPost, path, token, request, http.StatusCreated, &response); err != nil {
		return 0, err
	}
	if response.ID <= 0 {
		return 0, fmt.Errorf("GitHub returned an invalid check run ID")
	}
	return response.ID, nil
}

func (client *Client) UpdateCheckRun(ctx context.Context, token, repository string, checkRunID int64, update CheckRunUpdate) error {
	owner, name, err := splitRepository(repository)
	if err != nil {
		return err
	}
	if checkRunID <= 0 {
		return fmt.Errorf("check run ID is required")
	}
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/check-runs/" + strconv.FormatInt(checkRunID, 10)
	return client.do(ctx, http.MethodPatch, path, token, update, http.StatusOK, nil)
}

func (client *Client) DispatchWorkflow(ctx context.Context, token, repository, workflow string, dispatch WorkflowDispatch) (int64, error) {
	owner, name, err := splitRepository(repository)
	if err != nil {
		return 0, err
	}
	if strings.TrimSpace(workflow) == "" {
		return 0, fmt.Errorf("fallback workflow is required")
	}
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/actions/workflows/" + url.PathEscape(workflow) + "/dispatches"
	var response struct {
		WorkflowRunID int64 `json:"workflow_run_id"`
	}
	if err := client.do(ctx, http.MethodPost, path, token, dispatch, http.StatusOK, &response); err != nil {
		return 0, err
	}
	if response.WorkflowRunID <= 0 {
		return 0, fmt.Errorf("GitHub did not return a workflow run ID; fallback cannot be correlated safely")
	}
	return response.WorkflowRunID, nil
}

func (client *Client) GetWorkflowJob(ctx context.Context, token, repository string, runID int64, jobName string) (WorkflowJob, error) {
	owner, name, err := splitRepository(repository)
	if err != nil {
		return WorkflowJob{}, err
	}
	if runID <= 0 || strings.TrimSpace(jobName) == "" {
		return WorkflowJob{}, fmt.Errorf("workflow run ID and job name are required")
	}
	var response struct {
		Jobs []struct {
			ID          int64     `json:"id"`
			Name        string    `json:"name"`
			Status      string    `json:"status"`
			Conclusion  string    `json:"conclusion"`
			StartedAt   time.Time `json:"started_at"`
			CompletedAt time.Time `json:"completed_at"`
		} `json:"jobs"`
	}
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/actions/runs/" + strconv.FormatInt(runID, 10) + "/jobs?filter=latest&per_page=100"
	if err := client.do(ctx, http.MethodGet, path, token, nil, http.StatusOK, &response); err != nil {
		return WorkflowJob{}, err
	}
	var matched WorkflowJob
	for _, job := range response.Jobs {
		if job.Name != jobName {
			continue
		}
		if matched.ID != 0 {
			return WorkflowJob{}, fmt.Errorf("GitHub workflow run contains multiple jobs named %q", jobName)
		}
		if job.ID <= 0 || job.Status != "completed" || job.Conclusion == "" || job.StartedAt.IsZero() || job.CompletedAt.IsZero() || job.CompletedAt.Before(job.StartedAt) {
			return WorkflowJob{}, fmt.Errorf("GitHub workflow job %q is incomplete", jobName)
		}
		matched = WorkflowJob{ID: job.ID, Name: job.Name, Conclusion: job.Conclusion, StartedAt: job.StartedAt.UTC(), CompletedAt: job.CompletedAt.UTC()}
	}
	if matched.ID == 0 {
		return WorkflowJob{}, fmt.Errorf("GitHub workflow run does not contain job %q", jobName)
	}
	return matched, nil
}

func (client *Client) appJWT() (string, error) {
	now := client.now()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(struct {
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
		Issuer    string `json:"iss"`
	}{
		IssuedAt:  now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(9 * time.Minute).Unix(),
		Issuer:    client.clientID,
	})
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claims)
	unsigned := encodedHeader + "." + encodedClaims
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, client.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign GitHub App JWT: %w", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (client *Client) do(ctx context.Context, method, path, token string, body any, expectedStatus int, output any) error {
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode GitHub request: %w", err)
		}
		requestBody = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, client.baseURL+path, requestBody)
	if err != nil {
		return fmt.Errorf("create GitHub request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	request.Header.Set("User-Agent", "cihash/0.1")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("GitHub request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("GitHub %s %s returned %d: %s", method, path, response.StatusCode, strings.TrimSpace(string(message)))
	}
	if output == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode GitHub response: %w", err)
	}
	return nil
}

func splitRepository(repository string) (string, string, error) {
	parts := strings.Split(repository, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", fmt.Errorf("repository must be owner/name")
	}
	return parts[0], parts[1], nil
}

func validGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}
