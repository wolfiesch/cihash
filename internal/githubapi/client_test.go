package githubapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wolfiesch/cihash/internal/githubapp"
)

func TestInstallationTokenUsesValidAppJWTAndRepositoryScope(t *testing.T) {
	privateKey := generateRSAKey(t)
	fixedNow := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/app/installations/42/access_tokens" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		jwt := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
		claims := verifyJWT(t, jwt, &privateKey.PublicKey)
		if claims.Issuer != "client-id" || claims.IssuedAt != fixedNow.Add(-time.Minute).Unix() || claims.ExpiresAt != fixedNow.Add(9*time.Minute).Unix() {
			t.Fatalf("claims = %+v", claims)
		}
		var body struct {
			Repositories []string          `json:"repositories"`
			Permissions  map[string]string `json:"permissions"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Repositories) != 1 || body.Repositories[0] != "project" {
			t.Fatalf("repositories = %v", body.Repositories)
		}
		if body.Permissions != nil {
			t.Fatalf("permissions = %v, want installation defaults", body.Permissions)
		}
		response.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(response, `{"token":"installation-token"}`)
	}))
	defer server.Close()
	client, err := New(server.URL, "client-id", privateKey, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return fixedNow }
	token, err := client.InstallationToken(context.Background(), 42, "owner/project")
	if err != nil {
		t.Fatal(err)
	}
	if token != "installation-token" {
		t.Fatalf("token = %q", token)
	}
}

func TestCheckAndWorkflowRequestsUseInstallationToken(t *testing.T) {
	privateKey := generateRSAKey(t)
	var createSeen, updateSeen, dispatchSeen, pullSeen, mergeCommitSeen, jobSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer installation-token" {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/project/pulls/7":
			if version := request.Header.Get("X-GitHub-Api-Version"); version != pullRequestMergeAPIVersion {
				t.Fatalf("pull request API version = %q", version)
			}
			pullSeen = true
			response.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(response, `{"state":"open","head":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","repo":{"full_name":"owner/project"}},"base":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","ref":"main"},"merge_commit_sha":"cccccccccccccccccccccccccccccccccccccccc"}`)
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/project/git/commits/cccccccccccccccccccccccccccccccccccccccc":
			if version := request.Header.Get("X-GitHub-Api-Version"); version != apiVersion {
				t.Fatalf("merge commit API version = %q", version)
			}
			mergeCommitSeen = true
			response.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(response, `{"tree":{"sha":"dddddddddddddddddddddddddddddddddddddddd"},"parents":[{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`)
		case request.Method == http.MethodPost && request.URL.Path == "/repos/owner/project/check-runs":
			createSeen = true
			response.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(response, `{"id":71}`)
		case request.Method == http.MethodPatch && request.URL.Path == "/repos/owner/project/check-runs/71":
			updateSeen = true
			response.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(response, `{}`)
		case request.Method == http.MethodPost && request.URL.Path == "/repos/owner/project/actions/workflows/fallback.yml/dispatches":
			dispatchSeen = true
			var dispatch WorkflowDispatch
			if err := json.NewDecoder(request.Body).Decode(&dispatch); err != nil {
				t.Fatal(err)
			}
			if dispatch.Ref != "main" || dispatch.Inputs["cihash_head_sha"] != strings.Repeat("a", 40) {
				t.Fatalf("dispatch = %+v", dispatch)
			}
			response.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(response, `{"workflow_run_id":99}`)
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/project/actions/runs/99/attempts/1/jobs":
			jobSeen = true
			if request.URL.RawQuery != "per_page=100" {
				t.Fatalf("workflow jobs query = %q", request.URL.RawQuery)
			}
			response.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(response, `{"jobs":[{"id":101,"run_attempt":1,"name":"tooling","status":"completed","conclusion":"success","started_at":"2026-07-20T12:00:00Z","completed_at":"2026-07-20T12:01:00Z"}]}`)
		default:
			http.Error(response, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "client-id", privateKey, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	pullRequest, err := client.GetPullRequest(context.Background(), "installation-token", "owner/project", 7)
	if err != nil {
		t.Fatal(err)
	}
	if pullRequest.HeadSHA != strings.Repeat("a", 40) || pullRequest.BaseSHA != strings.Repeat("b", 40) ||
		pullRequest.HeadRepository != "owner/project" || pullRequest.BaseRef != "main" ||
		pullRequest.TreeSHA != strings.Repeat("d", 40) {
		t.Fatalf("GetPullRequest = %+v", pullRequest)
	}
	checkID, err := client.CreateCheckRun(context.Background(), "installation-token", "owner/project", githubapp.CheckRunRequest{
		Name:    githubapp.CheckName,
		HeadSHA: strings.Repeat("a", 40),
		Status:  "queued",
		Output:  githubapp.CheckRunOutput{Title: "queued", Summary: "queued"},
	})
	if err != nil || checkID != 71 {
		t.Fatalf("CreateCheckRun = %d, %v", checkID, err)
	}
	if err := client.UpdateCheckRun(context.Background(), "installation-token", "owner/project", checkID, CheckRunUpdate{
		Status:     "completed",
		Conclusion: "success",
		Output:     githubapp.CheckRunOutput{Title: "passed", Summary: "passed"},
	}); err != nil {
		t.Fatal(err)
	}
	runID, err := client.DispatchWorkflow(context.Background(), "installation-token", "owner/project", "fallback.yml", WorkflowDispatch{
		Ref: "main",
		Inputs: map[string]string{
			"cihash_head_sha": strings.Repeat("a", 40),
		},
	})
	if err != nil || runID != 99 {
		t.Fatalf("DispatchWorkflow = %d, %v", runID, err)
	}
	job, err := client.GetWorkflowJob(context.Background(), "installation-token", "owner/project", runID, 1, "tooling")
	if err != nil || job.ID != 101 || job.Conclusion != "success" || job.CompletedAt.Sub(job.StartedAt) != time.Minute {
		t.Fatalf("GetWorkflowJob = %+v, %v", job, err)
	}
	if !pullSeen || !mergeCommitSeen || !createSeen || !updateSeen || !dispatchSeen || !jobSeen {
		t.Fatalf("requests seen: pull=%v mergeCommit=%v create=%v update=%v dispatch=%v job=%v", pullSeen, mergeCommitSeen, createSeen, updateSeen, dispatchSeen, jobSeen)
	}
}

func TestGetWorkflowJobRejectsDifferentAttempt(t *testing.T) {
	privateKey := generateRSAKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet ||
			request.URL.RequestURI() != "/repos/owner/project/actions/runs/99/attempts/1/jobs?per_page=100" {
			http.Error(response, "unexpected request", http.StatusNotFound)
			return
		}
		response.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(response, `{"jobs":[{"id":101,"run_attempt":2,"name":"tooling","status":"completed","conclusion":"success","started_at":"2026-07-20T12:00:00Z","completed_at":"2026-07-20T12:01:00Z"}]}`)
	}))
	defer server.Close()
	client, err := New(server.URL, "client-id", privateKey, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	job, err := client.GetWorkflowJob(context.Background(), "installation-token", "owner/project", 99, 1, "tooling")
	if err == nil || !strings.Contains(err.Error(), "does not belong to requested attempt 1") || job.ID != 0 {
		t.Fatalf("GetWorkflowJob = %+v, %v; want attempt mismatch", job, err)
	}
}

func TestGetPullRequestFailsClosedWithoutAuthoritativeMergeTree(t *testing.T) {
	const (
		headSHA        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		baseSHA        = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		mergeCommitSHA = "cccccccccccccccccccccccccccccccccccccccc"
	)
	validPull := `{"state":"open","head":{"sha":"` + headSHA + `","repo":{"full_name":"owner/project"}},"base":{"sha":"` + baseSHA + `","ref":"main"},"merge_commit_sha":"` + mergeCommitSHA + `"}`
	validParents := `"parents":[{"sha":"` + baseSHA + `"},{"sha":"` + headSHA + `"}]`
	tests := []struct {
		name       string
		pullBody   string
		commitBody string
		commitCode int
		wantCommit bool
		wantError  string
	}{
		{
			name:      "malformed pull request identity",
			pullBody:  `{"state":"open","head":{"sha":"not-a-git-object","repo":{"full_name":"owner/project"}},"base":{"sha":"` + baseSHA + `","ref":"main"},"merge_commit_sha":"` + mergeCommitSHA + `"}`,
			wantError: "GitHub returned malformed pull request identity",
		},
		{
			name:      "closed pull request",
			pullBody:  `{"state":"closed","head":{"sha":"` + headSHA + `","repo":{"full_name":"owner/project"}},"base":{"sha":"` + baseSHA + `","ref":"main"},"merge_commit_sha":"` + mergeCommitSHA + `"}`,
			wantError: "GitHub pull request is not open",
		},
		{
			name:      "missing test merge commit",
			pullBody:  `{"state":"open","head":{"sha":"` + headSHA + `","repo":{"full_name":"owner/project"}},"base":{"sha":"` + baseSHA + `","ref":"main"}}`,
			wantError: "GitHub returned no test merge commit SHA",
		},
		{
			name:      "malformed test merge commit",
			pullBody:  `{"state":"open","head":{"sha":"` + headSHA + `","repo":{"full_name":"owner/project"}},"base":{"sha":"` + baseSHA + `","ref":"main"},"merge_commit_sha":"not-a-git-object"}`,
			wantError: "GitHub returned malformed test merge commit SHA",
		},
		{
			name:       "merge commit unavailable",
			pullBody:   validPull,
			commitCode: http.StatusServiceUnavailable,
			wantCommit: true,
			wantError:  "fetch GitHub pull request merge commit",
		},
		{
			name:       "merge commit parents do not match pull request",
			pullBody:   validPull,
			commitBody: `{"tree":{"sha":"dddddddddddddddddddddddddddddddddddddddd"},"parents":[{"sha":"` + headSHA + `"},{"sha":"` + baseSHA + `"}]}`,
			wantCommit: true,
			wantError:  "test merge commit does not match current base and head",
		},
		{
			name:       "missing merge tree",
			pullBody:   validPull,
			commitBody: `{"tree":{},` + validParents + `}`,
			wantCommit: true,
			wantError:  "GitHub returned no tree SHA",
		},
		{
			name:       "malformed merge tree",
			pullBody:   validPull,
			commitBody: `{"tree":{"sha":"not-a-git-object"},` + validParents + `}`,
			wantCommit: true,
			wantError:  "GitHub returned malformed pull request merge tree SHA",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var commitRequested bool
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/repos/owner/project/pulls/7":
					response.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(response, test.pullBody)
				case "/repos/owner/project/git/commits/" + mergeCommitSHA:
					commitRequested = true
					if test.commitCode != 0 {
						http.Error(response, "unavailable", test.commitCode)
						return
					}
					response.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(response, test.commitBody)
				default:
					http.Error(response, "unexpected request", http.StatusNotFound)
				}
			}))
			defer server.Close()
			client, err := New(server.URL, "client-id", generateRSAKey(t), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.GetPullRequest(context.Background(), "installation-token", "owner/project", 7); err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("GetPullRequest error = %v, want %q", err, test.wantError)
			}
			if commitRequested != test.wantCommit {
				t.Fatalf("commit requested = %v, want %v", commitRequested, test.wantCommit)
			}
		})
	}
}

type jwtClaims struct {
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Issuer    string `json:"iss"`
}

func verifyJWT(t *testing.T, token string, publicKey *rsa.PublicKey) jwtClaims {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var decodedHeader map[string]string
	if err := json.Unmarshal(header, &decodedHeader); err != nil {
		t.Fatal(err)
	}
	if decodedHeader["alg"] != "RS256" {
		t.Fatalf("JWT algorithm = %q", decodedHeader["alg"])
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("verify JWT: %v", err)
	}
	claimsData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsData, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
