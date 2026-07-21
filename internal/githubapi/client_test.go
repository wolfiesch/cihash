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
	var createSeen, updateSeen, dispatchSeen, pullSeen, mergeRefSeen, mergeCommitSeen, jobSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer installation-token" {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/project/pulls/7":
			pullSeen = true
			response.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(response, `{"head":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","repo":{"full_name":"owner/project"}},"base":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","ref":"main"}}`)
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/project/git/ref/pull/7/merge":
			mergeRefSeen = true
			response.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(response, `{"object":{"type":"commit","sha":"cccccccccccccccccccccccccccccccccccccccc"}}`)
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/project/git/commits/cccccccccccccccccccccccccccccccccccccccc":
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
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/project/actions/runs/99/jobs":
			jobSeen = true
			if request.URL.Query().Get("filter") != "latest" || request.URL.Query().Get("per_page") != "100" {
				t.Fatalf("workflow jobs query = %q", request.URL.RawQuery)
			}
			response.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(response, `{"jobs":[{"id":101,"name":"tooling","status":"completed","conclusion":"success","started_at":"2026-07-20T12:00:00Z","completed_at":"2026-07-20T12:01:00Z"}]}`)
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
	job, err := client.GetWorkflowJob(context.Background(), "installation-token", "owner/project", runID, "tooling")
	if err != nil || job.ID != 101 || job.Conclusion != "success" || job.CompletedAt.Sub(job.StartedAt) != time.Minute {
		t.Fatalf("GetWorkflowJob = %+v, %v", job, err)
	}
	if !pullSeen || !mergeRefSeen || !mergeCommitSeen || !createSeen || !updateSeen || !dispatchSeen || !jobSeen {
		t.Fatalf("requests seen: pull=%v mergeRef=%v mergeCommit=%v create=%v update=%v dispatch=%v job=%v", pullSeen, mergeRefSeen, mergeCommitSeen, createSeen, updateSeen, dispatchSeen, jobSeen)
	}
}

func TestGetPullRequestFailsClosedWithoutAuthoritativeMergeTree(t *testing.T) {
	const (
		headSHA        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		baseSHA        = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		mergeCommitSHA = "cccccccccccccccccccccccccccccccccccccccc"
	)
	validPull := `{"head":{"sha":"` + headSHA + `","repo":{"full_name":"owner/project"}},"base":{"sha":"` + baseSHA + `","ref":"main"}}`
	validRef := `{"object":{"type":"commit","sha":"` + mergeCommitSHA + `"}}`
	validParents := `"parents":[{"sha":"` + baseSHA + `"},{"sha":"` + headSHA + `"}]`
	tests := []struct {
		name       string
		pullBody   string
		refBody    string
		refCode    int
		commitBody string
		commitCode int
		wantRef    bool
		wantCommit bool
		wantError  string
	}{
		{
			name:      "malformed pull request identity",
			pullBody:  `{"head":{"sha":"not-a-git-object","repo":{"full_name":"owner/project"}},"base":{"sha":"` + baseSHA + `","ref":"main"}}`,
			wantError: "GitHub returned malformed pull request identity",
		},
		{
			name:      "merge ref unavailable",
			pullBody:  validPull,
			refCode:   http.StatusServiceUnavailable,
			wantRef:   true,
			wantError: "fetch GitHub pull request merge ref",
		},
		{
			name:      "malformed merge ref",
			pullBody:  validPull,
			refBody:   `{"object":{"type":"commit","sha":"not-a-git-object"}}`,
			wantRef:   true,
			wantError: "GitHub returned malformed pull request merge ref",
		},
		{
			name:       "merge commit unavailable",
			pullBody:   validPull,
			refBody:    validRef,
			commitCode: http.StatusServiceUnavailable,
			wantRef:    true,
			wantCommit: true,
			wantError:  "fetch GitHub pull request merge commit",
		},
		{
			name:       "merge commit parents do not match pull request",
			pullBody:   validPull,
			refBody:    validRef,
			commitBody: `{"tree":{"sha":"dddddddddddddddddddddddddddddddddddddddd"},"parents":[{"sha":"` + headSHA + `"},{"sha":"` + baseSHA + `"}]}`,
			wantRef:    true,
			wantCommit: true,
			wantError:  "merge ref does not match current base and head",
		},
		{
			name:       "missing merge tree",
			pullBody:   validPull,
			refBody:    validRef,
			commitBody: `{"tree":{},` + validParents + `}`,
			wantRef:    true,
			wantCommit: true,
			wantError:  "GitHub returned no tree SHA",
		},
		{
			name:       "malformed merge tree",
			pullBody:   validPull,
			refBody:    validRef,
			commitBody: `{"tree":{"sha":"not-a-git-object"},` + validParents + `}`,
			wantRef:    true,
			wantCommit: true,
			wantError:  "GitHub returned malformed pull request merge tree SHA",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var refRequested, commitRequested bool
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/repos/owner/project/pulls/7":
					response.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(response, test.pullBody)
				case "/repos/owner/project/git/ref/pull/7/merge":
					refRequested = true
					if test.refCode != 0 {
						http.Error(response, "unavailable", test.refCode)
						return
					}
					response.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(response, test.refBody)
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
			if refRequested != test.wantRef || commitRequested != test.wantCommit {
				t.Fatalf("requests: ref=%v commit=%v, want ref=%v commit=%v", refRequested, commitRequested, test.wantRef, test.wantCommit)
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
