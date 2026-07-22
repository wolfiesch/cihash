// Package remotesigner signs validated CIHash results outside the workload host.
package remotesigner

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/rungrant"
	"github.com/wolfiesch/cihash/internal/verifier"
)

const (
	SignPath       = "/api/v1/sign"
	maxRequestBody = 1 << 20
)

type SignRequest struct {
	Grant  rungrant.Grant         `json:"grant"`
	Result attestation.TestResult `json:"result"`
}

type SignResponse struct {
	Envelope attestation.Envelope `json:"envelope"`
}

type Server struct {
	privateKey ed25519.PrivateKey
	token      []byte
	now        func() time.Time
}

func NewServer(token []byte, privateKey ed25519.PrivateKey) (*Server, error) {
	trimmedToken := strings.TrimSpace(string(token))
	if len(trimmedToken) < 32 || strings.ContainsAny(trimmedToken, " \t\r\n") {
		return nil, fmt.Errorf("signer token must contain at least 32 non-whitespace bytes")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signer private key is invalid")
	}
	return &Server{privateKey: privateKey, token: []byte(trimmedToken), now: time.Now}, nil
}

func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(SignPath, server.handleSign)
	mux.HandleFunc("/health", func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			response.Header().Set("Allow", http.MethodGet)
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"status":"ok"}`+"\n")
	})
	return mux
}

func (server *Server) handleSign(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !server.authorized(request) {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	if request.Header.Get("Content-Type") != "application/json" {
		http.Error(response, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	var signRequest SignRequest
	if err := decodeRequest(response, request, &signRequest); err != nil {
		http.Error(response, "invalid sign request", statusForDecodeError(err))
		return
	}
	if err := signRequest.Grant.Validate(); err != nil {
		http.Error(response, "invalid run grant", http.StatusUnprocessableEntity)
		return
	}
	now := server.now().UTC()
	if !now.Before(signRequest.Grant.ExpiresAt) {
		http.Error(response, "run grant expired", http.StatusGone)
		return
	}
	envelope, err := attestation.Sign(attestation.NewStatement(signRequest.Result), server.privateKey)
	if err != nil {
		http.Error(response, "signing failed", http.StatusInternalServerError)
		return
	}
	decision := verifier.Verify(envelope, server.privateKey.Public().(ed25519.PublicKey), expected(signRequest.Grant, now))
	if !decision.Accepted && decision.Code != "job_failed" && decision.Code != "proof_failed" {
		http.Error(response, "result does not match run grant", http.StatusUnprocessableEntity)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(response).Encode(SignResponse{Envelope: envelope})
}

func (server *Server) authorized(request *http.Request) bool {
	const prefix = "Bearer "
	value := request.Header.Get("Authorization")
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	candidate := sha256.Sum256([]byte(value[len(prefix):]))
	expected := sha256.Sum256(server.token)
	return hmac.Equal(candidate[:], expected[:])
}

func expected(grant rungrant.Grant, now time.Time) verifier.Expected {
	return verifier.Expected{
		Repository:        grant.Policy.Repository,
		HeadSHA:           grant.HeadSHA,
		BaseSHA:           grant.BaseSHA,
		TreeSHA:           grant.TreeSHA,
		Profile:           grant.Policy.Profile,
		PolicyDigest:      grant.PolicyDigest,
		WorkflowDigest:    grant.WorkflowDigest,
		EnvironmentDigest: grant.EnvironmentDigest,
		Architecture:      grant.Architecture,
		Jobs: []verifier.ExpectedJob{{
			Name:    grant.Policy.Profile,
			Command: append([]string(nil), grant.Policy.Command...),
		}},
		Nonce:     grant.Nonce,
		MaxAge:    grant.ExpiresAt.Sub(grant.IssuedAt),
		NotBefore: grant.IssuedAt,
		ExpiresAt: grant.ExpiresAt,
		Now:       now,
	}
}

func decodeRequest(response http.ResponseWriter, request *http.Request, destination any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, maxRequestBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON data")
		}
		return err
	}
	return nil
}

func statusForDecodeError(err error) int {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}
