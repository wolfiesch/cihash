package producer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/rungrant"
)

const maxResponseBody = 1 << 20

type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
}

type receiptSubmission struct {
	Envelope attestation.Envelope `json:"envelope"`
	Log      []byte               `json:"log"`
}

func New(rawBaseURL string, token []byte, httpClient *http.Client) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimRight(rawBaseURL, "/"))
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("producer server URL is invalid")
	}
	if baseURL.Scheme != "https" && !(baseURL.Scheme == "http" && (baseURL.Hostname() == "127.0.0.1" || baseURL.Hostname() == "localhost" || baseURL.Hostname() == "::1")) {
		return nil, fmt.Errorf("producer server URL must use HTTPS")
	}
	trimmedToken := strings.TrimSpace(string(token))
	if len(trimmedToken) < 32 || strings.ContainsAny(trimmedToken, " \t\r\n") {
		return nil, fmt.Errorf("producer token must contain at least 32 non-whitespace bytes")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{baseURL: baseURL, token: trimmedToken, httpClient: httpClient}, nil
}

func (client *Client) Issue(ctx context.Context, installationID, pullRequestNumber int64) (rungrant.Grant, error) {
	if installationID <= 0 || pullRequestNumber <= 0 {
		return rungrant.Grant{}, fmt.Errorf("installation and pull request identities are required")
	}
	var grant rungrant.Grant
	if err := client.post(ctx, "/api/v1/runs", map[string]int64{
		"installationId":    installationID,
		"pullRequestNumber": pullRequestNumber,
	}, http.StatusCreated, &grant); err != nil {
		return rungrant.Grant{}, err
	}
	if err := grant.Validate(); err != nil {
		return rungrant.Grant{}, fmt.Errorf("server returned an invalid run grant: %w", err)
	}
	return grant, nil
}

func (client *Client) Submit(ctx context.Context, runID string, envelope attestation.Envelope, log []byte) (string, error) {
	if runID == "" {
		return "", fmt.Errorf("run ID is required")
	}
	var result struct {
		ReceiptDigest string `json:"receiptDigest"`
	}
	if err := client.post(ctx, "/api/v1/runs/"+url.PathEscape(runID)+"/receipt", receiptSubmission{Envelope: envelope, Log: log}, http.StatusCreated, &result); err != nil {
		return "", err
	}
	if err := attestation.ValidateDigest(result.ReceiptDigest); err != nil {
		return "", fmt.Errorf("server returned an invalid receipt digest: %w", err)
	}
	return result.ReceiptDigest, nil
}

func (client *Client) post(ctx context.Context, path string, requestBody any, expectedStatus int, responseBody any) error {
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("encode producer request: %w", err)
	}
	endpoint := *client.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("create producer request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send producer request: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if err != nil {
		return fmt.Errorf("read producer response: %w", err)
	}
	if len(body) > maxResponseBody {
		return fmt.Errorf("producer response exceeds limit")
	}
	if response.StatusCode != expectedStatus && !(expectedStatus == http.StatusCreated && response.StatusCode == http.StatusOK) {
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = http.StatusText(response.StatusCode)
		}
		return fmt.Errorf("producer server returned %d: %s", response.StatusCode, message)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(responseBody); err != nil {
		return fmt.Errorf("decode producer response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("decode producer response: trailing data")
	}
	return nil
}
