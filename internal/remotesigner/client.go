package remotesigner

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

func New(rawBaseURL string, token []byte, httpClient *http.Client) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimRight(rawBaseURL, "/"))
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("signer URL is invalid")
	}
	if baseURL.Scheme != "https" && !(baseURL.Scheme == "http" && (baseURL.Hostname() == "127.0.0.1" || baseURL.Hostname() == "localhost" || baseURL.Hostname() == "::1")) {
		return nil, fmt.Errorf("signer URL must use HTTPS")
	}
	trimmedToken := strings.TrimSpace(string(token))
	if len(trimmedToken) < 32 || strings.ContainsAny(trimmedToken, " \t\r\n") {
		return nil, fmt.Errorf("signer token must contain at least 32 non-whitespace bytes")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{baseURL: baseURL, token: trimmedToken, httpClient: httpClient}, nil
}

func (client *Client) Sign(ctx context.Context, grant rungrant.Grant, result attestation.TestResult) (attestation.Envelope, error) {
	encoded, err := json.Marshal(SignRequest{Grant: grant, Result: result})
	if err != nil {
		return attestation.Envelope{}, fmt.Errorf("encode signer request: %w", err)
	}
	endpoint := *client.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + SignPath
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(encoded))
	if err != nil {
		return attestation.Envelope{}, fmt.Errorf("create signer request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return attestation.Envelope{}, fmt.Errorf("send signer request: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if err != nil {
		return attestation.Envelope{}, fmt.Errorf("read signer response: %w", err)
	}
	if len(body) > maxResponseBody {
		return attestation.Envelope{}, fmt.Errorf("signer response exceeds limit")
	}
	if response.StatusCode != http.StatusCreated {
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = http.StatusText(response.StatusCode)
		}
		return attestation.Envelope{}, fmt.Errorf("signer returned %d: %s", response.StatusCode, message)
	}
	var resultEnvelope SignResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&resultEnvelope); err != nil {
		return attestation.Envelope{}, fmt.Errorf("decode signer response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return attestation.Envelope{}, fmt.Errorf("decode signer response: trailing data")
	}
	if len(resultEnvelope.Envelope.Signatures) != 1 {
		return attestation.Envelope{}, fmt.Errorf("signer returned an invalid envelope")
	}
	return resultEnvelope.Envelope, nil
}
