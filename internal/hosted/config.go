package hosted

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/wolfiesch/cihash/internal/githubapp"
)

type Config struct {
	Listen               string         `json:"listen"`
	WebhookPath          string         `json:"webhookPath"`
	Repository           string         `json:"repository"`
	PolicyFile           string         `json:"policyFile"`
	ReceiptPublicKeyFile string         `json:"receiptPublicKeyFile"`
	ReceiptStore         string         `json:"receiptStore"`
	StateDirectory       string         `json:"stateDirectory"`
	Mode                 githubapp.Mode `json:"mode"`
	FallbackWorkflow     string         `json:"fallbackWorkflow,omitempty"`
	GitHubAPIBaseURL     string         `json:"githubApiBaseUrl,omitempty"`
	DetailsURL           string         `json:"detailsUrl,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read hosted config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var configured Config
	if err := decoder.Decode(&configured); err != nil {
		return Config{}, fmt.Errorf("decode hosted config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Config{}, fmt.Errorf("decode hosted config: trailing data")
	}
	configured.applyDefaults()
	configured.resolvePaths(filepath.Dir(path))
	if err := configured.Validate(); err != nil {
		return Config{}, err
	}
	return configured, nil
}

func (configured *Config) applyDefaults() {
	if configured.Listen == "" {
		configured.Listen = "127.0.0.1:8080"
	}
	if configured.WebhookPath == "" {
		configured.WebhookPath = "/webhooks/github"
	}
	if configured.GitHubAPIBaseURL == "" {
		configured.GitHubAPIBaseURL = "https://api.github.com"
	}
	if configured.Mode == "" {
		configured.Mode = githubapp.ShadowMode
	}
}

func (configured *Config) resolvePaths(base string) {
	configured.PolicyFile = resolvePath(base, configured.PolicyFile)
	configured.ReceiptPublicKeyFile = resolvePath(base, configured.ReceiptPublicKeyFile)
	configured.ReceiptStore = resolvePath(base, configured.ReceiptStore)
	configured.StateDirectory = resolvePath(base, configured.StateDirectory)
}

func (configured Config) Validate() error {
	parts := strings.Split(configured.Repository, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("hosted repository must be owner/name")
	}
	if configured.WebhookPath == "" || configured.WebhookPath[0] != '/' {
		return fmt.Errorf("webhookPath must start with /")
	}
	if configured.PolicyFile == "" || configured.ReceiptPublicKeyFile == "" || configured.ReceiptStore == "" || configured.StateDirectory == "" {
		return fmt.Errorf("policyFile, receiptPublicKeyFile, receiptStore, and stateDirectory are required")
	}
	if configured.Mode != githubapp.ShadowMode && configured.Mode != githubapp.EnforceMode {
		return fmt.Errorf("hosted mode must be shadow or enforce")
	}
	if configured.Mode == githubapp.EnforceMode {
		if configured.FallbackWorkflow == "" {
			return fmt.Errorf("fallbackWorkflow is required in enforce mode")
		}
		if filepath.Base(configured.FallbackWorkflow) != configured.FallbackWorkflow {
			return fmt.Errorf("fallbackWorkflow must be a workflow file name or numeric ID")
		}
	}
	return nil
}

func resolvePath(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Clean(filepath.Join(base, path))
}
