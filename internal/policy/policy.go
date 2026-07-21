package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const Version = "0.1"

type Policy struct {
	Version        string   `json:"version"`
	Repository     string   `json:"repository"`
	Profile        string   `json:"profile"`
	Command        []string `json:"command"`
	Environment    string   `json:"environment"`
	MaxAgeSeconds  int64    `json:"maxAgeSeconds"`
	TimeoutSeconds int64    `json:"timeoutSeconds"`
}

func Load(path string) (Policy, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, nil, fmt.Errorf("read policy: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var configured Policy
	if err := decoder.Decode(&configured); err != nil {
		return Policy{}, nil, fmt.Errorf("decode policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Policy{}, nil, fmt.Errorf("decode policy: trailing data")
	}
	if err := configured.Validate(); err != nil {
		return Policy{}, nil, err
	}
	canonical, err := configured.CanonicalJSON()
	if err != nil {
		return Policy{}, nil, err
	}
	return configured, canonical, nil
}

func (p Policy) Validate() error {
	if p.Version != Version {
		return fmt.Errorf("unsupported policy version %q", p.Version)
	}
	if strings.TrimSpace(p.Repository) == "" {
		return fmt.Errorf("policy repository is required")
	}
	if strings.TrimSpace(p.Profile) == "" {
		return fmt.Errorf("policy profile is required")
	}
	if len(p.Command) == 0 || strings.TrimSpace(p.Command[0]) == "" {
		return fmt.Errorf("policy command is required")
	}
	for _, argument := range p.Command {
		if strings.ContainsRune(argument, '\x00') {
			return fmt.Errorf("policy command contains a null byte")
		}
	}
	if strings.TrimSpace(p.Environment) == "" {
		return fmt.Errorf("policy environment is required")
	}
	if p.MaxAgeSeconds < 1 || p.MaxAgeSeconds > 24*60*60 {
		return fmt.Errorf("policy maxAgeSeconds must be between 1 and 86400")
	}
	if p.TimeoutSeconds < 1 || p.TimeoutSeconds > 2*60*60 {
		return fmt.Errorf("policy timeoutSeconds must be between 1 and 7200")
	}
	return nil
}

func (p Policy) CanonicalJSON() ([]byte, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical policy: %w", err)
	}
	return data, nil
}

func (p Policy) Digest() (string, error) {
	data, err := p.CanonicalJSON()
	if err != nil {
		return "", err
	}
	return digest(data), nil
}

func (p Policy) WorkflowDigest() (string, error) {
	workflow := struct {
		Version string   `json:"version"`
		Profile string   `json:"profile"`
		Command []string `json:"command"`
	}{Version: p.Version, Profile: p.Profile, Command: p.Command}
	data, err := json.Marshal(workflow)
	if err != nil {
		return "", fmt.Errorf("marshal workflow identity: %w", err)
	}
	return digest(data), nil
}

func (p Policy) EnvironmentDigest() string {
	return digest([]byte(p.Environment))
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
