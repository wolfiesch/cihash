package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/githubapp"
	"github.com/wolfiesch/cihash/internal/policy"
	"github.com/wolfiesch/cihash/internal/runner"
	"github.com/wolfiesch/cihash/internal/store"
	"github.com/wolfiesch/cihash/internal/verifier"
)

const version = "0.1.0-dev"

type commandError struct {
	code int
	err  error
}

func main() {
	if err := execute(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "cihash:", err.err)
		os.Exit(err.code)
	}
}

func execute(arguments []string, output io.Writer) *commandError {
	if len(arguments) == 0 {
		printUsage(output)
		return &commandError{code: 2, err: errors.New("a command is required")}
	}
	switch arguments[0] {
	case "keygen":
		return keygenCommand(arguments[1:], output)
	case "policy":
		return policyCommand(arguments[1:], output)
	case "run":
		return runCommand(arguments[1:], output)
	case "verify":
		return verifyCommand(arguments[1:], output)
	case "check":
		return checkCommand(arguments[1:], output)
	case "version":
		fmt.Fprintln(output, version)
		return nil
	case "help", "-h", "--help":
		printUsage(output)
		return nil
	default:
		printUsage(output)
		return &commandError{code: 2, err: fmt.Errorf("unknown command %q", arguments[0])}
	}
}

func keygenCommand(arguments []string, output io.Writer) *commandError {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	privatePath := flags.String("private", "", "private key output path")
	publicPath := flags.String("public", "", "public key output path")
	if err := flags.Parse(arguments); err != nil {
		return usageError(err)
	}
	if *privatePath == "" || *publicPath == "" {
		return usageError(errors.New("--private and --public are required"))
	}
	keyID, err := attestation.GenerateKeyPair(*privatePath, *publicPath)
	if err != nil {
		return operationalError(err)
	}
	return writeJSON(output, map[string]string{
		"keyId":      keyID,
		"privateKey": *privatePath,
		"publicKey":  *publicPath,
	})
}

func policyCommand(arguments []string, output io.Writer) *commandError {
	flags := flag.NewFlagSet("policy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("file", "", "approved policy file")
	if err := flags.Parse(arguments); err != nil {
		return usageError(err)
	}
	if *path == "" {
		return usageError(errors.New("--file is required"))
	}
	configured, _, err := policy.Load(*path)
	if err != nil {
		return operationalError(err)
	}
	policyDigest, err := configured.Digest()
	if err != nil {
		return operationalError(err)
	}
	workflowDigest, err := configured.WorkflowDigest()
	if err != nil {
		return operationalError(err)
	}
	return writeJSON(output, map[string]string{
		"repository":        configured.Repository,
		"profile":           configured.Profile,
		"policyDigest":      policyDigest,
		"workflowDigest":    workflowDigest,
		"environmentDigest": configured.EnvironmentDigest(),
	})
}

func runCommand(arguments []string, output io.Writer) *commandError {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	repositoryPath := flags.String("repo", ".", "path to the clean Git repository")
	head := flags.String("head", "HEAD", "head revision to verify")
	base := flags.String("base", "", "base revision to merge into the head")
	policyPath := flags.String("policy", "", "approved policy file")
	privateKeyPath := flags.String("private-key", "", "Ed25519 private key")
	storePath := flags.String("store", defaultStorePath(), "receipt store path")
	if err := flags.Parse(arguments); err != nil {
		return usageError(err)
	}
	if *base == "" || *policyPath == "" || *privateKeyPath == "" {
		return usageError(errors.New("--base, --policy, and --private-key are required"))
	}
	configured, _, err := policy.Load(*policyPath)
	if err != nil {
		return operationalError(err)
	}
	privateKey, err := attestation.LoadPrivateKey(*privateKeyPath)
	if err != nil {
		return operationalError(err)
	}
	nonce, err := newNonce()
	if err != nil {
		return operationalError(err)
	}
	outcome, err := runner.Run(context.Background(), runner.Request{
		RepositoryPath: *repositoryPath,
		HeadRevision:   *head,
		BaseRevision:   *base,
		Policy:         configured,
		Nonce:          nonce,
	})
	if err != nil {
		return operationalError(err)
	}
	envelope, err := attestation.Sign(attestation.NewStatement(outcome.Result), privateKey)
	if err != nil {
		return operationalError(err)
	}
	receiptStore := store.New(*storePath)
	receiptPath, logPath, err := receiptStore.Save(store.IdentityFromResult(outcome.Result), envelope, outcome.Log)
	if err != nil {
		return operationalError(err)
	}
	summary := map[string]any{
		"conclusion":  outcome.Result.Conclusion,
		"headSha":     outcome.Result.HeadSHA,
		"baseSha":     outcome.Result.BaseSHA,
		"treeSha":     outcome.Result.TreeSHA,
		"nonce":       outcome.Result.Nonce,
		"receiptPath": receiptPath,
		"logPath":     logPath,
	}
	if writeErr := writeJSON(output, summary); writeErr != nil {
		return writeErr
	}
	if outcome.Result.Conclusion != "success" {
		return &commandError{code: 1, err: errors.New("verification command failed; signed failure receipt stored")}
	}
	return nil
}

func verifyCommand(arguments []string, output io.Writer) *commandError {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	receiptPath := flags.String("receipt", "", "receipt envelope file")
	policyPath := flags.String("policy", "", "approved policy file")
	publicKeyPath := flags.String("public-key", "", "trusted Ed25519 public key")
	head := flags.String("head", "", "expected head commit SHA")
	base := flags.String("base", "", "expected base commit SHA")
	nonce := flags.String("nonce", "", "expected job nonce")
	if err := flags.Parse(arguments); err != nil {
		return usageError(err)
	}
	if *receiptPath == "" || *policyPath == "" || *publicKeyPath == "" || *head == "" || *base == "" {
		return usageError(errors.New("--receipt, --policy, --public-key, --head, and --base are required"))
	}
	configured, _, err := policy.Load(*policyPath)
	if err != nil {
		return operationalError(err)
	}
	publicKey, err := attestation.LoadPublicKey(*publicKeyPath)
	if err != nil {
		return operationalError(err)
	}
	data, err := os.ReadFile(*receiptPath)
	if err != nil {
		return operationalError(fmt.Errorf("read receipt: %w", err))
	}
	envelope, err := attestation.UnmarshalEnvelope(data)
	if err != nil {
		return operationalError(err)
	}
	expected, err := expectedFromPolicy(configured, *head, *base, *nonce)
	if err != nil {
		return operationalError(err)
	}
	decision := verifier.Verify(envelope, publicKey, expected)
	if err := writeJSON(output, decision); err != nil {
		return err
	}
	if !decision.Accepted {
		return &commandError{code: 1, err: fmt.Errorf("%s: %s", decision.Code, decision.Message)}
	}
	return nil
}

func checkCommand(arguments []string, output io.Writer) *commandError {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policyPath := flags.String("policy", "", "approved policy file")
	publicKeyPath := flags.String("public-key", "", "trusted Ed25519 public key")
	storePath := flags.String("store", defaultStorePath(), "receipt store path")
	head := flags.String("head", "", "expected head commit SHA")
	base := flags.String("base", "", "expected base commit SHA")
	nonce := flags.String("nonce", "", "expected job nonce")
	modeValue := flags.String("mode", string(githubapp.ShadowMode), "shadow or enforce")
	if err := flags.Parse(arguments); err != nil {
		return usageError(err)
	}
	if *policyPath == "" || *publicKeyPath == "" || *head == "" || *base == "" {
		return usageError(errors.New("--policy, --public-key, --head, and --base are required"))
	}
	mode := githubapp.Mode(*modeValue)
	if mode != githubapp.ShadowMode && mode != githubapp.EnforceMode {
		return usageError(errors.New("--mode must be shadow or enforce"))
	}
	configured, _, err := policy.Load(*policyPath)
	if err != nil {
		return operationalError(err)
	}
	publicKey, err := attestation.LoadPublicKey(*publicKeyPath)
	if err != nil {
		return operationalError(err)
	}
	expected, err := expectedFromPolicy(configured, *head, *base, *nonce)
	if err != nil {
		return operationalError(err)
	}
	result := githubapp.Evaluate(store.New(*storePath), publicKey, expected, mode)
	if err := writeJSON(output, result); err != nil {
		return err
	}
	if !result.Accepted {
		return &commandError{code: 1, err: fmt.Errorf("%s: %s", result.Code, result.Message)}
	}
	return nil
}

func expectedFromPolicy(configured policy.Policy, head, base, nonce string) (verifier.Expected, error) {
	policyDigest, err := configured.Digest()
	if err != nil {
		return verifier.Expected{}, err
	}
	workflowDigest, err := configured.WorkflowDigest()
	if err != nil {
		return verifier.Expected{}, err
	}
	return verifier.Expected{
		Repository:        configured.Repository,
		HeadSHA:           head,
		BaseSHA:           base,
		Profile:           configured.Profile,
		PolicyDigest:      policyDigest,
		WorkflowDigest:    workflowDigest,
		EnvironmentDigest: configured.EnvironmentDigest(),
		Command:           append([]string(nil), configured.Command...),
		RequiredJobs:      []string{configured.Profile},
		Nonce:             nonce,
		MaxAge:            time.Duration(configured.MaxAgeSeconds) * time.Second,
		Now:               time.Now().UTC(),
	}, nil
}

func newNonce() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func defaultStorePath() string {
	cacheDirectory, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "cihash")
	}
	return filepath.Join(cacheDirectory, "cihash")
}

func writeJSON(output io.Writer, value any) *commandError {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return operationalError(fmt.Errorf("write JSON output: %w", err))
	}
	return nil
}

func usageError(err error) *commandError {
	return &commandError{code: 2, err: err}
}

func operationalError(err error) *commandError {
	return &commandError{code: 1, err: err}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: cihash <keygen|policy|run|verify|check|version> [options]")
}
