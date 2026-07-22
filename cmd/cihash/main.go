package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/wolfiesch/cihash/internal/attestation"
	"github.com/wolfiesch/cihash/internal/conformance"
	"github.com/wolfiesch/cihash/internal/containerexec"
	"github.com/wolfiesch/cihash/internal/githubapi"
	"github.com/wolfiesch/cihash/internal/githubapp"
	"github.com/wolfiesch/cihash/internal/hosted"
	"github.com/wolfiesch/cihash/internal/lab"
	"github.com/wolfiesch/cihash/internal/policy"
	"github.com/wolfiesch/cihash/internal/producer"
	"github.com/wolfiesch/cihash/internal/remotesigner"
	"github.com/wolfiesch/cihash/internal/rungrant"
	"github.com/wolfiesch/cihash/internal/runner"
	"github.com/wolfiesch/cihash/internal/shadow"
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
	case "hosted-run":
		return hostedRunCommand(arguments[1:], output)
	case "signer-serve":
		return signerServeCommand(arguments[1:], output)
	case "container-exec":
		return containerExecCommand(arguments[1:], output)
	case "verify":
		return verifyCommand(arguments[1:], output)
	case "check":
		return checkCommand(arguments[1:], output)
	case "serve":
		return serveCommand(arguments[1:], output)
	case "lab":
		return labCommand(arguments[1:], output)
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
	repositoryPath := flags.String("repo", ".", "path to the Git repository")
	head := flags.String("head", "HEAD", "head revision to verify")
	base := flags.String("base", "", "base revision to merge with the head")
	policyPath := flags.String("policy", "", "approved policy file")
	privateKeyPath := flags.String("private-key", "", "Ed25519 private key")
	storePath := flags.String("store", defaultStorePath(), "receipt store path")
	docker := flags.String("docker", "docker", "Docker-compatible CLI")
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
	runContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	headSHA, baseSHA, err := runner.ResolveRevisions(runContext, *repositoryPath, *head, *base)
	if err != nil {
		return operationalError(err)
	}
	treeSHA, err := runner.ResolveMergeTree(runContext, *repositoryPath, baseSHA, headSHA)
	if err != nil {
		return operationalError(err)
	}
	grant, err := rungrant.Issue(configured, headSHA, baseSHA, treeSHA, time.Now().UTC())
	if err != nil {
		return operationalError(err)
	}
	outcome, err := runner.Run(runContext, runner.Request{
		RepositoryPath: *repositoryPath,
		Grant:          grant,
		Container:      runner.ContainerConfig{DockerBinary: *docker},
	})
	if err != nil {
		return operationalError(err)
	}
	privateKey, err := attestation.LoadPrivateKey(*privateKeyPath)
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
		"runId":       grant.ID,
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

func hostedRunCommand(arguments []string, output io.Writer) *commandError {
	flags := flag.NewFlagSet("hosted-run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	serverURL := flags.String("server", "", "CIHash control-plane base URL")
	tokenPath := flags.String("token-file", "", "producer bearer token file")
	installationID := flags.Int64("installation", 0, "GitHub App installation ID")
	pullRequestNumber := flags.Int64("pull-request", 0, "pull request number")
	repositoryPath := flags.String("repo", ".", "path to the Git repository")
	privateKeyPath := flags.String("private-key", "", "local Ed25519 private key")
	signerURL := flags.String("signer", "", "remote signer base URL")
	signerTokenPath := flags.String("signer-token-file", "", "remote signer bearer token file")
	docker := flags.String("docker", "docker", "Docker-compatible CLI")
	if err := flags.Parse(arguments); err != nil {
		return usageError(err)
	}
	if *serverURL == "" || *tokenPath == "" || *installationID <= 0 || *pullRequestNumber <= 0 {
		return usageError(errors.New("--server, --token-file, --installation, and --pull-request are required"))
	}
	localSigning := *privateKeyPath != ""
	remoteSigning := *signerURL != "" || *signerTokenPath != ""
	if localSigning == remoteSigning || (remoteSigning && (*signerURL == "" || *signerTokenPath == "")) {
		return usageError(errors.New("use exactly one of --private-key or --signer with --signer-token-file"))
	}
	token, err := os.ReadFile(*tokenPath)
	if err != nil {
		return operationalError(fmt.Errorf("read producer token: %w", err))
	}
	client, err := producer.New(*serverURL, token, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		return operationalError(err)
	}
	var signResult func(context.Context, rungrant.Grant, attestation.TestResult) (attestation.Envelope, error)
	if localSigning {
		privateKey, err := attestation.LoadPrivateKey(*privateKeyPath)
		if err != nil {
			return operationalError(err)
		}
		signResult = func(_ context.Context, _ rungrant.Grant, result attestation.TestResult) (attestation.Envelope, error) {
			return attestation.Sign(attestation.NewStatement(result), privateKey)
		}
	} else {
		signerToken, err := os.ReadFile(*signerTokenPath)
		if err != nil {
			return operationalError(fmt.Errorf("read signer token: %w", err))
		}
		signerClient, err := remotesigner.New(*signerURL, signerToken, &http.Client{Timeout: 30 * time.Second})
		if err != nil {
			return operationalError(err)
		}
		signResult = signerClient.Sign
	}
	runContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	grant, err := client.Issue(runContext, *installationID, *pullRequestNumber)
	if err != nil {
		return operationalError(err)
	}
	outcome, err := runner.Run(runContext, runner.Request{
		RepositoryPath: *repositoryPath,
		Grant:          grant,
		Container:      runner.ContainerConfig{DockerBinary: *docker},
	})
	if err != nil {
		return operationalError(err)
	}
	envelope, err := signResult(runContext, grant, outcome.Result)
	if err != nil {
		return operationalError(err)
	}
	receiptDigest, err := client.Submit(runContext, grant.ID, envelope, outcome.Log)
	if err != nil {
		return operationalError(err)
	}
	summary := map[string]any{
		"runId":         grant.ID,
		"conclusion":    outcome.Result.Conclusion,
		"headSha":       outcome.Result.HeadSHA,
		"baseSha":       outcome.Result.BaseSHA,
		"treeSha":       outcome.Result.TreeSHA,
		"receiptDigest": receiptDigest,
	}
	if writeErr := writeJSON(output, summary); writeErr != nil {
		return writeErr
	}
	if outcome.Result.Conclusion != "success" {
		return &commandError{code: 1, err: errors.New("verification command failed; signed failure receipt submitted")}
	}
	return nil
}

func signerServeCommand(arguments []string, output io.Writer) *commandError {
	flags := flag.NewFlagSet("signer-serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	listen := flags.String("listen", "127.0.0.1:18082", "signer listen address")
	privateKeyPath := flags.String("private-key", "", "Ed25519 private key")
	tokenPath := flags.String("token-file", "", "supervisor bearer token file")
	tlsCertificatePath := flags.String("tls-cert", "", "TLS certificate file")
	tlsKeyPath := flags.String("tls-key", "", "TLS private key file")
	checkConfig := flags.Bool("check-config", false, "validate signer configuration without listening")
	if err := flags.Parse(arguments); err != nil {
		return usageError(err)
	}
	if *privateKeyPath == "" || *tokenPath == "" {
		return usageError(errors.New("--private-key and --token-file are required"))
	}
	tlsEnabled := *tlsCertificatePath != "" || *tlsKeyPath != ""
	if tlsEnabled && (*tlsCertificatePath == "" || *tlsKeyPath == "") {
		return usageError(errors.New("--tls-cert and --tls-key must be used together"))
	}
	if tlsEnabled {
		if _, err := tls.LoadX509KeyPair(*tlsCertificatePath, *tlsKeyPath); err != nil {
			return operationalError(fmt.Errorf("load signer TLS key pair: %w", err))
		}
	}
	privateKey, err := attestation.LoadPrivateKey(*privateKeyPath)
	if err != nil {
		return operationalError(err)
	}
	token, err := os.ReadFile(*tokenPath)
	if err != nil {
		return operationalError(fmt.Errorf("read signer token: %w", err))
	}
	signerServer, err := remotesigner.NewServer(token, privateKey)
	if err != nil {
		return operationalError(err)
	}
	if *checkConfig {
		return writeJSON(output, map[string]any{"listen": *listen, "tls": tlsEnabled, "valid": true})
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return operationalError(fmt.Errorf("listen on %s: %w", *listen, err))
	}
	httpServer := &http.Server{
		Handler:           signerServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := writeJSON(output, map[string]any{"listen": listener.Addr().String()}); err != nil {
		_ = listener.Close()
		return err
	}
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverError := make(chan error, 1)
	go func() {
		if tlsEnabled {
			serverError <- httpServer.ServeTLS(listener, *tlsCertificatePath, *tlsKeyPath)
			return
		}
		serverError <- httpServer.Serve(listener)
	}()
	select {
	case err := <-serverError:
		if !errors.Is(err, http.ErrServerClosed) {
			return operationalError(err)
		}
		return nil
	case <-signalContext.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownContext); err != nil {
			return operationalError(fmt.Errorf("shut down signer service: %w", err))
		}
		return nil
	}
}

func verifyCommand(arguments []string, output io.Writer) *commandError {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	receiptPath := flags.String("receipt", "", "receipt envelope file")
	policyPath := flags.String("policy", "", "approved policy file")
	publicKeyPath := flags.String("public-key", "", "trusted Ed25519 public key")
	head := flags.String("head", "", "expected head commit SHA")
	base := flags.String("base", "", "expected base commit SHA")
	tree := flags.String("tree", "", "expected GitHub merge-tree SHA")
	nonce := flags.String("nonce", "", "expected job nonce")
	if err := flags.Parse(arguments); err != nil {
		return usageError(err)
	}
	if *receiptPath == "" || *policyPath == "" || *publicKeyPath == "" || *head == "" || *base == "" || *tree == "" || *nonce == "" {
		return usageError(errors.New("--receipt, --policy, --public-key, --head, --base, --tree, and --nonce are required"))
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
	expected, err := verifier.ExpectedFromPolicy(configured, *head, *base, *nonce, time.Now().UTC())
	if err != nil {
		return operationalError(err)
	}
	expected.TreeSHA = *tree
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
	tree := flags.String("tree", "", "expected GitHub merge-tree SHA")
	nonce := flags.String("nonce", "", "expected job nonce")
	modeValue := flags.String("mode", string(githubapp.ShadowMode), "shadow or enforce")
	if err := flags.Parse(arguments); err != nil {
		return usageError(err)
	}
	if *policyPath == "" || *publicKeyPath == "" || *head == "" || *base == "" || *tree == "" || *nonce == "" {
		return usageError(errors.New("--policy, --public-key, --head, --base, --tree, and --nonce are required"))
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
	expected, err := verifier.ExpectedFromPolicy(configured, *head, *base, *nonce, time.Now().UTC())
	if err != nil {
		return operationalError(err)
	}
	expected.TreeSHA = *tree
	result := githubapp.Evaluate(store.New(*storePath), publicKey, expected, mode)
	if err := writeJSON(output, result); err != nil {
		return err
	}
	if !result.Accepted {
		return &commandError{code: 1, err: fmt.Errorf("%s: %s", result.Code, result.Message)}
	}
	return nil
}

func containerExecCommand(arguments []string, output io.Writer) *commandError {
	flags := flag.NewFlagSet("container-exec", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	image := flags.String("image", "", "immutable container image digest")
	platform := flags.String("platform", containerexec.DefaultPlatform, "container platform")
	network := flags.String("network", "none", "container network: none or bridge")
	memory := flags.String("memory", "8g", "container memory limit")
	cpus := flags.String("cpus", "6", "container CPU limit")
	pidsLimit := flags.Int("pids-limit", containerexec.DefaultPIDsLimit, "container PID limit")
	if err := flags.Parse(arguments); err != nil {
		return usageError(err)
	}
	if *image == "" || len(flags.Args()) == 0 {
		return usageError(errors.New("--image and a command after -- are required"))
	}
	directory, err := os.Getwd()
	if err != nil {
		return operationalError(fmt.Errorf("resolve container workspace: %w", err))
	}
	runContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := containerexec.Run(runContext, containerexec.Options{
		Image:     *image,
		Platform:  *platform,
		Network:   *network,
		Memory:    *memory,
		CPUs:      *cpus,
		PIDsLimit: *pidsLimit,
		Command:   flags.Args(),
		Directory: directory,
	})
	if len(result) > 0 {
		if _, writeErr := output.Write(result); writeErr != nil {
			return operationalError(fmt.Errorf("write container output: %w", writeErr))
		}
	}
	if err != nil {
		return operationalError(err)
	}
	return nil
}

func serveCommand(arguments []string, output io.Writer) *commandError {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "hosted service configuration")
	checkConfig := flags.Bool("check-config", false, "validate configuration and credentials without listening")
	if err := flags.Parse(arguments); err != nil {
		return usageError(err)
	}
	if *configPath == "" {
		return usageError(errors.New("--config is required"))
	}
	configured, err := hosted.LoadConfig(*configPath)
	if err != nil {
		return operationalError(err)
	}
	clientID := os.Getenv("CIHASH_GITHUB_CLIENT_ID")
	privateKeyPath := os.Getenv("CIHASH_GITHUB_PRIVATE_KEY_PATH")
	webhookSecret := os.Getenv("CIHASH_GITHUB_WEBHOOK_SECRET")
	producerToken := os.Getenv("CIHASH_PRODUCER_TOKEN")
	if clientID == "" || privateKeyPath == "" || webhookSecret == "" || producerToken == "" {
		return operationalError(errors.New("CIHASH_GITHUB_CLIENT_ID, CIHASH_GITHUB_PRIVATE_KEY_PATH, CIHASH_GITHUB_WEBHOOK_SECRET, and CIHASH_PRODUCER_TOKEN are required"))
	}
	privateKey, err := githubapi.LoadRSAPrivateKey(privateKeyPath)
	if err != nil {
		return operationalError(err)
	}
	githubClient, err := githubapi.New(configured.GitHubAPIBaseURL, clientID, privateKey, nil)
	if err != nil {
		return operationalError(err)
	}
	configuredPolicy, _, err := policy.Load(configured.PolicyFile)
	if err != nil {
		return operationalError(err)
	}
	receiptPublicKey, err := attestation.LoadPublicKey(configured.ReceiptPublicKeyFile)
	if err != nil {
		return operationalError(err)
	}
	logger := log.New(os.Stderr, "cihash: ", log.LstdFlags|log.LUTC)
	webhookServer, err := hosted.NewServer(configured, []byte(webhookSecret), []byte(producerToken), configuredPolicy, receiptPublicKey, githubClient, logger)
	if err != nil {
		return operationalError(err)
	}
	if *checkConfig {
		return writeJSON(output, map[string]any{
			"listen":      configured.Listen,
			"checkName":   configured.CheckName,
			"mode":        configured.Mode,
			"repository":  configured.Repository,
			"webhookPath": configured.WebhookPath,
			"valid":       true,
		})
	}

	listener, err := net.Listen("tcp", configured.Listen)
	if err != nil {
		return operationalError(fmt.Errorf("listen on %s: %w", configured.Listen, err))
	}
	httpServer := &http.Server{
		Handler:           webhookServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := writeJSON(output, map[string]any{
		"listen":      listener.Addr().String(),
		"mode":        configured.Mode,
		"repository":  configured.Repository,
		"webhookPath": configured.WebhookPath,
	}); err != nil {
		_ = listener.Close()
		return err
	}
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverError := make(chan error, 1)
	go func() {
		serverError <- httpServer.Serve(listener)
	}()
	select {
	case err := <-serverError:
		if !errors.Is(err, http.ErrServerClosed) {
			return operationalError(err)
		}
		return nil
	case <-signalContext.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownContext); err != nil {
			return operationalError(fmt.Errorf("shut down hosted service: %w", err))
		}
		return nil
	}
}

func labCommand(arguments []string, output io.Writer) *commandError {
	const usage = "usage: cihash lab <trust-quorum|applicability|confirmer|tree-isolation|tree-reuse|job-set|producer-conformance|shadow-report>"
	if len(arguments) > 0 && arguments[0] == "shadow-report" {
		return shadowReportCommand(arguments[1:], output)
	}
	if len(arguments) > 1 && arguments[0] == "producer-conformance" {
		return producerConformanceCommand(arguments[1:], output)
	}
	if len(arguments) != 1 {
		return usageError(errors.New(usage))
	}
	if arguments[0] == "producer-conformance" {
		report, err := lab.RunProducerConformance()
		if err != nil {
			return operationalError(err)
		}
		if err := writeJSON(output, report); err != nil {
			return err
		}
		if !report.Passed {
			return operationalError(errors.New("producer-conformance experiment did not satisfy expected decisions"))
		}
		return nil
	}

	var (
		report lab.Report
		err    error
	)
	switch arguments[0] {
	case "trust-quorum":
		report, err = lab.RunTrustQuorum()
	case "applicability":
		report, err = lab.RunApplicability()
	case "confirmer":
		report, err = lab.RunConfirmer()
	case "tree-isolation":
		report, err = lab.RunTreeIsolation()
	case "tree-reuse":
		report, err = lab.RunTreeReuse()
	case "job-set":
		report, err = lab.RunJobSet()
	default:
		return usageError(errors.New(usage))
	}
	if err != nil {
		return operationalError(err)
	}
	if err := writeJSON(output, report); err != nil {
		return err
	}
	if !report.Passed {
		return operationalError(fmt.Errorf("%s experiment did not satisfy expected decisions", arguments[0]))
	}
	return nil
}

func producerConformanceCommand(arguments []string, output io.Writer) *commandError {
	flags := flag.NewFlagSet("producer-conformance", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	grantPath := flags.String("grant", "", "server-issued run grant JSON")
	resultPath := flags.String("result", "", "normalized unsigned test result JSON")
	nowValue := flags.String("now", "", "evaluation time in RFC3339 format")
	if err := flags.Parse(arguments); err != nil {
		return usageError(err)
	}
	if *grantPath == "" || *resultPath == "" {
		return usageError(errors.New("--grant and --result are required"))
	}
	var grant rungrant.Grant
	if err := conformance.Load(*grantPath, &grant); err != nil {
		return operationalError(err)
	}
	var result attestation.TestResult
	if err := conformance.Load(*resultPath, &result); err != nil {
		return operationalError(err)
	}
	var now time.Time
	if *nowValue != "" {
		parsed, err := time.Parse(time.RFC3339, *nowValue)
		if err != nil {
			return usageError(fmt.Errorf("--now must use RFC3339: %w", err))
		}
		now = parsed
	}
	report := conformance.Check(grant, result, now)
	if err := writeJSON(output, report); err != nil {
		return err
	}
	if !report.Conformant {
		return operationalError(errors.New("producer result is not conformant"))
	}
	return nil
}

func shadowReportCommand(arguments []string, output io.Writer) *commandError {
	flags := flag.NewFlagSet("shadow-report", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDirectory := flags.String("state-directory", "", "hosted service state directory")
	if err := flags.Parse(arguments); err != nil {
		return usageError(err)
	}
	if *stateDirectory == "" {
		return usageError(errors.New("--state-directory is required"))
	}
	report, err := shadow.New(*stateDirectory).Report(time.Now().UTC())
	if err != nil {
		return operationalError(err)
	}
	if err := writeJSON(output, report); err != nil {
		return err
	}
	if !report.EnforcementReady {
		return operationalError(errors.New("shadow evidence does not satisfy the enforcement gate"))
	}
	return nil
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
	fmt.Fprintln(output, "usage: cihash <keygen|policy|run|hosted-run|signer-serve|container-exec|verify|check|serve|lab|version> [options]")
}
