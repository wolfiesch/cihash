package shadow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const SchemaVersion = "https://cihash.dev/shadow/observation/v0.1"

const (
	ParityPending       = "pending"
	ParityMatch         = "match"
	ParityMismatch      = "mismatch"
	ParityNotComparable = "not_comparable"
)

type Decision struct {
	Repository            string    `json:"repository"`
	PullRequestNumber     int64     `json:"pullRequestNumber"`
	HeadSHA               string    `json:"headSha"`
	BaseSHA               string    `json:"baseSha"`
	TreeSHA               string    `json:"treeSha"`
	PolicyDigest          string    `json:"policyDigest"`
	ProofAccepted         bool      `json:"proofAccepted"`
	ProofCode             string    `json:"proofCode"`
	Comparable            bool      `json:"comparable"`
	CheckRunID            int64     `json:"checkRunId"`
	EvaluatedAt           time.Time `json:"evaluatedAt"`
	VerificationMillis    int64     `json:"verificationMillis"`
	AppDecisionMillis     int64     `json:"appDecisionMillis"`
	ServiceSourceRevision string    `json:"serviceSourceRevision"`
	ServiceBinaryDigest   string    `json:"serviceBinaryDigest"`
	ServiceBuildMode      string    `json:"serviceBuildMode"`
	ServiceSourceModified bool      `json:"serviceSourceModified"`
	ServiceStartedAt      time.Time `json:"serviceStartedAt"`
	PolicyTimeoutSeconds  int64     `json:"policyTimeoutSeconds"`
}

type Workflow struct {
	Name           string    `json:"name"`
	RunID          int64     `json:"runId"`
	HeadSHA        string    `json:"headSha"`
	Conclusion     string    `json:"conclusion"`
	StartedAt      time.Time `json:"startedAt"`
	CompletedAt    time.Time `json:"completedAt"`
	DurationMillis int64     `json:"durationMillis"`
}

type Observation struct {
	SchemaVersion string    `json:"schemaVersion"`
	ID            string    `json:"id"`
	Decision      Decision  `json:"decision"`
	Workflow      *Workflow `json:"workflow,omitempty"`
	Parity        string    `json:"parity"`
}

type Report struct {
	SchemaVersion         string        `json:"schemaVersion"`
	GeneratedAt           time.Time     `json:"generatedAt"`
	Total                 int           `json:"total"`
	Comparable            int           `json:"comparable"`
	Pending               int           `json:"pending"`
	Matches               int           `json:"matches"`
	Mismatches            int           `json:"mismatches"`
	BuildEvidenceComplete bool          `json:"buildEvidenceComplete"`
	NotComparable         int           `json:"notComparable"`
	EnforcementReady      bool          `json:"enforcementReady"`
	Observations          []Observation `json:"observations"`
}

type Store struct {
	root string
}

func New(root string) Store {
	return Store{root: filepath.Join(root, "shadow")}
}

func (store Store) RecordDecision(decision Decision) (Observation, error) {
	if err := validateDecision(decision); err != nil {
		return Observation{}, err
	}
	decision.EvaluatedAt = decision.EvaluatedAt.UTC()
	id := observationID(decision)
	var observation Observation
	err := store.withHeadLock(decision.Repository, decision.HeadSHA, func() error {
		path := store.observationPath(id)
		existing, found, err := readObservation(path)
		if err != nil {
			return err
		}
		if found {
			if !sameDecision(existing.Decision, decision) {
				return fmt.Errorf("shadow decision conflicts with existing observation")
			}
			observation = existing
		} else {
			observation = Observation{
				SchemaVersion: SchemaVersion,
				ID:            id,
				Decision:      decision,
				Parity:        ParityPending,
			}
			pending, pendingFound, err := store.readPending(decision.Repository, decision.HeadSHA)
			if err != nil {
				return err
			}
			if pendingFound {
				observation.Workflow = &pending
				observation.Parity = parity(decision, &pending)
			}
			if err := writeJSONAtomic(path, observation); err != nil {
				return err
			}
		}
		if err := store.writeHeadIndex(decision.Repository, decision.HeadSHA, id); err != nil {
			return err
		}
		return store.removePending(decision.Repository, decision.HeadSHA)
	})
	return observation, err
}

func (store Store) RecordWorkflow(repository string, workflow Workflow) (Observation, bool, error) {
	if err := validateWorkflow(repository, workflow); err != nil {
		return Observation{}, false, err
	}
	workflow.StartedAt = workflow.StartedAt.UTC()
	workflow.CompletedAt = workflow.CompletedAt.UTC()
	workflow.DurationMillis = workflow.CompletedAt.Sub(workflow.StartedAt).Milliseconds()
	var observation Observation
	var found bool
	err := store.withHeadLock(repository, workflow.HeadSHA, func() error {
		id, indexFound, err := store.readHeadIndex(repository, workflow.HeadSHA)
		if err != nil {
			return err
		}
		if !indexFound {
			return store.writePending(repository, workflow)
		}
		path := store.observationPath(id)
		observation, found, err = readObservation(path)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("shadow observation index points to missing evidence")
		}
		if observation.Workflow != nil && !workflow.CompletedAt.After(observation.Workflow.CompletedAt) {
			return nil
		}
		observation.Workflow = &workflow
		observation.Parity = parity(observation.Decision, &workflow)
		return writeJSONAtomic(path, observation)
	})
	return observation, found, err
}

func (store Store) Report(now time.Time) (Report, error) {
	report := Report{
		SchemaVersion:         SchemaVersion,
		GeneratedAt:           now.UTC(),
		EnforcementReady:      false,
		BuildEvidenceComplete: true,
		Observations:          []Observation{},
	}
	directory := filepath.Join(store.root, "observations")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return report, nil
	}
	if err != nil {
		return Report{}, fmt.Errorf("read shadow observations: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		observation, found, err := readObservation(filepath.Join(directory, entry.Name()))
		if err != nil {
			return Report{}, err
		}
		if !found {
			continue
		}
		if !validGitObjectID(observation.Decision.ServiceSourceRevision) || observation.Decision.ServiceSourceModified || observation.Decision.ServiceBuildMode != "production" {
			report.BuildEvidenceComplete = false
		}
		report.Observations = append(report.Observations, observation)
		switch observation.Parity {
		case ParityPending:
			report.Pending++
		case ParityMatch:
			report.Matches++
			report.Comparable++
		case ParityMismatch:
			report.Mismatches++
			report.Comparable++
		case ParityNotComparable:
			report.NotComparable++
		default:
			return Report{}, fmt.Errorf("shadow observation %q has invalid parity %q", observation.ID, observation.Parity)
		}
	}
	sort.Slice(report.Observations, func(i, j int) bool {
		return report.Observations[i].Decision.EvaluatedAt.Before(report.Observations[j].Decision.EvaluatedAt)
	})
	report.Total = len(report.Observations)
	report.EnforcementReady = report.Comparable > 0 && report.Pending == 0 && report.Mismatches == 0 && report.BuildEvidenceComplete
	return report, nil
}

func validateDecision(decision Decision) error {
	if decision.Repository == "" || decision.PullRequestNumber <= 0 || decision.PolicyDigest == "" || decision.ProofCode == "" || decision.CheckRunID <= 0 || decision.EvaluatedAt.IsZero() {
		return fmt.Errorf("shadow decision is incomplete")
	}
	if !validGitObjectID(decision.HeadSHA) || !validGitObjectID(decision.BaseSHA) || !validGitObjectID(decision.TreeSHA) {
		return fmt.Errorf("shadow decision contains an invalid Git object ID")
	}
	if decision.VerificationMillis < 0 || decision.AppDecisionMillis < decision.VerificationMillis || decision.PolicyTimeoutSeconds <= 0 {
		return fmt.Errorf("shadow decision timing is invalid")
	}
	if decision.ServiceSourceRevision == "" || decision.ServiceBinaryDigest == "" || decision.ServiceBuildMode == "" {
		return fmt.Errorf("shadow decision build identity is incomplete")
	}
	if decision.ServiceStartedAt.IsZero() || decision.ServiceStartedAt.After(decision.EvaluatedAt) {
		return fmt.Errorf("shadow decision service timing is invalid")
	}
	return nil
}

func validateWorkflow(repository string, workflow Workflow) error {
	if repository == "" || workflow.Name == "" || workflow.RunID <= 0 || workflow.Conclusion == "" || workflow.StartedAt.IsZero() || workflow.CompletedAt.IsZero() {
		return fmt.Errorf("shadow workflow result is incomplete")
	}
	if !validGitObjectID(workflow.HeadSHA) || workflow.CompletedAt.Before(workflow.StartedAt) {
		return fmt.Errorf("shadow workflow result is invalid")
	}
	return nil
}

func parity(decision Decision, workflow *Workflow) string {
	if workflow == nil {
		return ParityPending
	}
	if !decision.Comparable {
		return ParityNotComparable
	}
	if decision.ProofAccepted == (workflow.Conclusion == "success") {
		return ParityMatch
	}
	return ParityMismatch
}

func sameDecision(left, right Decision) bool {
	left.EvaluatedAt = left.EvaluatedAt.UTC()
	right.EvaluatedAt = right.EvaluatedAt.UTC()
	return left == right
}

func observationID(decision Decision) string {
	return digest(strings.Join([]string{decision.Repository, decision.HeadSHA, decision.BaseSHA, decision.TreeSHA, decision.PolicyDigest}, "\x00"))
}

func validGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func (store Store) withHeadLock(repository, headSHA string, operation func() error) error {
	if err := os.MkdirAll(filepath.Join(store.root, "locks"), 0o700); err != nil {
		return fmt.Errorf("create shadow lock directory: %w", err)
	}
	lock, err := os.OpenFile(filepath.Join(store.root, "locks", digest(repository+"\x00"+headSHA)+".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("open shadow evidence lock: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock shadow evidence: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return operation()
}

func (store Store) observationPath(id string) string {
	return filepath.Join(store.root, "observations", id+".json")
}

func (store Store) writeHeadIndex(repository, headSHA, id string) error {
	path := filepath.Join(store.root, "heads", digest(repository+"\x00"+headSHA))
	return writeBytesAtomic(path, []byte(id+"\n"), 0o600)
}

func (store Store) readHeadIndex(repository, headSHA string) (string, bool, error) {
	path := filepath.Join(store.root, "heads", digest(repository+"\x00"+headSHA))
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read shadow head index: %w", err)
	}
	id := strings.TrimSpace(string(data))
	if len(id) != sha256.Size*2 {
		return "", false, fmt.Errorf("shadow head index is malformed")
	}
	return id, true, nil
}

func (store Store) pendingPath(repository, headSHA string) string {
	return filepath.Join(store.root, "pending", digest(repository+"\x00"+headSHA)+".json")
}

func (store Store) writePending(repository string, workflow Workflow) error {
	path := store.pendingPath(repository, workflow.HeadSHA)
	existing, found, err := readWorkflow(path)
	if err != nil {
		return err
	}
	if found && !workflow.CompletedAt.After(existing.CompletedAt) {
		return nil
	}
	return writeJSONAtomic(path, workflow)
}

func (store Store) readPending(repository, headSHA string) (Workflow, bool, error) {
	return readWorkflow(store.pendingPath(repository, headSHA))
}

func (store Store) removePending(repository, headSHA string) error {
	err := os.Remove(store.pendingPath(repository, headSHA))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func readObservation(path string) (Observation, bool, error) {
	var observation Observation
	found, err := readJSON(path, &observation)
	if err != nil || !found {
		return Observation{}, found, err
	}
	if observation.SchemaVersion != SchemaVersion || observation.ID != strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)) {
		return Observation{}, false, fmt.Errorf("shadow observation identity is invalid")
	}
	if err := validateDecision(observation.Decision); err != nil {
		return Observation{}, false, err
	}
	if observation.Workflow != nil {
		if err := validateWorkflow(observation.Decision.Repository, *observation.Workflow); err != nil {
			return Observation{}, false, err
		}
	}
	if observation.Parity != parity(observation.Decision, observation.Workflow) {
		return Observation{}, false, fmt.Errorf("shadow observation parity is invalid")
	}
	return observation, true, nil
}

func readWorkflow(path string) (Workflow, bool, error) {
	var workflow Workflow
	found, err := readJSON(path, &workflow)
	return workflow, found, err
}

func readJSON(path string, destination any) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read shadow evidence: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false, fmt.Errorf("decode shadow evidence: %w", err)
	}
	return true, nil
}

func writeJSONAtomic(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode shadow evidence: %w", err)
	}
	return writeBytesAtomic(path, append(data, '\n'), 0o600)
}

func writeBytesAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create shadow evidence directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".cihash-shadow-*")
	if err != nil {
		return fmt.Errorf("create temporary shadow evidence: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace shadow evidence: %w", err)
	}
	return nil
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
