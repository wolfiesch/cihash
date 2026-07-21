package confirmer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/wolfiesch/cihash/internal/attestation"
)

const (
	AgreementPredicateType = "https://cihash.dev/attestation/confirmer-agreement/v0.1"
	AgreementSchemaVersion = "0.1"
	AgreementConclusion    = "agreement"
)

var (
	ErrInvalidObservation = errors.New("invalid observation")
	ErrDiverged           = errors.New("observations diverge")
	ErrInvalidAgreement   = errors.New("invalid agreement")
)

type Divergence string

const (
	DivergenceNone                    Divergence = ""
	DivergenceIdentity                Divergence = "identity"
	DivergencePolicyWorkflow          Divergence = "policy_workflow"
	DivergenceEnvironmentArchitecture Divergence = "environment_architecture"
	DivergenceJobSetCommand           Divergence = "job_set_command"
	DivergenceResult                  Divergence = "result"
	DivergenceLog                     Divergence = "log"
)

type JobClaim struct {
	Name       string   `json:"name"`
	Command    []string `json:"command"`
	ExitCode   int      `json:"exitCode"`
	Conclusion string   `json:"conclusion"`
	LogDigest  string   `json:"logDigest"`
}

type Claim struct {
	Repository        string     `json:"repository"`
	HeadSHA           string     `json:"headSha"`
	BaseSHA           string     `json:"baseSha"`
	TreeSHA           string     `json:"treeSha"`
	Profile           string     `json:"profile"`
	PolicyDigest      string     `json:"policyDigest"`
	WorkflowDigest    string     `json:"workflowDigest"`
	EnvironmentDigest string     `json:"environmentDigest"`
	Architecture      string     `json:"architecture"`
	Jobs              []JobClaim `json:"jobs"`
	Conclusion        string     `json:"conclusion"`
}

// TrustDomain binds an administrator-approved domain name to the receipt key
// that represents that execution boundary.
type TrustDomain struct {
	Name       string
	ReceiptKey ed25519.PublicKey
}

type Observation struct {
	trustDomain    string
	signerKeyID    string
	signerKey      ed25519.PublicKey
	envelopeDigest string
	claim          Claim
}

type Comparison struct {
	Agrees      bool
	Divergence  Divergence
	Claim       Claim
	Fingerprint string
}

type Evidence struct {
	TrustDomain    string `json:"trustDomain"`
	SignerKeyID    string `json:"signerKeyId"`
	EnvelopeDigest string `json:"envelopeDigest"`
}

type AgreementPredicate struct {
	SchemaVersion    string     `json:"schemaVersion"`
	Conclusion       string     `json:"conclusion"`
	Claim            Claim      `json:"claim"`
	ClaimFingerprint string     `json:"claimFingerprint"`
	Evidence         []Evidence `json:"evidence"`
}

type AgreementStatement struct {
	Type          string                `json:"_type"`
	Subject       []attestation.Subject `json:"subject"`
	PredicateType string                `json:"predicateType"`
	Predicate     AgreementPredicate    `json:"predicate"`
}

func VerifyObservation(domain TrustDomain, envelope attestation.Envelope) (Observation, error) {
	if domain.Name == "" {
		return Observation{}, fmt.Errorf("%w: trust domain is empty", ErrInvalidObservation)
	}
	if len(domain.ReceiptKey) != ed25519.PublicKeySize {
		return Observation{}, fmt.Errorf("%w: receipt signer key is invalid", ErrInvalidObservation)
	}
	statement, err := attestation.VerifySignature(envelope, domain.ReceiptKey)
	if err != nil {
		return Observation{}, fmt.Errorf("%w: verify receipt: %v", ErrInvalidObservation, err)
	}
	if statement.Type != attestation.StatementType || statement.PredicateType != attestation.PredicateType || statement.Predicate.SchemaVersion != attestation.SchemaVersion {
		return Observation{}, fmt.Errorf("%w: receipt is not a v0.1 test-result statement", ErrInvalidObservation)
	}
	if len(statement.Subject) != 1 ||
		statement.Subject[0].Name != statement.Predicate.Repository ||
		len(statement.Subject[0].Digest) != 1 ||
		statement.Subject[0].Digest["gitCommit"] != statement.Predicate.HeadSHA {
		return Observation{}, fmt.Errorf("%w: receipt subject does not identify predicate head", ErrInvalidObservation)
	}
	claim := ProjectClaim(statement.Predicate)
	if err := validateClaim(claim, ErrInvalidObservation); err != nil {
		return Observation{}, err
	}
	envelopeBytes, err := attestation.MarshalEnvelope(envelope)
	if err != nil {
		return Observation{}, fmt.Errorf("%w: marshal evidence envelope: %v", ErrInvalidObservation, err)
	}
	return Observation{
		trustDomain:    domain.Name,
		signerKeyID:    attestation.KeyID(domain.ReceiptKey),
		signerKey:      append(ed25519.PublicKey(nil), domain.ReceiptKey...),
		envelopeDigest: attestation.Digest(envelopeBytes),
		claim:          claim,
	}, nil
}

func (observation Observation) TrustDomain() string {
	return observation.trustDomain
}

func (observation Observation) EnvelopeDigest() string {
	return observation.envelopeDigest
}

func (observation Observation) SignerKeyID() string {
	return observation.signerKeyID
}

func (observation Observation) Claim() Claim {
	return cloneClaim(observation.claim)
}

func ProjectClaim(result attestation.TestResult) Claim {
	claim := Claim{
		Repository:        result.Repository,
		HeadSHA:           result.HeadSHA,
		BaseSHA:           result.BaseSHA,
		TreeSHA:           result.TreeSHA,
		Profile:           result.Profile,
		PolicyDigest:      result.PolicyDigest,
		WorkflowDigest:    result.WorkflowDigest,
		EnvironmentDigest: result.EnvironmentDigest,
		Architecture:      result.Architecture,
		Jobs:              make([]JobClaim, len(result.Jobs)),
		Conclusion:        result.Conclusion,
	}
	for index, job := range result.Jobs {
		claim.Jobs[index] = JobClaim{
			Name:       job.Name,
			Command:    append([]string(nil), job.Command...),
			ExitCode:   job.ExitCode,
			Conclusion: job.Conclusion,
			LogDigest:  job.LogDigest,
		}
	}
	return normalizeClaim(claim)
}

func CompareObservations(left, right Observation) (Comparison, error) {
	if err := validateObservation(left); err != nil {
		return Comparison{}, err
	}
	if err := validateObservation(right); err != nil {
		return Comparison{}, err
	}
	leftClaim := normalizeClaim(left.claim)
	rightClaim := normalizeClaim(right.claim)
	if differsIdentity(leftClaim, rightClaim) {
		return Comparison{Divergence: DivergenceIdentity}, nil
	}
	if leftClaim.PolicyDigest != rightClaim.PolicyDigest || leftClaim.WorkflowDigest != rightClaim.WorkflowDigest {
		return Comparison{Divergence: DivergencePolicyWorkflow}, nil
	}
	if leftClaim.EnvironmentDigest != rightClaim.EnvironmentDigest || leftClaim.Architecture != rightClaim.Architecture {
		return Comparison{Divergence: DivergenceEnvironmentArchitecture}, nil
	}
	if differsJobSetCommand(leftClaim.Jobs, rightClaim.Jobs) {
		return Comparison{Divergence: DivergenceJobSetCommand}, nil
	}
	if leftClaim.Conclusion != rightClaim.Conclusion || differsResult(leftClaim.Jobs, rightClaim.Jobs) {
		return Comparison{Divergence: DivergenceResult}, nil
	}
	if differsLog(leftClaim.Jobs, rightClaim.Jobs) {
		return Comparison{Divergence: DivergenceLog}, nil
	}
	fingerprint, err := ClaimFingerprint(leftClaim)
	if err != nil {
		return Comparison{}, err
	}
	return Comparison{Agrees: true, Claim: leftClaim, Fingerprint: fingerprint}, nil
}

func ClaimFingerprint(claim Claim) (string, error) {
	claim = normalizeClaim(claim)
	data, err := json.Marshal(claim)
	if err != nil {
		return "", fmt.Errorf("marshal claim: %w", err)
	}
	return attestation.Digest(data), nil
}

func BuildAgreement(left, right Observation) (AgreementStatement, error) {
	if err := validateObservation(left); err != nil {
		return AgreementStatement{}, err
	}
	if err := validateObservation(right); err != nil {
		return AgreementStatement{}, err
	}
	if left.trustDomain == right.trustDomain {
		return AgreementStatement{}, fmt.Errorf("%w: evidence trust domains must be distinct", ErrInvalidAgreement)
	}
	if left.signerKeyID == right.signerKeyID {
		return AgreementStatement{}, fmt.Errorf("%w: evidence receipt signers must be distinct", ErrInvalidAgreement)
	}
	if left.envelopeDigest == right.envelopeDigest {
		return AgreementStatement{}, fmt.Errorf("%w: evidence envelope digests must be distinct", ErrInvalidAgreement)
	}
	comparison, err := CompareObservations(left, right)
	if err != nil {
		return AgreementStatement{}, err
	}
	if !comparison.Agrees {
		return AgreementStatement{}, fmt.Errorf("%w: %s", ErrDiverged, comparison.Divergence)
	}
	evidence := []Evidence{
		{TrustDomain: left.trustDomain, SignerKeyID: left.signerKeyID, EnvelopeDigest: left.envelopeDigest},
		{TrustDomain: right.trustDomain, SignerKeyID: right.signerKeyID, EnvelopeDigest: right.envelopeDigest},
	}
	sortEvidence(evidence)
	return AgreementStatement{
		Type: attestation.StatementType,
		Subject: []attestation.Subject{{
			Name:   comparison.Claim.Repository,
			Digest: map[string]string{"gitCommit": comparison.Claim.HeadSHA},
		}},
		PredicateType: AgreementPredicateType,
		Predicate: AgreementPredicate{
			SchemaVersion:    AgreementSchemaVersion,
			Conclusion:       AgreementConclusion,
			Claim:            comparison.Claim,
			ClaimFingerprint: comparison.Fingerprint,
			Evidence:         evidence,
		},
	}, nil
}

func SignAgreement(left, right Observation, privateKey ed25519.PrivateKey) (attestation.Envelope, error) {
	payload, err := agreementPayload(left, right)
	if err != nil {
		return attestation.Envelope{}, err
	}
	signerKeyID, err := agreementSignerKeyID(privateKey)
	if err != nil {
		return attestation.Envelope{}, err
	}
	if signerKeyID != left.signerKeyID && signerKeyID != right.signerKeyID {
		return attestation.Envelope{}, fmt.Errorf("%w: agreement signer is not an evidence signer", ErrInvalidAgreement)
	}
	return attestation.SignPayload(attestation.PayloadType, payload, privateKey)
}

func AddAgreementSignature(envelope attestation.Envelope, left, right Observation, privateKey ed25519.PrivateKey) (attestation.Envelope, error) {
	payload, err := agreementPayload(left, right)
	if err != nil {
		return attestation.Envelope{}, err
	}
	if envelope.PayloadType != attestation.PayloadType ||
		envelope.Payload != base64.StdEncoding.EncodeToString(payload) {
		return attestation.Envelope{}, fmt.Errorf("%w: envelope does not contain the expected agreement", ErrInvalidAgreement)
	}
	signerKeyID, err := agreementSignerKeyID(privateKey)
	if err != nil {
		return attestation.Envelope{}, err
	}
	var otherSigner ed25519.PublicKey
	switch signerKeyID {
	case left.signerKeyID:
		otherSigner = right.signerKey
	case right.signerKeyID:
		otherSigner = left.signerKey
	default:
		return attestation.Envelope{}, fmt.Errorf("%w: agreement signer is not an evidence signer", ErrInvalidAgreement)
	}
	if len(envelope.Signatures) != 1 {
		return attestation.Envelope{}, fmt.Errorf("%w: agreement must have exactly one existing signature", ErrInvalidAgreement)
	}
	if _, err := attestation.VerifyThresholdPayload(envelope, []ed25519.PublicKey{otherSigner}, 1); err != nil {
		return attestation.Envelope{}, fmt.Errorf("%w: existing signature is not from the other evidence signer", ErrInvalidAgreement)
	}
	return attestation.AddSignature(envelope, privateKey)
}

func agreementPayload(left, right Observation) ([]byte, error) {
	statement, err := BuildAgreement(left, right)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("marshal agreement statement: %w", err)
	}
	return payload, nil
}

func agreementSignerKeyID(privateKey ed25519.PrivateKey) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("%w: agreement signing key is invalid", ErrInvalidAgreement)
	}
	return attestation.KeyID(privateKey.Public().(ed25519.PublicKey)), nil
}

func VerifyAgreement(envelope attestation.Envelope, domains []TrustDomain) (AgreementStatement, error) {
	if envelope.PayloadType != attestation.PayloadType {
		return AgreementStatement{}, fmt.Errorf("%w: payload type %q", ErrInvalidAgreement, envelope.PayloadType)
	}
	publicKeys, trustedEvidence, err := validateTrustDomains(domains)
	if err != nil {
		return AgreementStatement{}, err
	}
	payload, err := attestation.VerifyThresholdPayload(envelope, publicKeys, len(publicKeys))
	if err != nil {
		return AgreementStatement{}, fmt.Errorf("%w: verify signatures: %v", ErrInvalidAgreement, err)
	}
	statement, err := decodeAgreementStatement(payload)
	if err != nil {
		return AgreementStatement{}, err
	}
	if err := validateAgreement(statement, trustedEvidence); err != nil {
		return AgreementStatement{}, err
	}
	return statement, nil
}

func decodeAgreementStatement(payload []byte) (AgreementStatement, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var statement AgreementStatement
	if err := decoder.Decode(&statement); err != nil {
		return AgreementStatement{}, fmt.Errorf("%w: decode statement: %v", ErrInvalidAgreement, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return AgreementStatement{}, fmt.Errorf("%w: trailing statement data", ErrInvalidAgreement)
	}
	return statement, nil
}

func validateAgreement(statement AgreementStatement, trustedEvidence map[string]string) error {
	if statement.Type != attestation.StatementType {
		return fmt.Errorf("%w: statement type %q", ErrInvalidAgreement, statement.Type)
	}
	if statement.PredicateType != AgreementPredicateType {
		return fmt.Errorf("%w: predicate type %q", ErrInvalidAgreement, statement.PredicateType)
	}
	if statement.Predicate.SchemaVersion != AgreementSchemaVersion {
		return fmt.Errorf("%w: schema version %q", ErrInvalidAgreement, statement.Predicate.SchemaVersion)
	}
	if statement.Predicate.Conclusion != AgreementConclusion {
		return fmt.Errorf("%w: conclusion %q", ErrInvalidAgreement, statement.Predicate.Conclusion)
	}
	if err := validateClaim(statement.Predicate.Claim, ErrInvalidAgreement); err != nil {
		return err
	}
	fingerprint, err := ClaimFingerprint(statement.Predicate.Claim)
	if err != nil {
		return fmt.Errorf("%w: claim fingerprint: %v", ErrInvalidAgreement, err)
	}
	if statement.Predicate.ClaimFingerprint != fingerprint {
		return fmt.Errorf("%w: claim fingerprint mismatch", ErrInvalidAgreement)
	}
	if len(statement.Predicate.Evidence) != 2 {
		return fmt.Errorf("%w: expected two evidence references", ErrInvalidAgreement)
	}
	if statement.Predicate.Evidence[0].TrustDomain == "" || statement.Predicate.Evidence[1].TrustDomain == "" {
		return fmt.Errorf("%w: evidence trust domain is empty", ErrInvalidAgreement)
	}
	if statement.Predicate.Evidence[0].TrustDomain == statement.Predicate.Evidence[1].TrustDomain {
		return fmt.Errorf("%w: evidence trust domains must be distinct", ErrInvalidAgreement)
	}
	if statement.Predicate.Evidence[0].SignerKeyID == statement.Predicate.Evidence[1].SignerKeyID {
		return fmt.Errorf("%w: evidence receipt signers must be distinct", ErrInvalidAgreement)
	}
	if statement.Predicate.Evidence[0].EnvelopeDigest == statement.Predicate.Evidence[1].EnvelopeDigest {
		return fmt.Errorf("%w: evidence envelope digests must be distinct", ErrInvalidAgreement)
	}
	for _, evidence := range statement.Predicate.Evidence {
		expectedKeyID, trusted := trustedEvidence[evidence.TrustDomain]
		if !trusted || evidence.SignerKeyID != expectedKeyID {
			return fmt.Errorf("%w: evidence trust binding is not approved", ErrInvalidAgreement)
		}
		if err := attestation.ValidateDigest(evidence.SignerKeyID); err != nil {
			return fmt.Errorf("%w: evidence signer key id: %v", ErrInvalidAgreement, err)
		}
		if err := attestation.ValidateDigest(evidence.EnvelopeDigest); err != nil {
			return fmt.Errorf("%w: evidence envelope digest: %v", ErrInvalidAgreement, err)
		}
	}
	evidence := append([]Evidence(nil), statement.Predicate.Evidence...)
	sortEvidence(evidence)
	if !equalEvidence(evidence, statement.Predicate.Evidence) {
		return fmt.Errorf("%w: evidence is not canonical", ErrInvalidAgreement)
	}
	if len(statement.Subject) != 1 || statement.Subject[0].Name != statement.Predicate.Claim.Repository || len(statement.Subject[0].Digest) != 1 || statement.Subject[0].Digest["gitCommit"] != statement.Predicate.Claim.HeadSHA {
		return fmt.Errorf("%w: subject does not identify claim head", ErrInvalidAgreement)
	}
	return nil
}

func validateObservation(observation Observation) error {
	if observation.trustDomain == "" || observation.signerKeyID == "" || observation.envelopeDigest == "" {
		return fmt.Errorf("%w: observation was not verified", ErrInvalidObservation)
	}
	if len(observation.signerKey) != ed25519.PublicKeySize || attestation.KeyID(observation.signerKey) != observation.signerKeyID {
		return fmt.Errorf("%w: receipt signer key binding is invalid", ErrInvalidObservation)
	}
	if err := attestation.ValidateDigest(observation.signerKeyID); err != nil {
		return fmt.Errorf("%w: receipt signer key id: %v", ErrInvalidObservation, err)
	}
	if err := attestation.ValidateDigest(observation.envelopeDigest); err != nil {
		return fmt.Errorf("%w: evidence envelope digest: %v", ErrInvalidObservation, err)
	}
	return nil
}

func validateClaim(claim Claim, sentinel error) error {
	if claim.Repository == "" || claim.Profile == "" || claim.Architecture == "" {
		return fmt.Errorf("%w: incomplete claim identity", sentinel)
	}
	for name, objectID := range map[string]string{
		"head": claim.HeadSHA,
		"base": claim.BaseSHA,
		"tree": claim.TreeSHA,
	} {
		if !validGitObjectID(objectID) {
			return fmt.Errorf("%w: invalid %s Git object id", sentinel, name)
		}
	}
	for _, digest := range []string{claim.PolicyDigest, claim.WorkflowDigest, claim.EnvironmentDigest} {
		if err := attestation.ValidateDigest(digest); err != nil {
			return fmt.Errorf("%w: claim digest: %v", sentinel, err)
		}
	}
	if !validConclusion(claim.Conclusion) {
		return fmt.Errorf("%w: invalid overall conclusion", sentinel)
	}
	if len(claim.Jobs) == 0 {
		return fmt.Errorf("%w: claim has no jobs", sentinel)
	}
	normalized := normalizeClaim(claim)
	if !equalClaim(normalized, claim) {
		return fmt.Errorf("%w: claim jobs are not canonical", sentinel)
	}
	jobNames := make(map[string]struct{}, len(claim.Jobs))
	for _, job := range claim.Jobs {
		if job.Name == "" || len(job.Command) == 0 || !validConclusion(job.Conclusion) {
			return fmt.Errorf("%w: incomplete job claim", sentinel)
		}
		if _, duplicate := jobNames[job.Name]; duplicate {
			return fmt.Errorf("%w: duplicate job name %q", sentinel, job.Name)
		}
		jobNames[job.Name] = struct{}{}
		if err := attestation.ValidateDigest(job.LogDigest); err != nil {
			return fmt.Errorf("%w: job log digest: %v", sentinel, err)
		}
	}
	return nil
}

func validateTrustDomains(domains []TrustDomain) ([]ed25519.PublicKey, map[string]string, error) {
	if len(domains) != 2 {
		return nil, nil, fmt.Errorf("%w: expected two approved trust domains", ErrInvalidAgreement)
	}
	publicKeys := make([]ed25519.PublicKey, 0, len(domains))
	trustedEvidence := make(map[string]string, len(domains))
	seenKeys := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		if domain.Name == "" || len(domain.ReceiptKey) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("%w: invalid trust-domain binding", ErrInvalidAgreement)
		}
		if _, duplicate := trustedEvidence[domain.Name]; duplicate {
			return nil, nil, fmt.Errorf("%w: duplicate trust domain %q", ErrInvalidAgreement, domain.Name)
		}
		keyID := attestation.KeyID(domain.ReceiptKey)
		if _, duplicate := seenKeys[keyID]; duplicate {
			return nil, nil, fmt.Errorf("%w: receipt signer keys must be distinct", ErrInvalidAgreement)
		}
		seenKeys[keyID] = struct{}{}
		trustedEvidence[domain.Name] = keyID
		publicKeys = append(publicKeys, domain.ReceiptKey)
	}
	return publicKeys, trustedEvidence, nil
}

func validGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

func validConclusion(value string) bool {
	return value == "success" || value == "failure"
}

func differsIdentity(left, right Claim) bool {
	return left.Repository != right.Repository || left.HeadSHA != right.HeadSHA || left.BaseSHA != right.BaseSHA || left.TreeSHA != right.TreeSHA || left.Profile != right.Profile
}

func differsJobSetCommand(left, right []JobClaim) bool {
	if len(left) != len(right) {
		return true
	}
	for index := range left {
		if left[index].Name != right[index].Name || !equalStrings(left[index].Command, right[index].Command) {
			return true
		}
	}
	return false
}

func differsResult(left, right []JobClaim) bool {
	for index := range left {
		if left[index].ExitCode != right[index].ExitCode || left[index].Conclusion != right[index].Conclusion {
			return true
		}
	}
	return false
}

func differsLog(left, right []JobClaim) bool {
	for index := range left {
		if left[index].LogDigest != right[index].LogDigest {
			return true
		}
	}
	return false
}

func normalizeClaim(claim Claim) Claim {
	claim = cloneClaim(claim)
	sort.Slice(claim.Jobs, func(left, right int) bool {
		return compareJobs(claim.Jobs[left], claim.Jobs[right]) < 0
	})
	return claim
}

func compareJobs(left, right JobClaim) int {
	if left.Name != right.Name {
		if left.Name < right.Name {
			return -1
		}
		return 1
	}
	if command := compareStrings(left.Command, right.Command); command != 0 {
		return command
	}
	if left.ExitCode != right.ExitCode {
		if left.ExitCode < right.ExitCode {
			return -1
		}
		return 1
	}
	if left.Conclusion != right.Conclusion {
		if left.Conclusion < right.Conclusion {
			return -1
		}
		return 1
	}
	if left.LogDigest < right.LogDigest {
		return -1
	}
	if left.LogDigest > right.LogDigest {
		return 1
	}
	return 0
}

func compareStrings(left, right []string) int {
	for index := 0; index < len(left) && index < len(right); index++ {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	return 0
}

func equalStrings(left, right []string) bool {
	return compareStrings(left, right) == 0
}

func cloneClaim(claim Claim) Claim {
	claim.Jobs = append([]JobClaim(nil), claim.Jobs...)
	for index := range claim.Jobs {
		claim.Jobs[index].Command = append([]string(nil), claim.Jobs[index].Command...)
	}
	return claim
}

func equalClaim(left, right Claim) bool {
	if differsIdentity(left, right) || left.PolicyDigest != right.PolicyDigest || left.WorkflowDigest != right.WorkflowDigest || left.EnvironmentDigest != right.EnvironmentDigest || left.Architecture != right.Architecture || left.Conclusion != right.Conclusion || len(left.Jobs) != len(right.Jobs) {
		return false
	}
	for index := range left.Jobs {
		if compareJobs(left.Jobs[index], right.Jobs[index]) != 0 {
			return false
		}
	}
	return true
}

func sortEvidence(evidence []Evidence) {
	sort.Slice(evidence, func(left, right int) bool {
		if evidence[left].TrustDomain != evidence[right].TrustDomain {
			return evidence[left].TrustDomain < evidence[right].TrustDomain
		}
		return evidence[left].EnvelopeDigest < evidence[right].EnvelopeDigest
	})
}

func equalEvidence(left, right []Evidence) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
