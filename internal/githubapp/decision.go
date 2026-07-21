package githubapp

import (
	"crypto/ed25519"
	"fmt"

	"github.com/wolfiesch/cihash/internal/store"
	"github.com/wolfiesch/cihash/internal/verifier"
)

const CheckName = "cihash/verify"

type Mode string

const (
	ShadowMode  Mode = "shadow"
	EnforceMode Mode = "enforce"
)

type CheckRunRequest struct {
	Name       string         `json:"name"`
	HeadSHA    string         `json:"head_sha"`
	Status     string         `json:"status"`
	Conclusion string         `json:"conclusion,omitempty"`
	ExternalID string         `json:"external_id,omitempty"`
	Output     CheckRunOutput `json:"output"`
}

type CheckRunOutput struct {
	Title   string `json:"title"`
	Summary string `json:"summary"`
}

type Result struct {
	Accepted         bool            `json:"accepted"`
	Code             string          `json:"code"`
	Message          string          `json:"message"`
	FallbackRequired bool            `json:"fallbackRequired"`
	ReceiptPath      string          `json:"receiptPath,omitempty"`
	CheckRun         CheckRunRequest `json:"checkRun"`
}

func Evaluate(receiptStore store.Store, publicKey ed25519.PublicKey, expected verifier.Expected, mode Mode) Result {
	identity := store.Identity{
		Repository:        expected.Repository,
		HeadSHA:           expected.HeadSHA,
		BaseSHA:           expected.BaseSHA,
		Profile:           expected.Profile,
		PolicyDigest:      expected.PolicyDigest,
		WorkflowDigest:    expected.WorkflowDigest,
		EnvironmentDigest: expected.EnvironmentDigest,
	}
	envelope, receiptPath, found, err := receiptStore.Lookup(identity)
	if err != nil {
		return rejectedResult(mode, expected.HeadSHA, "malformed_receipt", err.Error(), receiptPath)
	}
	if !found {
		return rejectedResult(mode, expected.HeadSHA, "proof_missing", "no proof matches the required identity", receiptPath)
	}
	decision := verifier.Verify(envelope, publicKey, expected)
	if !decision.Accepted {
		return rejectedResult(mode, expected.HeadSHA, decision.Code, decision.Message, receiptPath)
	}
	return Result{
		Accepted:    true,
		Code:        decision.Code,
		Message:     decision.Message,
		ReceiptPath: receiptPath,
		CheckRun: CheckRunRequest{
			Name:       CheckName,
			HeadSHA:    expected.HeadSHA,
			Status:     "completed",
			Conclusion: "success",
			ExternalID: externalID(identity),
			Output: CheckRunOutput{
				Title:   "CIHash proof accepted",
				Summary: decision.Message,
			},
		},
	}
}

func rejectedResult(mode Mode, headSHA, code, message, receiptPath string) Result {
	result := Result{
		Code:        code,
		Message:     message,
		ReceiptPath: receiptPath,
		CheckRun: CheckRunRequest{
			Name:    CheckName,
			HeadSHA: headSHA,
			Output: CheckRunOutput{
				Title:   "CIHash proof not accepted",
				Summary: fmt.Sprintf("%s: %s", code, message),
			},
		},
	}
	if mode == EnforceMode {
		result.FallbackRequired = true
		result.CheckRun.Status = "queued"
		result.CheckRun.Output.Title = "CIHash fallback required"
		return result
	}
	result.CheckRun.Status = "completed"
	result.CheckRun.Conclusion = "neutral"
	return result
}

func externalID(identity store.Identity) string {
	key, err := identity.Key()
	if err != nil {
		return ""
	}
	return key
}
