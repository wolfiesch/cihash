package githubapp

import (
	"crypto/ed25519"
	"fmt"

	"github.com/wolfiesch/cihash/internal/acceptance"
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
	DetailsURL string         `json:"details_url,omitempty"`
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
	decision := acceptance.Evaluate(
		receiptStore,
		acceptance.Ed25519Evaluator{PublicKey: publicKey},
		expected,
	)
	if !decision.Accepted {
		return rejectedResult(mode, expected.HeadSHA, decision.Code, decision.Message, decision.ReceiptPath, decision.Identity)
	}
	return Result{
		Accepted:    true,
		Code:        decision.Code,
		Message:     decision.Message,
		ReceiptPath: decision.ReceiptPath,
		CheckRun: CheckRunRequest{
			Name:       CheckName,
			HeadSHA:    expected.HeadSHA,
			Status:     "completed",
			Conclusion: "success",
			ExternalID: externalID(decision.Identity),
			Output: CheckRunOutput{
				Title:   "CIHash proof accepted",
				Summary: decision.Message,
			},
		},
	}
}

func rejectedResult(mode Mode, headSHA, code, message, receiptPath string, identity store.Identity) Result {
	result := Result{
		Code:        code,
		Message:     message,
		ReceiptPath: receiptPath,
		CheckRun: CheckRunRequest{
			Name:       CheckName,
			HeadSHA:    headSHA,
			ExternalID: externalID(identity),
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
