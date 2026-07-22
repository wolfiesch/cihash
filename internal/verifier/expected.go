package verifier

import (
	"time"

	"github.com/wolfiesch/cihash/internal/policy"
)

func ExpectedFromPolicy(configured policy.Policy, head, base, nonce string, now time.Time) (Expected, error) {
	policyDigest, err := configured.Digest()
	if err != nil {
		return Expected{}, err
	}
	workflowDigest, err := configured.WorkflowDigest()
	if err != nil {
		return Expected{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return Expected{
		Repository:        configured.Repository,
		HeadSHA:           head,
		BaseSHA:           base,
		Profile:           configured.Profile,
		PolicyDigest:      policyDigest,
		WorkflowDigest:    workflowDigest,
		EnvironmentDigest: configured.EnvironmentDigest(),
		Architecture:      configured.Environment.Platform,
		Jobs: []ExpectedJob{{
			Name:    configured.Profile,
			Command: append([]string(nil), configured.Command...),
		}},
		Nonce:  nonce,
		MaxAge: time.Duration(configured.MaxAgeSeconds) * time.Second,
		Now:    now.UTC(),
	}, nil
}
