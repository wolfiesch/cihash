// Package applicability evaluates whether a tested claim can be reused for a
// current GitHub pull-request or merge-group state.
package applicability

import (
	"strings"

	"github.com/wolfiesch/cihash/internal/attestation"
)

// Context identifies the GitHub state that produced or consumes a claim.
type Context string

const (
	PullRequestContext Context = "pull_request"
	MergeGroupContext  Context = "merge_group"
)

// ReuseMode selects the identity that must remain immutable before a claim can
// be reused.
type ReuseMode string

const (
	StrictCommits ReuseMode = "strict_commits"

	// MergeTree is a lab-only reuse experiment. It is sound only when execution
	// consumed a tree-only archive, commit/base/context metadata was
	// unobservable to that execution, and an administrator-approved policy
	// binding authorizes that mode. This evaluator verifies matching policy
	// digests, but cannot prove that execution was isolated in this way. The
	// current hosted runner MUST NOT use this mode.
	MergeTree ReuseMode = "merge_tree"
)

// Claim is the identity and execution configuration bound by a completed test.
// MergeTreeSHA is the Git tree object that was executed, not a commit SHA.
type Claim struct {
	Repository        string
	HeadSHA           string
	BaseSHA           string
	MergeTreeSHA      string
	PolicyDigest      string
	WorkflowDigest    string
	EnvironmentDigest string
	Context           Context
}

// Decision is the deterministic result of comparing a tested claim with the
// current GitHub state. Code is stable for callers that need to explain a
// rejection without parsing prose.
type Decision struct {
	Accepted bool
	Code     string
}

// Evaluate determines whether claim applies to current under mode. Both values
// are fully validated before any equality comparison. Rejections use this
// precedence: mode, claim validation, current validation, repository, then the
// mode-specific identity fields and execution digests.
func Evaluate(claim, current Claim, mode ReuseMode) Decision {
	if !validMode(mode) {
		return reject("invalid_reuse_mode")
	}
	if code := validate(claim); code != "" {
		return reject(code)
	}
	if code := validate(current); code != "" {
		return reject(code)
	}
	if claim.Repository != current.Repository {
		return reject("repository_mismatch")
	}

	switch mode {
	case StrictCommits:
		if claim.Context != current.Context {
			return reject("context_mismatch")
		}
		if claim.HeadSHA != current.HeadSHA {
			return reject("head_mismatch")
		}
		if claim.BaseSHA != current.BaseSHA {
			return reject("base_mismatch")
		}
		if claim.MergeTreeSHA != current.MergeTreeSHA {
			return reject("merge_tree_mismatch")
		}
		if code := compareDigests(claim, current); code != "" {
			return reject(code)
		}
		return Decision{Accepted: true, Code: "accepted"}
	case MergeTree:
		if claim.MergeTreeSHA != current.MergeTreeSHA {
			return reject("merge_tree_mismatch")
		}
		if code := compareDigests(claim, current); code != "" {
			return reject(code)
		}
		if claim.Context == current.Context && claim.HeadSHA == current.HeadSHA && claim.BaseSHA == current.BaseSHA {
			return Decision{Accepted: true, Code: "accepted"}
		}
		return Decision{Accepted: true, Code: "tree_equivalent"}
	default:
		// validMode above makes this unreachable; keep this fail-closed if modes
		// are extended without updating this switch.
		return reject("invalid_reuse_mode")
	}
}

func compareDigests(claim, current Claim) string {
	if claim.PolicyDigest != current.PolicyDigest {
		return "policy_mismatch"
	}
	if claim.WorkflowDigest != current.WorkflowDigest {
		return "workflow_mismatch"
	}
	if claim.EnvironmentDigest != current.EnvironmentDigest {
		return "environment_mismatch"
	}
	return ""
}

func validate(claim Claim) string {
	if !validRepository(claim.Repository) {
		return "invalid_repository"
	}
	if !validGitObjectID(claim.HeadSHA) {
		return "invalid_head_sha"
	}
	if !validGitObjectID(claim.BaseSHA) {
		return "invalid_base_sha"
	}
	if !validGitObjectID(claim.MergeTreeSHA) {
		return "invalid_merge_tree_sha"
	}
	if attestation.ValidateDigest(claim.PolicyDigest) != nil {
		return "invalid_policy_digest"
	}
	if attestation.ValidateDigest(claim.WorkflowDigest) != nil {
		return "invalid_workflow_digest"
	}
	if attestation.ValidateDigest(claim.EnvironmentDigest) != nil {
		return "invalid_environment_digest"
	}
	if !validContext(claim.Context) {
		return "invalid_context"
	}
	return ""
}

func validMode(mode ReuseMode) bool {
	return mode == StrictCommits || mode == MergeTree
}

func validContext(context Context) bool {
	return context == PullRequestContext || context == MergeGroupContext
}

func validRepository(repository string) bool {
	const host = "github.com/"
	if !strings.HasPrefix(repository, host) {
		return false
	}
	repository = repository[len(host):]
	separator := strings.IndexByte(repository, '/')
	if separator <= 0 || separator == len(repository)-1 || strings.IndexByte(repository[separator+1:], '/') >= 0 {
		return false
	}
	return validRepositorySegment(repository[:separator]) && validRepositorySegment(repository[separator+1:])
}

func validRepositorySegment(segment string) bool {
	for index := range len(segment) {
		character := segment[index]
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
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

func reject(code string) Decision {
	return Decision{Code: code}
}
