package main

import (
	"io"
	"testing"
)

func TestVerifyRequiresNonceAndMergeTree(t *testing.T) {
	err := execute([]string{"verify", "--receipt", "receipt.json", "--policy", "policy.json", "--public-key", "receipt.pub", "--head", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--base", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "--nonce", "nonce"}, io.Discard)
	if err == nil || err.code != 2 {
		t.Fatalf("verify error = %+v, want usage error", err)
	}
}

func TestCheckRequiresNonceAndMergeTree(t *testing.T) {
	err := execute([]string{"check", "--policy", "policy.json", "--public-key", "receipt.pub", "--head", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--base", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "--tree", "cccccccccccccccccccccccccccccccccccccccc"}, io.Discard)
	if err == nil || err.code != 2 {
		t.Fatalf("check error = %+v, want usage error", err)
	}
}
