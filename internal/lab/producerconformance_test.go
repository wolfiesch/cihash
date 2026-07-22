package lab

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRunProducerConformanceSeparatesShapeFromAuthorization(t *testing.T) {
	report, err := RunProducerConformance()
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("report = %+v", report)
	}
	if len(report.Scenarios) != 6 {
		t.Fatalf("scenarios = %d, want 6", len(report.Scenarios))
	}
	if !report.Scenarios[1].Passed || !report.Scenarios[1].Conformant || !report.Scenarios[1].SigningEligible || report.Scenarios[1].ResultSucceeded {
		t.Fatalf("failed diagnostic result = %+v", report.Scenarios[1])
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"accepted"`) || strings.Contains(string(encoded), "authoriz") {
		t.Fatalf("unsigned conformance report claims authorization: %s", encoded)
	}
}
