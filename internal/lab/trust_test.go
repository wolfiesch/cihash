package lab_test

import (
	"testing"

	"github.com/wolfiesch/cihash/internal/lab"
)

func TestRunTrustQuorumPassesEveryScenario(t *testing.T) {
	report, err := lab.RunTrustQuorum()
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("report = %+v, want passing experiment", report)
	}
	if len(report.Scenarios) != 9 {
		t.Fatalf("scenarios = %d, want 9", len(report.Scenarios))
	}
	for _, scenario := range report.Scenarios {
		if !scenario.Passed || scenario.Code == "" {
			t.Fatalf("scenario = %+v, want explicit passing decision", scenario)
		}
	}
}
