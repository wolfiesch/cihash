package lab

import "testing"

func TestRunJobSetProvesCompletePolicyOwnedContract(t *testing.T) {
	report, err := RunJobSet()
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("report = %+v", report)
	}
	if len(report.Scenarios) != 6 {
		t.Fatalf("scenarios = %d, want 6", len(report.Scenarios))
	}
	for _, scenario := range report.Scenarios {
		if !scenario.Passed {
			t.Fatalf("scenario = %+v", scenario)
		}
	}
}
