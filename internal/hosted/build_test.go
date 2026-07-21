package hosted

import (
	"strings"
	"testing"
)

func TestProductionBuildRequiresExactCleanSource(t *testing.T) {
	valid := serviceBuild{sourceRevision: strings.Repeat("a", 40)}
	if err := valid.validateProduction(); err != nil {
		t.Fatalf("valid production build: %v", err)
	}

	for name, build := range map[string]serviceBuild{
		"unknown revision": {sourceRevision: "unknown"},
		"modified source":  {sourceRevision: strings.Repeat("a", 40), sourceModified: true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := build.validateProduction(); err == nil {
				t.Fatal("validateProduction accepted invalid build")
			}
		})
	}
}
