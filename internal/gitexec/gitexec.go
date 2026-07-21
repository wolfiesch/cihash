// Package gitexec creates Git commands with repository-controlled process overrides disabled.
package gitexec

import (
	"context"
	"os"
	"os/exec"
	"strings"
)

func Command(ctx context.Context, binary, directory string, arguments ...string) *exec.Cmd {
	if binary == "" {
		binary = "git"
	}
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Dir = directory
	command.Env = environment()
	return command
}

func environment() []string {
	current := os.Environ()
	result := make([]string, 0, len(current)+2)
	for _, variable := range current {
		name, _, _ := strings.Cut(variable, "=")
		if !blocked(name) {
			result = append(result, variable)
		}
	}
	return append(result, "GIT_NO_REPLACE_OBJECTS=1", "GIT_CONFIG_NOSYSTEM=1")
}

func blocked(name string) bool {
	if strings.HasPrefix(name, "GIT_CONFIG_KEY_") || strings.HasPrefix(name, "GIT_CONFIG_VALUE_") {
		return true
	}
	switch name {
	case "GIT_ALTERNATE_OBJECT_DIRECTORIES",
		"GIT_CONFIG_COUNT",
		"GIT_CONFIG_GLOBAL",
		"GIT_CONFIG_SYSTEM",
		"GIT_DIR",
		"GIT_INDEX_FILE",
		"GIT_OBJECT_DIRECTORY",
		"GIT_REPLACE_REF_BASE",
		"GIT_SHALLOW_FILE",
		"GIT_WORK_TREE":
		return true
	default:
		return false
	}
}
