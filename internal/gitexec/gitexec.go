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

func ObjectCommand(ctx context.Context, binary, gitDirectory, objectDirectory, alternateObjectDirectory string, arguments ...string) *exec.Cmd {
	command := Command(ctx, binary, "", arguments...)
	command.Env = append(command.Env,
		"GIT_DIR="+gitDirectory,
		"GIT_OBJECT_DIRECTORY="+objectDirectory,
		"GIT_ALTERNATE_OBJECT_DIRECTORIES="+alternateObjectDirectory,
	)
	return command
}

func environment() []string {
	allowed := map[string]struct{}{
		"LANG":     {},
		"LC_ALL":   {},
		"LC_CTYPE": {},
		"PATH":     {},
		"TEMP":     {},
		"TMP":      {},
		"TMPDIR":   {},
	}
	current := os.Environ()
	result := make([]string, 0, len(allowed)+5)
	for _, variable := range current {
		name, _, _ := strings.Cut(variable, "=")
		if _, ok := allowed[name]; ok {
			result = append(result, variable)
		}
	}
	return append(result,
		"HOME=/nonexistent",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_NO_REPLACE_OBJECTS=1",
	)
}
