package hosted

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

type serviceBuild struct {
	sourceRevision string
	sourceModified bool
	binaryDigest   string
}

func inspectServiceBuild() (serviceBuild, error) {
	executable, err := os.Executable()
	if err != nil {
		return serviceBuild{}, fmt.Errorf("resolve service executable: %w", err)
	}
	file, err := os.Open(executable)
	if err != nil {
		return serviceBuild{}, fmt.Errorf("open service executable: %w", err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		_ = file.Close()
		return serviceBuild{}, fmt.Errorf("digest service executable: %w", err)
	}
	if err := file.Close(); err != nil {
		return serviceBuild{}, fmt.Errorf("close service executable: %w", err)
	}
	build := serviceBuild{
		sourceRevision: "unknown",
		sourceModified: true,
		binaryDigest:   "sha256:" + hex.EncodeToString(hash.Sum(nil)),
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if setting.Value != "" {
					build.sourceRevision = setting.Value
				}
			case "vcs.modified":
				build.sourceModified = setting.Value != "false"
			}
		}
	}
	return build, nil
}
