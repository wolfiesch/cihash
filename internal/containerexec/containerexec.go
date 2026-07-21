package containerexec

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	imagePattern  = regexp.MustCompile(`^(?:[a-z0-9][a-z0-9._/-]*@)?sha256:[0-9a-f]{64}$`)
	memoryPattern = regexp.MustCompile(`^[1-9][0-9]*[mg]$`)
)

const (
	DefaultPIDsLimit      = 1024
	DefaultMaxOutputBytes = int64(16 << 20)
)

type Options struct {
	Image          string
	Network        string
	Memory         string
	CPUs           string
	PIDsLimit      int
	MaxOutputBytes int64
	Command        []string
	Directory      string
	DockerBinary   string
}

func Run(ctx context.Context, options Options) ([]byte, error) {
	arguments, cidFile, err := dockerArguments(options)
	if err != nil {
		return nil, err
	}
	defer os.Remove(cidFile)

	maxOutputBytes := options.MaxOutputBytes
	if maxOutputBytes == 0 {
		maxOutputBytes = DefaultMaxOutputBytes
	}
	if maxOutputBytes < 1 {
		return nil, fmt.Errorf("container output limit must be positive")
	}
	docker := options.DockerBinary
	if docker == "" {
		docker = "docker"
	}
	capture := boundedOutput{limit: maxOutputBytes}
	command := exec.CommandContext(ctx, docker, arguments...)
	command.Stdout = &capture
	command.Stderr = &capture
	runErr := command.Run()
	output := capture.Bytes()
	if ctx.Err() != nil {
		removeContainer(docker, cidFile)
	}
	if runErr != nil {
		return output, fmt.Errorf("isolated workload failed: %w", runErr)
	}
	return output, nil
}

type boundedOutput struct {
	buffer    bytes.Buffer
	limit     int64
	truncated bool
}

func (output *boundedOutput) Write(data []byte) (int, error) {
	originalLength := len(data)
	remaining := output.limit - int64(output.buffer.Len())
	if remaining > 0 {
		if int64(len(data)) > remaining {
			data = data[:remaining]
		}
		_, _ = output.buffer.Write(data)
	}
	if int64(originalLength) > remaining {
		output.truncated = true
	}
	return originalLength, nil
}

func (output *boundedOutput) Bytes() []byte {
	result := append([]byte(nil), output.buffer.Bytes()...)
	if output.truncated {
		result = append(result, []byte(fmt.Sprintf("\n[cihash] output truncated after %d bytes\n", output.limit))...)
	}
	return result
}

func dockerArguments(options Options) ([]string, string, error) {
	if !imagePattern.MatchString(options.Image) {
		return nil, "", fmt.Errorf("container image must be pinned by sha256 digest")
	}
	if options.Network != "none" && options.Network != "bridge" {
		return nil, "", fmt.Errorf("container network must be none or bridge")
	}
	if !memoryPattern.MatchString(options.Memory) {
		return nil, "", fmt.Errorf("container memory must use a positive m or g suffix")
	}
	cpus, err := strconv.ParseFloat(options.CPUs, 64)
	if err != nil || cpus <= 0 {
		return nil, "", fmt.Errorf("container CPUs must be positive")
	}
	pidsLimit := options.PIDsLimit
	if pidsLimit == 0 {
		pidsLimit = DefaultPIDsLimit
	}
	if pidsLimit < 1 {
		return nil, "", fmt.Errorf("container PID limit must be positive")
	}
	if len(options.Command) == 0 || strings.TrimSpace(options.Command[0]) == "" {
		return nil, "", fmt.Errorf("container command is required")
	}
	directory, err := filepath.Abs(options.Directory)
	if err != nil {
		return nil, "", fmt.Errorf("resolve container workspace: %w", err)
	}
	info, err := os.Stat(directory)
	if err != nil {
		return nil, "", fmt.Errorf("inspect container workspace: %w", err)
	}
	if !info.IsDir() {
		return nil, "", fmt.Errorf("container workspace must be a directory")
	}
	cidFile, err := temporaryCIDFile()
	if err != nil {
		return nil, "", err
	}
	identity := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	tmpfsIdentity := ",uid=" + strconv.Itoa(os.Getuid()) + ",gid=" + strconv.Itoa(os.Getgid())
	arguments := []string{
		"run", "--rm", "--pull=never", "--init",
		"--cidfile", cidFile,
		"--read-only",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--pids-limit=" + strconv.Itoa(pidsLimit),
		"--memory=" + options.Memory,
		"--cpus=" + options.CPUs,
		"--network=" + options.Network,
		"--hostname=cihash-worker",
		"--user=" + identity,
		"--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=2g" + tmpfsIdentity,
		"--tmpfs", "/home/cihash:rw,nosuid,nodev,size=512m" + tmpfsIdentity,
		"--tmpfs", "/work:rw,nosuid,nodev,size=" + options.Memory + tmpfsIdentity,
		"--env=CI=1",
		"--env=CIHASH=1",
		"--env=HOME=/home/cihash",
		"--env=TMPDIR=/tmp",
		"--env=CIHASH_INPUT=/input",
		"--mount", "type=bind,src=" + directory + ",dst=/input,readonly",
		"--workdir=/work",
		options.Image,
	}
	return append(arguments, options.Command...), cidFile, nil
}

func temporaryCIDFile() (string, error) {
	file, err := os.CreateTemp("", "cihash-container-*.cid")
	if err != nil {
		return "", fmt.Errorf("create container ID file: %w", err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close container ID file: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("prepare container ID file: %w", err)
	}
	return path, nil
}

func removeContainer(docker, cidFile string) {
	data, err := os.ReadFile(cidFile)
	if err != nil {
		return
	}
	containerID := strings.TrimSpace(string(data))
	if containerID == "" {
		return
	}
	_ = exec.Command(docker, "rm", "--force", containerID).Run()
}
