package installer

import (
	"context"
	"fmt"
	"os/exec"
)

const maxVerifierOutput = 4 << 10

type outputRunner struct {
	output string
}

type cappedWriter struct {
	data     []byte
	exceeded bool
}

func (writer *cappedWriter) Write(data []byte) (int, error) {
	remaining := maxVerifierOutput - len(writer.data)
	if remaining > 0 {
		if remaining > len(data) {
			remaining = len(data)
		}
		writer.data = append(writer.data, data[:remaining]...)
	}
	if len(data) > remaining {
		writer.exceeded = true
	}
	return len(data), nil
}

func (r *outputRunner) run(ctx context.Context, dir string, env []string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	var stdout, stderr cappedWriter
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("verify checked-out commit: %w", err)
	}
	if stdout.exceeded || stderr.exceeded {
		return fmt.Errorf("verify checked-out commit: verifier output exceeds %d bytes", maxVerifierOutput)
	}
	r.output = string(stdout.data)
	return nil
}
