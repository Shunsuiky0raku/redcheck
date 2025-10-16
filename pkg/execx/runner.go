package execx

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

type Runner interface {
	Run(cmd string, args []string, timeout time.Duration) (string, string, int, error)
}

type LocalRunner struct{}

func (LocalRunner) Run(cmd string, args []string, timeout time.Duration) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, cmd, args...)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	err := c.Run()
	code := 0
	if c.ProcessState != nil {
		code = c.ProcessState.ExitCode()
	}
	return out.String(), errb.String(), code, err
}
