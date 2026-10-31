//go:build !linux && !windows

package main

import (
	"os"
	"os/exec"
)

func configureCommand(_ *exec.Cmd) error { return nil }

func containStartedProcess(_ *os.Process) (func() error, error) {
	return func() error { return nil }, nil
}
