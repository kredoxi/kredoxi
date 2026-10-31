//go:build linux

package main

import (
	"os"
	"os/exec"
	"syscall"
)

func configureCommand(command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, Pdeathsig: syscall.SIGKILL,
	}
	return nil
}

func containStartedProcess(_ *os.Process) (func() error, error) {
	return func() error { return nil }, nil
}
