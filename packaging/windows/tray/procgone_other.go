//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

func processGone(cmd *exec.Cmd) bool {
	if cmd == nil || cmd.Process == nil {
		return true
	}
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return true
	}
	err := cmd.Process.Signal(syscall.Signal(0))
	return err != nil
}
