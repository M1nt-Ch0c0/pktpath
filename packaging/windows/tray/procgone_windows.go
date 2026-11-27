//go:build windows

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
	// OpenProcess via Find; a zero-timeout WaitForSingleObject would be
	// ideal, but standard library Process.Signal on Windows does not
	// implement signal 0. Try waiting 0 via wait helpers after Kill only.
	// While the process is running and Wait has not been called,
	// ProcessState is nil; treat as still alive.
	h, err := syscall.OpenProcess(syscall.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return true
	}
	defer syscall.CloseHandle(h)
	ev, err := syscall.WaitForSingleObject(h, 0)
	if err != nil {
		return false
	}
	// WAIT_OBJECT_0 = 0 => signaled (exited); WAIT_TIMEOUT = 258
	return ev == 0
}
