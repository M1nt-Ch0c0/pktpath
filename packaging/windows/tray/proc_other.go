//go:build !windows

package main

import "os/exec"

func applyHiddenWindow(cmd *exec.Cmd) {
	// No-op off Windows: there is no console window to hide.
}
