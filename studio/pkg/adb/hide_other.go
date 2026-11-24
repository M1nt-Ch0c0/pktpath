//go:build !windows

package adb

import "os/exec"

// HideConsole is a no-op outside Windows.
func HideConsole(cmd *exec.Cmd) *exec.Cmd { return cmd }
