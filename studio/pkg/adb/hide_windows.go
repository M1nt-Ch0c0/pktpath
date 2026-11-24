//go:build windows

package adb

import (
	"os/exec"
	"syscall"
)

// createNoWindow is the Win32 CREATE_NO_WINDOW process creation flag.
const createNoWindow = 0x08000000

// HideConsole makes sure a child process never flashes a console window.
// Every exec.Command in PktPath Studio (adb.exe, powershell.exe, msedge.exe...)
// MUST go through this helper.
func HideConsole(cmd *exec.Cmd) *exec.Cmd {
	if cmd == nil {
		return nil
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= createNoWindow
	return cmd
}
