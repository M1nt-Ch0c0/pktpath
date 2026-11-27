//go:build windows

package main

import (
	"os"
	"time"
)

func main() {
	os.Exit(runWindowsTray())
}

func runWindowsTray() int {
	opt := ParseTrayArgs(os.Args[1:], os.Getenv, currentExecutable())
	host := newTrayHost(opt)
	globalTray = host

	// Single-instance mutex keyed by the data directory.
	hMutex, already, err := createMutex(MutexName(host.paths.AppDir))
	if err != nil {
		messageBox(0, "无法创建单实例锁，启动中止。\n"+err.Error(), "PktPath Studio", mbOK|mbIconError|mbSetForeground|mbTopmost)
		return 1
	}
	defer closeHandle(hMutex)
	if already {
		url, ok := ProbeExistingWait(host.paths.RuntimePath, ProbeWait)
		if ok && safeLocalURL(url) && !opt.NoOpen {
			shellExecuteOpen(url)
			return 0
		}
		// First instance exists (or is still starting). Do not start a second
		// backend. If we found a live window, we already tried to open it.
		_ = findTrayWindow()
		return 0
	}

	if err := ValidateInstall(host.paths, opt.SkipHash); err != nil {
		messageBox(0, err.Error()+"\n\n日志目录（若已创建）：\n"+host.paths.LogsDir, "PktPath Studio", mbOK|mbIconError|mbSetForeground|mbTopmost)
		return 1
	}

	host.hInst = getModuleHandle()
	host.hIcon = loadAppIcon(host.hInst)
	if err := registerClass(TrayWindowClass, trayWndProc, host.hInst, host.hIcon); err != nil {
		messageBox(0, "无法注册托盘窗口类。\n"+err.Error(), "PktPath Studio", mbOK|mbIconError|mbSetForeground|mbTopmost)
		return 1
	}
	hwnd, err := createHiddenWindow(TrayWindowClass, "PktPath Studio", host.hInst)
	if err != nil {
		messageBox(0, "无法创建托盘窗口。\n"+err.Error(), "PktPath Studio", mbOK|mbIconError|mbSetForeground|mbTopmost)
		return 1
	}
	host.hwnd = hwnd
	host.tbCreated = registerTaskbarCreated()
	if host.tbCreated != 0 {
		allowMessage(hwnd, host.tbCreated)
	}
	host.addIcon()
	host.setTip("PktPath Studio 正在启动…")

	// Start the Node backend on a goroutine so the message loop is live
	// (Explorer / NSIS can already see the window class).
	go func() {
		if err := host.launcher.Start(); err != nil {
			host.setTip("PktPath Studio 启动失败，请查看日志")
			messageBox(hwnd, err.Error()+"\n\n日志目录：\n"+host.paths.LogsDir, "PktPath Studio", mbOK|mbIconError|mbSetForeground|mbTopmost)
			return
		}
		url := host.launcher.URL()
		host.setTip(tipForURL(url))
		if !opt.NoOpen && safeLocalURL(url) {
			shellExecuteOpen(url)
		}
	}()

	code := messageLoop()
	// Belt and suspenders if the loop exits without shutdown.
	host.mu.Lock()
	done := host.shutting
	host.mu.Unlock()
	if !done {
		host.shutdown()
		// Give shutdown a moment if we raced with WM_QUIT from elsewhere.
		time.Sleep(50 * time.Millisecond)
	}
	return code
}
