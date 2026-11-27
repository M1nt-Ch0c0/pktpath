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
		messageBox(0, "无法启动 PktPath Studio，请关闭后重试。", "PktPath Studio", mbOK|mbIconError|mbSetForeground|mbTopmost)
		return 1
	}
	defer closeHandle(hMutex)
	if already {
		outcome := HandleSecondInstance(
			func() (string, bool) { return ProbeExisting(host.paths.RuntimePath) },
			findTrayWindow,
			postActivateMessage,
			func(url string) {
				if safeLocalURL(url) {
					shellExecuteOpen(url)
				}
			},
			opt.NoOpen,
			SecondInstanceWait,
			SecondInstancePoll,
		)
		if outcome == OutcomeUnresponsive {
			messageBox(
				0,
				"PktPath Studio 后台程序未响应，请先在任务栏右下角托盘图标右键选择「退出」（或在任务管理器结束 PktPathStudio.exe）后重试。",
				"PktPath Studio",
				mbOK|mbIconWarning|mbSetForeground|mbTopmost,
			)
			return 1
		}
		return 0
	}

	if err := ValidateInstall(host.paths, opt.SkipHash); err != nil {
		messageBox(0, err.Error()+"\n\n日志目录（若已创建）：\n"+host.paths.LogsDir, "PktPath Studio", mbOK|mbIconError|mbSetForeground|mbTopmost)
		return 1
	}

	host.hInst = getModuleHandle()
	host.hIcon = loadAppIcon(host.hInst)
	if err := registerClass(TrayWindowClass, trayWndProc, host.hInst, host.hIcon); err != nil {
		messageBox(0, "无法在系统托盘创建图标，请关闭后重试或重启电脑。", "PktPath Studio", mbOK|mbIconError|mbSetForeground|mbTopmost)
		return 1
	}
	hwnd, err := createHiddenWindow(TrayWindowClass, "PktPath Studio", host.hInst)
	if err != nil {
		messageBox(0, "无法在系统托盘创建图标，请关闭后重试或重启电脑。", "PktPath Studio", mbOK|mbIconError|mbSetForeground|mbTopmost)
		return 1
	}
	host.hwnd = hwnd
	allowMessage(hwnd, wmActivate)
	host.tbCreated = registerTaskbarCreated()
	if host.tbCreated != 0 {
		allowMessage(hwnd, host.tbCreated)
	}
	host.addIcon()
	host.setTip("PktPath Studio 正在启动…")

	// Start the Node backend on a goroutine so the message loop is live
	// (Explorer / NSIS / second launches can already reach the tray window).
	go func() {
		if err := host.launcher.Start(); err != nil {
			host.consumePendingOpen()
			host.setTip("PktPath Studio 启动失败，请查看日志")
			messageBox(hwnd, err.Error()+"\n\n日志目录：\n"+host.paths.LogsDir, "PktPath Studio", mbOK|mbIconError|mbSetForeground|mbTopmost)
			// Exit the tray cleanly instead of leaving an empty shell holding
			// the single-instance mutex.
			postMessage(hwnd, wmClose, 0, 0)
			return
		}
		url := host.launcher.URL()
		host.setTip(tipForURL(url))
		shouldOpen := !opt.NoOpen || host.consumePendingOpen()
		if shouldOpen && safeLocalURL(url) {
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
