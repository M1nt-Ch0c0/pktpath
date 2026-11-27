//go:build windows

package main

import (
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// TrayHost is the hidden window + tray icon + Node backend owner.
type TrayHost struct {
	opts      TrayOptions
	paths     Paths
	launcher  *Launcher
	hwnd      uintptr
	hInst     uintptr
	hIcon     uintptr
	nid       notifyIconDataW
	tbCreated uint32

	mu          sync.Mutex
	shutting    bool
	busy        bool
	pendingOpen bool
}

var trayWndProc = syscall.NewCallback(trayWindowProc)
var globalTray *TrayHost

func newTrayHost(opt TrayOptions) *TrayHost {
	p := ResolvePaths(opt.InstallDir, opt.AppDir)
	l := NewLauncher(p)
	l.SkipHash = opt.SkipHash
	h := &TrayHost{opts: opt, paths: p, launcher: l}
	l.SetOnUnexpectedExit(func(err error) {
		if err == nil {
			// Backend exited cleanly (for example, user clicked Exit in the web UI).
			// Shut down the tray host too so it does not stay behind as an empty shell.
			if h.hwnd != 0 {
				postMessage(h.hwnd, wmClose, 0, 0)
			}
			return
		}
		h.setTip("PktPath Studio 已停止，再次打开或右键「重启服务」即可恢复")
	})
	return h
}

func (h *TrayHost) setTip(s string) {
	if h.hwnd == 0 {
		return
	}
	h.nid.UFlags = nifMessage | nifIcon | nifTip
	copyUTF16(h.nid.SzTip[:], s)
	notifyIcon(nimModify, &h.nid)
}

func (h *TrayHost) addIcon() {
	h.nid.CbSize = uint32(unsafe.Sizeof(h.nid))
	h.nid.HWnd = h.hwnd
	h.nid.UID = 1
	h.nid.UFlags = nifMessage | nifIcon | nifTip
	h.nid.UCallbackMessage = wmTray
	h.nid.HIcon = h.hIcon
	copyUTF16(h.nid.SzTip[:], "PktPath Studio")
	if !notifyIcon(nimAdd, &h.nid) {
		notifyIcon(nimModify, &h.nid)
	}
}

func (h *TrayHost) deleteIcon() {
	if h.hwnd == 0 {
		return
	}
	h.nid.CbSize = uint32(unsafe.Sizeof(h.nid))
	h.nid.HWnd = h.hwnd
	h.nid.UID = 1
	notifyIcon(nimDelete, &h.nid)
}

func (h *TrayHost) consumePendingOpen() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := h.pendingOpen
	h.pendingOpen = false
	return v
}

func (h *TrayHost) openStudio() {
	h.handleActivate(false)
}

// handleActivate is called both on tray left-click/"Open" and when a second
// PktPathStudio.exe launch posts wmActivate. It guarantees that clicking or
// double-clicking always either opens the live UI, waits for an in-flight
// start, or restarts a stopped backend automatically.
func (h *TrayHost) handleActivate(noOpen bool) {
	h.mu.Lock()
	shutting := h.shutting
	busy := h.busy
	h.mu.Unlock()

	decision := DecideTrayActivate(h.launcher.Running(), h.launcher.Starting(), busy, shutting)
	switch decision {
	case ActivateIgnore:
		return
	case ActivateOpenBrowser:
		if noOpen {
			return
		}
		url := h.launcher.URL()
		if url == "" {
			if u, ok := ProbeExisting(h.paths.RuntimePath); ok {
				url = u
			}
		}
		if safeLocalURL(url) {
			shellExecuteOpen(url)
			return
		}
		// URL disappeared unexpectedly; restart the backend cleanly.
		h.restartAsyncWithOpen(true)
	case ActivateWaitAndOpen:
		if !noOpen {
			h.mu.Lock()
			h.pendingOpen = true
			h.mu.Unlock()
		}
	case ActivateRestartAndOpen:
		h.restartAsyncWithOpen(!noOpen)
	}
}

func (h *TrayHost) openDir(dir string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		messageBox(h.hwnd, "无法打开目录：\n"+dir+"\n"+err.Error(), "PktPath Studio", mbOK|mbIconError|mbSetForeground|mbTopmost)
		return
	}
	shellExecuteOpen(dir)
}

func (h *TrayHost) restartAsync() {
	h.restartAsyncWithOpen(!h.opts.NoOpen)
}

func (h *TrayHost) restartAsyncWithOpen(openAfter bool) {
	h.mu.Lock()
	if h.shutting || h.busy {
		if openAfter {
			h.pendingOpen = true
		}
		h.mu.Unlock()
		return
	}
	h.busy = true
	h.mu.Unlock()
	go func() {
		defer func() {
			h.mu.Lock()
			h.busy = false
			h.mu.Unlock()
		}()
		h.setTip("PktPath Studio 正在启动…")
		if err := h.launcher.Restart(); err != nil {
			h.consumePendingOpen()
			h.setTip("PktPath Studio 启动失败，请查看日志")
			messageBox(h.hwnd, err.Error()+"\n\n日志目录：\n"+h.paths.LogsDir, "PktPath Studio", mbOK|mbIconError|mbSetForeground|mbTopmost)
			return
		}
		url := h.launcher.URL()
		h.setTip(tipForURL(url))
		shouldOpen := openAfter || h.consumePendingOpen()
		if shouldOpen && safeLocalURL(url) {
			shellExecuteOpen(url)
		}
	}()
}

// shutdown performs the graceful-exit path and is safe to call more than once.
// It is deliberately synchronous so an NSIS SendMessage(WM_CLOSE) waits until
// the Node backend has been asked to quit.
func (h *TrayHost) shutdown() {
	h.mu.Lock()
	if h.shutting {
		h.mu.Unlock()
		return
	}
	h.shutting = true
	h.mu.Unlock()

	h.setTip("PktPath Studio 正在退出…")
	_ = h.launcher.Stop()
	h.deleteIcon()
	RemoveRuntime(h.paths.RuntimePath)
	if h.hwnd != 0 {
		destroyWindow(h.hwnd)
	}
}

func tipForURL(url string) string {
	if url == "" {
		return "PktPath Studio"
	}
	return "PktPath Studio\n" + url
}

func safeLocalURL(url string) bool {
	u := strings.ToLower(strings.TrimSpace(url))
	return strings.HasPrefix(u, "http://127.0.0.1:") ||
		strings.HasPrefix(u, "http://127.0.0.1/") ||
		strings.HasPrefix(u, "http://localhost:") ||
		strings.HasPrefix(u, "http://localhost/")
}

func trayWindowProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	h := globalTray
	if h == nil {
		return defWindowProc(hwnd, msg, wparam, lparam)
	}
	switch msg {
	case wmTray:
		switch loWord(lparam) {
		case wmLButtonUp, wmLButtonDblClk:
			h.openStudio()
		case wmRButtonUp:
			popupTrayMenu(hwnd)
		}
		return 0
	case wmActivate:
		h.handleActivate(wparam != 0)
		return 0
	case wmCommand:
		switch loWord(wparam) {
		case menuOpen:
			h.openStudio()
		case menuSessions:
			h.openDir(h.paths.SessionsDir)
		case menuLogs:
			h.openDir(h.paths.LogsDir)
		case menuRestart:
			h.restartAsync()
		case menuExit:
			h.shutdown()
		}
		return 0
	case wmClose:
		h.shutdown()
		return 0
	case wmQueryEndSession:
		return 1
	case wmEndSession:
		if wparam != 0 {
			h.shutdown()
		}
		return 0
	case wmDestroy:
		postQuitMessage(0)
		return 0
	default:
		if h.tbCreated != 0 && msg == uintptr(h.tbCreated) {
			h.addIcon()
			return 0
		}
	}
	return defWindowProc(hwnd, msg, wparam, lparam)
}
