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

	mu       sync.Mutex
	shutting bool
	busy     bool
}

var trayWndProc = syscall.NewCallback(trayWindowProc)
var globalTray *TrayHost

func newTrayHost(opt TrayOptions) *TrayHost {
	p := ResolvePaths(opt.InstallDir, opt.AppDir)
	l := NewLauncher(p)
	l.SkipHash = opt.SkipHash
	h := &TrayHost{opts: opt, paths: p, launcher: l}
	l.SetOnUnexpectedExit(func(err error) {
		h.setTip("PktPath Studio 已停止，可通过托盘「重启服务」恢复")
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

func (h *TrayHost) openStudio() {
	url := h.launcher.URL()
	if url == "" {
		if u, ok := ProbeExisting(h.paths.RuntimePath); ok {
			url = u
		}
	}
	if !safeLocalURL(url) {
		messageBox(h.hwnd, "Studio 尚未就绪，请稍候或从托盘「查看日志」。\n日志目录：\n"+h.paths.LogsDir, "PktPath Studio", mbOK|mbIconWarning|mbSetForeground|mbTopmost)
		return
	}
	shellExecuteOpen(url)
}

func (h *TrayHost) openDir(dir string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		messageBox(h.hwnd, "无法打开目录：\n"+dir+"\n"+err.Error(), "PktPath Studio", mbOK|mbIconError|mbSetForeground|mbTopmost)
		return
	}
	shellExecuteOpen(dir)
}

func (h *TrayHost) restartAsync() {
	h.mu.Lock()
	if h.shutting || h.busy {
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
		h.setTip("PktPath Studio 正在重启…")
		if err := h.launcher.Restart(); err != nil {
			h.setTip("PktPath Studio 重启失败，请查看日志")
			messageBox(h.hwnd, err.Error()+"\n\n日志目录：\n"+h.paths.LogsDir, "PktPath Studio", mbOK|mbIconError|mbSetForeground|mbTopmost)
			return
		}
		url := h.launcher.URL()
		h.setTip(tipForURL(url))
		if !h.opts.NoOpen && safeLocalURL(url) {
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
