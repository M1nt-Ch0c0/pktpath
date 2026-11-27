//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

const (
	wmNull            = 0x0000
	wmDestroy         = 0x0002
	wmClose           = 0x0010
	wmQueryEndSession = 0x0011
	wmEndSession      = 0x0016
	wmContextMenu     = 0x007B
	wmCommand         = 0x0111
	wmRButtonUp       = 0x0205
	wmLButtonUp       = 0x0202
	wmLButtonDblClk   = 0x0203
	wmApp             = 0x8000
	wmTray            = wmApp + 1
	wmActivate        = wmApp + 2

	wsOverlapped = 0x00000000
	swHide       = 0
	swShowNormal = 1

	mfString    = 0x0000
	mfSeparator = 0x0800
	mfDefault   = 0x1000

	tpmLeftAlign   = 0x0000
	tpmRightButton = 0x0002
	tpmBottomAlign = 0x0020
	tpmRightAlign  = 0x0008

	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004
	nifInfo    = 0x00000010

	idiApplication = 32512
	idcArrow       = 32512

	mbOK            = 0x00000000
	mbIconError     = 0x00000010
	mbIconWarning   = 0x00000030
	mbSetForeground = 0x00010000
	mbTopmost       = 0x00040000
	mbOKCancel      = 0x00000001

	errorAlreadyExists = 183

	msgfltAllow = 1

	menuOpen     = 1001
	menuSessions = 1002
	menuLogs     = 1003
	menuRestart  = 1004
	menuExit     = 1005
)

var (
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modUser32   = syscall.NewLazyDLL("user32.dll")
	modShell32  = syscall.NewLazyDLL("shell32.dll")

	procGetModuleHandleW = modKernel32.NewProc("GetModuleHandleW")
	procCreateMutexW     = modKernel32.NewProc("CreateMutexW")
	procGetLastError     = modKernel32.NewProc("GetLastError")
	procCloseHandle      = modKernel32.NewProc("CloseHandle")

	procRegisterClassExW            = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW             = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW              = modUser32.NewProc("DefWindowProcW")
	procGetMessageW                 = modUser32.NewProc("GetMessageW")
	procTranslateMessage            = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW            = modUser32.NewProc("DispatchMessageW")
	procPostQuitMessage             = modUser32.NewProc("PostQuitMessage")
	procPostMessageW                = modUser32.NewProc("PostMessageW")
	procDestroyWindow               = modUser32.NewProc("DestroyWindow")
	procShowWindow                  = modUser32.NewProc("ShowWindow")
	procLoadIconW                   = modUser32.NewProc("LoadIconW")
	procLoadCursorW                 = modUser32.NewProc("LoadCursorW")
	procRegisterWindowMessageW      = modUser32.NewProc("RegisterWindowMessageW")
	procChangeWindowMessageFilterEx = modUser32.NewProc("ChangeWindowMessageFilterEx")
	procMessageBoxW                 = modUser32.NewProc("MessageBoxW")
	procCreatePopupMenu             = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW                 = modUser32.NewProc("AppendMenuW")
	procSetMenuDefaultItem          = modUser32.NewProc("SetMenuDefaultItem")
	procTrackPopupMenu              = modUser32.NewProc("TrackPopupMenu")
	procDestroyMenu                 = modUser32.NewProc("DestroyMenu")
	procGetCursorPos                = modUser32.NewProc("GetCursorPos")
	procSetForegroundWindow         = modUser32.NewProc("SetForegroundWindow")
	procFindWindowW                 = modUser32.NewProc("FindWindowW")

	procShellNotifyIconW = modShell32.NewProc("Shell_NotifyIconW")
	procShellExecuteW    = modShell32.NewProc("ShellExecuteW")
)

type wndClassExW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type msg struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	_       uint32 // alignment on 64-bit sometimes includes lPrivate
}

type point struct {
	X int32
	Y int32
}

// notifyIconDataW matches NOTIFYICONDATAW on 64-bit Windows (cbSize=976).
type notifyIconDataW struct {
	CbSize           uint32
	_pad0            uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	_pad1            uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         [16]byte
	HBalloonIcon     uintptr
}

func utf16Ptr(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		p, _ = syscall.UTF16PtrFromString("")
	}
	return p
}

func copyUTF16(dst []uint16, s string) {
	clear(dst)
	u, _ := syscall.UTF16FromString(s)
	n := len(u)
	if n > len(dst) {
		n = len(dst)
		u = u[:n]
		u[n-1] = 0
	}
	copy(dst, u)
}

func loWord(v uintptr) uint32 { return uint32(v) & 0xFFFF }
func hiWord(v uintptr) uint32 { return uint32(v>>16) & 0xFFFF }

func getModuleHandle() uintptr {
	r, _, _ := procGetModuleHandleW.Call(0)
	return r
}

func loadAppIcon(hInst uintptr) uintptr {
	r, _, _ := procLoadIconW.Call(hInst, 1) // MAKEINTRESOURCE(1)
	if r != 0 {
		return r
	}
	r, _, _ = procLoadIconW.Call(0, uintptr(idiApplication))
	return r
}

func loadArrowCursor() uintptr {
	r, _, _ := procLoadCursorW.Call(0, uintptr(idcArrow))
	return r
}

func registerClass(class string, proc uintptr, hInst, hIcon uintptr) error {
	var wc wndClassExW
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	wc.LpfnWndProc = proc
	wc.HInstance = hInst
	wc.HIcon = hIcon
	wc.HIconSm = hIcon
	wc.HCursor = loadArrowCursor()
	wc.LpszClassName = utf16Ptr(class)
	r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if r == 0 {
		return err
	}
	return nil
}

func createHiddenWindow(class, title string, hInst uintptr) (uintptr, error) {
	r, _, err := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(utf16Ptr(class))),
		uintptr(unsafe.Pointer(utf16Ptr(title))),
		wsOverlapped,
		0, 0, 0, 0,
		0, 0, hInst, 0,
	)
	if r == 0 {
		return 0, err
	}
	procShowWindow.Call(r, uintptr(swHide))
	return r, nil
}

func defWindowProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}

func postQuitMessage(code int) {
	procPostQuitMessage.Call(uintptr(code))
}

func destroyWindow(hwnd uintptr) {
	procDestroyWindow.Call(hwnd)
}

func postMessage(hwnd uintptr, msg uint32, wparam, lparam uintptr) bool {
	r, _, _ := procPostMessageW.Call(hwnd, uintptr(msg), wparam, lparam)
	return r != 0
}

func postActivateMessage(hwnd uintptr, noOpen bool) bool {
	var wp uintptr
	if noOpen {
		wp = 1
	}
	return postMessage(hwnd, wmActivate, wp, 0)
}

func messageLoop() int {
	var m msg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		// GetMessage returns 0 on WM_QUIT, -1 on error.
		if int32(r) == 0 {
			return int(m.WParam)
		}
		if int32(r) < 0 {
			return 1
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func registerTaskbarCreated() uint32 {
	r, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(utf16Ptr("TaskbarCreated"))))
	return uint32(r)
}

func allowMessage(hwnd uintptr, msg uint32) {
	// ChangeWindowMessageFilterEx(hwnd, msg, MSGFLT_ALLOW, NULL)
	procChangeWindowMessageFilterEx.Call(hwnd, uintptr(msg), msgfltAllow, 0)
}

func messageBox(hwnd uintptr, text, caption string, flags uint32) {
	procMessageBoxW.Call(
		hwnd,
		uintptr(unsafe.Pointer(utf16Ptr(text))),
		uintptr(unsafe.Pointer(utf16Ptr(caption))),
		uintptr(flags),
	)
}

func shellExecuteOpen(target string) {
	procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(utf16Ptr("open"))),
		uintptr(unsafe.Pointer(utf16Ptr(target))),
		0,
		0,
		uintptr(swShowNormal),
	)
}

func createMutex(name string) (handle uintptr, already bool, err error) {
	h, _, callErr := procCreateMutexW.Call(0, 1, uintptr(unsafe.Pointer(utf16Ptr(name))))
	if h == 0 {
		return 0, false, callErr
	}
	// last error is also returned in callErr when ERROR_ALREADY_EXISTS
	if errno, ok := callErr.(syscall.Errno); ok && errno == errorAlreadyExists {
		return h, true, nil
	}
	// Belt and suspenders: query GetLastError as well.
	le, _, _ := procGetLastError.Call()
	if le == errorAlreadyExists {
		return h, true, nil
	}
	return h, false, nil
}

func closeHandle(h uintptr) {
	procCloseHandle.Call(h)
}

func notifyIcon(dwMessage uint32, nid *notifyIconDataW) bool {
	r, _, _ := procShellNotifyIconW.Call(uintptr(dwMessage), uintptr(unsafe.Pointer(nid)))
	return r != 0
}

func popupTrayMenu(hwnd uintptr) {
	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	append := func(flags, id uint32, text string) {
		procAppendMenuW.Call(hMenu, uintptr(flags), uintptr(id), uintptr(unsafe.Pointer(utf16Ptr(text))))
	}
	append(mfString|mfDefault, menuOpen, "打开 PktPath Studio")
	append(mfString, menuSessions, "打开会话目录")
	append(mfString, menuLogs, "查看日志")
	append(mfSeparator, 0, "")
	append(mfString, menuRestart, "重启服务")
	append(mfString, menuExit, "退出")
	procSetMenuDefaultItem.Call(hMenu, uintptr(menuOpen), 0)

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(hwnd)
	procTrackPopupMenu.Call(
		hMenu,
		uintptr(tpmLeftAlign|tpmRightButton|tpmBottomAlign),
		uintptr(pt.X),
		uintptr(pt.Y),
		0,
		hwnd,
		0,
	)
	postMessage(hwnd, wmNull, 0, 0)
}

func findTrayWindow() uintptr {
	r, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(utf16Ptr(TrayWindowClass))), 0)
	return r
}
