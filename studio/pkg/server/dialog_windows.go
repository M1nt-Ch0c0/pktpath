//go:build windows

package server

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"pktpath/studio/pkg/adb"
)

var (
	modComdlg32              = syscall.NewLazyDLL("comdlg32.dll")
	procGetSaveFileNameW     = modComdlg32.NewProc("GetSaveFileNameW")
	procCommDlgExtendedError = modComdlg32.NewProc("CommDlgExtendedError")

	modUser32            = syscall.NewLazyDLL("user32.dll")
	procCreateWindowExW  = modUser32.NewProc("CreateWindowExW")
	procDestroyWindow    = modUser32.NewProc("DestroyWindow")
	procSetForegroundWnd = modUser32.NewProc("SetForegroundWindow")
)

const (
	ofnOverwritePrompt = 0x00000002
	ofnNoChangeDir     = 0x00000008
	ofnPathMustExist   = 0x00000800
	ofnExplorer        = 0x00080000

	wsPopup      = 0x80000000
	wsExTopmost  = 0x00000008
	wsExToolWnd  = 0x00000080
)

// openFileNameW matches Win32 OPENFILENAMEW on 64-bit/32-bit Windows.
type openFileNameW struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        uintptr
	dwReserved        uint32
	flagsEx           uint32
}

// saveFileNative opens the fast Win32 comdlg32 GetSaveFileNameW modal dialog.
func saveFileNative(_ context.Context, defaultName, initialDir, filter string) (string, bool, error) {
	type res struct {
		path      string
		cancelled bool
		err       error
	}
	ch := make(chan res, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		if initialDir == "" {
			if up := os.Getenv("USERPROFILE"); up != "" {
				dl := filepath.Join(up, "Downloads")
				if st, err := os.Stat(dl); err == nil && st.IsDir() {
					initialDir = dl
				} else {
					initialDir = up
				}
			}
		} else if st, err := os.Stat(initialDir); err != nil || !st.IsDir() {
			initialDir = ""
		}

		cleanName := sanitizeSaveFileName(defaultName)
		defExt := strings.TrimPrefix(filepath.Ext(cleanName), ".")
		if defExt == "" {
			defExt = "pcapng"
		}

		fileBuf := make([]uint16, 4096)
		if cleanName != "" {
			u, _ := syscall.UTF16FromString(cleanName)
			copy(fileBuf, u)
		}

		filterUTF16 := encodeWin32Filter(filter)
		titleUTF16, _ := syscall.UTF16PtrFromString("导出保存位置 - PktPath Studio")
		defExtUTF16, _ := syscall.UTF16PtrFromString(defExt)
		var initDirUTF16 *uint16
		if initialDir != "" {
			initDirUTF16, _ = syscall.UTF16PtrFromString(initialDir)
		}

		// Create a tiny invisible topmost owner window so the Save-As dialog
		// always appears in front of the user's browser window.
		cls, _ := syscall.UTF16PtrFromString("STATIC")
		empty, _ := syscall.UTF16PtrFromString("")
		hwnd, _, _ := procCreateWindowExW.Call(
			wsExTopmost|wsExToolWnd,
			uintptr(unsafe.Pointer(cls)),
			uintptr(unsafe.Pointer(empty)),
			wsPopup,
			0, 0, 0, 0,
			0, 0, 0, 0,
		)
		if hwnd != 0 {
			defer procDestroyWindow.Call(hwnd)
			_, _, _ = procSetForegroundWnd.Call(hwnd)
		}

		ofn := openFileNameW{
			lStructSize:     uint32(unsafe.Sizeof(openFileNameW{})),
			hwndOwner:       hwnd,
			lpstrFilter:     &filterUTF16[0],
			nFilterIndex:    1,
			lpstrFile:       &fileBuf[0],
			nMaxFile:        uint32(len(fileBuf)),
			lpstrInitialDir: initDirUTF16,
			lpstrTitle:      titleUTF16,
			flags:           ofnOverwritePrompt | ofnPathMustExist | ofnNoChangeDir | ofnExplorer,
			lpstrDefExt:     defExtUTF16,
		}

		ret, _, _ := procGetSaveFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
		if ret == 0 {
			extErr, _, _ := procCommDlgExtendedError.Call()
			if extErr == 0 {
				ch <- res{cancelled: true}
				return
			}
			ch <- res{err: fmt.Errorf("GetSaveFileNameW error 0x%x", extErr)}
			return
		}
		chosen := syscall.UTF16ToString(fileBuf)
		if chosen == "" {
			ch <- res{cancelled: true}
			return
		}
		ch <- res{path: chosen}
	}()
	r := <-ch
	return r.path, r.cancelled, r.err
}

func sanitizeSaveFileName(name string) string {
	name = strings.TrimSpace(filepath.Base(name))
	if name == "." || name == ".." || name == string(os.PathSeparator) {
		return ""
	}
	var b strings.Builder
	for _, r := range name {
		switch r {
		case '<', '>', ':', '"', '/', '\\', '|', '?', '*':
			b.WriteByte('_')
		default:
			if r >= 32 {
				b.WriteRune(r)
			}
		}
	}
	return strings.TrimSpace(b.String())
}

// encodeWin32Filter converts pipe-delimited "Desc|*.ext|All|*.*" into a
// double-NUL-terminated UTF-16 slice required by OPENFILENAMEW.
func encodeWin32Filter(filter string) []uint16 {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		filter = "Wireshark Capture (*.pcapng)|*.pcapng|All Files (*.*)|*.*"
	}
	parts := strings.Split(filter, "|")
	if len(parts)%2 != 0 {
		parts = append(parts, "*.*")
	}
	var out []uint16
	for _, p := range parts {
		u, _ := syscall.UTF16FromString(p)
		out = append(out, u...) // includes trailing 0
	}
	out = append(out, 0) // final terminating 0
	return out
}

// revealPathNative opens Windows Explorer in the foreground (selecting the file
// when isDir is false, or opening the folder directly when isDir is true).
func revealPathNative(abs string, isDir bool) error {
	// Intentionally DO NOT call adb.HideConsole here so Explorer opens in front!
	var cmd *exec.Cmd
	if isDir {
		cmd = exec.Command("explorer.exe", abs)
	} else {
		cmd = exec.Command("explorer.exe")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			CmdLine: fmt.Sprintf(`explorer.exe /select,"%s"`, abs),
		}
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// pickFolderNative opens a native Windows FolderBrowserDialog on a hidden STA
// PowerShell process (zero console flash via adb.HideConsole).
func pickFolderNative(ctx context.Context, initialDir string) (string, bool, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	psScript := `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()
$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$owner.ShowInTaskbar = $false
$owner.Width = 1
$owner.Height = 1
$owner.StartPosition = 'CenterScreen'
$owner.Opacity = 0
$owner.Show()
$dlg = New-Object System.Windows.Forms.FolderBrowserDialog
$dlg.Description = '选择 PktPath 会话文件夹'
$dlg.UseDescriptionForTitle = $true
$dlg.ShowNewFolderButton = $true
$init = $env:PKTPATH_INIT_DIR
if ($init -and (Test-Path -LiteralPath $init)) {
    $dlg.SelectedPath = $init
}
$res = $dlg.ShowDialog($owner)
$owner.Close()
if ($res -eq [System.Windows.Forms.DialogResult]::OK -and $dlg.SelectedPath) {
    Write-Output ("@@path=" + $dlg.SelectedPath)
} else {
    Write-Output "@@cancelled=1"
}
`
	exe := "powershell.exe"
	if p, err := exec.LookPath("powershell.exe"); err == nil {
		exe = p
	}
	cmd := adb.HideConsole(exec.CommandContext(cctx, exe,
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-STA",
		"-Command", psScript,
	))
	if initialDir != "" {
		cmd.Env = append(cmd.Environ(), "PKTPATH_INIT_DIR="+initialDir)
	}
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	for _, ln := range strings.Split(strings.ReplaceAll(out.String(), "\r\n", "\n"), "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "@@path=") {
			p := strings.TrimSpace(strings.TrimPrefix(ln, "@@path="))
			if p != "" {
				return p, false, nil
			}
		}
		if ln == "@@cancelled=1" {
			return "", true, nil
		}
	}
	if err != nil {
		return "", false, err
	}
	return "", true, nil
}
