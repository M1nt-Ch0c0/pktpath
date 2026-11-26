//go:build windows

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/jchv/go-webview2"

	"pktpath/studio"
	"pktpath/studio/pkg/adb"
	"pktpath/studio/pkg/kernel"
	"pktpath/studio/pkg/server"
)

const studioVersion = "2.0.0"

type instanceInfo struct {
	PID  int    `json:"pid"`
	Port int    `json:"port"`
	URL  string `json:"url"`
}

func main() {
	enableHighDPI()

	var (
		flagHeadless      = flag.Bool("headless", false, "Run localhost HTTP server without opening a browser or window")
		flagWindow        = flag.Bool("window", false, "Open inside native Win32 WebView2 window instead of system default browser")
		flagPort          = flag.Int("port", 0, "TCP port on 127.0.0.1 (0 = ephemeral)")
		flagSelftest      = flag.Bool("selftest", false, "Run automated runtime + live-device E2E self-test and exit")
		flagSerial        = flag.String("serial", "", "Target Android device serial for --selftest")
		flagDev           = flag.String("dev", "wlan0", "Target network interface for --selftest")
		flagReport        = flag.String("report", "", "Write --selftest JSON report to this path")
		flagOut           = flag.String("out", "", "Alias for --report")
		flagKeepSession   = flag.Bool("keep-session", false, "Keep pulled session directory after --selftest")
		flagAppDir        = flag.String("app-dir", "", "Override %LOCALAPPDATA%\\PktPathStudio directory")
		flagAdb           = flag.String("adb", "", "Override path to system adb executable")
		flagPluginDir     = flag.String("plugin-dir", "", "Override runtime plugin JSON directory (default <app-dir>\\plugins)")
		flagConfigTxn     = flag.Bool("cordis-config-transactions", false, "EXPERIMENTAL F03.0 metadata config compensation; requires cordis-plugin-host")
		flagPluginHost    = flag.String("cordis-plugin-host", "", "EXPERIMENTAL F02: Cordis3 lifecycle.mjs metadata scheduler; empty leaves F02 off")
		flagPluginNode    = flag.String("cordis-plugin-node", "node", "EXPERIMENTAL F02: explicit candidate Node runtime; no auto install")
		flagCordisHost    = flag.String("cordis-analyzer-host", "", "EXPERIMENTAL F01: absolute legacy host.mjs path; empty leaves F01 off")
		flagCordisNode    = flag.String("cordis-analyzer-node", "", "Explicit Node executable for optional F01 analyzer host or plugin runtime; empty auto-resolves PKTPATH_CORDIS_NODE / bundled Node / PATH")
		flagPluginRuntime = flag.String("cordis-plugin-runtime", "", "Cordis in-process plugin runtime (plugin-runtime.mjs); empty uses the bundled new-preview default")
		flagDebug         = flag.Bool("debug", true, "Enable WebView2 context menu & DevTools")
	)

	// Attach to parent console ONLY for CLI modes when stdout isn't already piped.
	// Never allocate a new console window (zero black window flash on double-click).
	for _, a := range os.Args[1:] {
		if a == "--headless" || a == "-headless" || a == "--selftest" || a == "-selftest" || a == "-h" || a == "--help" {
			attachParentConsoleIfNeeded()
			break
		}
	}
	flag.Parse()

	appDir := *flagAppDir
	if appDir == "" {
		appDir = adb.DefaultAppDir()
	}
	_ = os.MkdirAll(appDir, 0o755)
	instancePath := filepath.Join(appDir, "instance.json")

	// Single-instance reuse for default browser mode (double-click .exe).
	if *flagPort == 0 && !*flagHeadless && !*flagSelftest && !*flagWindow {
		if existingURL := probeExistingInstance(instancePath); existingURL != "" {
			_ = openDefaultBrowser(existingURL + "/")
			os.Exit(0)
		}
	}

	logFile, logger := openLogger(appDir, *flagHeadless || *flagSelftest)
	if logFile != nil {
		defer logFile.Close()
	}

	stageFS, _ := studio.AssetsStageFS()
	webFS, err := studio.WebFS()
	if err != nil {
		logger.Printf("fatal: embedded web assets error: %v", err)
		os.Exit(1)
	}

	rt, err := adb.ExtractRuntime(stageFS, filepath.Join(appDir, "runtime"))
	if err != nil {
		logger.Printf("runtime extraction warning: %v", err)
	}
	if strings.TrimSpace(*flagAdb) != "" {
		rt.AdbPath = strings.TrimSpace(*flagAdb)
		rt.AdbEmbedded = false
	}
	logger.Printf("PktPath Studio v%s runtime ready in %.2fms (adb=%s embedded=%v agent_sha=%s)",
		studioVersion, rt.ExtractMs, rt.AdbPath, rt.AdbEmbedded, adb.ShortSHA(rt.AgentSHA256, 12))

	runtimeHost, runtimeNode, runtimeErr := kernel.ResolveDefaultPluginRuntime(strings.TrimSpace(*flagPluginRuntime), strings.TrimSpace(*flagCordisNode))
	if strings.TrimSpace(*flagPluginRuntime) != "" && runtimeErr != nil {
		logger.Printf("fatal: cordis plugin runtime: %v", runtimeErr)
		os.Exit(1)
	}
	if runtimeErr != nil {
		logger.Printf("warning: new preview default Cordis plugin runtime not resolved (%v); entrypoint.module plugins will not load", runtimeErr)
	} else {
		logger.Printf("Cordis plugin runtime default host=%s node=%s", runtimeHost, runtimeNode)
	}

	srv := server.New(server.Options{
		Runtime:                  rt,
		Web:                      webFS,
		AppDir:                   appDir,
		PluginsDir:               strings.TrimSpace(*flagPluginDir),
		Logger:                   logger,
		Version:                  studioVersion,
		CordisAnalyzerHost:       strings.TrimSpace(*flagCordisHost),
		CordisAnalyzerNode:       defaultNodeIfEmpty(*flagCordisNode),
		CordisPluginHost:         strings.TrimSpace(*flagPluginHost),
		CordisPluginNode:         *flagPluginNode,
		CordisConfigTransactions: *flagConfigTxn,
		CordisPluginRuntime:      runtimeHost,
		CordisPluginRuntimeNode:  runtimeNode,
	})

	if *flagSelftest {
		reportPath := *flagReport
		if reportPath == "" {
			reportPath = *flagOut
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		rep := srv.RunSelftest(ctx, server.SelftestOptions{
			Serial:      *flagSerial,
			Dev:         *flagDev,
			KeepSession: *flagKeepSession,
		})
		outBytes, _ := json.MarshalIndent(rep, "", "  ")
		outBytes = append(outBytes, '\n')
		if reportPath != "" {
			_ = os.MkdirAll(filepath.Dir(reportPath), 0o755)
			if werr := os.WriteFile(reportPath, outBytes, 0o644); werr != nil {
				logger.Printf("failed to write selftest report %s: %v", reportPath, werr)
				os.Exit(1)
			}
		}
		_, _ = os.Stdout.Write(outBytes)
		if !rep.OK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	bindAddr := fmt.Sprintf("127.0.0.1:%d", *flagPort)
	ln, err := srv.Listen(bindAddr)
	if err != nil {
		logger.Printf("fatal: failed to listen on %s: %v", bindAddr, err)
		os.Exit(1)
	}
	baseURL := "http://" + ln.Addr().String()
	logger.Printf("HTTP workbench listening at %s", baseURL)

	writeInstanceFile(instancePath, srv.Port(), baseURL)
	defer cleanupInstanceFile(instancePath)

	go func() {
		if err := srv.Serve(ln); err != nil {
			logger.Printf("server error: %v", err)
		}
	}()

	if *flagHeadless {
		fmt.Fprintf(os.Stdout, "PKTPATH_STUDIO_URL=%s\n", baseURL)
		sigCh := make(chan os.Signal, 2)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		select {
		case <-sigCh:
			logger.Printf("headless signal shutdown requested")
		case <-srv.QuitRequested():
			logger.Printf("headless API quit requested")
		}
	} else if *flagWindow {
		runDesktopWindow(srv, appDir, baseURL, *flagDebug, logger)
	} else {
		runDefaultBrowserMode(srv, appDir, baseURL, logger)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	logger.Printf("PktPath Studio exited cleanly")
}

func runDefaultBrowserMode(srv *server.Server, appDir, baseURL string, logger *log.Logger) {
	if err := openDefaultBrowser(baseURL + "/"); err != nil {
		logger.Printf("default browser launch error (%v); trying Edge/Chrome fallback", err)
		_ = launchBrowserApp(appDir, baseURL)
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	const idleTimeout = 25 * time.Second
	var idleSince time.Time
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			logger.Printf("signal received; shutting down browser-mode server")
			return
		case <-srv.QuitRequested():
			logger.Printf("POST /api/app/quit received; shutting down cleanly")
			return
		case <-ticker.C:
			if !srv.EverHadClient() {
				continue
			}
			if srv.ActiveClients() == 0 && !srv.HasActiveCapture() {
				if idleSince.IsZero() {
					idleSince = time.Now()
				} else if time.Since(idleSince) >= idleTimeout {
					logger.Printf("0 browser tabs & 0 active captures for %s; auto-shutting down", idleTimeout)
					return
				}
			} else {
				idleSince = time.Time{}
			}
		}
	}
}

func openDefaultBrowser(targetURL string) error {
	cmd := adb.HideConsole(exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", targetURL))
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func probeExistingInstance(instancePath string) string {
	b, err := os.ReadFile(instancePath)
	if err != nil {
		return ""
	}
	var inst instanceInfo
	if json.Unmarshal(b, &inst) != nil || inst.Port <= 0 {
		return ""
	}
	base := fmt.Sprintf("http://127.0.0.1:%d", inst.Port)
	hc := &http.Client{Timeout: 600 * time.Millisecond}
	resp, err := hc.Get(base + "/api/health")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var health struct {
		OK bool `json:"ok"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&health) != nil || !health.OK {
		return ""
	}
	return strings.TrimRight(base, "/")
}

func writeInstanceFile(instancePath string, port int, baseURL string) {
	b, err := json.MarshalIndent(instanceInfo{
		PID:  os.Getpid(),
		Port: port,
		URL:  baseURL,
	}, "", "  ")
	if err != nil {
		return
	}
	tmp := fmt.Sprintf("%s.%d.tmp", instancePath, os.Getpid())
	if os.WriteFile(tmp, b, 0o644) == nil {
		if os.Rename(tmp, instancePath) != nil {
			_ = os.Remove(tmp)
		}
	}
}

func cleanupInstanceFile(instancePath string) {
	b, err := os.ReadFile(instancePath)
	if err != nil {
		return
	}
	var inst instanceInfo
	if json.Unmarshal(b, &inst) == nil && inst.PID == os.Getpid() {
		_ = os.Remove(instancePath)
	}
}

func runDesktopWindow(srv *server.Server, appDir, baseURL string, debug bool, logger *log.Logger) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	wvData := filepath.Join(appDir, "webview2")
	_ = os.MkdirAll(wvData, 0o755)

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     debug,
		AutoFocus: true,
		DataPath:  wvData,
		WindowOptions: webview2.WindowOptions{
			Title:  "PktPath Studio · 单包路径跟踪工作台",
			Width:  1400,
			Height: 880,
			Center: true,
		},
	})

	if w != nil {
		sigCh := make(chan os.Signal, 2)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		doneCh := make(chan struct{})
		go func() {
			select {
			case <-sigCh:
				logger.Printf("signal received; closing WebView2 window")
				w.Terminate()
			case <-srv.QuitRequested():
				logger.Printf("quit requested; closing WebView2 window")
				w.Terminate()
			case <-doneCh:
			}
		}()

		w.SetSize(980, 620, webview2.HintMin)
		w.SetSize(1400, 880, webview2.HintNone)
		w.Navigate(baseURL + "/")
		w.Run()
		close(doneCh)
		w.Destroy()
		return
	}

	logger.Printf("WebView2 runtime unavailable; falling back to Edge/Chrome --app mode")
	cmd := launchBrowserApp(appDir, baseURL)
	if cmd == nil {
		logger.Printf("no Edge/Chrome found for fallback; exiting")
		return
	}
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	select {
	case <-waitCh:
	case <-srv.QuitRequested():
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	case <-sigCh:
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
}

func launchBrowserApp(appDir, baseURL string) *exec.Cmd {
	var candidates []string
	for _, name := range []string{"msedge.exe", "chrome.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			candidates = append(candidates, p)
		}
	}
	for _, env := range []string{"ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"} {
		root := os.Getenv(env)
		if root == "" {
			continue
		}
		candidates = append(candidates,
			filepath.Join(root, "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(root, "Google", "Chrome", "Application", "chrome.exe"),
		)
	}
	profileDir := filepath.Join(appDir, "browser_app")
	_ = os.MkdirAll(profileDir, 0o755)
	for _, exe := range candidates {
		if st, err := os.Stat(exe); err != nil || st.IsDir() {
			continue
		}
		cmd := adb.HideConsole(exec.Command(exe,
			"--app="+baseURL+"/",
			"--window-size=1400,880",
			"--user-data-dir="+profileDir,
			"--no-first-run",
			"--no-default-browser-check",
		))
		if cmd.Start() == nil {
			return cmd
		}
	}
	return nil
}

func openLogger(appDir string, echoStderr bool) (*os.File, *log.Logger) {
	logPath := filepath.Join(appDir, "studio.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	var writers []io.Writer
	if err == nil {
		if st, serr := f.Stat(); serr == nil && st.Size() > 8<<20 {
			_ = f.Truncate(0)
			_, _ = f.Seek(0, 0)
		}
		writers = append(writers, f)
	}
	if echoStderr {
		writers = append(writers, os.Stderr)
	}
	if len(writers) == 0 {
		return nil, log.New(io.Discard, "", 0)
	}
	return f, log.New(io.MultiWriter(writers...), "[studio] ", log.LstdFlags)
}

func enableHighDPI() {
	u32 := syscall.NewLazyDLL("user32.dll")
	// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = (DPI_AWARENESS_CONTEXT)-4 = ^uintptr(3)
	setCtx := u32.NewProc("SetProcessDpiAwarenessContext")
	if setCtx.Find() == nil {
		if r, _, _ := setCtx.Call(^uintptr(3)); r != 0 {
			return
		}
	}
	setAware := u32.NewProc("SetProcessDPIAware")
	if setAware.Find() == nil {
		_, _, _ = setAware.Call()
	}
}

func attachParentConsoleIfNeeded() {
	if st, err := os.Stdout.Stat(); err == nil && st != nil {
		return
	}
	k32 := syscall.NewLazyDLL("kernel32.dll")
	attach := k32.NewProc("AttachConsole")
	const attachParentProcess = ^uintptr(0) // (DWORD)-1
	r, _, _ := attach.Call(attachParentProcess)
	if r == 0 {
		return
	}
	if out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = out
	}
	if errOut, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stderr = errOut
	}
}

func defaultNodeIfEmpty(v string) string {
	if s := strings.TrimSpace(v); s != "" {
		return s
	}
	return "node"
}
