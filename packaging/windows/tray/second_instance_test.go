package main

import (
	"os"
	"testing"
	"time"
)

func TestDecideTrayActivate(t *testing.T) {
	cases := []struct {
		name     string
		running  bool
		starting bool
		busy     bool
		shutting bool
		want     ActivateDecision
	}{
		{"shutting ignores", true, false, false, true, ActivateIgnore},
		{"running opens browser", true, false, false, false, ActivateOpenBrowser},
		{"starting waits and opens", false, true, false, false, ActivateWaitAndOpen},
		{"restarting busy waits and opens", false, false, true, false, ActivateWaitAndOpen},
		{"stopped restarts and opens", false, false, false, false, ActivateRestartAndOpen},
	}
	for _, tc := range cases {
		if got := DecideTrayActivate(tc.running, tc.starting, tc.busy, tc.shutting); got != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestHandleSecondInstanceOpensHealthyImmediately(t *testing.T) {
	var opened string
	signaled := false
	got := HandleSecondInstance(
		func() (string, bool) { return "http://127.0.0.1:43210", true },
		func() uintptr { return 99 },
		func(hwnd uintptr, noOpen bool) bool { signaled = true; return true },
		func(url string) { opened = url },
		false,
		time.Second,
		10*time.Millisecond,
	)
	if got != OutcomeOpenedExisting {
		t.Fatalf("got %v, want OutcomeOpenedExisting", got)
	}
	if opened != "http://127.0.0.1:43210" || signaled {
		t.Fatalf("opened=%q signaled=%v", opened, signaled)
	}
}

func TestHandleSecondInstanceSignalsTrayWhenBackendDown(t *testing.T) {
	var gotHwnd uintptr
	var gotNoOpen bool
	start := time.Now()
	got := HandleSecondInstance(
		func() (string, bool) { return "", false },
		func() uintptr { return 0x1234 },
		func(hwnd uintptr, noOpen bool) bool {
			gotHwnd = hwnd
			gotNoOpen = noOpen
			return true
		},
		func(url string) { t.Fatalf("should not open directly: %q", url) },
		false,
		2*time.Second,
		10*time.Millisecond,
	)
	if got != OutcomeSignaledTray {
		t.Fatalf("got %v, want OutcomeSignaledTray", got)
	}
	if gotHwnd != 0x1234 || gotNoOpen {
		t.Fatalf("hwnd=%x noOpen=%v", gotHwnd, gotNoOpen)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("should signal tray immediately instead of stalling: %v", time.Since(start))
	}
}

func TestHandleSecondInstanceReportsUnresponsiveWhenNoTrayWindow(t *testing.T) {
	got := HandleSecondInstance(
		func() (string, bool) { return "", false },
		func() uintptr { return 0 },
		func(hwnd uintptr, noOpen bool) bool { return false },
		func(url string) { t.Fatalf("unexpected open: %q", url) },
		false,
		60*time.Millisecond,
		15*time.Millisecond,
	)
	if got != OutcomeUnresponsive {
		t.Fatalf("got %v, want OutcomeUnresponsive", got)
	}
}

func TestLauncherCleansRuntimeFileOnUnexpectedExit(t *testing.T) {
	p, flagsPath := writeFakeInstall(t, nil)
	t.Setenv("PKTPATH_MOCK_FLAGS", flagsPath)
	t.Setenv(SkipNodeHashEnv, "1")
	l := newTestLauncher(p, flagsPath)
	exited := make(chan error, 1)
	l.SetOnUnexpectedExit(func(err error) { exited <- err })
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	cmd := l.cmd
	l.mu.Unlock()
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for exit callback")
	}
	if _, err := os.Stat(p.RuntimePath); !os.IsNotExist(err) {
		t.Fatalf("expected runtime file to be removed after child exit, stat err=%v", err)
	}
	if l.URL() != "" {
		t.Fatalf("expected empty URL after child exit, got %q", l.URL())
	}
	_ = l.Stop()
}
