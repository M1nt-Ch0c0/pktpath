package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// Launcher owns the bundled Node child process, log files, and the
// launcher-runtime.json record.
type Launcher struct {
	Paths    Paths
	Host     string
	Port     int
	SkipHash bool
	ReadyFor time.Duration
	QuitFor  time.Duration
	Now      func() time.Time
	LookPath func(string) (string, error) // unused; kept closed to PATH on purpose

	mu         sync.Mutex
	cmd        *exec.Cmd
	state      launchState
	url        string
	ready      *ReadyInfo
	unexpected bool
	onExit     func(err error)
	cancelLog  context.CancelFunc
}

type launchState int

const (
	stateIdle launchState = iota
	stateStarting
	stateRunning
	stateStopping
	stateExited
	stateFailed
)

func NewLauncher(p Paths) *Launcher {
	return &Launcher{
		Paths:    p,
		Host:     DefaultHost,
		Port:     0,
		ReadyFor: ReadyTimeout,
		QuitFor:  QuitWait,
		Now:      time.Now,
	}
}

func (l *Launcher) URL() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.url
}

func (l *Launcher) Running() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state == stateRunning && l.cmd != nil && l.cmd.Process != nil && !processExited(l.cmd)
}

func (l *Launcher) UnexpectedExit() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.unexpected
}

func (l *Launcher) SetOnUnexpectedExit(fn func(err error)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onExit = fn
}

// Start validates the install root, launches the bundled Node, waits for
// READY + /api/health, and writes launcher-runtime.json. On timeout or
// early exit it stops the child and cleans the runtime file.
func (l *Launcher) Start() error {
	if err := ValidateInstall(l.Paths, l.SkipHash); err != nil {
		return err
	}
	if err := os.MkdirAll(l.Paths.LogsDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(l.Paths.SessionsDir, 0o755); err != nil {
		return err
	}

	l.mu.Lock()
	if l.state == stateRunning || l.state == stateStarting {
		l.mu.Unlock()
		return &LaunchError{Code: "busy", Message: "PktPath Studio 已在启动或运行中。"}
	}
	l.state = stateStarting
	l.unexpected = false
	l.url = ""
	l.ready = nil
	l.mu.Unlock()

	if err := l.startLocked(); err != nil {
		l.mu.Lock()
		l.state = stateFailed
		l.cmd = nil
		l.mu.Unlock()
		RemoveRuntime(l.Paths.RuntimePath)
		return err
	}
	return nil
}

func (l *Launcher) startLocked() error {
	outFile, err := os.Create(l.Paths.OutLog)
	if err != nil {
		return err
	}
	errFile, err := os.Create(l.Paths.ErrLog)
	if err != nil {
		outFile.Close()
		return err
	}

	scan := newReadyScanner()
	outW := io.MultiWriter(outFile, scan)
	errW := io.MultiWriter(errFile, scan)

	args := BuildNodeArgs(l.Paths, l.Host, l.Port)
	cmd := exec.Command(l.Paths.Node, args...)
	cmd.Dir = l.Paths.InstallDir
	cmd.Stdout = outW
	cmd.Stderr = errW
	cmd.Env = os.Environ()
	applyHiddenWindow(cmd)

	if err := cmd.Start(); err != nil {
		outFile.Close()
		errFile.Close()
		return &LaunchError{Code: "spawn", Message: "无法启动随包 Node（node\\node.exe），拒绝启动，不会回退到 PATH。"}
	}

	l.mu.Lock()
	l.cmd = cmd
	l.mu.Unlock()

	waitDone := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		outFile.Close()
		errFile.Close()
		waitDone <- err
		l.mu.Lock()
		running := l.cmd == cmd && l.state == stateRunning
		var cb func(error)
		if running {
			l.state = stateExited
			l.unexpected = true
			cb = l.onExit
		} else if l.cmd == cmd && l.state == stateStopping {
			l.state = stateExited
		}
		l.mu.Unlock()
		if cb != nil {
			cb(err)
		}
	}()

	readyFor := l.ReadyFor
	if readyFor <= 0 {
		readyFor = ReadyTimeout
	}
	deadline := time.Now().Add(readyFor)
	var ready *ReadyInfo
	healthy := false
	exitedEarly := false

	for time.Now().Before(deadline) {
		if processExited(cmd) {
			exitedEarly = true
			break
		}
		if r := scan.Ready(); r != nil {
			ready = r
			ctx, cancel := context.WithTimeout(context.Background(), HealthWait)
			ok := CheckHealth(ctx, r.URL)
			cancel()
			if ok {
				healthy = true
				break
			}
		}
		time.Sleep(80 * time.Millisecond)
	}
	if !healthy && ready != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		healthy = CheckHealth(ctx, ready.URL)
		cancel()
	}

	if ready == nil || !healthy {
		url := ""
		if ready != nil {
			url = ready.URL
		}
		// Capture this before stopChild, which always kills a still-running
		// child and would otherwise turn a timeout into an "exited" error.
		early := exitedEarly || processExited(cmd)
		l.stopChild(url)
		select {
		case <-waitDone:
		case <-time.After(ForceKillWait):
		}
		RemoveRuntime(l.Paths.RuntimePath)
		if early {
			return &LaunchError{
				Code:    "exited",
				Message: "Studio 在就绪前已退出。请查看日志：" + l.Paths.OutLog,
			}
		}
		return &LaunchError{
			Code:    "timeout",
			Message: "等待 Studio 就绪超时，已停止后台进程。请查看日志：" + l.Paths.OutLog,
		}
	}

	studioPID := ready.PID
	if studioPID <= 0 {
		studioPID = cmd.Process.Pid
	}
	st := RuntimeState{
		PID:         studioPID,
		LauncherPID: cmd.Process.Pid,
		URL:         ready.URL,
		Host:        l.Host,
		AppDir:      l.Paths.AppDir,
		Entry:       l.Paths.Entry,
		Node:        l.Paths.Node,
		StartedAt:   FormatStartedAt(l.Now()),
		Logs:        RuntimeLogs{Out: l.Paths.OutLog, Err: l.Paths.ErrLog},
	}
	if err := WriteRuntime(l.Paths.RuntimePath, st); err != nil {
		l.stopChild(ready.URL)
		select {
		case <-waitDone:
		case <-time.After(ForceKillWait):
		}
		RemoveRuntime(l.Paths.RuntimePath)
		return err
	}

	l.mu.Lock()
	l.state = stateRunning
	l.url = ready.URL
	l.ready = ready
	l.mu.Unlock()
	return nil
}

// Stop posts /api/app/quit, waits up to QuitFor, then kills the child if
// needed and removes launcher-runtime.json.
func (l *Launcher) Stop() error {
	l.mu.Lock()
	cmd := l.cmd
	url := l.url
	if l.state == stateIdle || cmd == nil {
		l.state = stateIdle
		l.mu.Unlock()
		RemoveRuntime(l.Paths.RuntimePath)
		return nil
	}
	l.state = stateStopping
	l.mu.Unlock()

	l.stopChild(url)

	l.mu.Lock()
	l.cmd = nil
	l.url = ""
	l.ready = nil
	l.state = stateIdle
	l.unexpected = false
	l.mu.Unlock()
	RemoveRuntime(l.Paths.RuntimePath)
	return nil
}

func (l *Launcher) stopChild(url string) {
	l.mu.Lock()
	cmd := l.cmd
	l.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	if !processExited(cmd) && url != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = PostQuit(ctx, url)
		cancel()
		waitFor := l.QuitFor
		if waitFor <= 0 {
			waitFor = QuitWait
		}
		waitProcess(cmd, waitFor)
	}
	if !processExited(cmd) {
		_ = cmd.Process.Kill()
		waitProcess(cmd, ForceKillWait)
	}
}

// Restart stops a running backend (if any) and starts a fresh one.
func (l *Launcher) Restart() error {
	_ = l.Stop()
	return l.Start()
}

func processExited(cmd *exec.Cmd) bool {
	if cmd == nil || cmd.Process == nil {
		return true
	}
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return true
	}
	// Non-blocking wait via signal 0 / ProcessState. On Unix, Wait is in a
	// goroutine after start; until then inspect via a short signal.
	return processGone(cmd)
}

func waitProcess(cmd *exec.Cmd, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if processExited(cmd) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// readyScanner tees process output and extracts the READY line.
type readyScanner struct {
	mu  sync.Mutex
	buf bytes.Buffer
	got *ReadyInfo
}

func newReadyScanner() *readyScanner { return &readyScanner{} }

func (s *readyScanner) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.buf.Write(p)
	if s.got == nil {
		if r := ParseReadyLine(s.buf.String()); r != nil {
			s.got = r
		}
		// Bound the buffer so a noisy child cannot grow it forever.
		if s.buf.Len() > 1<<20 {
			keep := s.buf.Bytes()[s.buf.Len()-64*1024:]
			s.buf.Reset()
			s.buf.Write(keep)
		}
	}
	return len(p), nil
}

func (s *readyScanner) Ready() *ReadyInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.got
}
