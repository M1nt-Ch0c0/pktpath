package adb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Remote layout on the Android device.
const (
	RemoteDir        = "/data/local/tmp/.pktpath_studio"
	RemoteAgent      = RemoteDir + "/pktpath"
	RemotePluginsDir = RemoteDir + "/plugins"
	RemoteTmp        = "/data/local/tmp/pktpath_tmp"
)

// Root modes reported to the UI.
const (
	RootUnknown  = ""
	RootAdbd     = "adbd-root" // adbd already running as uid 0
	RootAdbRoot  = "adb-root"  // became root after `adb root` (userdebug/eng)
	RootSu       = "su"        // Magisk / KernelSU `su -c`
	RootNone     = "none"
	defaultShell = 20 * time.Second
)

// ErrNoAdb is returned when no adb executable could be resolved.
var ErrNoAdb = errors.New("adb executable not available")

// Client drives a headless adb.exe. All process launches hide the console.
type Client struct {
	Path string

	mu      sync.Mutex
	root    map[string]string // serial -> root mode
	started bool
}

// NewClient creates a client for the given adb executable.
func NewClient(path string) *Client {
	return &Client{Path: path, root: map[string]string{}}
}

// Result of an adb invocation.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Combined returns stdout+stderr trimmed.
func (r Result) Combined() string {
	return strings.TrimSpace(strings.TrimSpace(r.Stdout) + "\n" + strings.TrimSpace(r.Stderr))
}

// ensureServer starts the adb server with stdio bound to NUL so the forked
// daemon never inherits (and pins) one of our pipes.
func (c *Client) ensureServer(ctx context.Context) {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return
	}
	c.started = true
	c.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := HideConsole(exec.CommandContext(cctx, c.Path, "start-server"))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	cmd.WaitDelay = 2 * time.Second
	_ = cmd.Run()
}

// Run executes adb with args, hidden, with a timeout.
func (c *Client) Run(ctx context.Context, timeout time.Duration, args ...string) (Result, error) {
	if c == nil || c.Path == "" {
		return Result{ExitCode: -1}, ErrNoAdb
	}
	c.ensureServer(ctx)
	if timeout <= 0 {
		timeout = defaultShell
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := HideConsole(exec.CommandContext(cctx, c.Path, args...))
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	res := Result{Stdout: normNL(so.String()), Stderr: normNL(se.String())}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if cctx.Err() == context.DeadlineExceeded {
		return res, fmt.Errorf("adb %s: timeout after %s", strings.Join(redactArgs(args), " "), timeout)
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return res, fmt.Errorf("adb %s: exit %d: %s", strings.Join(redactArgs(args), " "), res.ExitCode, lastLine(res.Combined()))
		}
		return res, fmt.Errorf("adb %s: %w", strings.Join(redactArgs(args), " "), err)
	}
	return res, nil
}

func redactArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if len(a) > 160 {
			a = a[:160] + "…"
		}
		out[i] = a
	}
	return out
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return s
}

func normNL(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

// ShQuote single-quotes s for a POSIX shell.
func ShQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Shell runs a command as the adb shell user (or root if adbd is root).
func (c *Client) Shell(ctx context.Context, serial, command string, timeout time.Duration) (Result, error) {
	return c.Run(ctx, timeout, "-s", serial, "shell", command)
}

// RootMode returns the cached root mode for serial ("" if never probed).
func (c *Client) RootMode(serial string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.root[serial]
}

func (c *Client) setRoot(serial, mode string) {
	c.mu.Lock()
	c.root[serial] = mode
	c.mu.Unlock()
}

// ForgetRoot drops cached root state (e.g. device disconnected/rebooted).
func (c *Client) ForgetRoot(serial string) {
	c.mu.Lock()
	delete(c.root, serial)
	c.mu.Unlock()
}

// WrapPriv returns the shell command line that runs command as root under mode.
func WrapPriv(mode, command string) string {
	if mode == RootSu {
		return "su -c " + ShQuote(command)
	}
	return command
}

// Priv runs command with root privileges using the auto-detected root mode.
func (c *Client) Priv(ctx context.Context, serial, command string, timeout time.Duration) (Result, error) {
	mode := c.RootMode(serial)
	if mode == RootUnknown {
		var err error
		if mode, err = c.EnsureRoot(ctx, serial); err != nil {
			return Result{ExitCode: -1}, err
		}
	}
	return c.Shell(ctx, serial, WrapPriv(mode, command), timeout)
}

func firstLineIs0(s string) bool {
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		return ln == "0"
	}
	return false
}

// EnsureRoot performs dual root auto-adaptation:
//  1. `id -u` == 0 -> adbd already root;
//  2. `adb root` (+1 s, wait-for-device) then re-check (userdebug builds);
//  3. `su -c id -u` == 0 -> Magisk / KernelSU (user builds).
func (c *Client) EnsureRoot(ctx context.Context, serial string) (string, error) {
	r, err := c.Shell(ctx, serial, "id -u", 10*time.Second)
	if err != nil && strings.TrimSpace(r.Stdout) == "" {
		return RootUnknown, fmt.Errorf("device %s not reachable: %w", serial, err)
	}
	if firstLineIs0(r.Stdout) {
		c.setRoot(serial, RootAdbd)
		return RootAdbd, nil
	}

	rr, _ := c.Run(ctx, 15*time.Second, "-s", serial, "root")
	out := strings.ToLower(rr.Combined())
	if !strings.Contains(out, "cannot run as root") && !strings.Contains(out, "not allowed") {
		time.Sleep(time.Second)
		_, _ = c.Run(ctx, 15*time.Second, "-s", serial, "wait-for-device")
		for i := 0; i < 5; i++ {
			r, err = c.Shell(ctx, serial, "id -u", 8*time.Second)
			if err == nil && firstLineIs0(r.Stdout) {
				c.setRoot(serial, RootAdbRoot)
				return RootAdbRoot, nil
			}
			if err == nil {
				break // adbd is back but still non-root
			}
			time.Sleep(700 * time.Millisecond)
		}
	}

	// su may block on a Magisk grant prompt on the phone screen: allow time.
	r, _ = c.Shell(ctx, serial, "su -c 'id -u'", 25*time.Second)
	if firstLineIs0(r.Stdout) {
		c.setRoot(serial, RootSu)
		return RootSu, nil
	}
	r2, _ := c.Shell(ctx, serial, "su 0 id -u", 15*time.Second)
	if firstLineIs0(r2.Stdout) {
		// Rare su builds that only accept `su 0 <cmd>`; `su -c` still works on
		// nearly all of these, so keep RootSu semantics.
		c.setRoot(serial, RootSu)
		return RootSu, nil
	}
	c.setRoot(serial, RootNone)
	return RootNone, nil
}

// DeviceEntry is one line of `adb devices -l`.
type DeviceEntry struct {
	Serial  string `json:"serial"`
	State   string `json:"state"`
	Model   string `json:"model"`
	Product string `json:"product"`
	Device  string `json:"device"`
}

// ParseDevicesL parses `adb devices -l` output.
func ParseDevicesL(out string) []DeviceEntry {
	var res []DeviceEntry
	for _, ln := range strings.Split(normNL(out), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "List of devices") || strings.HasPrefix(ln, "*") || strings.HasPrefix(ln, "adb server") {
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		e := DeviceEntry{Serial: f[0], State: f[1]}
		rest := f[2:]
		if f[1] == "no" && len(f) > 2 && f[2] == "permissions" {
			e.State = "no permissions"
			rest = f[3:]
		}
		for _, kv := range rest {
			k, v, ok := strings.Cut(kv, ":")
			if !ok {
				continue
			}
			switch k {
			case "model":
				e.Model = strings.ReplaceAll(v, "_", " ")
			case "product":
				e.Product = v
			case "device":
				e.Device = v
			}
		}
		res = append(res, e)
	}
	return res
}

// Devices lists attached devices.
func (c *Client) Devices(ctx context.Context) ([]DeviceEntry, error) {
	r, err := c.Run(ctx, 10*time.Second, "devices", "-l")
	if err != nil {
		return nil, err
	}
	return ParseDevicesL(r.Stdout), nil
}

// DeviceProps is a cheap (non-root) property probe.
type DeviceProps struct {
	Model       string
	Product     string
	AndroidVer  string
	Kernel      string
	ShellUID    string
	AgentSHA256 string
}

// ParseMarked parses lines like "@@key=value".
func ParseMarked(out string) map[string]string {
	m := map[string]string{}
	for _, ln := range strings.Split(normNL(out), "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "@@") {
			continue
		}
		k, v, ok := strings.Cut(ln[2:], "=")
		if ok {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// Props fetches model/android/kernel/uid/agent hash in ONE adb shell round-trip
// without invoking su (no Magisk toast spam on periodic refresh).
func (c *Client) Props(ctx context.Context, serial string) (DeviceProps, error) {
	script := strings.Join([]string{
		`echo "@@model=$(getprop ro.product.model)"`,
		`echo "@@product=$(getprop ro.product.name)"`,
		`echo "@@android=$(getprop ro.build.version.release)"`,
		`echo "@@kernel=$(uname -r)"`,
		`echo "@@uid=$(id -u)"`,
		`echo "@@agent=$(sha256sum ` + RemoteAgent + ` 2>/dev/null | cut -d' ' -f1)"`,
	}, "; ")
	r, err := c.Shell(ctx, serial, script, 10*time.Second)
	m := ParseMarked(r.Stdout)
	p := DeviceProps{
		Model: m["model"], Product: m["product"], AndroidVer: m["android"],
		Kernel: m["kernel"], ShellUID: m["uid"], AgentSHA256: m["agent"],
	}
	if err != nil && len(m) == 0 {
		return p, err
	}
	return p, nil
}

// RemoteAgentSHA returns the sha256 of the injected agent ("" if missing).
func (c *Client) RemoteAgentSHA(ctx context.Context, serial string) string {
	r, _ := c.Shell(ctx, serial, "sha256sum "+RemoteAgent+" 2>/dev/null", 10*time.Second)
	f := strings.Fields(r.Stdout)
	if len(f) > 0 && len(f[0]) == 64 {
		return strings.ToLower(f[0])
	}
	// Directory may be root-only on some devices: retry privileged.
	if c.RootMode(serial) == RootSu {
		r, _ = c.Priv(ctx, serial, "sha256sum "+RemoteAgent+" 2>/dev/null", 15*time.Second)
		f = strings.Fields(r.Stdout)
		if len(f) > 0 && len(f[0]) == 64 {
			return strings.ToLower(f[0])
		}
	}
	return ""
}

// EnsureAgent silently injects the embedded agent if missing or mismatched.
// Returns (pushed, remoteSHA, error).
func (c *Client) EnsureAgent(ctx context.Context, serial, localPath, wantSHA string) (bool, string, error) {
	wantSHA = strings.ToLower(strings.TrimSpace(wantSHA))
	if localPath == "" || wantSHA == "" {
		return false, "", errors.New("embedded pktpath agent unavailable in this build")
	}
	if got := c.RemoteAgentSHA(ctx, serial); got == wantSHA {
		return false, got, nil
	}
	if r, err := c.Run(ctx, 60*time.Second, "-s", serial, "push", localPath, RemoteTmp); err != nil {
		return false, "", fmt.Errorf("push agent: %v (%s)", err, lastLine(r.Combined()))
	}
	install := strings.Join([]string{
		"umask 022",
		"mkdir -p " + RemoteDir,
		"chmod 755 " + RemoteDir,
		"mv -f " + RemoteTmp + " " + RemoteAgent,
		"chmod 755 " + RemoteAgent,
		"sha256sum " + RemoteAgent,
	}, " && ")
	r, err := c.Priv(ctx, serial, install, 30*time.Second)
	f := strings.Fields(r.Stdout)
	got := ""
	if len(f) > 0 && len(f[0]) == 64 {
		got = strings.ToLower(f[0])
	}
	if got != wantSHA {
		_, _ = c.Shell(ctx, serial, "rm -f "+RemoteTmp, 10*time.Second)
		if err != nil {
			return true, got, fmt.Errorf("install agent: %v", err)
		}
		return true, got, fmt.Errorf("agent sha256 mismatch after install: got %q want %q", got, wantSHA)
	}
	return true, got, nil
}

// Iface is one interface parsed from `ip -br addr`.
type Iface struct {
	Name  string   `json:"name"`
	State string   `json:"state"`
	Addrs []string `json:"addrs"`
}

// ParseIPBrAddr parses `ip -br addr` output.
func ParseIPBrAddr(out string) []Iface {
	res := []Iface{}
	seen := map[string]int{}
	for _, ln := range strings.Split(normNL(out), "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		name := f[0]
		if i := strings.Index(name, "@"); i > 0 {
			name = name[:i]
		}
		addrs := []string{}
		for _, a := range f[2:] {
			if strings.Contains(a, ".") || strings.Contains(a, ":") {
				addrs = append(addrs, a)
			}
		}
		if idx, ok := seen[name]; ok {
			res[idx].Addrs = append(res[idx].Addrs, addrs...)
			continue
		}
		seen[name] = len(res)
		res = append(res, Iface{Name: name, State: f[1], Addrs: addrs})
	}
	return res
}

// App is one installed package and its UID.
type App struct {
	Pkg string `json:"pkg"`
	UID int    `json:"uid"`
}

var pkgLineRe = regexp.MustCompile(`^package:(\S+)\s+uid:(\d+)`)

// ParsePackages parses `cmd package list packages -U` or `/data/system/packages.list`.
func ParsePackages(out string) []App {
	m := map[string]int{}
	for _, ln := range strings.Split(normNL(out), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		var pkg string
		var uid int
		if mm := pkgLineRe.FindStringSubmatch(ln); mm != nil {
			u, err := strconv.Atoi(mm[2])
			if err != nil {
				continue
			}
			pkg, uid = mm[1], u
		} else {
			f := strings.Fields(ln)
			if len(f) >= 2 && strings.Contains(f[0], ".") {
				u, err := strconv.Atoi(f[1])
				if err != nil || u < 0 {
					continue
				}
				pkg, uid = f[0], u
			} else {
				continue
			}
		}
		if old, ok := m[pkg]; !ok || uid < old {
			m[pkg] = uid
		}
	}
	apps := make([]App, 0, len(m))
	for p, u := range m {
		apps = append(apps, App{Pkg: p, UID: u})
	}
	sort.Slice(apps, func(i, j int) bool {
		// Third-party apps (uid >= 10000) first, then system; alphabetical within.
		ai, aj := apps[i].UID >= 10000, apps[j].UID >= 10000
		if ai != aj {
			return ai
		}
		return apps[i].Pkg < apps[j].Pkg
	})
	return apps
}

// Pull copies a remote file or directory to a local path.
func (c *Client) Pull(ctx context.Context, serial, remote, local string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		return err
	}
	r, err := c.Run(ctx, timeout, "-s", serial, "pull", remote, local)
	if err != nil {
		return fmt.Errorf("adb pull %s: %v (%s)", remote, err, lastLine(r.Combined()))
	}
	return nil
}

// SyncPluginFiles uploads the specified local *.json plugin manifests into
// RemotePluginsDir on the device (and clears stale manifests).
func (c *Client) SyncPluginFiles(ctx context.Context, serial string, localPaths []string) (int, error) {
	if len(localPaths) == 0 {
		_, _ = c.Priv(ctx, serial, "rm -rf "+RemotePluginsDir, 10*time.Second)
		return 0, nil
	}
	if _, err := c.Priv(ctx, serial, "rm -rf "+RemotePluginsDir+" && mkdir -p "+RemotePluginsDir+" && chmod 755 "+RemotePluginsDir, 15*time.Second); err != nil {
		return 0, err
	}
	pushed := 0
	for _, localPath := range localPaths {
		name := filepath.Base(localPath)
		stage := RemoteTmp + "_plug_" + name
		if _, err := c.Run(ctx, 20*time.Second, "-s", serial, "push", localPath, stage); err != nil {
			return pushed, fmt.Errorf("push plugin %s: %w", name, err)
		}
		dst := RemotePluginsDir + "/" + name
		mv := fmt.Sprintf("mv -f %s %s && chmod 644 %s", ShQuote(stage), ShQuote(dst), ShQuote(dst))
		if _, err := c.Priv(ctx, serial, mv, 10*time.Second); err != nil {
			return pushed, fmt.Errorf("install plugin %s: %w", name, err)
		}
		pushed++
	}
	return pushed, nil
}

// SyncPlugins uploads local *.json plugin manifests into RemotePluginsDir on the device.
func (c *Client) SyncPlugins(ctx context.Context, serial, localDir string) (int, error) {
	if localDir == "" {
		return 0, nil
	}
	ents, err := os.ReadDir(localDir)
	if err != nil {
		return 0, nil
	}
	var paths []string
	for _, e := range ents {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		paths = append(paths, filepath.Join(localDir, e.Name()))
	}
	sort.Strings(paths)
	return c.SyncPluginFiles(ctx, serial, paths)
}
