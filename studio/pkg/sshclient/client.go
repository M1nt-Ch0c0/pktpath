// Package sshclient implements zero-console-window Linux remote target
// management over system ssh/scp for PktPath Studio (supporting x86_64 and arm64).
package sshclient

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"pktpath/studio/pkg/adb"
)

const (
	DefaultRemoteDir = "/tmp/.pktpath_studio"
	SerialPrefix     = "ssh:"
)

// Target represents one saved Linux SSH host profile.
type Target struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	User         string `json:"user"`
	IdentityFile string `json:"identity_file,omitempty"`
	UseSudo      bool   `json:"use_sudo"`
	RemoteDir    string `json:"remote_dir,omitempty"`
}

// ProbeInfo is the result of probing a Linux SSH host.
type ProbeInfo struct {
	Arch     string `json:"arch"`      // x86_64 | aarch64
	Kernel   string `json:"kernel"`    // uname -r
	Hostname string `json:"hostname"`  // hostname
	UID      string `json:"uid"`       // id -u
	RootMode string `json:"root_mode"` // root | sudo | none
}

// RemoteDirOrDefault returns the sanitized remote working directory.
func (t Target) RemoteDirOrDefault() string {
	d := strings.TrimSpace(t.RemoteDir)
	if d == "" {
		return DefaultRemoteDir
	}
	return strings.TrimRight(d, "/")
}

// Serial returns the unified Studio device identifier (`ssh:<id>`).
func (t Target) Serial() string { return SerialPrefix + t.ID }

// IsSSHSerial reports whether serial refers to a Linux SSH target.
func IsSSHSerial(serial string) (string, bool) {
	if strings.HasPrefix(serial, SerialPrefix) {
		return strings.TrimPrefix(serial, SerialPrefix), true
	}
	return "", false
}

// Store persists Linux SSH target profiles in a JSON file.
type Store struct {
	path string
	mu   sync.Mutex
	list []Target
}

// NewStore opens or initializes the SSH target store at path.
func NewStore(path string) *Store {
	s := &Store{path: path}
	s.load()
	return s
}

func (s *Store) load() {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var list []Target
	if json.Unmarshal(b, &list) == nil {
		s.list = list
	}
}

func (s *Store) saveLocked() error {
	_ = os.MkdirAll(filepath.Dir(s.path), 0o755)
	b, err := json.MarshalIndent(s.list, "", "  ")
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", s.path, os.Getpid())
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// List returns a copy of all saved targets.
func (s *Store) List() []Target {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Target, len(s.list))
	copy(out, s.list)
	return out
}

// Get finds a target by ID.
func (s *Store) Get(id string) (Target, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.list {
		if t.ID == id {
			return t, true
		}
	}
	return Target{}, false
}

var reSafeID = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// Upsert validates and saves an SSH target profile.
func (s *Store) Upsert(t Target) (Target, error) {
	t.Host = strings.TrimSpace(t.Host)
	t.User = strings.TrimSpace(t.User)
	t.Name = strings.TrimSpace(t.Name)
	t.IdentityFile = strings.TrimSpace(t.IdentityFile)
	t.RemoteDir = strings.TrimSpace(t.RemoteDir)
	if t.Host == "" {
		return Target{}, fmt.Errorf("missing ssh host")
	}
	if strings.ContainsAny(t.Host, " \t\r\n;|&$`") {
		return Target{}, fmt.Errorf("invalid ssh host %q", t.Host)
	}
	if strings.ContainsAny(t.User, " \t\r\n;|&$`") {
		return Target{}, fmt.Errorf("invalid ssh user %q", t.User)
	}
	if t.Port <= 0 || t.Port > 65535 {
		t.Port = 22
	}
	if t.Name == "" {
		if t.User != "" {
			t.Name = t.User + "@" + t.Host
		} else {
			t.Name = t.Host
		}
	}
	if t.ID == "" {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s@%s:%d", t.User, t.Host, t.Port)))
		base := strings.Trim(reSafeID.ReplaceAllString(t.Host, "-"), "-.")
		if len(base) > 20 {
			base = base[:20]
		}
		if base == "" {
			base = "host"
		}
		t.ID = base + "-" + hex.EncodeToString(h[:])[:6]
	} else {
		t.ID = strings.Trim(reSafeID.ReplaceAllString(t.ID, "-"), "-.")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	replaced := false
	for i := range s.list {
		if s.list[i].ID == t.ID {
			s.list[i] = t
			replaced = true
			break
		}
	}
	if !replaced {
		s.list = append(s.list, t)
	}
	return t, s.saveLocked()
}

// Delete removes a target by ID.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.list[:0]
	for _, t := range s.list {
		if t.ID != id {
			out = append(out, t)
		}
	}
	s.list = out
	return s.saveLocked()
}

// Client invokes system ssh/scp with HideConsole (zero console flash on Windows).
type Client struct {
	SSHPath string
	SCPPath string
}

// NewClient discovers system ssh/scp executables.
func NewClient() *Client {
	return &Client{
		SSHPath: findBin("ssh"),
		SCPPath: findBin("scp"),
	}
}

func findBin(base string) string {
	name := base
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	if runtime.GOOS == "windows" {
		for _, cand := range []string{
			filepath.Join(`C:\Windows\System32\OpenSSH`, name),
			filepath.Join(`C:\Program Files\OpenSSH`, name),
		} {
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				return cand
			}
		}
	}
	return ""
}

// Available reports whether system ssh is installed.
func (c *Client) Available() bool { return c.SSHPath != "" }

func (c *Client) baseSSHArgs(t Target) []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=8",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ServerAliveInterval=15",
	}
	if t.Port > 0 && t.Port != 22 {
		args = append(args, "-p", strconv.Itoa(t.Port))
	}
	if t.IdentityFile != "" {
		args = append(args, "-i", t.IdentityFile)
	}
	dest := t.Host
	if t.User != "" {
		dest = t.User + "@" + t.Host
	}
	return append(args, dest)
}

func (c *Client) baseSCPArgs(t Target) []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=8",
		"-o", "StrictHostKeyChecking=accept-new",
	}
	if t.Port > 0 && t.Port != 22 {
		args = append(args, "-P", strconv.Itoa(t.Port))
	}
	if t.IdentityFile != "" {
		args = append(args, "-i", t.IdentityFile)
	}
	return args
}

func scpDest(t Target, remotePath string) string {
	if t.User != "" {
		return t.User + "@" + t.Host + ":" + remotePath
	}
	return t.Host + ":" + remotePath
}

// ExecResult holds stdout/stderr/exit code of a remote ssh command.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Combined returns stdout and stderr concatenated.
func (r ExecResult) Combined() string {
	return strings.TrimSpace(r.Stdout + "\n" + r.Stderr)
}

// Exec runs a shell command on the remote Linux host (optionally with sudo -n).
func (c *Client) Exec(ctx context.Context, t Target, shellCmd string, priv bool, timeout time.Duration) (ExecResult, error) {
	if c.SSHPath == "" {
		return ExecResult{ExitCode: -1}, fmt.Errorf("system ssh executable not found (install OpenSSH Client)")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	remoteCmd := shellCmd
	if priv && t.UseSudo {
		remoteCmd = "if [ \"$(id -u)\" = \"0\" ]; then " + shellCmd + "; else sudo -n sh -c " + adb.ShQuote(shellCmd) + "; fi"
	}
	args := append(c.baseSSHArgs(t), remoteCmd)
	cmd := adb.HideConsole(exec.CommandContext(cctx, c.SSHPath, args...))
	cmd.WaitDelay = 2 * time.Second
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	res := ExecResult{
		Stdout: strings.ReplaceAll(out.String(), "\r\n", "\n"),
		Stderr: strings.ReplaceAll(errb.String(), "\r\n", "\n"),
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		} else {
			res.ExitCode = -1
		}
		return res, fmt.Errorf("ssh %s: %w (%s)", t.Host, err, strings.TrimSpace(res.Stderr))
	}
	return res, nil
}

// Probe checks remote architecture, kernel version, hostname, and root/sudo status.
func (c *Client) Probe(ctx context.Context, t Target) (ProbeInfo, error) {
	script := `printf 'ARCH=%s\nKERNEL=%s\nHOST=%s\nUID=%s\n' "$(uname -m)" "$(uname -r)" "$(hostname 2>/dev/null || uname -n)" "$(id -u)"; if [ "$(id -u)" = "0" ]; then echo SUDO=root; elif sudo -n true 2>/dev/null; then echo SUDO=sudo; else echo SUDO=none; fi`
	r, err := c.Exec(ctx, t, script, false, 12*time.Second)
	if err != nil {
		return ProbeInfo{}, err
	}
	var p ProbeInfo
	for _, ln := range strings.Split(r.Stdout, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if !ok {
			continue
		}
		switch k {
		case "ARCH":
			p.Arch = v
		case "KERNEL":
			p.Kernel = v
		case "HOST":
			p.Hostname = v
		case "UID":
			p.UID = v
		case "SUDO":
			p.RootMode = v
		}
	}
	if p.RootMode == "" {
		if p.UID == "0" {
			p.RootMode = "root"
		} else {
			p.RootMode = "none"
		}
	}
	return p, nil
}

// RemoteAgentPath returns the remote pktpath binary path on the SSH target.
func (c *Client) RemoteAgentPath(t Target) string {
	return t.RemoteDirOrDefault() + "/pktpath"
}

// RemotePluginsDir returns the remote plugins directory on the SSH target.
func (c *Client) RemotePluginsDir(t Target) string {
	return t.RemoteDirOrDefault() + "/plugins"
}

// EnsureAgent uploads the matching Linux collector binary if missing or hash differs.
func (c *Client) EnsureAgent(ctx context.Context, t Target, localPath, wantSHA string) (bool, string, error) {
	if localPath == "" {
		return false, "", fmt.Errorf("no matching pktpath collector binary for this target architecture")
	}
	rdir := t.RemoteDirOrDefault()
	rbin := c.RemoteAgentPath(t)
	if wantSHA != "" {
		chk, _ := c.Exec(ctx, t, fmt.Sprintf("sha256sum %s 2>/dev/null | awk '{print $1}'", adb.ShQuote(rbin)), false, 10*time.Second)
		got := strings.ToLower(strings.TrimSpace(chk.Stdout))
		if got == strings.ToLower(wantSHA) {
			return false, got, nil
		}
	}
	if _, err := c.Exec(ctx, t, fmt.Sprintf("mkdir -p %s && chmod 755 %s", adb.ShQuote(rdir), adb.ShQuote(rdir)), false, 10*time.Second); err != nil {
		return false, "", err
	}
	tmpRemote := rbin + ".upload"
	if err := c.pushFile(ctx, t, localPath, tmpRemote, 60*time.Second); err != nil {
		return false, "", err
	}
	mvCmd := fmt.Sprintf("mv -f %s %s && chmod 755 %s && sha256sum %s 2>/dev/null | awk '{print $1}'",
		adb.ShQuote(tmpRemote), adb.ShQuote(rbin), adb.ShQuote(rbin), adb.ShQuote(rbin))
	r, err := c.Exec(ctx, t, mvCmd, false, 15*time.Second)
	if err != nil {
		return false, "", err
	}
	got := strings.ToLower(strings.TrimSpace(r.Stdout))
	if got == "" {
		got = wantSHA
	}
	return true, got, nil
}

func (c *Client) pushFile(ctx context.Context, t Target, localPath, remotePath string, timeout time.Duration) error {
	if c.SCPPath == "" {
		// Fallback: stream via ssh cat
		f, err := os.Open(localPath)
		if err != nil {
			return err
		}
		defer f.Close()
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		args := append(c.baseSSHArgs(t), "cat > "+adb.ShQuote(remotePath))
		cmd := adb.HideConsole(exec.CommandContext(cctx, c.SSHPath, args...))
		cmd.Stdin = f
		var errb bytes.Buffer
		cmd.Stderr = &errb
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("ssh upload %s: %w (%s)", filepath.Base(localPath), err, strings.TrimSpace(errb.String()))
		}
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	args := append(c.baseSCPArgs(t), localPath, scpDest(t, remotePath))
	cmd := adb.HideConsole(exec.CommandContext(cctx, c.SCPPath, args...))
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("scp %s: %w (%s)", filepath.Base(localPath), err, strings.TrimSpace(errb.String()))
	}
	return nil
}

// SyncPluginFiles uploads enabled local *.json plugin manifests into RemotePluginsDir.
func (c *Client) SyncPluginFiles(ctx context.Context, t Target, localPaths []string) (int, error) {
	pdir := c.RemotePluginsDir(t)
	if len(localPaths) == 0 {
		_, _ = c.Exec(ctx, t, "rm -rf "+adb.ShQuote(pdir), false, 10*time.Second)
		return 0, nil
	}
	if _, err := c.Exec(ctx, t, fmt.Sprintf("rm -rf %s && mkdir -p %s && chmod 755 %s", adb.ShQuote(pdir), adb.ShQuote(pdir), adb.ShQuote(pdir)), false, 10*time.Second); err != nil {
		return 0, err
	}
	pushed := 0
	for _, lp := range localPaths {
		dst := pdir + "/" + filepath.Base(lp)
		if err := c.pushFile(ctx, t, lp, dst, 20*time.Second); err != nil {
			return pushed, err
		}
		pushed++
	}
	return pushed, nil
}

// StartRecord launches `pktpath record` detached on the remote Linux host.
func (c *Client) StartRecord(ctx context.Context, t Target, id string, args []string) (*adb.RemoteRun, error) {
	rdir := t.RemoteDirOrDefault()
	pidPath := rdir + "/run_" + id + ".pid"
	run := &adb.RemoteRun{
		ID:      id,
		OutDir:  rdir + "/run_" + id,
		LogPath: rdir + "/run_" + id + ".log",
	}
	var quoted []string
	quoted = append(quoted, adb.ShQuote(c.RemoteAgentPath(t)), "record")
	for _, a := range args {
		quoted = append(quoted, adb.ShQuote(a))
	}
	quoted = append(quoted, "--out", adb.ShQuote(run.OutDir))
	run.Command = strings.Join(quoted, " ")

	launch := fmt.Sprintf(
		"rm -rf %s %s %s && mkdir -p %s && nohup %s >%s 2>&1 </dev/null & echo $! > %s && cat %s",
		adb.ShQuote(run.OutDir), adb.ShQuote(run.LogPath), adb.ShQuote(pidPath),
		adb.ShQuote(rdir),
		run.Command, adb.ShQuote(run.LogPath), adb.ShQuote(pidPath), adb.ShQuote(pidPath),
	)
	r, err := c.Exec(ctx, t, launch, true, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("start ssh record: %w", err)
	}
	pidStr := ""
	for _, ln := range strings.Split(strings.TrimSpace(r.Stdout), "\n") {
		ln = strings.TrimSpace(ln)
		if _, perr := strconv.Atoi(ln); perr == nil {
			pidStr = ln
		}
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		return nil, fmt.Errorf("failed to obtain remote PID (stdout=%q stderr=%q)", r.Stdout, r.Stderr)
	}
	run.PID = pid
	return run, nil
}

// Poll checks whether the remote recorder PID is alive and fetches tail log lines.
func (c *Client) Poll(ctx context.Context, t Target, run *adb.RemoteRun, tailLines int) (bool, []string, error) {
	if tailLines <= 0 {
		tailLines = 60
	}
	script := fmt.Sprintf(
		"if kill -0 %d 2>/dev/null; then echo ALIVE=1; else echo ALIVE=0; fi; echo '---LOG---'; tail -n %d %s 2>/dev/null || true",
		run.PID, tailLines, adb.ShQuote(run.LogPath),
	)
	r, err := c.Exec(ctx, t, script, true, 10*time.Second)
	if err != nil && r.Stdout == "" {
		return false, nil, err
	}
	alive := false
	var lines []string
	inLog := false
	for _, ln := range strings.Split(r.Stdout, "\n") {
		if !inLog {
			if ln == "ALIVE=1" {
				alive = true
			} else if ln == "---LOG---" {
				inLog = true
			}
			continue
		}
		if ln != "" {
			lines = append(lines, ln)
		}
	}
	return alive, lines, nil
}

// Signal sends SIGINT/SIGTERM/SIGKILL/SIGUSR1 to the remote recorder process.
func (c *Client) Signal(ctx context.Context, t Target, pid int, sig string) error {
	_, err := c.Exec(ctx, t, fmt.Sprintf("kill -%s %d 2>/dev/null || true", sig, pid), true, 10*time.Second)
	return err
}

// RemoteExists checks whether a remote file or directory exists.
func (c *Client) RemoteExists(ctx context.Context, t Target, remotePath string) bool {
	r, err := c.Exec(ctx, t, fmt.Sprintf("test -e %s && echo YES || echo NO", adb.ShQuote(remotePath)), true, 8*time.Second)
	return err == nil && strings.Contains(r.Stdout, "YES")
}

// PullDir streams a remote capture directory into localDst via `tar` over SSH.
func (c *Client) PullDir(ctx context.Context, t Target, remoteDir, localDst string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	if err := os.MkdirAll(localDst, 0o755); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	parent := path.Dir(remoteDir)
	base := path.Base(remoteDir)
	tarCmd := fmt.Sprintf("tar -C %s -cf - %s", adb.ShQuote(parent), adb.ShQuote(base))
	if t.UseSudo {
		tarCmd = "if [ \"$(id -u)\" = \"0\" ]; then " + tarCmd + "; else sudo -n sh -c " + adb.ShQuote(tarCmd) + "; fi"
	}
	args := append(c.baseSSHArgs(t), tarCmd)
	cmd := adb.HideConsole(exec.CommandContext(cctx, c.SSHPath, args...))
	var errb bytes.Buffer
	cmd.Stderr = &errb
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	tr := tar.NewReader(stdout)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = cmd.Wait()
			return fmt.Errorf("tar stream: %w (%s)", err, strings.TrimSpace(errb.String()))
		}
		rel := strings.TrimPrefix(path.Clean(hdr.Name), "./")
		rel = strings.TrimPrefix(rel, base+"/")
		if rel == base || rel == "." || rel == "" || strings.HasPrefix(rel, "..") {
			continue
		}
		outPath := filepath.Join(localDst, filepath.FromSlash(rel))
		if hdr.Typeflag == tar.TypeDir {
			_ = os.MkdirAll(outPath, 0o755)
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		_ = os.MkdirAll(filepath.Dir(outPath), 0o755)
		f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(f, tr)
		_ = f.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("ssh pull %s: %w (%s)", remoteDir, err, strings.TrimSpace(errb.String()))
	}
	return nil
}

// CleanupRun removes temporary capture files on the remote Linux host.
func (c *Client) CleanupRun(ctx context.Context, t Target, run *adb.RemoteRun) bool {
	pidPath := t.RemoteDirOrDefault() + "/run_" + run.ID + ".pid"
	cmd := fmt.Sprintf("rm -rf %s %s %s", adb.ShQuote(run.OutDir), adb.ShQuote(run.LogPath), adb.ShQuote(pidPath))
	_, err := c.Exec(ctx, t, cmd, true, 15*time.Second)
	return err == nil
}

// ListUsersAndProcs returns Linux users & running process names mapped to UIDs
// so the Studio traffic filter works identically to Android packages.
func (c *Client) ListUsersAndProcs(ctx context.Context, t Target) ([]adb.App, error) {
	script := `awk -F: '{print "USER:"$1":"$3}' /etc/passwd 2>/dev/null; for p in /proc/[0-9]*/status; do awk '/^Name:/{n=$2} /^Uid:/{u=$2} END{if(n!="" && u!="") print "PROC:"n":"u}' "$p" 2>/dev/null; done | sort -u | head -n 400`
	r, err := c.Exec(ctx, t, script, false, 15*time.Second)
	if err != nil && r.Stdout == "" {
		return nil, err
	}
	seen := map[string]bool{}
	var apps []adb.App
	for _, ln := range strings.Split(r.Stdout, "\n") {
		ln = strings.TrimSpace(ln)
		parts := strings.Split(ln, ":")
		if len(parts) != 3 {
			continue
		}
		kind, name, uidStr := parts[0], parts[1], parts[2]
		uid, err := strconv.Atoi(uidStr)
		if err != nil || name == "" {
			continue
		}
		label := name
		if kind == "USER" {
			label = "user:" + name
		}
		key := fmt.Sprintf("%s#%d", label, uid)
		if seen[key] {
			continue
		}
		seen[key] = true
		apps = append(apps, adb.App{Pkg: label, UID: uid})
	}
	sort.Slice(apps, func(i, j int) bool {
		ui, uj := strings.HasPrefix(apps[i].Pkg, "user:"), strings.HasPrefix(apps[j].Pkg, "user:")
		if ui != uj {
			return !ui // running processes first, then system users
		}
		return apps[i].Pkg < apps[j].Pkg
	})
	return apps, nil
}
