package adb

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// RemoteRun describes a background `pktpath record` on the device.
type RemoteRun struct {
	ID      string `json:"id"`
	OutDir  string `json:"out_dir"`
	LogPath string `json:"log_path"`
	PID     int    `json:"pid"`
	Command string `json:"command"`
}

// RunPaths returns remote paths for a capture id.
func RunPaths(id string) (outDir, logPath, pidPath string) {
	outDir = RemoteDir + "/run_" + id
	return outDir, outDir + ".log", outDir + ".pid"
}

// StartRecord launches `pktpath record <args> --out <run dir>` detached on the
// device (new session via setsid, stdio redirected to a log file) so it keeps
// running even if USB hiccups, and returns the remote PID.
func (c *Client) StartRecord(ctx context.Context, serial, id string, args []string) (*RemoteRun, error) {
	outDir, logPath, pidPath := RunPaths(id)
	quoted := make([]string, 0, len(args)+2)
	for _, a := range args {
		quoted = append(quoted, ShQuote(a))
	}
	quoted = append(quoted, "--out", ShQuote(outDir))
	agentCmd := RemoteAgent + " record " + strings.Join(quoted, " ")
	inner := "echo $$ > " + pidPath + "; exec " + agentCmd
	script := strings.Join([]string{
		"umask 022",
		"cd " + RemoteDir,
		"rm -rf " + outDir + " " + logPath + " " + pidPath,
		"S=; command -v setsid >/dev/null 2>&1 && S=setsid",
		"($S sh -c " + ShQuote(inner) + " > " + logPath + " 2>&1 < /dev/null &)",
		"i=0; while [ ! -s " + pidPath + " ] && [ $i -lt 30 ]; do sleep 0.1; i=$((i+1)); done",
		`echo "@@pid=$(cat ` + pidPath + ` 2>/dev/null)"`,
	}, "; ")
	r, err := c.Priv(ctx, serial, script, 20*time.Second)
	m := ParseMarked(r.Stdout)
	pid, _ := strconv.Atoi(m["pid"])
	if pid <= 0 {
		if err == nil {
			err = fmt.Errorf("record did not report a PID: %s", lastLine(r.Combined()))
		}
		return nil, err
	}
	return &RemoteRun{ID: id, OutDir: outDir, LogPath: logPath, PID: pid, Command: "pktpath record " + strings.Join(args, " ") + " --out " + outDir}, nil
}

// Poll returns (alive, last log lines) running privileged so Android hidepid=2
// never hides the root pktpath process.
func (c *Client) Poll(ctx context.Context, serial string, run *RemoteRun, tail int) (bool, []string, error) {
	if tail <= 0 {
		tail = 60
	}
	script := fmt.Sprintf(
		`tail -n %d %s 2>/dev/null; echo ""; echo "@@comm=$(cat /proc/%d/comm 2>/dev/null)"; echo "@@stat=$(cut -d' ' -f3 /proc/%d/stat 2>/dev/null)"`,
		tail, run.LogPath, run.PID, run.PID,
	)
	r, err := c.Priv(ctx, serial, script, 10*time.Second)
	if err != nil && r.Stdout == "" {
		return true, nil, err // transient adb hiccup: assume still alive
	}
	var lines []string
	comm := ""
	state := ""
	for _, ln := range strings.Split(r.Stdout, "\n") {
		if strings.HasPrefix(ln, "@@comm=") {
			comm = strings.TrimSpace(strings.TrimPrefix(ln, "@@comm="))
			continue
		}
		if strings.HasPrefix(ln, "@@stat=") {
			state = strings.TrimSpace(strings.TrimPrefix(ln, "@@stat="))
			continue
		}
		if strings.TrimSpace(ln) == "" {
			continue
		}
		lines = append(lines, strings.TrimRight(ln, "\r"))
	}
	alive := comm != "" && state != "Z" && (strings.Contains(comm, "pktpath") || comm == "sh")
	return alive, lines, nil
}

// Signal sends a signal (INT, TERM, USR1, KILL) to the remote PID as root.
func (c *Client) Signal(ctx context.Context, serial string, pid int, sig string) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid %d", pid)
	}
	_, err := c.Priv(ctx, serial, fmt.Sprintf("kill -%s %d", sig, pid), 10*time.Second)
	return err
}

// PrepareForPull makes the run dir world-readable for `adb pull` (sync service
// runs as the shell user on non-adbd-root devices).
func (c *Client) PrepareForPull(ctx context.Context, serial string, run *RemoteRun) {
	_, _ = c.Priv(ctx, serial, fmt.Sprintf("chmod -R a+rX %s 2>/dev/null; chmod a+r %s 2>/dev/null; true", run.OutDir, run.LogPath), 15*time.Second)
}

// RemoteExists reports whether a remote path exists.
func (c *Client) RemoteExists(ctx context.Context, serial, path string) bool {
	r, _ := c.Priv(ctx, serial, fmt.Sprintf(`[ -e %s ] && echo "@@exists=1" || echo "@@exists=0"`, path), 10*time.Second)
	return ParseMarked(r.Stdout)["exists"] == "1"
}

// CleanupRun removes the remote run dir, log and pid file; returns whether
// the run dir is verified gone.
func (c *Client) CleanupRun(ctx context.Context, serial string, run *RemoteRun) bool {
	pidPath := strings.TrimSuffix(run.LogPath, ".log") + ".pid"
	r, _ := c.Priv(ctx, serial, fmt.Sprintf(`rm -rf %s %s %s; [ -e %s ] && echo "@@gone=0" || echo "@@gone=1"`, run.OutDir, run.LogPath, pidPath, run.OutDir), 20*time.Second)
	return ParseMarked(r.Stdout)["gone"] == "1"
}
