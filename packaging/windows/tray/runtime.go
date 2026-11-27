package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// RuntimeState is the on-disk launcher-runtime.json, kept compatible with
// start-studio.ps1 (pid, launcher_pid, url, host, app_dir, entry, node,
// started_at, logs).
type RuntimeState struct {
	PID         int         `json:"pid"`
	LauncherPID int         `json:"launcher_pid"`
	URL         string      `json:"url"`
	Host        string      `json:"host"`
	AppDir      string      `json:"app_dir"`
	Entry       string      `json:"entry"`
	Node        string      `json:"node"`
	StartedAt   string      `json:"started_at"`
	Logs        RuntimeLogs `json:"logs"`
}

type RuntimeLogs struct {
	Out string `json:"out"`
	Err string `json:"err"`
}

func ReadRuntime(path string) (*RuntimeState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st RuntimeState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func WriteRuntime(path string, st RuntimeState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func RemoveRuntime(path string) {
	_ = os.Remove(path)
	_ = os.Remove(path + ".tmp")
}

func FormatStartedAt(t time.Time) string {
	return t.Format("2006-01-02T15:04:05-07:00")
}
