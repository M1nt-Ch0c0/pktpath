package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var readyLine = regexp.MustCompile(`PKTPATH_STUDIO_READY\s+url=(\S+)\s+pid=(\d+)`)

// ReadyInfo is parsed from a PKTPATH_STUDIO_READY log line.
type ReadyInfo struct {
	URL string
	PID int
}

func ParseReadyLine(text string) *ReadyInfo {
	m := readyLine.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	pid, err := strconv.Atoi(m[2])
	if err != nil {
		return nil
	}
	return &ReadyInfo{URL: m[1], PID: pid}
}

type healthBody struct {
	OK bool `json:"ok"`
}

func joinURL(base, path string) string {
	return strings.TrimRight(base, "/") + path
}

func CheckHealth(ctx context.Context, baseURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(baseURL, HealthPath), nil)
	if err != nil {
		return false
	}
	client := &http.Client{Timeout: HealthWait, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false
	}
	var parsed healthBody
	if json.Unmarshal(body, &parsed) == nil && parsed.OK {
		return true
	}
	// Tolerate compact spacing variants around "ok": true.
	s := string(body)
	return strings.Contains(s, `"ok":true`) || strings.Contains(s, `"ok": true`)
}

func PostQuit(ctx context.Context, baseURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, joinURL(baseURL, QuitPath), strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("quit status %d", resp.StatusCode)
	}
	return nil
}

// ProbeExisting reads launcher-runtime.json and reports whether the recorded
// URL currently answers /api/health with {"ok":true}. Used by the single-
// instance path so a second launch can just open the browser.
func ProbeExisting(runtimePath string) (url string, healthy bool) {
	st, err := ReadRuntime(runtimePath)
	if err != nil || st == nil || strings.TrimSpace(st.URL) == "" {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), HealthWait)
	defer cancel()
	if CheckHealth(ctx, st.URL) {
		return st.URL, true
	}
	return st.URL, false
}

// ProbeExistingWait retries ProbeExisting until healthy or the timeout elapses
// (the first instance may still be starting).
func ProbeExistingWait(runtimePath string, timeout time.Duration) (url string, healthy bool) {
	deadline := time.Now().Add(timeout)
	var last string
	for {
		u, ok := ProbeExisting(runtimePath)
		if u != "" {
			last = u
		}
		if ok {
			return u, true
		}
		if time.Now().After(deadline) {
			return last, false
		}
		time.Sleep(150 * time.Millisecond)
	}
}
