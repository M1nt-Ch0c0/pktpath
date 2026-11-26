package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"pktpath/studio/pkg/reconstruct"
)

// This helper is the actual harmless stdio hook, executed as a direct child.
// It never opens a socket, accesses a device, or creates grandchildren.
func TestF01HookProcess(t *testing.T) {
	found := false
	for _, arg := range os.Args {
		if arg == "--f01-hook" {
			found = true
		}
	}
	if !found {
		return
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(80)
	}
	var payload struct {
		Config map[string]any `json:"config"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		os.Exit(81)
	}
	cfg := payload.Config
	text := func(key string) string { v, _ := cfg[key].(string); return v }
	cwd, _ := os.Getwd()
	if path := text("capture"); path != "" {
		record, _ := json.Marshal(struct {
			Payload json.RawMessage `json:"payload"`
			CWD     string          `json:"cwd"`
			Args    []string        `json:"args"`
		}{raw, cwd, os.Args[1:]})
		if os.WriteFile(path, record, 0600) != nil {
			os.Exit(82)
		}
	}
	if path := text("count"); path != "" {
		f, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if e != nil {
			os.Exit(83)
		}
		_, _ = f.WriteString("hook\n")
		_ = f.Close()
	}
	resourceBefore, _ := os.ReadFile("resource.txt")
	if path := text("entered"); path != "" {
		_ = os.WriteFile(path, []byte("entered"), 0600)
	}
	if text("mode") == "block" || text("mode") == "hang" {
		deadline := time.Now().Add(25 * time.Second)
		for time.Now().Before(deadline) {
			if _, e := os.Stat(text("release")); e == nil {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	switch text("mode") {
	case "bad-json":
		fmt.Print("not-json")
		os.Exit(0)
	case "exit":
		fmt.Fprint(os.Stderr, "hook-sentinel-stderr")
		os.Exit(7)
	case "raw":
		fmt.Print(text("raw"))
		os.Exit(0)
	}
	resourceAfter, _ := os.ReadFile("resource.txt")
	if !bytes.Equal(resourceBefore, resourceAfter) {
		fmt.Fprint(os.Stderr, "bundle resource changed during task")
		os.Exit(84)
	}
	fmt.Printf(`{"insights":[{"id":"u64","severity":"warn","title":"fixture","sample_ids":[9007199254740991,9007199254740992,9007199254740993,18446744073709551615]}],"kpis":[{"label":"fixture","value":"1"}],"notes":[%q,%q]}`, text("label"), string(resourceAfter))
	os.Exit(0)
}

func f01Options(t *testing.T) CordisAnalyzerOptions {
	t.Helper()
	host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if host == "" {
		t.Skip("optional integration: set PKTPATH_TEST_CORDIS_HOST after explicit npm ci --ignore-scripts")
	}
	abs, err := filepath.Abs(host)
	if err != nil {
		t.Fatal(err)
	}
	return CordisAnalyzerOptions{NodePath: os.Getenv("PKTPATH_TEST_CORDIS_NODE"), HostPath: abs}
}
func f01External(t *testing.T) *externalPlugin {
	t.Helper()
	bundle := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"id": "f01.fixture", "name": "F01 fixture", "version": "1", "entrypoint": map[string]any{"command": []string{exe, "-test.run=^TestF01HookProcess$", "--", "--f01-hook", "resource.txt"}}, "analyzers": []any{map[string]any{"id": "a", "name": "A", "priority": 12}, map[string]any{"id": "b", "name": "B", "priority": 12}}})
	manifest, meta, _, err := parseExternalManifest("fixture", raw, filepath.Join(bundle, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(bundle, "resource.txt"), []byte("resource-v1"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(bundle, "manifest.json"), raw, 0600)
	return &externalPlugin{bundleDir: bundle, manifest: manifest, meta: meta}
}
func f01Kernel(t *testing.T, ep *externalPlugin, cfg map[string]any, h *CordisAnalyzerHost) *Kernel {
	t.Helper()
	app := t.TempDir()
	document := map[string]any{"version": 2, "plugins": map[string]any{ep.meta.ID: map[string]any{"enabled": true, "config": cfg}}}
	raw, _ := json.Marshal(document)
	if err := os.WriteFile(filepath.Join(app, "plugins_config.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	k := New(HostServices{AppDir: app, AnalyzerHost: h})
	k.RegisterBuiltin(ep, true)
	if err := k.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		k.Shutdown()
		if h != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := h.Close(ctx); err != nil {
				t.Logf("candidate cleanup observed: %v", err)
			}
		}
	})
	return k
}
func f01Active(t *testing.T, k *Kernel) {
	t.Helper()
	if !k.IsPluginActive("f01.fixture") {
		t.Fatalf("candidate not active: %+v", k.Snapshot("test").Plugins)
	}
}
func f01WaitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("hook did not reach barrier: %s", path)
}
func f01Input() *AnalyzeInput {
	return &AnalyzeInput{SessionID: "frozen-session", SessionDir: "offline-session", Overview: &reconstruct.SessionOverview{Samples: []reconstruct.SampleRow{{SampleID: 9007199254740993, PktLen: math.MaxUint64}}}}
}

func TestF01OldNewDifferentialRawU64(t *testing.T) {
	opts := f01Options(t)
	ep := f01External(t)
	dir := t.TempDir()
	capture := filepath.Join(dir, "request.json")
	count := filepath.Join(dir, "count")
	cfg := map[string]any{"capture": capture, "count": count, "label": "A"}
	old := f01Kernel(t, ep, cfg, nil)
	legacy := old.AnalyzeSession(context.Background(), f01Input())
	oldRaw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	h := NewCordisAnalyzerHost(opts)
	candidate := f01Kernel(t, ep, cfg, h)
	f01Active(t, candidate)
	next := candidate.AnalyzeSession(context.Background(), f01Input())
	newRaw, _ := os.ReadFile(capture)
	if !reflect.DeepEqual(legacy, next) {
		t.Fatalf("old/new result difference:\n%+v\n%+v", legacy, next)
	}
	if !bytes.Equal(oldRaw, newRaw) {
		t.Fatalf("original stdio payload/cwd/relative argv changed:\n%s\n%s", oldRaw, newRaw)
	}
	for _, decimal := range []string{"9007199254740993", "18446744073709551615"} {
		if !bytes.Contains(newRaw, []byte(decimal)) {
			t.Fatalf("raw request integer missing: %s", decimal)
		}
	}
	want := []uint64{9007199254740991, 9007199254740992, 9007199254740993, math.MaxUint64}
	if len(next.Insights) != 2 {
		t.Fatalf("analyzer ordering/count changed: %+v", next)
	}
	for _, ins := range next.Insights {
		if !reflect.DeepEqual(ins.SampleIDs, want) {
			t.Fatalf("u64 lost: %v", ins.SampleIDs)
		}
	}
	calls, _ := os.ReadFile(count)
	if strings.Count(string(calls), "hook\n") != 4 {
		t.Fatalf("old/new must each execute two hooks once, got %s", calls)
	}
	tasks := h.Tasks()
	if len(tasks) != 2 {
		t.Fatal(tasks)
	}
	for _, task := range tasks {
		if task.State != "succeeded" || task.TerminalCommits != 1 || !task.HookExited || task.Admission != "acknowledged" {
			t.Fatalf("bad task terminal %+v", task)
		}
	}
}

func TestF01ErrorsAndCallerCancel(t *testing.T) {
	opts := f01Options(t)
	for _, mode := range []string{"bad-json", "exit", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ep := f01External(t)
			ep.manifest.Analyzers = ep.manifest.Analyzers[:1]
			entered := filepath.Join(t.TempDir(), "entered")
			cfg := map[string]any{"mode": mode, "entered": entered}
			if mode == "cancel" {
				cfg["mode"] = "hang"
			}
			h := NewCordisAnalyzerHost(opts)
			k := f01Kernel(t, ep, cfg, h)
			f01Active(t, k)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := k.Analyzers()[0].Run(ctx, f01Input()); result <- err }()
			if mode == "cancel" {
				f01WaitFile(t, entered)
				cancel()
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("expected hook failure")
				}
				if mode == "bad-json" && !strings.Contains(err.Error(), "invalid analyzer JSON output") {
					t.Fatal(err)
				}
				if mode == "exit" && !strings.Contains(err.Error(), "hook-sentinel-stderr") {
					t.Fatal(err)
				}
				if mode == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("hook cancellation/error hung")
			}
			tasks := h.Tasks()
			if len(tasks) != 1 || tasks[0].TerminalCommits != 1 || !tasks[0].HookExited || tasks[0].ResultAccepted {
				t.Fatal(tasks)
			}
		})
	}
}

func TestF01TimeoutOriginal15Seconds(t *testing.T) {
	opts := f01Options(t)
	if testing.Short() {
		t.Skip("real original 15s deadline")
	}
	ep := f01External(t)
	ep.manifest.Analyzers = ep.manifest.Analyzers[:1]
	h := NewCordisAnalyzerHost(opts)
	k := f01Kernel(t, ep, map[string]any{"mode": "hang"}, h)
	f01Active(t, k)
	start := time.Now()
	_, err := k.Analyzers()[0].Run(context.Background(), f01Input())
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) < 14*time.Second || time.Since(start) > 20*time.Second {
		t.Fatalf("original 15s timeout: elapsed=%s err=%v", time.Since(start), err)
	}
	if tasks := h.Tasks(); len(tasks) != 1 || !tasks[0].HookExited || tasks[0].TerminalCommits != 1 {
		t.Fatal(tasks)
	}
}

func TestF01SameIDReloadLeaseAndDrain(t *testing.T) {
	opts := f01Options(t)
	ep := f01External(t)
	ep.manifest.Analyzers = ep.manifest.Analyzers[:1]
	dir := t.TempDir()
	entered, release := filepath.Join(dir, "entered"), filepath.Join(dir, "release")
	cfg := map[string]any{"mode": "block", "entered": entered, "release": release, "label": "A"}
	h := NewCordisAnalyzerHost(opts)
	k := f01Kernel(t, ep, cfg, h)
	f01Active(t, k)
	oldRun := k.Analyzers()[0].Run
	done := make(chan error, 1)
	go func() { _, err := oldRun(context.Background(), f01Input()); done <- err }()
	f01WaitFile(t, entered)
	// Real current API implementations must reject actual deletion/replacement.
	if err := k.UninstallExternal(ep.meta.ID); !errors.Is(err, ErrAnalyzerBundleBusy) {
		t.Fatalf("uninstall bypassed lease: %v", err)
	}
	if _, err := k.InstallExternal(ep.bundleDir, nil, ""); !errors.Is(err, ErrAnalyzerBundleBusy) {
		t.Fatalf("replace bypassed lease: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(ep.bundleDir, "resource.txt"))
	if string(raw) != "resource-v1" {
		t.Fatal("leased resource deleted")
	}
	if _, err := k.SetConfig(ep.meta.ID, map[string]any{"label": "B"}); err != nil {
		t.Fatal(err)
	}
	if err := k.SetEnabled(ep.meta.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := k.SetEnabled(ep.meta.ID, true); err != nil {
		t.Fatal(err)
	}
	f01Active(t, k)
	fresh, err := k.Analyzers()[0].Run(context.Background(), f01Input())
	if err != nil || fresh.Notes[0] != "B" {
		t.Fatalf("new activation did not use B: %+v %v", fresh, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	if err = h.Drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain falsely completed before hook exited: %v", err)
	}
	cancel()
	_ = os.WriteFile(release, []byte("go"), 0600)
	select {
	case err = <-done:
		if !errors.Is(err, ErrAnalyzerStale) {
			t.Fatalf("old result not fenced: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("old task did not finish")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = h.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if h.Snapshot().Leases != 0 {
		t.Fatal("drain returned before package lease release")
	}
	tasks := h.Tasks()
	if len(tasks) != 2 || tasks[0].State != "completed-stale" || !tasks[0].HookExited || tasks[0].ResultAccepted || tasks[0].Output.Notes[1] != "resource-v1" || tasks[0].Generation == tasks[1].Generation {
		t.Fatalf("old history/new result/lease: %+v", tasks)
	}
	if _, err = oldRun(context.Background(), f01Input()); !errors.Is(err, ErrAnalyzerStale) {
		t.Fatalf("old callback admitted new work: %v", err)
	}
	// Reverse interleaving: mutation already admitted, a new task rejects promptly.
	endMutation, err := h.ProtectPackageMutation()
	if err != nil {
		t.Fatal(err)
	}
	_, err = k.Analyzers()[0].Run(context.Background(), f01Input())
	endMutation()
	if !errors.Is(err, ErrAnalyzerBundleBusy) {
		t.Fatalf("new task entered half-mutated package: %v", err)
	}
}

func TestF01DefaultNoNodeAndMissingCandidate(t *testing.T) {
	ep := f01External(t)
	ep.manifest.Analyzers = ep.manifest.Analyzers[:1]
	t.Setenv("PATH", t.TempDir()) // hook executable is absolute; no node/npm available.
	old := f01Kernel(t, ep, map[string]any{"label": "old"}, nil)
	before, _ := os.ReadFile(old.configPath)
	// New preview: entrypoint.command is not loaded and does not fall back to Go stdio.
	if old.IsPluginActive(ep.meta.ID) || len(old.Analyzers()) != 0 {
		t.Fatal("new preview still loaded entrypoint.command as Go stdio default")
	}
	out := old.AnalyzeSession(context.Background(), f01Input())
	after, _ := os.ReadFile(old.configPath)
	if len(out.Insights) != 0 || !bytes.Equal(before, after) {
		t.Fatalf("command-only plugin still produced insights or wrote config: %+v", out)
	}
	h := NewCordisAnalyzerHost(CordisAnalyzerOptions{NodePath: filepath.Join(t.TempDir(), "missing-node"), HostPath: "unused.mjs"})
	candidate := f01Kernel(t, ep, nil, h)
	if candidate.IsPluginActive(ep.meta.ID) || len(candidate.Analyzers()) != 0 || len(h.Tasks()) != 0 {
		t.Fatal("command-only plugin or missing Node silently fell back")
	}
	snap := candidate.Snapshot("test")
	if len(snap.Plugins) != 1 {
		t.Fatalf("missing plugin diagnosis: %+v", snap)
	}
	errText := snap.Plugins[0].Error
	if !strings.Contains(errText, "entrypoint.command") && !strings.Contains(errText, "Cordis analyzer activation") {
		t.Fatalf("command-only/missing runtime not diagnosable: %+v", snap)
	}
}

// Controlled transport fault injection, not an alternate production host.
func f01FaultHost(t *testing.T, op string) CordisAnalyzerOptions {
	t.Helper()
	opts := f01Options(t)
	file := filepath.Join(t.TempDir(), "fault.mjs")
	script := `import {createInterface} from 'node:readline';
const protocol='pktpath.cordis3.analyzer/1';
createInterface({input:process.stdin}).on('line',line=>{const r=JSON.parse(line);
 if(r.op===` + fmt.Sprintf("%q", op) + `){process.exit(23);return;}
 let x={id:r.id,protocol,ok:true,core:'3.18.1',node:process.version,generation:r.generation,accepted:true,drained:true,cleanupDone:true};
 if(r.op==='hello'&&` + fmt.Sprintf("%q", op) + `==='bad-protocol')x.protocol='wrong/1';
 if(r.op==='hello'&&` + fmt.Sprintf("%q", op) + `==='bad-core')x.core='4.0.0-rc.13';
 process.stdout.write(JSON.stringify(x)+'\n',()=>{if(r.op==='shutdown')process.exit(0)});
});`
	if err := os.WriteFile(file, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	opts.HostPath = file
	return opts
}
func TestF01LostAckNeverReexecutes(t *testing.T) {
	for _, op := range []string{"begin", "finish", "bad-protocol", "bad-core"} {
		t.Run(op, func(t *testing.T) {
			h := NewCordisAnalyzerHost(f01FaultHost(t, op))
			ep := f01External(t)
			ep.manifest.Analyzers = ep.manifest.Analyzers[:1]
			count := filepath.Join(t.TempDir(), "calls")
			k := f01Kernel(t, ep, map[string]any{"count": count}, h)
			if op == "bad-protocol" || op == "bad-core" {
				if k.IsPluginActive(ep.meta.ID) {
					t.Fatal("bad protocol accepted")
				}
				return
			}
			f01Active(t, k)
			_, err := k.Analyzers()[0].Run(context.Background(), f01Input())
			if err == nil {
				t.Fatal("lost ACK accepted as success")
			}
			raw, _ := os.ReadFile(count)
			want := 0
			if op == "finish" {
				want = 1
			}
			if strings.Count(string(raw), "hook\n") != want {
				t.Fatalf("ACK loss re-executed hook: %s", raw)
			}
			tasks := h.Tasks()
			if len(tasks) != 1 || tasks[0].State != "unknown" || tasks[0].TerminalCommits != 1 || tasks[0].ResultAccepted {
				t.Fatalf("missing unknown terminal: %+v", tasks)
			}
		})
	}
}
func TestF01CancelSuccessSingleTerminal(t *testing.T) {
	h := NewCordisAnalyzerHost(f01Options(t))
	a, err := h.activate("race", "test-package", nil, []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	for n := 0; n < 20; n++ {
		ctx, cancel := context.WithCancel(context.Background())
		entered, release := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		go func() {
			_, err := a.run(ctx, "a", "race", func() bool { return true }, func() (*AnalyzeOutput, error) {
				close(entered)
				<-release
				return &AnalyzeOutput{Notes: []string{"done"}}, nil
			})
			done <- err
		}()
		<-entered
		go cancel()
		close(release)
		err = <-done
		cancel()
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	tasks := h.Tasks()
	if len(tasks) != 20 {
		t.Fatal(len(tasks))
	}
	for _, task := range tasks {
		if task.TerminalCommits != 1 || task.State == "running" || task.State == "admitting" {
			t.Fatalf("not exactly one terminal: %+v", task)
		}
	}
}
func TestF01RawResponseIntegerAndNullPolicy(t *testing.T) {
	opts := f01Options(t)
	ep := f01External(t)
	ep.manifest.Analyzers = ep.manifest.Analyzers[:1]
	h := NewCordisAnalyzerHost(opts)
	k := f01Kernel(t, ep, map[string]any{}, h)
	f01Active(t, k)
	cases := []struct {
		raw    string
		reject bool
		count  int
	}{
		{`{}`, false, 0}, {`{"insights":null}`, false, 0}, {`{"insights":[]}`, false, 0},
		{`{"insights":[{"sample_ids":[0]}]}`, false, 1},
		{`{"insights":[{"sample_ids":[-1]}]}`, true, 0},
		{`{"insights":[{"sample_ids":[1.5]}]}`, true, 0},
		{`{"insights":[{"sample_ids":[18446744073709551616]}]}`, true, 0},
		{`{"insights":[{"sample_ids":[" 1"]}]}`, true, 0},
		{`{"insights":[{"sample_ids":["01"]}]}`, true, 0},
	}
	for _, c := range cases {
		cfg := map[string]any{"mode": "raw", "raw": c.raw}
		// Two controlled experiments: one direct old runner, one candidate callback.
		legacy, oldErr := ep.invokeExternalAnalyzer(context.Background(), ep.manifest.Entrypoint.Command, cfg, "a", f01Input())
		if _, err := k.SetConfig(ep.meta.ID, cfg); err != nil {
			t.Fatal(err)
		}
		next, newErr := k.Analyzers()[0].Run(context.Background(), f01Input())
		if (newErr != nil) != c.reject || (oldErr != nil) != (newErr != nil) || !reflect.DeepEqual(legacy, next) {
			t.Fatalf("raw response policy changed %s: old=%+v/%v new=%+v/%v", c.raw, legacy, oldErr, next, newErr)
		}
	}
}
func TestF01ConfigFailureExplicitRestoreAndSameConfigReload(t *testing.T) {
	opts := f01Options(t)
	h := NewCordisAnalyzerHost(opts)
	ep := f01External(t)
	ep.manifest.Analyzers = ep.manifest.Analyzers[:1]
	k := f01Kernel(t, ep, map[string]any{"label": "A", "unknown": "preserved-with-nil-schema"}, h)
	f01Active(t, k)
	if _, err := k.Analyzers()[0].Run(context.Background(), f01Input()); err != nil {
		t.Fatal(err)
	}
	first := h.Tasks()[0]
	if err := k.Reload(ep.meta.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Analyzers()[0].Run(context.Background(), f01Input()); err != nil {
		t.Fatal(err)
	}
	second := h.Tasks()[1]
	if first.Generation == second.Generation || first.ConfigDigest != second.ConfigDigest {
		t.Fatalf("same config reload is not a new generation: %+v %+v", first, second)
	}
	h.opts.HostPath = filepath.Join(t.TempDir(), "missing-host.mjs")
	if _, err := k.SetConfig(ep.meta.ID, map[string]any{"label": "B"}); err == nil {
		t.Fatal("B Apply must fail")
	}
	// Deliberately document the old non-transactional writer: B remains persisted.
	persisted, _ := os.ReadFile(k.configPath)
	if !bytes.Contains(persisted, []byte(`"B"`)) {
		t.Fatalf("fixture did not exercise existing config failure semantics: %s", persisted)
	}
	h.opts = opts
	if _, err := k.SetConfig(ep.meta.ID, map[string]any{"label": "A", "unknown": "preserved-with-nil-schema"}); err != nil {
		t.Fatal(err)
	}
	restored, err := k.Analyzers()[0].Run(context.Background(), f01Input())
	if err != nil || restored.Notes[0] != "A" {
		t.Fatalf("explicit restore failed: %+v %v", restored, err)
	}
	// This is explicit recovery, NOT automatic rollback or schema migration PASS.
	if h.Tasks()[2].Generation == first.Generation {
		t.Fatal("A return reused original activation")
	}
}
func TestF01IncarnationAndMutationAdmission(t *testing.T) {
	a, b := NewCordisAnalyzerHost(CordisAnalyzerOptions{}), NewCordisAnalyzerHost(CordisAnalyzerOptions{})
	if a.incarnation == b.incarnation {
		t.Fatal("host incarnation reused")
	}
	release, err := a.acquirePackage()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ProtectPackageMutation(); !errors.Is(err, ErrAnalyzerBundleBusy) {
		t.Fatal("lease check/delete admission are not atomic")
	}
	release()
	end, err := a.ProtectPackageMutation()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.acquirePackage(); !errors.Is(err, ErrAnalyzerBundleBusy) {
		t.Fatal("half-mutated package admitted task")
	}
	end()
}

func TestF01HostCrashDoesNotCancelOrRerunGoTask(t *testing.T) {
	h := NewCordisAnalyzerHost(f01Options(t))
	ep := f01External(t)
	ep.manifest.Analyzers = ep.manifest.Analyzers[:1]
	dir := t.TempDir()
	entered, release, count := filepath.Join(dir, "entered"), filepath.Join(dir, "release"), filepath.Join(dir, "count")
	k := f01Kernel(t, ep, map[string]any{"mode": "block", "entered": entered, "release": release, "count": count}, h)
	f01Active(t, k)
	done := make(chan error, 1)
	go func() { _, err := k.Analyzers()[0].Run(context.Background(), f01Input()); done <- err }()
	f01WaitFile(t, entered)
	h.mu.Lock()
	worker := h.current[ep.meta.ID].worker
	h.mu.Unlock()
	worker.abort()
	<-worker.exited
	if err := k.UninstallExternal(ep.meta.ID); !errors.Is(err, ErrAnalyzerBundleBusy) {
		t.Fatal("host exit prematurely released hook package lease", err)
	}
	select {
	case err := <-done:
		t.Fatalf("Node exit incorrectly completed still-blocked Go hook: %v", err)
	default:
	}
	_ = os.WriteFile(release, []byte("continue"), 0600)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("lost host not unknown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Go hook did not finish")
	}
	raw, _ := os.ReadFile(count)
	if strings.Count(string(raw), "hook\n") != 1 {
		t.Fatalf("host crash reran Go task: %s", raw)
	}
	tasks := h.Tasks()
	if len(tasks) != 1 || tasks[0].State != "unknown" || !tasks[0].HookExited || tasks[0].ResultAccepted {
		t.Fatal(tasks)
	}
}
func TestF01LinuxNonASCIIAndSpacePaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this path fixture is Linux-only; Windows is not validated")
	}
	opts := f01Options(t)
	root := filepath.Join(t.TempDir(), "离线 runtime space")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	hostDir := filepath.Join(root, "宿主 package")
	if err := os.MkdirAll(hostDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := copyDirRecursive(filepath.Dir(opts.HostPath), hostDir); err != nil {
		t.Fatal(err)
	}
	opts.HostPath = filepath.Join(hostDir, "host.mjs")
	node := opts.NodePath
	if node == "" {
		var err error
		node, err = exec.LookPath("node")
		if err != nil {
			t.Fatal(err)
		}
	}
	nodeLink := filepath.Join(root, "节点 node")
	if err := os.Symlink(node, nodeLink); err != nil {
		t.Fatal(err)
	}
	opts.NodePath = nodeLink
	t.Setenv("PATH", t.TempDir()) // preinstalled packages; no global npm or node lookup
	ep := f01External(t)
	ep.manifest.Analyzers = ep.manifest.Analyzers[:1]
	bundle := filepath.Join(root, "插件 bundle")
	if err := os.MkdirAll(bundle, 0755); err != nil {
		t.Fatal(err)
	}
	if err := copyDirRecursive(ep.bundleDir, bundle); err != nil {
		t.Fatal(err)
	}
	ep.bundleDir = bundle
	h := NewCordisAnalyzerHost(opts)
	k := f01Kernel(t, ep, nil, h)
	f01Active(t, k)
	out, err := k.Analyzers()[0].Run(context.Background(), f01Input())
	if err != nil || len(out.Insights) != 1 {
		t.Fatalf("path quoting failed %+v %v", out, err)
	}
}

func TestF01MixedBundleNonAnalyzerExtensionsStayGo(t *testing.T) {
	ep := f01External(t)
	raw, _ := json.Marshal(ep.manifest)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	doc["ui_slots"] = []any{map[string]any{"id": "slot", "slot": "sample.extra", "script": "widget.js"}}
	doc["exporters"] = []any{map[string]any{"id": "export", "name": "Export"}}
	doc["kernel_extensions"] = map[string]any{"sock_fields": []any{map[string]any{"struct": "sock", "field": "sk_mark", "size": 4, "role": "tag", "label": "mark"}}}
	raw, _ = json.Marshal(doc)
	manifest, meta, _, err := parseExternalManifest("fixture", raw, filepath.Join(ep.bundleDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	ep.manifest = manifest
	ep.meta = meta
	old := f01Kernel(t, ep, nil, nil)
	h := NewCordisAnalyzerHost(f01Options(t))
	next := f01Kernel(t, ep, nil, h)
	f01Active(t, next)
	if !reflect.DeepEqual(old.UISlots(), next.UISlots()) || !reflect.DeepEqual(old.CollectKernelExtensions(), next.CollectKernelExtensions()) {
		t.Fatal("F01 changed other extension metadata")
	}
	a, _ := json.Marshal(old.Exporters())
	b, _ := json.Marshal(next.Exporters())
	if !bytes.Equal(a, b) {
		t.Fatal("F01 changed exporter metadata")
	}
	if len(next.UISlots()) != 1 || len(next.Exporters()) != 1 || len(next.Analyzers()) != 2 || len(next.CollectKernelExtensions()) != 1 {
		t.Fatal("duplicate/missing mixed registrations")
	}
}
