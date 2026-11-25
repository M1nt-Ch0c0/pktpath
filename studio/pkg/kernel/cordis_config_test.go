package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func f03Fixture(t *testing.T, apply func(*PluginContext, map[string]any) error) (*Kernel, *CordisLifecycleHost, []byte) {
	t.Helper()
	host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if host == "" {
		t.Skip("explicit controlled host")
	}
	dir := t.TempDir()
	raw := []byte("{\n \"version\":2, \"opaqueEnvelope\":{\"keep\":true},\n \"plugins\":{\"txn\":{\"enabled\":true,\"unknownEntry\":7,\"config\":{\"mode\":\"user-A\"}}}\n}\n")
	if err := os.WriteFile(filepath.Join(dir, "plugins_config.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	h := NewCordisLifecycleHost(CordisLifecycleOptions{HostPath: host, PluginIDs: []string{"txn"}, ConfigTransactions: true, CleanupTimeout: 250 * time.Millisecond, CleanupExecutionTimeout: 250 * time.Millisecond, OperationTimeout: 700 * time.Millisecond})
	k := New(HostServices{AppDir: dir, LifecycleHost: h})
	p := &stubPlugin{meta: PluginMeta{ID: "txn"}, schema: &ConfigSchema{Fields: []FieldSchema{{Key: "mode", Type: FieldString, Default: "schema-default"}}}, apply: apply}
	k.RegisterBuiltin(p, true)
	if err := k.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Shutdown)
	waitLifecycle(t, h, "txn")
	return k, h, raw
}
func f03Latest(h *CordisLifecycleHost) CordisConfigOperationView {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.configViewLocked(h.configCurrent["txn"])
}
func f03WaitTerminal(t *testing.T, h *CordisLifecycleHost) CordisConfigOperationView {
	t.Helper()
	deadline := time.After(4 * time.Second)
	for {
		h.mu.Lock()
		op := h.configCurrent["txn"]
		changed := h.changed
		if op != nil && op.terminal {
			v := h.configViewLocked(op)
			h.mu.Unlock()
			return v
		}
		h.mu.Unlock()
		select {
		case <-changed:
		case <-deadline:
			t.Fatal("F03 operation did not settle")
		}
	}
}
func f03Disk(t *testing.T, k *Kernel) []byte {
	t.Helper()
	b, e := os.ReadFile(k.configPath)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func f03Mode(t *testing.T, k *Kernel) string {
	t.Helper()
	v, ok := k.Service("txn.svc")
	if !ok {
		return "<inactive>"
	}
	s, _ := v.(string)
	return s
}
func TestCordisF03ConfigCompensationFaults(t *testing.T) {
	for _, mode := range []string{"success", "apply-failure", "short-write", "sync-failure", "rename-failure", "directory-sync-failure", "restore-write-failure", "A-reapply-failure", "cleanup-blocked", "host-EOF"} {
		t.Run(mode, func(t *testing.T) {
			var a, b atomic.Int32
			var h *CordisLifecycleHost
			k, host, raw := f03Fixture(t, func(c *PluginContext, cfg map[string]any) error {
				value := ConfigString(cfg, "mode", "")
				if value == "user-A" {
					n := a.Add(1)
					if mode == "A-reapply-failure" && n > 1 {
						return errors.New("A reApply rejected")
					}
				}
				if mode == "cleanup-blocked" {
					c.OnDisposeTask(func(context.Context) error { return errors.New("actual cleanup failure") })
				}
				if value == "B" {
					b.Add(1)
					if mode == "apply-failure" || mode == "A-reapply-failure" {
						return errors.New("B Apply rejected")
					}
					if mode == "host-EOF" {
						h.worker.abort()
						awaitSignal(t, h.worker.exited)
					}
				}
				c.Provide("txn.svc", value)
				return nil
			})
			h = host
			oldGen := generationOf(h, "txn")
			ioFault := &cordisConfigIO{}
			switch mode {
			case "short-write":
				ioFault.write = func(f *os.File, data []byte, phase string) (int, error) {
					if phase == "commit" {
						return f.Write(data[:len(data)/2])
					}
					return f.Write(data)
				}
			case "sync-failure":
				ioFault.sync = func(f *os.File, phase string) error {
					if phase == "commit" {
						return errors.New("controlled sync failure")
					}
					return f.Sync()
				}
			case "rename-failure":
				ioFault.rename = func(a, b, phase string) error {
					if phase == "commit" {
						return errors.New("controlled rename failure")
					}
					return os.Rename(a, b)
				}
			case "directory-sync-failure", "restore-write-failure":
				ioFault.syncDir = func(_, phase string) error {
					if phase == "commit" {
						return errors.New("controlled directory sync failure after rename")
					}
					return nil
				}
				if mode == "restore-write-failure" {
					ioFault.write = func(f *os.File, data []byte, phase string) (int, error) {
						if phase == "restore" {
							return 0, errors.New("controlled restore failure")
						}
						return f.Write(data)
					}
				}
			}
			h.configIO = ioFault
			_, err := k.SetConfig("txn", map[string]any{"mode": "B"})
			v := f03WaitTerminal(t, h)
			if mode == "success" {
				if err != nil || v.Phase != "committed" || f03Mode(t, k) != "B" || !v.RunningLive || v.RunningGeneration == oldGen {
					t.Fatalf("false commit: err=%v view=%+v", err, v)
				}
				var doc map[string]json.RawMessage
				if json.Unmarshal(f03Disk(t, k), &doc) != nil || doc["opaqueEnvelope"] == nil {
					t.Fatal("unrelated envelope lost")
				}
				return
			}
			if err == nil {
				t.Fatal("failed request falsely returned success")
			}
			bad := mode == "restore-write-failure" || mode == "A-reapply-failure" || mode == "cleanup-blocked" || mode == "host-EOF"
			if bad {
				if v.Phase != "recovery-required" {
					t.Fatalf("real failed compensation hidden: %+v err=%v", v, err)
				}
				if mode == "restore-write-failure" {
					if f03Mode(t, k) != "user-A" || string(f03Disk(t, k)) == string(raw) {
						t.Fatal("mixed real A/disk B not exposed")
					}
				}
				if mode == "A-reapply-failure" || mode == "cleanup-blocked" || mode == "host-EOF" {
					if v.RunningLive {
						t.Fatalf("old revision faked a live A: %+v", v)
					}
				}
				if _, e := k.ResetConfig("txn"); e == nil {
					t.Fatal("Reset washed recovery-required")
				}
			} else {
				if v.Phase != "recovered" || !v.RunningLive || f03Mode(t, k) != "user-A" || v.RunningGeneration == oldGen || string(f03Disk(t, k)) != string(raw) {
					t.Fatalf("rollback labels without real new A/raw bytes: %+v error=%v", v, err)
				}
				if a.Load() != 2 || b.Load() != 1 {
					t.Fatalf("not one B plus one compensating A: %d %d", a.Load(), b.Load())
				}
			}
			if v.LastSuccessfulConfig["mode"] != "user-A" {
				t.Fatal("failed B promoted to last-successful")
			}
		})
	}
}
func TestCordisF03ValidationAndResetAreDifferent(t *testing.T) {
	var calls atomic.Int32
	k, h, raw := f03Fixture(t, func(c *PluginContext, cfg map[string]any) error {
		calls.Add(1)
		c.Provide("txn.svc", ConfigString(cfg, "mode", ""))
		return nil
	})
	gen := generationOf(h, "txn")
	if _, err := k.SetConfig("txn", map[string]any{"unknown": true}); err == nil {
		t.Fatal("unknown field silently discarded")
	}
	if generationOf(h, "txn") != gen || calls.Load() != 1 || string(f03Disk(t, k)) != string(raw) || len(h.Snapshot().ConfigOperations) != 0 {
		t.Fatal("validation rejected after side effect")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := k.SetConfigContext(ctx, "txn", map[string]any{"mode": "B"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if generationOf(h, "txn") != gen || calls.Load() != 1 {
		t.Fatal("pre-admission cancel had effects")
	}
	if _, err := k.ResetConfig("txn"); err != nil {
		t.Fatal(err)
	}
	if f03Mode(t, k) != "schema-default" || f03Latest(h).LastSuccessfulConfig["mode"] != "schema-default" {
		t.Fatal("Reset confused with old user-A compensation")
	}
}
func TestCordisF03CancelAndSupersedingIntents(t *testing.T) {
	for _, mode := range []string{"caller-cancel", "new-C", "new-Reset", "disable"} {
		t.Run(mode, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var bCalls atomic.Int32
			k, h, _ := f03Fixture(t, func(c *PluginContext, cfg map[string]any) error {
				v := ConfigString(cfg, "mode", "")
				if v == "B" {
					bCalls.Add(1)
					close(entered)
					<-release
				}
				c.Provide("txn.svc", v)
				return nil
			})
			defer releaseV4(release)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			resultB := make(chan error, 1)
			go func() { _, err := k.SetConfigContext(ctx, "txn", map[string]any{"mode": "B"}); resultB <- err }()
			awaitSignal(t, entered)
			h.mu.Lock()
			opB := h.configCurrent["txn"]
			revisionB := opB.revision
			h.mu.Unlock()
			var resultC chan error
			switch mode {
			case "caller-cancel":
				cancel()
				if err := <-resultB; !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), opB.id) {
					t.Fatalf("cancel lost operation identity: %v", err)
				}
			case "new-C", "new-Reset":
				resultC = make(chan error, 1)
				go func() {
					var err error
					if mode == "new-Reset" {
						_, err = k.ResetConfig("txn")
					} else {
						_, err = k.SetConfig("txn", map[string]any{"mode": "C"})
					}
					resultC <- err
				}()
				deadline := time.After(time.Second)
				for {
					h.mu.Lock()
					changed := h.changed
					newRev := h.states["txn"].Desired
					h.mu.Unlock()
					if newRev != revisionB {
						break
					}
					select {
					case <-changed:
					case <-deadline:
						t.Fatal("new intent not admitted")
					}
				}
			case "disable":
				if err := k.SetEnabled("txn", false); err != nil {
					t.Fatal(err)
				}
			}
			releaseV4(release)
			if mode == "caller-cancel" {
				v := f03WaitTerminal(t, h)
				if v.Phase != "committed" || f03Mode(t, k) != "B" {
					t.Fatalf("caller cancellation abandoned/duplicated operation: %+v", v)
				}
			} else {
				if err := <-resultB; err == nil {
					t.Fatal("superseded B falsely succeeded")
				}
				v, ok := h.ConfigOperation(opB.id)
				if !ok || v.Phase != "superseded" {
					t.Fatalf("B did not settle superseded: %+v", v)
				}
				if resultC != nil {
					if err := <-resultC; err != nil {
						t.Fatal(err)
					}
					want := "C"
					if mode == "new-Reset" {
						want = "schema-default"
					}
					if f03Mode(t, k) != want || f03Latest(h).LastSuccessfulConfig["mode"] != want {
						t.Fatal("old B compensation covered new target")
					}
				}
				if mode == "disable" {
					if k.IsPluginActive("txn") {
						t.Fatal("old B revived disabled plugin")
					}
					if strings.Contains(string(f03Disk(t, k)), `"B"`) {
						t.Fatal("other writer persisted uncommitted B")
					}
				}
			}
			if bCalls.Load() != 1 {
				t.Fatal("B silently re-executed")
			}
		})
	}
}

func TestCordisF03SupersedeDuringCompensatingApply(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var a atomic.Int32
	k, h, _ := f03Fixture(t, func(c *PluginContext, cfg map[string]any) error {
		mode := ConfigString(cfg, "mode", "")
		if mode == "B" {
			return errors.New("B rejects")
		}
		if mode == "user-A" && a.Add(1) == 2 {
			close(entered)
			<-release
		}
		c.Provide("txn.svc", mode)
		return nil
	})
	defer releaseV4(release)
	resultB := make(chan error, 1)
	go func() { _, e := k.SetConfig("txn", map[string]any{"mode": "B"}); resultB <- e }()
	awaitSignal(t, entered)
	h.mu.Lock()
	old := h.configCurrent["txn"]
	oldRev := old.revision
	h.mu.Unlock()
	resultC := make(chan error, 1)
	go func() { _, e := k.SetConfig("txn", map[string]any{"mode": "C"}); resultC <- e }()
	deadline := time.After(time.Second)
	for {
		h.mu.Lock()
		rev, changed := h.states["txn"].Desired, h.changed
		h.mu.Unlock()
		if rev != oldRev {
			break
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatal("C not admitted while old A compensation waits")
		}
	}
	releaseV4(release)
	if e := <-resultB; e == nil {
		t.Fatal("old B reported success")
	}
	if e := <-resultC; e != nil {
		t.Fatal(e)
	}
	v, ok := h.ConfigOperation(old.id)
	if !ok || v.Phase != "superseded" || f03Mode(t, k) != "C" || f03Latest(h).Phase != "committed" {
		t.Fatalf("late A compensation overwrote C: %+v", v)
	}
	if !strings.Contains(string(f03Disk(t, k)), `"C"`) {
		t.Fatal("late raw disk rollback overwrote C")
	}
}
func TestCordisF03PostRenameCancellationAndHostDeath(t *testing.T) {
	for _, mode := range []string{"caller-cancel", "host-death", "rename-return-unknown"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			k, h, raw := f03Fixture(t, func(c *PluginContext, cfg map[string]any) error {
				if ConfigString(cfg, "mode", "") == "B" {
					calls.Add(1)
				}
				c.Provide("txn.svc", ConfigString(cfg, "mode", ""))
				return nil
			})
			entered, release := make(chan struct{}), make(chan struct{})
			defer releaseV4(release)
			if mode == "rename-return-unknown" {
				h.configIO = &cordisConfigIO{rename: func(a, b, phase string) error {
					err := os.Rename(a, b)
					if phase == "commit" && err == nil {
						return errors.New("rename completed but caller did not observe ACK")
					}
					return err
				}}
			} else {
				h.configIO = &cordisConfigIO{syncDir: func(_, phase string) error {
					if phase == "commit" {
						close(entered)
						<-release
					}
					return nil
				}}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, e := k.SetConfigContext(ctx, "txn", map[string]any{"mode": "B"}); result <- e }()
			if mode != "rename-return-unknown" {
				awaitSignal(t, entered)
				// Owner state is queryable while real FS is stalled; lifecycle lock is NOT held.
				v := f03Latest(h)
				if v.Phase != "persisting" || !v.RunningLive || v.RunningConfig["mode"] != "B" {
					t.Fatalf("wrong actual running state during FS: %+v", v)
				}
				if mode == "caller-cancel" {
					cancel()
					if e := <-result; !errors.Is(e, context.Canceled) {
						t.Fatal(e)
					}
				} else {
					h.worker.abort()
					awaitSignal(t, h.worker.exited)
				}
				releaseV4(release)
			}
			if mode != "caller-cancel" {
				if e := <-result; e == nil {
					t.Fatal("failed write/host loss falsely succeeded")
				}
			}
			v := f03WaitTerminal(t, h)
			switch mode {
			case "caller-cancel":
				if v.Phase != "committed" || f03Mode(t, k) != "B" {
					t.Fatalf("caller cancel double-executed/abandoned confirmed owner commit: %+v", v)
				}
			case "host-death":
				if v.Phase != "recovery-required" || v.RunningLive || string(f03Disk(t, k)) != string(raw) {
					t.Fatalf("dead host faked real A recovery/disk rollback: %+v", v)
				}
			case "rename-return-unknown":
				if v.Phase != "recovered" || f03Mode(t, k) != "user-A" || string(f03Disk(t, k)) != string(raw) {
					t.Fatalf("rename uncertainty not resolved through real bytes and new A: %+v", v)
				}
			}
			if calls.Load() != 1 {
				t.Fatal("B silently re-executed")
			}
		})
	}
}
func TestCordisF03LostPlanACKNeverReexecutes(t *testing.T) {
	for _, drop := range []int{2, 3} {
		t.Run(fmt.Sprintf("plan-%d", drop), func(t *testing.T) {
			actual := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
			if actual == "" {
				t.Skip("explicit host")
			}
			dir := t.TempDir()
			wrapper := filepath.Join(dir, "lost-plan-ack.mjs")
			marker := filepath.Join(dir, "dropped.txt")
			hp, _ := json.Marshal(actual)
			mp, _ := json.Marshal(marker)
			script := `import{appendFileSync}from'node:fs';import{pathToFileURL}from'node:url';let buffer='',plans=0;const requests=new Map();process.stdin.on('data',chunk=>{buffer+=String(chunk);let index;while((index=buffer.indexOf('\n'))>=0){let line=buffer.slice(0,index);buffer=buffer.slice(index+1);try{let r=JSON.parse(line);if(r.kind==='request')requests.set(r.id,r.op);}catch{}}});const out=process.stdout.write.bind(process.stdout);process.stdout.write=(chunk,...rest)=>{try{const f=JSON.parse(String(chunk));if(f.kind==='response'&&requests.get(f.id)==='plan'){plans++;if(plans===` + strconv.Itoa(drop) + `){appendFileSync(` + string(mp) + `,f.id+'\n');return true;}}}catch{}return out(chunk,...rest)};await import(pathToFileURL(` + string(hp) + `).href);`
			if e := os.WriteFile(wrapper, []byte(script), 0600); e != nil {
				t.Fatal(e)
			}
			t.Setenv("PKTPATH_TEST_CORDIS_HOST", wrapper)
			var a, b atomic.Int32
			k, h, raw := f03Fixture(t, func(c *PluginContext, cfg map[string]any) error {
				v := ConfigString(cfg, "mode", "")
				if v == "user-A" {
					a.Add(1)
				}
				if v == "B" {
					b.Add(1)
					if drop == 3 {
						return errors.New("B failure forces A compensation plan")
					}
				}
				c.Provide("txn.svc", v)
				return nil
			})
			if _, e := k.SetConfig("txn", map[string]any{"mode": "B"}); e == nil {
				t.Fatal("missing plan ACK falsely succeeded")
			}
			v := f03WaitTerminal(t, h)
			if v.Phase != "recovery-required" || v.RunningLive || string(f03Disk(t, k)) != string(raw) {
				t.Fatalf("ACK unknown faked rollback/live A: %+v", v)
			}
			if b.Load() != 1 || a.Load() != int32(drop-1) {
				t.Fatalf("unknown ACK retried a plan: A=%d B=%d", a.Load(), b.Load())
			}
			if data, e := os.ReadFile(marker); e != nil || len(data) == 0 {
				t.Fatal("lost ACK fixture did not actually drop response", e)
			}
		})
	}
}
func TestCordisF03ProviderAndOtherWriterInvalidation(t *testing.T) {
	host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if host == "" {
		t.Skip("explicit host")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	defer releaseV4(release)
	root := &stubPlugin{meta: PluginMeta{ID: "provider"}, apply: func(c *PluginContext, _ map[string]any) error { c.Provide("provider.svc", true); return nil }}
	leaf := &stubPlugin{meta: PluginMeta{ID: "txn", Requires: []string{"provider.svc"}}, schema: &ConfigSchema{Fields: []FieldSchema{{Key: "mode", Type: FieldString, Default: "user-A"}}}, apply: func(c *PluginContext, cfg map[string]any) error {
		v := ConfigString(cfg, "mode", "")
		if v == "B" {
			close(entered)
			<-release
		}
		c.Provide("txn.svc", v)
		return nil
	}}
	h := NewCordisLifecycleHost(CordisLifecycleOptions{HostPath: host, PluginIDs: []string{"provider", "txn"}, ConfigTransactions: true, CleanupTimeout: 200 * time.Millisecond, CleanupExecutionTimeout: 200 * time.Millisecond, OperationTimeout: 500 * time.Millisecond})
	k := New(HostServices{AppDir: t.TempDir(), LifecycleHost: h})
	k.RegisterBuiltin(leaf, true)
	k.RegisterBuiltin(root, true)
	if e := k.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(k.Shutdown)
	waitLifecycle(t, h, "provider", "txn")
	result := make(chan error, 1)
	go func() { _, e := k.SetConfig("txn", map[string]any{"mode": "B"}); result <- e }()
	awaitSignal(t, entered)
	if e := k.SetEnabled("provider", false); e != nil {
		t.Fatal(e)
	}
	providerDisk := string(f03Disk(t, k))
	releaseV4(release)
	if e := <-result; e == nil {
		t.Fatal("lost provider falsely committed")
	}
	v := f03WaitTerminal(t, h)
	if v.Phase != "recovery-required" || v.RunningLive || string(f03Disk(t, k)) != providerDisk || strings.Contains(providerDisk, `"B"`) {
		t.Fatalf("old compensation overwrote provider/file intent or faked A: %+v", v)
	}
}
func TestCordisF03AbsentDiskAndPreflightRejections(t *testing.T) {
	for _, mode := range []string{"restore-absence", "future-version", "malformed", "unknown-old-config", "nonregular"} {
		t.Run(mode, func(t *testing.T) {
			var applies atomic.Int32
			k, h, _ := f03Fixture(t, func(c *PluginContext, cfg map[string]any) error {
				applies.Add(1)
				c.Provide("txn.svc", ConfigString(cfg, "mode", ""))
				return nil
			})
			gen := generationOf(h, "txn")
			switch mode {
			case "restore-absence":
				if e := os.Remove(k.configPath); e != nil {
					t.Fatal(e)
				}
				h.configIO = &cordisConfigIO{syncDir: func(_, phase string) error {
					if phase == "commit" {
						return errors.New("committed file, no sync proof")
					}
					return nil
				}}
			case "future-version":
				os.WriteFile(k.configPath, []byte(`{"version":3,"plugins":{}}`), 0600)
			case "malformed":
				os.WriteFile(k.configPath, []byte("bad-json-original"), 0600)
			case "unknown-old-config":
				os.WriteFile(k.configPath, []byte(`{"version":2,"plugins":{"txn":{"config":{"mode":"user-A","future":7}}}}`), 0600)
			case "nonregular":
				os.Remove(k.configPath)
				os.Mkdir(k.configPath, 0700)
				os.WriteFile(filepath.Join(k.configPath, "keep"), []byte("sentinel"), 0600)
			}
			before, _ := os.ReadFile(k.configPath)
			if _, e := k.SetConfig("txn", map[string]any{"mode": "B"}); e == nil {
				t.Fatal("failure preflight/rollback falsely succeeded")
			}
			if mode == "restore-absence" {
				v := f03Latest(h)
				if v.Phase != "recovered" || v.LastObservedDiskHash != "absent" || v.RunningGeneration == gen || applies.Load() != 3 {
					t.Fatalf("absence not truly restored: %+v", v)
				}
				if _, e := os.Stat(k.configPath); !os.IsNotExist(e) {
					t.Fatal("original absence turned into a default file")
				}
			} else {
				after, _ := os.ReadFile(k.configPath)
				if applies.Load() != 1 || generationOf(h, "txn") != gen || string(after) != string(before) || len(h.Snapshot().ConfigOperations) != 0 {
					t.Fatal("preflight rejection had activation/disk side effects")
				}
			}
		})
	}
}
func TestCordisF03CancellationWhileWaitingFileAdmission(t *testing.T) {
	var calls atomic.Int32
	k, h, raw := f03Fixture(t, func(c *PluginContext, cfg map[string]any) error {
		calls.Add(1)
		c.Provide("txn.svc", ConfigString(cfg, "mode", ""))
		return nil
	})
	gen := generationOf(h, "txn")
	k.persistMu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, e := k.SetConfigContext(ctx, "txn", map[string]any{"mode": "B"}); result <- e }()
	cancel()
	k.persistMu.Unlock()
	if e := <-result; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if calls.Load() != 1 || generationOf(h, "txn") != gen || len(h.Snapshot().ConfigOperations) != 0 || string(f03Disk(t, k)) != string(raw) {
		t.Fatal("cancelled queued admission later performed effects")
	}
}
func TestCordisF03ProviderInstanceChangeIsNotRecoveredA(t *testing.T) {
	host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if host == "" {
		t.Skip("explicit host")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	defer releaseV4(release)
	var first atomic.Bool
	root := &stubPlugin{meta: PluginMeta{ID: "provider"}, apply: func(c *PluginContext, _ map[string]any) error { c.Provide("provider.svc", true); return nil }}
	leaf := &stubPlugin{meta: PluginMeta{ID: "txn", Requires: []string{"provider.svc"}}, schema: &ConfigSchema{Fields: []FieldSchema{{Key: "mode", Type: FieldString, Default: "user-A"}}}, apply: func(c *PluginContext, cfg map[string]any) error {
		v := ConfigString(cfg, "mode", "")
		if v == "B" && first.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		c.Provide("txn.svc", v)
		return nil
	}}
	h := NewCordisLifecycleHost(CordisLifecycleOptions{HostPath: host, PluginIDs: []string{"provider", "txn"}, ConfigTransactions: true, CleanupTimeout: 250 * time.Millisecond, CleanupExecutionTimeout: 250 * time.Millisecond, OperationTimeout: 600 * time.Millisecond})
	k := New(HostServices{AppDir: t.TempDir(), LifecycleHost: h})
	k.RegisterBuiltin(leaf, true)
	k.RegisterBuiltin(root, true)
	if e := k.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(k.Shutdown)
	waitLifecycle(t, h, "provider", "txn")
	result := make(chan error, 1)
	go func() { _, e := k.SetConfig("txn", map[string]any{"mode": "B"}); result <- e }()
	awaitSignal(t, entered)
	oldProvider := generationOf(h, "provider")
	if e := k.Reload("provider"); e != nil {
		t.Fatal(e)
	}
	if generationOf(h, "provider") == oldProvider {
		t.Fatal("test did not replace real provider")
	}
	releaseV4(release)
	if e := <-result; e == nil {
		t.Fatal("changed dependency instance falsely committed old transaction")
	}
	v := f03WaitTerminal(t, h)
	if v.Phase != "recovery-required" || v.LastSuccessfulConfig["mode"] != "user-A" || v.RunningLive {
		t.Fatalf("different provider mistaken for old baseline recovery: %+v", v)
	}
	if _, e := k.ResetConfig("txn"); e == nil {
		t.Fatal("Reset washed dependency recovery-required")
	}
}
