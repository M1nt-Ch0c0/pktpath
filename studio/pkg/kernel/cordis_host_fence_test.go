package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// A real Node/Core frame is dispatched by the production read loop, then parked
// before scope admission. No fake model of either scheduler or failHost is used.
func TestCordisF02V3QueuedAdmissionFence(t *testing.T) {
	for _, mode := range []string{"live-control", "cancel-before-admission", "EOF-before-admission", "exit-before-admission"} {
		t.Run(mode, func(t *testing.T) {
			host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
			if host == "" {
				t.Skip("explicit host")
			}
			var calls, clean atomic.Int32
			id := "fence.queued"
			p := &stubPlugin{meta: PluginMeta{ID: id}, apply: func(c *PluginContext, _ map[string]any) error {
				calls.Add(1)
				c.Provide("queued.svc", true)
				c.OnDispose(func() { clean.Add(1) })
				return nil
			}}
			h := NewCordisLifecycleHost(CordisLifecycleOptions{HostPath: host, PluginIDs: []string{id}, CleanupTimeout: 100 * time.Millisecond})
			k := New(HostServices{AppDir: t.TempDir(), LifecycleHost: h})
			k.RegisterBuiltin(p, true)
			h.kernel = k
			h.nextRevision = 1
			h.hostEpoch = 1
			h.states[id] = &CordisPluginState{Plugin: id, Desired: "1", State: "waiting-deps"}
			arrived, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var first atomic.Bool
			w, err := startCordisWorkerMode(CordisAnalyzerOptions{HostPath: host}, cordisLifecycleProtocol, func(w *cordisWorker, raw []byte) {
				var q cordisNodeRequest
				json.Unmarshal(raw, &q)
				if q.Op == "prepare" && first.CompareAndSwap(false, true) {
					close(arrived)
					<-release
					defer close(finished)
				}
				h.handle(w, raw)
			}, h.failWorker)
			if err != nil {
				t.Fatal(err)
			}
			h.mu.Lock()
			h.worker = w
			h.mu.Unlock()
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				h.Close(ctx)
			}()
			if err := w.control("plan", map[string]any{"entries": []cordisPlan{{id, "1", true, []string{}}}}, nil); err != nil {
				t.Fatal(err)
			}
			awaitSignal(t, arrived)
			switch mode {
			case "cancel-before-admission":
				if err := k.SetEnabled(id, false); err != nil {
					t.Fatal(err)
				}
			case "EOF-before-admission":
				w.input.Close()
				awaitSignal(t, w.exited)
			case "exit-before-admission":
				w.abort()
				awaitSignal(t, w.exited)
			}
			close(release)
			awaitSignal(t, finished)
			if mode == "live-control" {
				waitLifecycle(t, h, id)
				if calls.Load() != 1 {
					t.Fatal("valid live request incorrectly blocked")
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := h.Close(ctx); err != nil {
					t.Fatal(err)
				}
				if clean.Load() != 1 {
					t.Fatalf("cleanup=%d", clean.Load())
				}
			} else {
				if calls.Load() != 0 || k.IsPluginActive(id) {
					t.Fatalf("late admission: calls=%d", calls.Load())
				}
				if _, ok := k.Service("queued.svc"); ok {
					t.Fatal("late visible service")
				}
				h.mu.Lock()
				state := h.states[id].State
				h.mu.Unlock()
				if mode != "cancel-before-admission" && state != "host-unavailable" {
					t.Fatalf("failure state overwritten: %s", state)
				}
				if clean.Load() != 0 {
					t.Fatal("never-started scope got synthetic cleanup")
				}
			}
		})
	}
}

func TestCordisF02V3TransportDeadBeforeOwnerObserver(t *testing.T) {
	host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if host == "" {
		t.Skip("explicit host")
	}
	var calls atomic.Int32
	id := "dead-before-observer"
	h := NewCordisLifecycleHost(CordisLifecycleOptions{HostPath: host, PluginIDs: []string{id}})
	k := New(HostServices{AppDir: t.TempDir(), LifecycleHost: h})
	k.RegisterBuiltin(&stubPlugin{meta: PluginMeta{ID: id}, apply: func(*PluginContext, map[string]any) error { calls.Add(1); return nil }}, true)
	h.kernel = k
	h.states[id] = &CordisPluginState{Plugin: id, Desired: "1", State: "waiting-deps"}
	frame := make(chan cordisNodeRequest, 1)
	failureEntered, releaseFailure := make(chan struct{}), make(chan struct{})
	w, err := startCordisWorkerMode(CordisAnalyzerOptions{HostPath: host}, cordisLifecycleProtocol, func(_ *cordisWorker, raw []byte) { var req cordisNodeRequest; json.Unmarshal(raw, &req); frame <- req }, func(w *cordisWorker, err error) { close(failureEntered); <-releaseFailure; h.failWorker(w, err) })
	if err != nil {
		t.Fatal(err)
	}
	h.worker = w
	defer func() {
		select {
		case <-releaseFailure:
		default:
			close(releaseFailure)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		h.Close(ctx)
	}()
	if err = w.control("plan", map[string]any{"entries": []cordisPlan{{id, "1", true, []string{}}}}, nil); err != nil {
		t.Fatal(err)
	}
	var req cordisNodeRequest
	select {
	case req = <-frame:
	case <-time.After(time.Second):
		t.Fatal("no real frame")
	}
	w.abort()
	awaitSignal(t, failureEntered)
	h.mu.Lock()
	observed := h.startupError
	h.mu.Unlock()
	if observed != nil {
		t.Fatal("observer barrier was ineffective")
	}
	if _, err = h.prepareFrom(w, req); err == nil || calls.Load() != 0 {
		t.Fatal("transport-dead request admitted before owner observer")
	}
	close(releaseFailure)
	awaitSignal(t, w.exited)
}

func TestCordisF02V3AdmittedScopeEOFUniqueCleanup(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls, clean atomic.Int32
	k, h := lifecycleFixture(t, &stubPlugin{meta: PluginMeta{ID: "admitted"}, apply: func(c *PluginContext, _ map[string]any) error {
		calls.Add(1)
		c.Provide("stale.svc", true)
		c.OnDispose(func() { clean.Add(1) })
		close(entered)
		<-release
		return nil
	}})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	awaitSignal(t, entered)
	b := scopeFor(t, h, "admitted")
	h.worker.abort()
	awaitSignal(t, h.worker.exited)
	close(release)
	awaitSignal(t, b.cleanupDone)
	h.mu.Lock()
	h.revokeLocked(b, "duplicate local disposal")
	state := h.states["admitted"].State
	h.mu.Unlock()
	if calls.Load() != 1 || clean.Load() != 1 || k.IsPluginActive("admitted") || state != "host-unavailable" {
		t.Fatalf("calls=%d cleanup=%d state=%s", calls.Load(), clean.Load(), state)
	}
	if _, ok := k.Service("stale.svc"); ok {
		t.Fatal("late commit after EOF")
	}
}

func TestCordisF02V3DifferentRealHostCannotReplayOrFailCurrent(t *testing.T) {
	var c1, c2 atomic.Int32
	p := func(counter *atomic.Int32) *stubPlugin {
		return &stubPlugin{meta: PluginMeta{ID: "same.id"}, apply: func(c *PluginContext, _ map[string]any) error { counter.Add(1); c.Provide("current", true); return nil }}
	}
	_, h1 := lifecycleFixture(t, p(&c1))
	waitLifecycle(t, h1, "same.id")
	old := scopeFor(t, h1, "same.id")
	w1 := h1.worker
	k2, h2 := lifecycleFixture(t, p(&c2))
	waitLifecycle(t, h2, "same.id")
	generation := generationOf(h2, "same.id")
	req := cordisNodeRequest{Plugin: "same.id", Revision: "1", Attempt: "same.id/1/999", Incarnation: w1.incarnation, Deps: map[string]string{}}
	if _, err := h2.prepareFrom(w1, req); err == nil {
		t.Fatal("obsolete source worker admitted")
	}
	if _, err := h2.prepareFrom(h2.worker, req); err == nil {
		t.Fatal("old incarnation replay admitted via current route")
	}
	if err := h2.revokeFrom(h2.worker, req); err == nil {
		t.Fatal("old incarnation revoke accepted")
	}
	h2.failWorker(w1, errors.New("late old-host failure"))
	if c2.Load() != 1 || generationOf(h2, "same.id") != generation || !k2.IsPluginActive("same.id") {
		t.Fatal("old host changed current host")
	}
	if old.hostIncarnation == h2.worker.incarnation {
		t.Fatal("host nonce reused")
	}
}

func TestCordisF02V3CommitRechecksAdmissionEpoch(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var clean atomic.Int32
	k, h := lifecycleFixture(t, &stubPlugin{meta: PluginMeta{ID: "epoch"}, apply: func(c *PluginContext, _ map[string]any) error {
		c.Provide("epoch.svc", true)
		c.OnDispose(func() { clean.Add(1) })
		close(entered)
		<-release
		return nil
	}})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	awaitSignal(t, entered)
	b := scopeFor(t, h, "epoch")
	// Structural stronger check: same live worker/intent/deps, only owner epoch
	// has changed. This is not claimed as a production hot-restart API.
	h.mu.Lock()
	h.hostEpoch++
	h.mu.Unlock()
	close(release)
	awaitSignal(t, b.cleanupDone)
	if _, ok := k.Service("epoch.svc"); ok || k.IsPluginActive("epoch") || clean.Load() != 1 {
		t.Fatal(fmt.Sprintf("old admission epoch committed or cleanup=%d", clean.Load()))
	}
}
