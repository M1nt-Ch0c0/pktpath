package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func lifecycleFixture(t *testing.T, ps ...*stubPlugin) (*Kernel, *CordisLifecycleHost) {
	t.Helper()
	path := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if path == "" {
		t.Skip("explicit controlled Node host required")
	}
	ids := []string{}
	for _, p := range ps {
		ids = append(ids, p.meta.ID)
	}
	h := NewCordisLifecycleHost(CordisLifecycleOptions{HostPath: path, PluginIDs: ids, CleanupTimeout: 100 * time.Millisecond, OperationTimeout: 800 * time.Millisecond})
	k := New(HostServices{AppDir: t.TempDir(), LifecycleHost: h})
	for _, p := range ps {
		k.RegisterBuiltin(p, true)
	}
	if err := k.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Shutdown)
	return k, h
}
func waitLifecycle(t *testing.T, h *CordisLifecycleHost, ids ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := h.WaitActive(ctx, ids...); err != nil {
		state, _ := json.Marshal(h.Snapshot())
		node, _ := h.NodeState()
		t.Fatalf("%v\nGo=%s\nNode=%s", err, state, node)
	}
}
func awaitSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("barrier deadline")
	}
}
func scopeFor(t *testing.T, h *CordisLifecycleHost, id string) *cordisScope {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, b := range h.attempts {
		if b.plugin == id {
			return b
		}
	}
	t.Fatal("scope absent")
	return nil
}
func generationOf(h *CordisLifecycleHost, id string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.states[id].Generation
}

func TestCordisF02ChainLossRecoveryAndInstance(t *testing.T) {
	var aCount, bCount, cCount atomic.Int32
	a := &stubPlugin{meta: PluginMeta{ID: "a", Provides: []string{"svc.a"}}, apply: func(c *PluginContext, _ map[string]any) error {
		n := aCount.Add(1)
		c.Provide("svc.a", n)
		c.RegisterExtension("chain", "a")
		return nil
	}}
	b := &stubPlugin{meta: PluginMeta{ID: "b", Requires: []string{"svc.a"}}, apply: func(c *PluginContext, _ map[string]any) error {
		if _, ok := c.Inject("svc.a"); !ok {
			return errors.New("missing snapshot")
		}
		bCount.Add(1)
		c.Provide("svc.b", true)
		c.RegisterExtension("chain", "b")
		return nil
	}}
	c := &stubPlugin{meta: PluginMeta{ID: "c", Requires: []string{"svc.b"}}, apply: func(c *PluginContext, _ map[string]any) error {
		cCount.Add(1)
		c.RegisterExtension("chain", "c")
		return nil
	}}
	// Reverse registration defeats one-pass order; real shared Cordis graph starts it.
	k, h := lifecycleFixture(t, c, b, a)
	waitLifecycle(t, h, "a", "b", "c")
	before := map[string]string{}
	for _, id := range []string{"a", "b", "c"} {
		before[id] = generationOf(h, id)
	}
	if err := k.SetEnabled("a", false); err != nil {
		t.Fatal(err)
	}
	if len(k.Extensions("chain")) != 0 || k.IsPluginActive("b") || k.IsPluginActive("c") {
		t.Fatal("transitive Go visibility survived revoke")
	}
	if err := k.SetEnabled("a", true); err != nil {
		t.Fatal(err)
	}
	waitLifecycle(t, h, "a", "b", "c")
	for _, id := range []string{"a", "b", "c"} {
		if generationOf(h, id) == before[id] {
			t.Fatalf("%s reused activation", id)
		}
	}
	if aCount.Load() != 2 || bCount.Load() != 2 || cCount.Load() != 2 {
		t.Fatalf("duplicate/missing Apply: %d %d %d", aCount.Load(), bCount.Load(), cCount.Load())
	}
	node, err := h.NodeState()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(node), "cordis-dispose") || !strings.Contains(string(node), "cordis-apply") {
		t.Fatalf("not real Cordis trace: %s", node)
	}
	// Same-config reload must replace service instance and all required consumers.
	old := generationOf(h, "c")
	if err = k.Reload("a"); err != nil {
		t.Fatal(err)
	}
	waitLifecycle(t, h, "b", "c")
	if generationOf(h, "c") == old {
		t.Fatal("same-config provider reload did not rebuild C")
	}
}

func TestCordisF02AtomicStagingAllPointsAndLateApply(t *testing.T) {
	entered, release, disposed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	points := []string{ExtTransport, ExtCollector, ExtCaptureMode, ExtKernelExt, ExtAnalyzer, ExtExporter, ExtUISlot, ExtTheme, "custom.point"}
	p := &stubPlugin{meta: PluginMeta{ID: "late"}, apply: func(c *PluginContext, _ map[string]any) error {
		c.Provide("hidden", uint64(18446744073709551615))
		for _, point := range points {
			c.RegisterExtension(point, "opaque")
		}
		close(entered)
		<-release
		if err := c.OnDisposeTask(func(context.Context) error { close(disposed); return nil }); err != nil {
			return err
		}
		return nil
	}}
	k, h := lifecycleFixture(t, p)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	awaitSignal(t, entered)
	if _, ok := k.Service("hidden"); ok {
		t.Fatal("partial service visible")
	}
	for _, point := range points {
		if len(k.Extensions(point)) != 0 {
			t.Fatal("partial extension visible")
		}
	}
	if err := k.SetEnabled("late", false); err != nil {
		t.Fatal(err)
	}
	close(release)
	awaitSignal(t, disposed)
	b := scopeFor(t, h, "late")
	awaitSignal(t, b.cleanupDone)
	if k.IsPluginActive("late") {
		t.Fatal("stale Apply committed")
	}
	for _, point := range points {
		if len(k.Extensions(point)) != 0 {
			t.Fatal("stale extension resurrected")
		}
	}
	if _, ok := k.Service("hidden"); ok {
		t.Fatal("stale u64 service resurrected")
	}
}

func TestCordisF02ApplyFailureRollsBackAndCleanupLIFO(t *testing.T) {
	order := make(chan int, 2)
	p := &stubPlugin{meta: PluginMeta{ID: "failed"}, apply: func(c *PluginContext, _ map[string]any) error {
		c.Provide("failed.svc", true)
		c.RegisterExtension(ExtExporter, ExporterSpec{ID: "failed"})
		c.OnDispose(func() { order <- 1 })
		c.OnDisposeTask(func(context.Context) error { order <- 2; return nil })
		return errors.New("controlled fail")
	}}
	k, h := lifecycleFixture(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.WaitActive(ctx, "failed"); err == nil {
		t.Fatal("failure hidden")
	}
	b := scopeFor(t, h, "failed")
	awaitSignal(t, b.cleanupDone)
	if <-order != 2 || <-order != 1 {
		t.Fatal("not LIFO")
	}
	if _, ok := k.Service("failed.svc"); ok || len(k.Exporters()) != 0 {
		t.Fatal("failed staging leaked")
	}
}

func TestCordisF02ExplicitAsyncCleanupQuarantineAndRecovery(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var n atomic.Int32
	p := &stubPlugin{meta: PluginMeta{ID: "async"}, apply: func(c *PluginContext, _ map[string]any) error {
		v := n.Add(1)
		c.Provide("async.svc", v)
		if v == 1 {
			return c.OnDisposeTask(func(context.Context) error { close(started); <-release; return nil })
		}
		return nil
	}}
	k, h := lifecycleFixture(t, p)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	waitLifecycle(t, h, "async")
	old := scopeFor(t, h, "async")
	if err := k.SetEnabled("async", false); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, started)
	// Exercise a NEW enable only after the old drain already timed out, not just
	// the easier race in which the pending old timeout later updates new state.
	deadline, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for {
		h.mu.Lock()
		state := h.states["async"].State
		changed := h.changed
		h.mu.Unlock()
		if state == "cleanup-timeout-pending" {
			break
		}
		select {
		case <-changed:
		case <-deadline.Done():
			t.Fatal("cleanup deadline not surfaced")
		}
	}
	if err := k.SetEnabled("async", true); err == nil || !strings.Contains(err.Error(), "cleanup-timeout-pending") {
		t.Fatalf("known quarantine disguised as pending: %v", err)
	}
	if n.Load() != 1 {
		t.Fatal("new Apply ran while old cleanup blocked")
	}
	if _, ok := k.Service("async.svc"); ok {
		t.Fatal("revoked service survived")
	}
	close(release)
	awaitSignal(t, old.cleanupDone)
	// Explicit retry only after actual observed completion, not deadline.
	if err := k.Reload("async"); err != nil {
		t.Fatal(err)
	}
	waitLifecycle(t, h, "async")
	if n.Load() != 2 {
		t.Fatal("no explicit recovery")
	}
	// Delayed old exact-scope revoke must not erase the new same-ID service.
	h.mu.Lock()
	h.revokeLocked(old, "delayed old revoke")
	h.mu.Unlock()
	value, ok := k.Service("async.svc")
	if !ok || value != int32(2) {
		t.Fatalf("new service deleted: %#v", value)
	}
}

func TestCordisF02SavedFailedConfigAndExplicitReset(t *testing.T) {
	p := &stubPlugin{meta: PluginMeta{ID: "cfg"}, schema: &ConfigSchema{Fields: []FieldSchema{{Key: "mode", Type: FieldString, Default: "A"}}}, apply: func(c *PluginContext, cfg map[string]any) error {
		if ConfigString(cfg, "mode", "") == "B" {
			return errors.New("B activation rejected")
		}
		c.Provide("cfg.svc", ConfigString(cfg, "mode", ""))
		return nil
	}}
	k, h := lifecycleFixture(t, p)
	waitLifecycle(t, h, "cfg")
	before := generationOf(h, "cfg")
	if _, err := k.SetConfig("cfg", map[string]any{"mode": "B"}); err == nil || !strings.Contains(err.Error(), "已保存/激活失败") {
		t.Fatalf("ambiguous saved failure: %v", err)
	}
	if ConfigString(k.PluginConfig("cfg"), "mode", "") != "B" {
		t.Fatal("claimed automatic rollback")
	}
	persisted := k.readPersistedConfig()
	if ConfigString(persisted.Plugins["cfg"].Config, "mode", "") != "B" {
		t.Fatal("old saved-failed semantics changed")
	}
	snap := h.Snapshot()
	if snap.Plugins[0].Desired == snap.Plugins[0].Effective {
		t.Fatal("desired/effective revision conflated")
	}
	if _, err := k.ResetConfig("cfg"); err != nil {
		t.Fatal(err)
	}
	waitLifecycle(t, h, "cfg")
	if generationOf(h, "cfg") == before {
		t.Fatal("config hash used as generation")
	}
	if value, _ := k.Service("cfg.svc"); value != "A" {
		t.Fatalf("explicit reset failed: %v", value)
	}
}

func TestCordisF02DeclarationsNotProofAndPluginFallback(t *testing.T) {
	t.Run("false declaration", func(t *testing.T) {
		var applied atomic.Int32
		k, h := lifecycleFixture(t, &stubPlugin{meta: PluginMeta{ID: "consumer", Requires: []string{"missing"}}, apply: func(*PluginContext, map[string]any) error { applied.Add(1); return nil }}, &stubPlugin{meta: PluginMeta{ID: "declares", Provides: []string{"missing"}}})
		waitLifecycle(t, h, "declares")
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if h.WaitActive(ctx, "consumer") == nil || applied.Load() != 0 || k.IsPluginActive("consumer") {
			t.Fatal("Meta.Provides treated as proof")
		}
	})
	t.Run("active plugin ID fallback", func(t *testing.T) {
		_, h := lifecycleFixture(t, &stubPlugin{meta: PluginMeta{ID: "dependent", Requires: []string{"provider"}}}, &stubPlugin{meta: PluginMeta{ID: "provider"}})
		waitLifecycle(t, h, "provider", "dependent")
	})
}

func TestCordisF02HostFailureWithdrawsWithoutGoFallback(t *testing.T) {
	var n atomic.Int32
	k, h := lifecycleFixture(t, &stubPlugin{meta: PluginMeta{ID: "crash"}, apply: func(c *PluginContext, _ map[string]any) error { n.Add(1); c.Provide("crash.svc", true); return nil }})
	waitLifecycle(t, h, "crash")
	h.mu.Lock()
	w := h.worker
	h.mu.Unlock()
	w.abort()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for {
		h.mu.Lock()
		s := h.states["crash"].State
		changed := h.changed
		h.mu.Unlock()
		if s == "host-unavailable" {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("host failure not surfaced")
		}
	}
	if _, ok := k.Service("crash.svc"); ok || k.IsPluginActive("crash") {
		t.Fatal("failed host registrations survived")
	}
	if err := k.Reload("crash"); err == nil || n.Load() != 1 {
		t.Fatal("host failure retried Go Apply")
	}
}

func TestCordisF02LateRejectedApplyCannotCancelRebuiltScope(t *testing.T) {
	entered, release, second := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	a := &stubPlugin{meta: PluginMeta{ID: "source"}, apply: func(c *PluginContext, _ map[string]any) error { c.Provide("source.svc", true); return nil }}
	b := &stubPlugin{meta: PluginMeta{ID: "waiting", Requires: []string{"source.svc"}}, apply: func(c *PluginContext, _ map[string]any) error {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			return errors.New("late old failure")
		}
		c.Provide("rebuilt", true)
		close(second)
		return nil
	}}
	k, h := lifecycleFixture(t, b, a)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	awaitSignal(t, entered)
	if err := k.SetEnabled("source", false); err != nil {
		t.Fatal(err)
	}
	if err := k.SetEnabled("source", true); err != nil {
		t.Fatal(err)
	}
	close(release)
	awaitSignal(t, second)
	waitLifecycle(t, h, "source", "waiting")
	node, err := h.NodeState()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(node), "stale-apply-error") {
		t.Fatalf("old rejection was not specifically fenced: %s", node)
	}
	if _, ok := k.Service("rebuilt"); !ok {
		t.Fatal("old async rejection cancelled current scope")
	}
}

func TestCordisF02LostPlanAckAfterOneApplyDoesNotReplay(t *testing.T) {
	path := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if path == "" {
		t.Skip("controlled Node required")
	}
	_ = path
	script := filepath.Join(t.TempDir(), "lost-ack.mjs")
	// Protocol fault fixture only, NOT presented as a real Cordis graph test.
	os.WriteFile(script, []byte(`import{createInterface}from'node:readline';const protocol='pktpath.cordis3.lifecycle/2';let incarnation;const emit=x=>process.stdout.write(JSON.stringify({protocol,incarnation,...x})+'\n');const r=createInterface({input:process.stdin});r.on('line',l=>{const q=JSON.parse(l);if(q.op==='hello'){incarnation=q.incarnation;emit({id:q.id,kind:'response',ok:true,core:'3.18.1',node:process.version})}else if(q.op==='plan'){const e=q.entries[0];emit({id:'node/1',kind:'request',op:'prepare',plugin:e.plugin,revision:e.revision,attempt:e.plugin+'/'+e.revision+'/1',deps:{}})}else if(q.id==='node/1')process.exit(0)});`), 0600)
	var apply, cleanup atomic.Int32
	h := NewCordisLifecycleHost(CordisLifecycleOptions{HostPath: script, PluginIDs: []string{"one"}})
	k := New(HostServices{AppDir: t.TempDir(), LifecycleHost: h})
	k.RegisterBuiltin(&stubPlugin{meta: PluginMeta{ID: "one"}, apply: func(c *PluginContext, _ map[string]any) error {
		apply.Add(1)
		c.Provide("one.svc", true)
		c.OnDispose(func() { cleanup.Add(1) })
		return nil
	}}, true)
	k.Start()
	defer k.Shutdown()
	if apply.Load() != 1 {
		t.Fatalf("fault fixture did not execute exactly once: %d", apply.Load())
	}
	h.mu.Lock()
	startup := h.startupError
	h.mu.Unlock()
	if startup == nil || !strings.Contains(startup.Error(), "unknown") {
		t.Fatalf("ACK uncertainty hidden: %v", startup)
	}
	b := scopeFor(t, h, "one")
	awaitSignal(t, b.cleanupDone)
	if cleanup.Load() != 1 {
		t.Fatal("uncertain activation not cleaned")
	}
	if k.IsPluginActive("one") {
		t.Fatal("uncertain host remained active")
	}
	if err := k.Reload("one"); err == nil || apply.Load() != 1 {
		t.Fatal("silent legacy Go replay")
	}
}

func TestCordisF02ConcurrentIntentsPersistLatestDesired(t *testing.T) {
	k, h := lifecycleFixture(t, &stubPlugin{meta: PluginMeta{ID: "concurrent"}, apply: func(c *PluginContext, _ map[string]any) error { c.Provide("c.svc", true); return nil }})
	waitLifecycle(t, h, "concurrent")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(enabled bool) { defer wg.Done(); errs <- k.SetEnabled("concurrent", enabled) }(i%2 == 0)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil && strings.Contains(err.Error(), "rename") {
			t.Fatalf("writer conflict: %v", err)
		}
	}
	if err := k.SetEnabled("concurrent", true); err != nil {
		t.Fatal(err)
	}
	waitLifecycle(t, h, "concurrent")
	disk := k.readPersistedConfig()
	if disk.Plugins["concurrent"].Enabled == nil || !*disk.Plugins["concurrent"].Enabled {
		t.Fatal("latest desired not persisted")
	}
	if len(k.Extensions("unused")) != 0 {
		t.Fatal("unexpected extension")
	}
}

func TestCordisF02OpaqueAllPointsAndU64NeverSerialized(t *testing.T) {
	points := []string{ExtTransport, ExtCollector, ExtCaptureMode, ExtKernelExt, ExtAnalyzer, ExtExporter, ExtUISlot, ExtTheme, "custom.open"}
	max := uint64(18446744073709551615)
	callback := func() uint64 { return max }
	payload := &struct{ Run func() uint64 }{callback}
	k, h := lifecycleFixture(t, &stubPlugin{meta: PluginMeta{ID: "opaque"}, apply: func(c *PluginContext, _ map[string]any) error {
		c.Provide("exact", max)
		c.Provide("function", callback)
		for _, p := range points {
			c.RegisterExtension(p, payload)
		}
		value, ok := c.Inject("exact")
		if !ok || value != max {
			return errors.New("own staging overlay lost")
		}
		return nil
	}})
	waitLifecycle(t, h, "opaque")
	v, ok := k.Service("exact")
	if !ok || v != max {
		t.Fatal("uint64 lost")
	}
	f, _ := k.Service("function")
	if f.(func() uint64)() != max {
		t.Fatal("Go callback handle lost")
	}
	for _, p := range points {
		entries := k.Extensions(p)
		if len(entries) != 1 || entries[0].Value != payload || entries[0].Value.(*struct{ Run func() uint64 }).Run() != max {
			t.Fatalf("opaque registration %s changed", p)
		}
	}
	node, err := h.NodeState()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(node), "18446744073709551615") {
		t.Fatal("business value crossed metadata-only wire")
	}
}

func TestCordisF02ServiceWinsOverPluginIDFacade(t *testing.T) {
	k, h := lifecycleFixture(t,
		&stubPlugin{meta: PluginMeta{ID: "alias"}},
		&stubPlugin{meta: PluginMeta{ID: "real-service"}, apply: func(c *PluginContext, _ map[string]any) error { c.Provide("alias", "service-value"); return nil }},
		&stubPlugin{meta: PluginMeta{ID: "uses-alias", Requires: []string{"alias"}}, apply: func(c *PluginContext, _ map[string]any) error {
			value, ok := c.Inject("alias")
			if !ok {
				value = "plugin-only"
			}
			c.Provide("resolution", value)
			return nil
		}},
	)
	waitLifecycle(t, h, "alias", "real-service", "uses-alias")
	if value, _ := k.Service("resolution"); value != "service-value" {
		t.Fatalf("service priority lost: %v", value)
	}
}

func TestCordisF02BlockedCleanupDoesNotLockIndependentPlugin(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	a := &stubPlugin{meta: PluginMeta{ID: "blocked"}, apply: func(c *PluginContext, _ map[string]any) error {
		return c.OnDisposeTask(func(context.Context) error { close(started); <-release; return nil })
	}}
	b := &stubPlugin{meta: PluginMeta{ID: "independent"}, apply: func(c *PluginContext, _ map[string]any) error { c.Provide("independent.svc", true); return nil }}
	k, h := lifecycleFixture(t, a, b)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	waitLifecycle(t, h, "blocked", "independent")
	if err := k.SetEnabled("blocked", false); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, started)
	if err := k.Reload("independent"); err != nil {
		t.Fatal(err)
	}
	waitLifecycle(t, h, "independent")
	close(release)
}

func TestCordisF02CompletedScopeLedgerPrunedAndReplayRejected(t *testing.T) {
	var calls atomic.Int32
	k, h := lifecycleFixture(t, &stubPlugin{meta: PluginMeta{ID: "churn"}, apply: func(c *PluginContext, _ map[string]any) error { calls.Add(1); c.Provide("churn.svc", true); return nil }})
	waitLifecycle(t, h, "churn")
	for i := 0; i < 16; i++ {
		if err := k.Reload("churn"); err != nil {
			t.Fatal(err)
		}
	}
	h.mu.Lock()
	retained := len(h.attempts)
	revision := h.states["churn"].Desired
	h.mu.Unlock()
	if retained > 2 {
		t.Fatalf("unbounded completed scope retention: %d", retained)
	}
	// Current-revision replay with old counter is not allowed after pruning.
	_, err := h.prepare(cordisNodeRequest{Plugin: "churn", Revision: revision, Attempt: "churn/" + revision + "/1", Incarnation: h.worker.incarnation, Deps: map[string]string{}})
	if err == nil || calls.Load() != 17 {
		t.Fatalf("replayed pruned request: calls=%d err=%v", calls.Load(), err)
	}
}

func TestCordisF02ServiceConflictIsTerminalNotPending(t *testing.T) {
	p := func(id string) *stubPlugin {
		return &stubPlugin{meta: PluginMeta{ID: id}, apply: func(c *PluginContext, _ map[string]any) error { c.Provide("conflict", id); return nil }}
	}
	_, h := lifecycleFixture(t, p("left"), p("right"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for {
		h.mu.Lock()
		failed := false
		for _, s := range h.states {
			if s.State == "failed" && strings.Contains(s.Error, "service conflict") {
				failed = true
			}
		}
		changed := h.changed
		h.mu.Unlock()
		if failed {
			return
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatalf("known commit conflict not terminal: %+v", h.Snapshot())
		}
	}
}
