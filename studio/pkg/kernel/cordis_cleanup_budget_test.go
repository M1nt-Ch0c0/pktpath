package kernel

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func waitCleanupView(t *testing.T, h *CordisLifecycleHost, b *cordisScope, predicate func(CordisCleanupView) bool) CordisCleanupView {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		h.mu.Lock()
		v := h.cleanupViewLocked(b)
		changed := h.changed
		h.mu.Unlock()
		if predicate(v) {
			return v
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatalf("cleanup phase wait: %+v", v)
		}
	}
}
func assertV4NotClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatal(what)
	default:
	}
}
func releaseV4(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}

// Real shared Cordis3 Context + production Go Apply/cleanup: all interleavings
// are barriers, not a race-detector green substituted for the semantic oracle.
func TestCordisF02V4FreshCleanupBudgetAndFences(t *testing.T) {
	for _, mode := range []string{"delayed-success", "honors-execution-deadline", "ignores-execution-deadline", "cancelled-close-caller", "host-failure", "shutdown", "new-intent", "dependency-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
			if host == "" {
				t.Skip("explicit controlled host required")
			}
			applyEntered, applyRelease := make(chan struct{}), make(chan struct{})
			hookEntered, hookRelease := make(chan struct{}), make(chan struct{})
			var applies, cleans atomic.Int32
			hookContext := make(chan context.Context, 1)
			root := &stubPlugin{meta: PluginMeta{ID: "budget.root"}, apply: func(c *PluginContext, _ map[string]any) error { c.Provide("budget.root.svc", true); return nil }}
			mid := &stubPlugin{meta: PluginMeta{ID: "budget.mid", Requires: []string{"budget.root.svc"}}, apply: func(c *PluginContext, _ map[string]any) error { c.Provide("budget.mid.svc", true); return nil }}
			leaf := &stubPlugin{meta: PluginMeta{ID: "budget.leaf", Requires: []string{"budget.mid.svc"}}, apply: func(c *PluginContext, _ map[string]any) error {
				if applies.Add(1) != 1 {
					c.Provide("budget.fresh", true)
					return nil
				}
				if err := c.OnDisposeTask(func(ctx context.Context) error {
					cleans.Add(1)
					hookContext <- ctx
					close(hookEntered)
					if err := ctx.Err(); err != nil {
						return err
					}
					if _, ok := ctx.Deadline(); !ok {
						return errors.New("cleanup has no explicit execution bound")
					}
					if mode == "honors-execution-deadline" {
						<-ctx.Done()
						return ctx.Err()
					}
					<-hookRelease
					// The ignoring-deadline negative control must still fail even returning nil.
					if mode == "ignores-execution-deadline" {
						return nil
					}
					return ctx.Err()
				}); err != nil {
					return err
				}
				close(applyEntered)
				<-applyRelease
				c.Provide("budget.stale", true)
				return nil
			}}
			budget := 700 * time.Millisecond
			if strings.Contains(mode, "execution-deadline") {
				budget = 100 * time.Millisecond
			}
			h := NewCordisLifecycleHost(CordisLifecycleOptions{HostPath: host, PluginIDs: []string{"budget.root", "budget.mid", "budget.leaf"}, CleanupTimeout: 60 * time.Millisecond, CleanupExecutionTimeout: budget, OperationTimeout: 800 * time.Millisecond})
			k := New(HostServices{AppDir: t.TempDir(), LifecycleHost: h})
			k.RegisterBuiltin(leaf, true)
			k.RegisterBuiltin(mid, true)
			k.RegisterBuiltin(root, true)
			if err := k.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(k.Shutdown)
			defer releaseV4(hookRelease)
			defer releaseV4(applyRelease)
			waitLifecycle(t, h, "budget.root", "budget.mid")
			awaitSignal(t, applyEntered)
			old := scopeFor(t, h, "budget.leaf")
			if err := k.SetEnabled("budget.root", false); err != nil {
				t.Fatal(err)
			}
			if err := k.SetEnabled("budget.root", true); err != nil {
				t.Fatal(err)
			}
			waitLifecycle(t, h, "budget.root", "budget.mid")
			waitCordisState(t, h, "budget.leaf", func(s CordisPluginState) bool {
				return s.State == "cleanup-timeout-pending" && s.Recovery == "one-dependency-retry-armed"
			})
			before := waitCleanupView(t, h, old, func(v CordisCleanupView) bool { return v.ApplyWaitTimedOut })
			if !before.ResourceHeld || before.HooksStarted || before.CompletionObserved || before.ApplyExitObserved {
				t.Fatalf("waiting Apply misreported completion: %+v", before)
			}
			assertV4NotClosed(t, old.cleanupDone, "waiting Apply released slot")
			var closeResult chan error
			switch mode {
			case "cancelled-close-caller":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				err := h.Close(ctx)
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("caller cancellation hidden: %v", err)
				}
			case "host-failure":
				h.worker.abort()
				awaitSignal(t, h.worker.exited)
			case "shutdown":
				closeResult = make(chan error, 1)
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					closeResult <- h.Close(ctx)
				}()
				deadline := time.After(2 * time.Second)
				for {
					h.mu.Lock()
					closed, changed := h.closed, h.changed
					h.mu.Unlock()
					if closed {
						break
					}
					select {
					case <-changed:
					case <-deadline:
						t.Fatal("close fence not entered")
					}
				}
			case "new-intent":
				if err := k.Reload("budget.leaf"); err == nil || !strings.Contains(err.Error(), "cleanup-timeout-pending") {
					t.Fatalf("expected known pending new intent: %v", err)
				}
			case "dependency-unavailable":
				if err := k.SetEnabled("budget.mid", false); err != nil {
					t.Fatal(err)
				}
			}
			releaseV4(applyRelease)
			awaitSignal(t, hookEntered)
			ctx := <-hookContext
			if err := ctx.Err(); err != nil {
				t.Fatalf("fresh cleanup inherits expired Apply observation: %v", err)
			}
			running := waitCleanupView(t, h, old, func(v CordisCleanupView) bool { return v.HooksStarted })
			if !running.ApplyExitObserved || !running.ResourceHeld || running.CompletionObserved {
				t.Fatalf("running cleanup misreported: %+v", running)
			}
			if deadline, _ := ctx.Deadline(); time.Until(deadline) <= 0 {
				t.Fatal("hook did not receive fresh positive execution budget")
			}
			if mode == "ignores-execution-deadline" {
				overdue := waitCleanupView(t, h, old, func(v CordisCleanupView) bool { return v.ExecutionTimedOut })
				if !overdue.ResourceHeld || overdue.HooksReturned || overdue.CompletionObserved {
					t.Fatalf("unreturned hook released resources: %+v", overdue)
				}
				assertV4NotClosed(t, old.cleanupDone, "execution timeout pretended actual completion")
				if err := k.Reload("budget.leaf"); err == nil || !strings.Contains(err.Error(), "cleanup-execution-timeout-pending") {
					t.Fatalf("unreturned expired hook bypassed: %v", err)
				}
			}
			if mode != "honors-execution-deadline" {
				releaseV4(hookRelease)
			}
			awaitSignal(t, old.cleanupDone)
			done := waitCleanupView(t, h, old, func(v CordisCleanupView) bool { return v.CompletionObserved })
			if !done.HooksReturned || cleans.Load() != 1 {
				t.Fatalf("completion not exact once: %+v cleans=%d", done, cleans.Load())
			}
			if _, ok := k.Service("budget.stale"); ok {
				t.Fatal("old Apply staged value published")
			}
			if strings.Contains(mode, "execution-deadline") {
				if !done.ExecutionTimedOut || done.CleanupOK || !done.ResourceHeld {
					t.Fatalf("actual execution timeout treated as success: %+v", done)
				}
				waitCordisState(t, h, "budget.leaf", func(s CordisPluginState) bool { return s.State == "cleanup-failed" })
				for i := 0; i < 2; i++ {
					if err := k.Reload("budget.leaf"); err == nil || !strings.Contains(err.Error(), "cleanup-failed") {
						t.Fatalf("actual execution failure bypassed: %v", err)
					}
				}
				if applies.Load() != 1 || boundedRecoveryCount(t, h, "budget.leaf") != 0 {
					t.Fatal("execution failure retried")
				}
				return
			}
			if done.ExecutionTimedOut || !done.CleanupOK || done.ResourceHeld {
				t.Fatalf("genuine cleanup success misclassified: %+v", done)
			}
			switch mode {
			case "delayed-success":
				waitLifecycle(t, h, "budget.root", "budget.mid", "budget.leaf")
				if applies.Load() != 2 || boundedRecoveryCount(t, h, "budget.leaf") != 1 {
					t.Fatal("fresh successful drain did not retry exactly once")
				}
			case "cancelled-close-caller", "shutdown":
				final, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := h.Close(final); err != nil {
					t.Fatalf("owner lost cleanup obligation after caller cancellation/close: %v", err)
				}
				if closeResult != nil {
					if err := <-closeResult; err != nil {
						t.Fatal(err)
					}
				}
				if applies.Load() != 1 || k.IsPluginActive("budget.leaf") {
					t.Fatal("closed owner resurrected")
				}
			case "host-failure":
				if applies.Load() != 1 || k.IsPluginActive("budget.leaf") {
					t.Fatal("dead host revived by cleanup")
				}
			case "new-intent":
				waitCordisState(t, h, "budget.leaf", func(s CordisPluginState) bool { return s.State == "cleanup-ready-explicit-reload" })
				if applies.Load() != 1 || boundedRecoveryCount(t, h, "budget.leaf") != 0 {
					t.Fatal("old recovery crossed new intent")
				}
				if err := k.Reload("budget.leaf"); err != nil {
					t.Fatal(err)
				}
				waitLifecycle(t, h, "budget.leaf")
			case "dependency-unavailable":
				if applies.Load() != 1 || boundedRecoveryCount(t, h, "budget.leaf") != 0 {
					t.Fatal("old recovery ignored unavailable dependency")
				}
				if err := k.SetEnabled("budget.mid", true); err != nil {
					t.Fatal(err)
				}
				waitCordisState(t, h, "budget.leaf", func(s CordisPluginState) bool { return s.State == "active" })
				waitLifecycle(t, h, "budget.mid", "budget.leaf")
			}
		})
	}
}

// Owner shutdown has a finite observation bound, but no authority to kill an
// arbitrary in-process Go goroutine. Timeout preserves the exact unresolved
// obligation/quarantine; late success cannot revive this closed/dead host.
func TestCordisF02V4CloseTimeoutRetainsObligation(t *testing.T) {
	for _, phase := range []string{"waiting-apply", "running-hook"} {
		t.Run(phase, func(t *testing.T) {
			host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
			if host == "" {
				t.Skip("explicit controlled host required")
			}
			entered, releaseApply := make(chan struct{}), make(chan struct{})
			hookEntered, releaseHook := make(chan struct{}), make(chan struct{})
			var applies, cleans atomic.Int32
			p := &stubPlugin{meta: PluginMeta{ID: "closing"}, apply: func(c *PluginContext, _ map[string]any) error {
				applies.Add(1)
				c.OnDisposeTask(func(ctx context.Context) error {
					cleans.Add(1)
					close(hookEntered)
					if phase == "running-hook" {
						<-releaseHook
					}
					return ctx.Err()
				})
				close(entered)
				if phase == "waiting-apply" {
					<-releaseApply
				}
				c.Provide("closing.late", true)
				return nil
			}}
			h := NewCordisLifecycleHost(CordisLifecycleOptions{HostPath: host, PluginIDs: []string{"closing"}, CleanupTimeout: 40 * time.Millisecond, CleanupExecutionTimeout: 100 * time.Millisecond, OperationTimeout: 40 * time.Millisecond})
			k := New(HostServices{AppDir: t.TempDir(), LifecycleHost: h})
			k.RegisterBuiltin(p, true)
			if err := k.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(k.Shutdown)
			defer releaseV4(releaseHook)
			defer releaseV4(releaseApply)
			awaitSignal(t, entered)
			if phase == "running-hook" {
				waitLifecycle(t, h, "closing")
			}
			old := scopeFor(t, h, "closing")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err := h.Close(ctx)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("shutdown claimed completion while %s held: %v", phase, err)
			}
			if phase == "running-hook" {
				awaitSignal(t, hookEntered)
			}
			pending := waitCleanupView(t, h, old, func(v CordisCleanupView) bool { return v.CloseObservationTimedOut })
			if !pending.ResourceHeld || pending.CompletionObserved || pending.HooksReturned {
				t.Fatalf("owner timeout freed unresolved resource: %+v", pending)
			}
			if phase == "waiting-apply" && (!pending.ApplyWaitTimedOut || pending.HooksStarted) {
				t.Fatalf("waiting phase collapsed into hook timeout: %+v", pending)
			}
			if phase == "running-hook" && !pending.ExecutionTimedOut {
				t.Fatalf("real hook overrun not observable: %+v", pending)
			}
			assertV4NotClosed(t, old.cleanupDone, "shutdown timeout fabricated actual completion")
			releaseV4(releaseApply)
			releaseV4(releaseHook)
			awaitSignal(t, old.cleanupDone)
			done := waitCleanupView(t, h, old, func(v CordisCleanupView) bool { return v.CompletionObserved })
			if phase == "waiting-apply" && (!done.CleanupOK || done.ExecutionTimedOut || done.ResourceHeld) {
				t.Fatalf("shutdown abandonment poisoned fresh cleanup: %+v", done)
			}
			if phase == "running-hook" && (done.CleanupOK || !done.ExecutionTimedOut || !done.ResourceHeld) {
				t.Fatalf("actual hook timeout escaped quarantine: %+v", done)
			}
			if applies.Load() != 1 || cleans.Load() != 1 || k.IsPluginActive("closing") {
				t.Fatal("shutdown lost once-only ownership or revived plugin")
			}
			if _, ok := k.Service("closing.late"); ok {
				t.Fatal("closed host published late Apply")
			}
			if h.Snapshot().HostAlive {
				t.Fatal("closed host returned alive")
			}
			// Close result is historical/sticky, not silently rewritten by a late hook.
			if err := h.Close(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("late cleanup erased shutdown failure: %v", err)
			}
		})
	}
}
