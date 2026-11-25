package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func waitCordisState(t *testing.T, h *CordisLifecycleHost, id string, predicate func(CordisPluginState) bool) CordisPluginState {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		h.mu.Lock()
		state := *h.states[id]
		changed := h.changed
		h.mu.Unlock()
		if predicate(state) {
			return state
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatalf("%s state wait: %+v", id, h.Snapshot())
		}
	}
}
func boundedRecoveryCount(t *testing.T, h *CordisLifecycleHost, id string) int {
	t.Helper()
	raw, err := h.NodeState()
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		Trace []struct{ Phase, Plugin string }
	}
	if err = json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range state.Trace {
		if e.Plugin == id && e.Phase == "bounded-recovery" {
			n++
		}
	}
	return n
}
func TestCordisF02V3ThreeNodeBoundedDrainRecovery(t *testing.T) {
	for _, mode := range []string{"success-one-retry", "actual-cleanup-error", "retry-apply-fails-no-loop", "disable-cancels-ticket", "new-intent-cancels-ticket", "dependency-instance-invalidates-ticket"} {
		t.Run(mode, func(t *testing.T) {
			var rootCalls, midCalls, leafCalls, oldClean atomic.Int32
			entered, release := make(chan struct{}), make(chan struct{})
			root := &stubPlugin{meta: PluginMeta{ID: "root"}, apply: func(c *PluginContext, _ map[string]any) error {
				rootCalls.Add(1)
				c.Provide("root.svc", true)
				return nil
			}}
			mid := &stubPlugin{meta: PluginMeta{ID: "mid", Requires: []string{"root.svc"}}, apply: func(c *PluginContext, _ map[string]any) error {
				midCalls.Add(1)
				c.Provide("mid.svc", true)
				return nil
			}}
			leaf := &stubPlugin{meta: PluginMeta{ID: "leaf", Requires: []string{"mid.svc"}}, apply: func(c *PluginContext, _ map[string]any) error {
				n := leafCalls.Add(1)
				if n == 1 {
					c.OnDisposeTask(func(context.Context) error {
						oldClean.Add(1)
						if mode == "actual-cleanup-error" {
							return errors.New("controlled actual cleanup failure")
						}
						return nil
					})
					close(entered)
					<-release
					c.Provide("leaf.old", true)
					return nil
				}
				if mode == "retry-apply-fails-no-loop" {
					return errors.New("controlled replacement Apply failure")
				}
				c.Provide("leaf.fresh", n)
				return nil
			}}
			// Real Cordis3 Context, reverse registration, real production Go Apply/cleanup.
			k, h := lifecycleFixture(t, leaf, mid, root)
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			waitLifecycle(t, h, "root", "mid")
			awaitSignal(t, entered)
			old := scopeFor(t, h, "leaf")
			if err := k.SetEnabled("root", false); err != nil {
				t.Fatal(err)
			}
			if k.IsPluginActive("leaf") {
				t.Fatal("mid-Apply transitive fence failed")
			}
			if err := k.SetEnabled("root", true); err != nil {
				t.Fatal(err)
			}
			waitLifecycle(t, h, "root", "mid")
			waitCordisState(t, h, "leaf", func(s CordisPluginState) bool {
				return s.State == "cleanup-timeout-pending" && s.Recovery == "one-dependency-retry-armed"
			})
			if leafCalls.Load() != 1 {
				t.Fatal("reused unfinished old scope")
			}
			if _, ok := k.Service("leaf.old"); ok {
				t.Fatal("old staged value visible")
			}
			switch mode {
			case "disable-cancels-ticket":
				if err := k.SetEnabled("leaf", false); err != nil {
					t.Fatal(err)
				}
			case "new-intent-cancels-ticket":
				if err := k.Reload("leaf"); err == nil || !strings.Contains(err.Error(), "cleanup-timeout-pending") {
					t.Fatalf("known pending gate: %v", err)
				}
			case "dependency-instance-invalidates-ticket":
				if err := k.SetEnabled("root", false); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			awaitSignal(t, old.cleanupDone)
			if oldClean.Load() != 1 {
				t.Fatalf("old cleanup ran %d times", oldClean.Load())
			}
			switch mode {
			case "success-one-retry":
				waitLifecycle(t, h, "root", "mid", "leaf")
				if leafCalls.Load() != 2 || boundedRecoveryCount(t, h, "leaf") != 1 {
					t.Fatal("not exactly one actual Cordis retry")
				}
			case "actual-cleanup-error":
				waitCordisState(t, h, "leaf", func(s CordisPluginState) bool { return s.State == "cleanup-failed" })
				if err := k.Reload("leaf"); err == nil || !strings.Contains(err.Error(), "cleanup-failed") {
					t.Fatalf("failed cleanup bypassed by explicit intent: %v", err)
				}
				if leafCalls.Load() != 1 || boundedRecoveryCount(t, h, "leaf") != 0 {
					t.Fatal("actual cleanup failure retried")
				}
			case "retry-apply-fails-no-loop":
				waitCordisState(t, h, "leaf", func(s CordisPluginState) bool { return s.State == "failed" })
				if leafCalls.Load() != 2 || boundedRecoveryCount(t, h, "leaf") != 1 {
					t.Fatal("failed one-shot retry looped")
				}
				// Node's failed scope is stable; no second ticket can be armed by cleanup
				// success because only the consumed old generation held that ticket.
				h.mu.Lock()
				remaining := len(h.recoveries)
				h.mu.Unlock()
				if remaining != 0 {
					t.Fatal("retry budget/ticket leaked")
				}
			case "disable-cancels-ticket":
				if leafCalls.Load() != 1 || k.IsPluginActive("leaf") || boundedRecoveryCount(t, h, "leaf") != 0 {
					t.Fatal("disabled intent resurrected")
				}
				h.mu.Lock()
				state := h.states["leaf"].State
				h.mu.Unlock()
				if state != "disabled" {
					t.Fatalf("successful old cleanup overwrote disabled state: %s", state)
				}
			case "new-intent-cancels-ticket":
				waitCordisState(t, h, "leaf", func(s CordisPluginState) bool { return s.State == "cleanup-ready-explicit-reload" })
				if leafCalls.Load() != 1 || boundedRecoveryCount(t, h, "leaf") != 0 {
					t.Fatal("old ticket overrode new desired")
				}
				if err := k.Reload("leaf"); err != nil {
					t.Fatal(err)
				}
				waitLifecycle(t, h, "leaf")
				if leafCalls.Load() != 2 {
					t.Fatal("explicit recovery unavailable after successful drain")
				}
			case "dependency-instance-invalidates-ticket":
				if leafCalls.Load() != 1 || boundedRecoveryCount(t, h, "leaf") != 0 {
					t.Fatal("retry ignored missing/new provider instance")
				}
				if err := k.SetEnabled("root", true); err != nil {
					t.Fatal(err)
				}
				waitCordisState(t, h, "leaf", func(s CordisPluginState) bool { return s.State == "active" })
				waitLifecycle(t, h, "root", "mid", "leaf")
			}
			if _, ok := k.Service("leaf.old"); ok {
				t.Fatal("stale leaf returned after recovery")
			}
		})
	}
}
