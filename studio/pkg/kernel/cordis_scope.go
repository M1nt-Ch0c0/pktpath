package kernel

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// F02 staging is type-agnostic: opaque Go values/functions never cross the wire.
// Only enrolled activations use it. Other plugin types are NOT thereby migrated.
type cordisScope struct {
	configOperationID                                                               string         // immutable application operation fence, never config hash
	config                                                                          map[string]any // immutable actual Apply input, not rec desired label
	cleanupPhase, disposeCause                                                      string         // owner.mu; observations never count as actual completion
	applyExitObserved, applyWaitTimedOut, cleanupHooksStarted, cleanupHooksReturned bool
	cleanupExecutionTimedOut, cleanupCompletionObserved, closeObservationTimedOut   bool
	cleanupWaitStarted, cleanupStarted, cleanupDeadline                             time.Time
	cleanupHooksDone                                                                chan struct{}
	cleanupTimedOut                                                                 bool // owner.mu; not the actual cleanup return error
	host                                                                            *cordisWorker
	hostIncarnation                                                                 string
	admissionEpoch                                                                  uint64
	owner                                                                           *CordisLifecycleHost
	scope                                                                           *PluginContext
	plugin, revision, attempt, generation                                           string
	deps                                                                            map[string]string
	depOwners                                                                       map[string]string
	mu                                                                              sync.Mutex
	provided                                                                        map[string]any
	injected                                                                        map[string]any
	extensions                                                                      []RegisteredExtension
	cleanups                                                                        []func(context.Context) error
	revoked, sealed                                                                 bool
	applyDone, cleanupDone                                                          chan struct{}
	cleanupOnce                                                                     sync.Once
	cleanupError                                                                    error // protected by owner.mu
	cleanupOK                                                                       bool  // protected by owner.mu; actual callback completion, not deadline
}

func (b *cordisScope) provide(name string, value any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.revoked && !b.sealed {
		b.provided[name] = value
	}
}
func (b *cordisScope) inject(name string) (any, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.revoked {
		return nil, false
	}
	if value, ok := b.provided[name]; ok {
		return value, true
	}
	value, ok := b.injected[name]
	return value, ok
}
func (b *cordisScope) extension(point string, value any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.revoked && !b.sealed {
		b.extensions = append(b.extensions, RegisteredExtension{PluginID: b.plugin, Point: point, Value: value, owner: b.scope})
	}
}
func (b *cordisScope) cleanup(fn func(context.Context) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Registration belongs to Apply, not untracked post-Apply goroutines.
	if b.sealed {
		return errors.New("cleanup registration after Apply completed is unsupported")
	}
	b.cleanups = append(b.cleanups, fn)
	return nil
}
func (b *cordisScope) summary() ([]string, []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	points, services := []string{}, []string{}
	seen := map[string]bool{}
	for _, e := range b.extensions {
		if !seen[e.Point] {
			points = append(points, e.Point)
			seen[e.Point] = true
		}
	}
	for name := range b.provided {
		services = append(services, name)
	}
	sort.Strings(points)
	sort.Strings(services)
	return points, services
}

// OnDisposeTask explicitly exposes completion/error to the F02 application drain.
// Cordis3 itself does not await async disposers. A returned goroutine is NOT tracked.
// Must register during Apply; cleanup must return only when owned resources finish.
// One fresh bounded context covers the entire LIFO hook chain AFTER Apply exits.
// Cancelled RPC/Close observation does not abandon the owner cleanup obligation.
func (c *PluginContext) OnDisposeTask(fn func(context.Context) error) error {
	if c.staging == nil {
		return errors.New("OnDisposeTask requires opt-in F02 staging")
	}
	if fn == nil {
		return nil
	}
	return c.staging.cleanup(fn)
}

func applyCordisPlugin(p Plugin, c *PluginContext, cfg map[string]any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("plugin Apply panic: %v", r)
		}
	}()
	return p.Apply(c, cfg)
}
func runCordisCleanup(fn func(context.Context) error, ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("plugin cleanup panic: %v", r)
		}
	}()
	return fn(ctx)
}

// Each revoked scope has one retained cleanup obligation. Observation timeout
// never cancels that obligation, marks it successful, or licenses resource reuse.
func (h *CordisLifecycleHost) startCleanup(b *cordisScope) {
	b.cleanupOnce.Do(func() {
		go func() {
			h.mu.Lock()
			b.cleanupWaitStarted = time.Now()
			h.cleanupPhaseLocked(b, "waiting-apply-exit", "")
			h.mu.Unlock()
			wait := time.NewTimer(h.opts.CleanupTimeout)
			select {
			case <-b.applyDone:
				if !wait.Stop() {
					select {
					case <-wait.C:
					default:
					}
				}
			case <-wait.C:
				h.mu.Lock()
				b.applyWaitTimedOut = true
				b.cleanupTimedOut = true
				h.cleanupPhaseLocked(b, "apply-exit-timeout-pending", "Apply has not returned; resource remains held")
				h.mu.Unlock()
				<-b.applyDone // cannot force-kill arbitrary Go Apply; held slot, no retry/admission
			}
			// The hook-chain budget starts NOW, not while Apply was still being awaited.
			// This is an owner cleanup obligation, not a child of the cancelled RPC/Close
			// waiter or dead Node host. Owner close/failure still fences every recovery.
			b.mu.Lock()
			fns := append([]func(context.Context) error(nil), b.cleanups...)
			b.mu.Unlock()
			h.mu.Lock()
			ctx, cancel := context.WithTimeout(context.Background(), h.opts.CleanupExecutionTimeout)
			defer cancel()
			deadline, _ := ctx.Deadline()
			b.applyExitObserved = true
			b.cleanupHooksStarted = true
			b.cleanupStarted = time.Now()
			b.cleanupDeadline = deadline
			h.cleanupPhaseLocked(b, "running-cleanup-hooks", "")
			h.mu.Unlock()
			watchdog := time.AfterFunc(time.Until(deadline), func() {
				h.mu.Lock()
				defer h.mu.Unlock()
				select {
				case <-b.cleanupHooksDone:
					return
				default:
				}
				b.cleanupExecutionTimedOut = true
				if ticket := h.recoveries[b.plugin]; ticket != nil && ticket.old == b {
					delete(h.recoveries, b.plugin)
				}
				h.cleanupPhaseLocked(b, "cleanup-execution-timeout-pending", "hook-chain budget exceeded; completion unproved, resource quarantined")
			})
			var errs []error
			for i := len(fns) - 1; i >= 0; i-- {
				if err := runCordisCleanup(fns[i], ctx); err != nil {
					errs = append(errs, err)
				}
			}
			returned := time.Now()
			close(b.cleanupHooksDone) // actual hook return observation, independent of owner lock
			watchdog.Stop()
			h.mu.Lock()
			b.cleanupHooksReturned = true
			if returned.After(deadline) {
				b.cleanupExecutionTimedOut = true
			}
			if b.cleanupExecutionTimedOut {
				errs = append(errs, fmt.Errorf("cleanup execution budget exceeded: %w", context.DeadlineExceeded))
			}
			b.cleanupError = errors.Join(errs...)
			b.cleanupOK = b.cleanupError == nil
			b.cleanupCompletionObserved = true
			h.cleanupPhaseLocked(b, "cleanup-hooks-returned", "")
			action := h.cleanupFinishedLocked(b)
			close(b.cleanupDone) // all hooks returned AND owner recorded the actual result
			h.signalLocked()
			h.mu.Unlock()
			if action != nil {
				h.resumeAfterDrain(action)
			}
		}()
	})
}
