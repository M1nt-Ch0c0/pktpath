package kernel

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// F02 staging is type-agnostic: opaque Go values/functions never cross the wire.
// Only enrolled activations use it. Other plugin types are NOT thereby migrated.
type cordisScope struct {
	owner                                 *CordisLifecycleHost
	scope                                 *PluginContext
	plugin, revision, attempt, generation string
	deps                                  map[string]string
	depOwners                             map[string]string
	mu                                    sync.Mutex
	provided                              map[string]any
	injected                              map[string]any
	extensions                            []RegisteredExtension
	cleanups                              []func(context.Context) error
	revoked, sealed                       bool
	applyDone, cleanupDone                chan struct{}
	cleanupOnce                           sync.Once
	cleanupError                          error // protected by owner.mu
	cleanupOK                             bool  // protected by owner.mu; actual callback completion, not deadline
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

func (h *CordisLifecycleHost) startCleanup(b *cordisScope) {
	b.cleanupOnce.Do(func() {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), h.opts.CleanupTimeout)
			defer cancel()
			// A cancelled Apply can still be running: keep its resource slot until it
			// really returns, including cleanup hooks registered before that return.
			<-b.applyDone
			b.mu.Lock()
			fns := append([]func(context.Context) error(nil), b.cleanups...)
			b.mu.Unlock()
			var errs []error
			for i := len(fns) - 1; i >= 0; i-- {
				if err := runCordisCleanup(fns[i], ctx); err != nil {
					errs = append(errs, err)
				}
			}
			h.mu.Lock()
			b.cleanupError = errors.Join(errs...)
			b.cleanupOK = b.cleanupError == nil
			if !b.cleanupOK {
				h.eventLocked(b.plugin, "cleanup-blocked", b.generation, b.cleanupError.Error())
			} else {
				h.eventLocked(b.plugin, "disposed", b.generation, "")
			}
			close(b.cleanupDone)
			h.signalLocked()
			h.mu.Unlock()
		}()
	})
}
