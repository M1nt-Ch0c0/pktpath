package kernel

// F02 development candidate. Cordis is the dependency scheduler; Go remains
// intent/final-commit/config/task owner. No capture/transport/stdio business in JS.
import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const cordisLifecycleProtocol = "pktpath.cordis3.lifecycle/2"

// Only these four existing metadata-only Apply functions are enrolled by default.
var cordisCollectorPlugins = []string{"builtin.collector.ebpf-tc", "builtin.collector.kernel-ext", "builtin.mode.oneshot", "builtin.mode.daemon"}

type CordisLifecycleOptions struct {
	NodePath, HostPath               string
	PluginIDs                        []string // explicit trusted test/development enrollment, NOT a package loader
	CleanupTimeout, OperationTimeout time.Duration
}
type CordisPluginState struct {
	Plugin     string `json:"plugin"`
	Desired    string `json:"desired_revision"`
	Effective  string `json:"effective_revision"`
	Generation string `json:"generation"`
	State      string `json:"state"`
	Error      string `json:"error,omitempty"`
}
type CordisLifecycleEvent struct {
	Plugin     string `json:"plugin"`
	Phase      string `json:"phase"`
	Generation string `json:"generation"`
	Error      string `json:"error,omitempty"`
}
type CordisLifecycleSnapshot struct {
	Protocol string                 `json:"protocol"`
	Core     string                 `json:"core"`
	Node     string                 `json:"node,omitempty"`
	Plugins  []CordisPluginState    `json:"plugins"`
	Events   []CordisLifecycleEvent `json:"events"`
}
type CordisLifecycleHost struct {
	highestAttempt               map[string]uint64
	closeOnce                    sync.Once
	closeDone                    chan struct{}
	closeErr                     error
	incarnation                  string
	opts                         CordisLifecycleOptions
	mu                           sync.Mutex // only intent/state/CAS; never held across Apply/cleanup/RPC/FS
	kernel                       *Kernel
	worker                       *cordisWorker
	selected                     map[string]bool
	states                       map[string]*CordisPluginState
	attempts                     map[string]*cordisScope
	events                       []CordisLifecycleEvent
	changed                      chan struct{}
	nextRevision, nextGeneration uint64
	closed                       bool
	startupError                 error
}
type cordisPlan struct {
	Plugin   string   `json:"plugin"`
	Revision string   `json:"revision"`
	Enabled  bool     `json:"enabled"`
	Requires []string `json:"requires"`
}
type cordisNodeRequest struct {
	ID, Op, Plugin, Revision, Attempt string
	Deps                              map[string]string
}

func NewCordisLifecycleHost(opts CordisLifecycleOptions) *CordisLifecycleHost {
	if opts.CleanupTimeout <= 0 {
		opts.CleanupTimeout = 2 * time.Second
	}
	if opts.OperationTimeout <= 0 {
		opts.OperationTimeout = 3 * time.Second
	}
	if opts.PluginIDs == nil {
		opts.PluginIDs = append([]string(nil), cordisCollectorPlugins...)
	}
	h := &CordisLifecycleHost{opts: opts, selected: map[string]bool{}, states: map[string]*CordisPluginState{}, attempts: map[string]*cordisScope{}, changed: make(chan struct{}), highestAttempt: map[string]uint64{}, closeDone: make(chan struct{})}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		h.startupError = err
	} else {
		h.incarnation = hex.EncodeToString(nonce[:])
	}
	for _, id := range opts.PluginIDs {
		h.selected[id] = true
	}
	return h
}
func (h *CordisLifecycleHost) manages(id string) bool { return h != nil && h.selected[id] }
func (h *CordisLifecycleHost) signalLocked()          { close(h.changed); h.changed = make(chan struct{}) }
func (h *CordisLifecycleHost) eventLocked(id, phase, generation, err string) {
	h.events = append(h.events, CordisLifecycleEvent{id, phase, generation, err})
	if len(h.events) > 256 {
		h.events = h.events[len(h.events)-256:]
	}
	h.signalLocked()
}
func (h *CordisLifecycleHost) Snapshot() *CordisLifecycleSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := &CordisLifecycleSnapshot{Protocol: cordisLifecycleProtocol, Core: "3.18.1", Events: append([]CordisLifecycleEvent(nil), h.events...)}
	if h.worker != nil {
		s.Node = h.worker.nodeVersion
	}
	for _, v := range h.states {
		s.Plugins = append(s.Plugins, *v)
	}
	sort.Slice(s.Plugins, func(i, j int) bool { return s.Plugins[i].Plugin < s.Plugins[j].Plugin })
	return s
}
func (h *CordisLifecycleHost) start(k *Kernel) error {
	h.kernel = k
	if h.startupError != nil {
		return h.startupError
	}
	w, err := startCordisWorkerMode(CordisAnalyzerOptions{NodePath: h.opts.NodePath, HostPath: h.opts.HostPath}, cordisLifecycleProtocol, h.handle)
	if err != nil {
		h.mu.Lock()
		h.startupError = err
		h.mu.Unlock()
		return err
	}
	h.mu.Lock()
	h.worker = w
	k.mu.RLock()
	ids := k.sortedIDsLocked()
	plans := []cordisPlan{}
	for _, id := range ids {
		if !h.manages(id) {
			continue
		}
		rec := k.records[id]
		h.nextRevision++
		rev := strconv.FormatUint(h.nextRevision, 10)
		state := "waiting-deps"
		if !rec.enabled {
			state = "disabled"
		}
		h.states[id] = &CordisPluginState{Plugin: id, Desired: rev, State: state}
		plans = append(plans, cordisPlan{id, rev, rec.enabled, append([]string{}, rec.plugin.Meta().Requires...)})
	}
	k.mu.RUnlock()
	h.mu.Unlock()
	if err = w.control("plan", map[string]any{"entries": plans}, nil); err != nil {
		h.failHost(err)
		return err
	}
	go func() {
		<-w.failed
		h.mu.Lock()
		closed := h.closed
		h.mu.Unlock()
		if !closed {
			h.failHost(errors.New("lifecycle host unavailable; no Go fallback/retry"))
		}
	}()
	return nil
}
func (h *CordisLifecycleHost) failHost(err error) {
	h.mu.Lock()
	h.startupError = err
	for _, b := range h.attempts {
		h.revokeLocked(b, "host-unavailable")
	}
	for _, s := range h.states {
		s.State = "host-unavailable"
		s.Error = err.Error()
	}
	h.signalLocked()
	h.mu.Unlock()
}
func (h *CordisLifecycleHost) handle(w *cordisWorker, raw []byte) {
	var req cordisNodeRequest
	err := json.Unmarshal(raw, &req)
	var data any
	if err == nil {
		switch req.Op {
		case "prepare":
			data, err = h.prepare(req)
		case "revoke":
			err = h.revoke(req)
		default:
			err = errors.New("unknown Node operation")
		}
	}
	reply := map[string]any{"id": req.ID, "kind": "response", "protocol": cordisLifecycleProtocol, "ok": err == nil, "data": data}
	if err != nil {
		reply["error"] = err.Error()
	}
	encoded, marshalErr := json.Marshal(reply)
	if marshalErr != nil {
		w.fail(marshalErr)
		w.abort()
		return
	}
	// No callback can block the duplex reader; writes still have a finite bound.
	timer := time.AfterFunc(3*time.Second, w.abort)
	defer timer.Stop()
	w.writeMu.Lock()
	_, err = w.input.Write(append(encoded, '\n'))
	w.writeMu.Unlock()
	if err != nil {
		w.fail(err)
	}
}

// h.mu and kernel.mu must be held; actual service first, active-plugin fallback.
func (h *CordisLifecycleHost) resolveLocked(name string) (token, owner string, impl any, ok bool) {
	if ent, has := h.kernel.services[name]; has && ent.owner != nil && ent.owner.staging != nil {
		b := ent.owner.staging
		return b.generation + "/svc/" + name, b.plugin, ent.impl, true
	}
	if rec, has := h.kernel.records[name]; has && rec.active && rec.scope != nil && rec.scope.staging != nil {
		return rec.scope.staging.generation, name, nil, true
	}
	return "", "", nil, false // mixed foreign dependencies require a future explicit bridge
}
func (h *CordisLifecycleHost) depsMatchLocked(b *cordisScope) bool {
	for name, expected := range b.deps {
		actual, _, _, ok := h.resolveLocked(name)
		if !ok || actual != expected {
			return false
		}
	}
	return true
}
func cordisAttemptNumber(req cordisNodeRequest) (uint64, error) {
	prefix := req.Plugin + "/" + req.Revision + "/"
	if req.Plugin == "" || req.Revision == "" || !strings.HasPrefix(req.Attempt, prefix) {
		return 0, errors.New("invalid activation attempt identity")
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(req.Attempt, prefix), 10, 64)
	if err != nil || n == 0 {
		return 0, errors.New("invalid monotonic attempt number")
	}
	return n, nil
}
func (h *CordisLifecycleHost) prepare(req cordisNodeRequest) (any, error) {
	number, parseErr := cordisAttemptNumber(req)
	if parseErr != nil {
		return nil, parseErr
	}
	h.mu.Lock()
	k := h.kernel
	k.mu.Lock()
	s := h.states[req.Plugin]
	rec := k.records[req.Plugin]
	reject := func(err error) (any, error) { k.mu.Unlock(); h.mu.Unlock(); return nil, err }
	if h.closed || s == nil || rec == nil || !rec.enabled || s.Desired != req.Revision {
		return reject(errors.New("stale/cancelled activation intent"))
	}
	if number <= h.highestAttempt[req.Plugin] {
		return reject(errors.New("stale/duplicate/cancelled attempt; never re-execute"))
	}
	h.highestAttempt[req.Plugin] = number
	// Bound retained scopes: a monotonic per-plugin high-water mark rejects replay
	// after successfully drained handles are removed; failed/uncertain ones stay.
	for attempt, old := range h.attempts {
		select {
		case <-old.cleanupDone:
			if old.cleanupOK {
				delete(h.attempts, attempt)
			}
		default:
		}
	}
	if _, duplicate := h.attempts[req.Attempt]; duplicate {
		return reject(errors.New("duplicate prepare; never re-execute"))
	}
	// A revoked scope retains its resource slot until Apply and ALL tracked cleanup
	// actually return. A timeout alone never licenses reuse.
	for _, old := range h.attempts {
		if old.plugin != req.Plugin {
			continue
		}
		select {
		case <-old.cleanupDone:
			if old.cleanupOK {
				continue
			}
		default:
		}
		err := errors.New("cleanup-blocked: previous activation still owns resource slot")
		s.State = "cleanup-blocked"
		s.Error = err.Error()
		h.eventLocked(req.Plugin, "cleanup-blocked", old.generation, err.Error())
		return reject(err)
	}
	meta := rec.plugin.Meta()
	if len(req.Deps) != len(meta.Requires) {
		return reject(errors.New("dependency snapshot shape mismatch"))
	}
	injected := map[string]any{}
	owners := map[string]string{}
	for _, name := range meta.Requires {
		token, owner, value, ok := h.resolveLocked(name)
		if !ok || req.Deps[name] != token {
			return reject(errors.New("stale dependency service instance"))
		}
		owners[name] = owner
		if value != nil {
			injected[name] = value
		}
	}
	h.nextGeneration++
	generation := h.incarnation + "/" + strconv.FormatUint(h.nextGeneration, 10)
	c := &PluginContext{kernel: k, pluginID: req.Plugin}
	b := &cordisScope{owner: h, scope: c, plugin: req.Plugin, revision: req.Revision, attempt: req.Attempt, generation: generation, deps: req.Deps, depOwners: owners, provided: map[string]any{}, injected: injected, applyDone: make(chan struct{}), cleanupDone: make(chan struct{})}
	c.staging = b
	h.attempts[req.Attempt] = b
	s.State = "preparing"
	s.Generation = generation
	s.Error = ""
	rec.activationRevision++
	cfg, _ := DeepCloneValue(rec.config).(map[string]any)
	p := rec.plugin
	k.mu.Unlock()
	h.eventLocked(req.Plugin, "prepare", generation, "")
	h.mu.Unlock()
	err := applyCordisPlugin(p, c, cfg)
	applyFailed := err != nil
	b.mu.Lock()
	b.sealed = true
	provided := b.provided
	extensions := b.extensions
	b.mu.Unlock()
	close(b.applyDone)
	h.mu.Lock()
	k.mu.Lock()
	s = h.states[req.Plugin]
	if err == nil && (h.closed || b.revoked || s.Desired != b.revision || !rec.enabled || !h.depsMatchLocked(b)) {
		err = errors.New("stale Apply completion fenced")
	}
	if err == nil {
		for name := range provided {
			if current, ok := k.services[name]; ok && current.owner != c {
				err = fmt.Errorf("service conflict: %s", name)
				applyFailed = true // a known commit rejection, not a stale dependency epoch
				break
			}
		}
	}
	if err != nil {
		wasRevoked := b.revoked
		k.mu.Unlock()
		h.revokeLocked(b, "apply-rejected")
		if applyFailed && !wasRevoked && s.Desired == b.revision && s.Generation == b.generation {
			s.State = "failed"
			s.Error = err.Error()
			k.mu.Lock()
			rec.lastError = err.Error()
			k.mu.Unlock()
		}
		h.eventLocked(req.Plugin, "apply-rejected", generation, err.Error())
		h.mu.Unlock()
		return nil, err
	}
	services := []map[string]string{}
	for name, value := range provided {
		k.services[name] = serviceEntry{pluginID: req.Plugin, impl: value, owner: c}
		services = append(services, map[string]string{"name": name, "owner": req.Plugin, "instance": generation + "/svc/" + name})
	}
	for _, e := range extensions {
		k.extensions[e.Point] = append(k.extensions[e.Point], e)
	}
	rec.scope = c
	rec.active = true
	rec.lastError = ""
	rec.activatedAt = time.Now()
	s.State = "active"
	s.Effective = b.revision
	s.Generation = generation
	s.Error = ""
	k.mu.Unlock()
	h.eventLocked(req.Plugin, "commit", generation, "")
	h.mu.Unlock()
	// Legacy not-enrolled dependents may reconcile, but enrolled ones MUST not.
	go func() { k.reconcileDependents(); k.notifyChange() }()
	return map[string]any{"generation": generation, "services": services}, nil
}

// Revoke transitive Go visibility synchronously, including a dependent whose
// Apply is still blocked. Cordis independently chooses subsequent starts.
// h.mu held; no user hook runs here, no lock held while cleanup waits.
func (h *CordisLifecycleHost) revokeLocked(b *cordisScope, reason string) {
	b.mu.Lock()
	already := b.revoked
	b.revoked = true
	b.mu.Unlock()
	if already {
		return
	}
	k := h.kernel
	k.mu.Lock()
	for name, ent := range k.services {
		if ent.owner == b.scope {
			delete(k.services, name)
		}
	}
	for point, list := range k.extensions {
		kept := list[:0]
		for _, e := range list {
			if e.owner != b.scope {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(k.extensions, point)
		} else {
			k.extensions[point] = kept
		}
	}
	if rec := k.records[b.plugin]; rec != nil && rec.scope == b.scope {
		rec.active = false
		rec.scope = nil
		rec.lastError = reason
	}
	if s := h.states[b.plugin]; s != nil && s.Generation == b.generation {
		s.State = "draining"
		s.Error = reason
	}
	k.mu.Unlock()
	h.eventLocked(b.plugin, "revoke", b.generation, reason)
	h.startCleanup(b)
	// Iterate to a fixed point, not one reverse registration pass.
	for _, child := range h.attempts {
		if child == b {
			continue
		}
		for _, owner := range child.depOwners {
			if owner == b.plugin {
				h.revokeLocked(child, "dependency-invalidated")
				break
			}
		}
	}
}
func (h *CordisLifecycleHost) revoke(req cordisNodeRequest) error {
	h.mu.Lock()
	number, err := cordisAttemptNumber(req)
	if err != nil || !h.manages(req.Plugin) {
		h.mu.Unlock()
		return errors.New("invalid revoke identity")
	}
	if number > h.highestAttempt[req.Plugin] {
		h.highestAttempt[req.Plugin] = number
	}
	b := h.attempts[req.Attempt]
	if b == nil {
		h.mu.Unlock()
		return nil
	}
	if b.plugin != req.Plugin || b.revision != req.Revision {
		h.mu.Unlock()
		return errors.New("revoke identity mismatch")
	}
	h.revokeLocked(b, "cordis-dispose")
	h.mu.Unlock()
	timer := time.NewTimer(h.opts.CleanupTimeout)
	defer timer.Stop()
	select {
	case <-b.cleanupDone:
		h.mu.Lock()
		err := b.cleanupError
		h.mu.Unlock()
		return err
	case <-timer.C:
		h.mu.Lock()
		select {
		case <-b.cleanupDone:
			err := b.cleanupError
			h.mu.Unlock()
			return err
		default:
		}
		b.cleanupError = errors.New("cleanup deadline: resource remains quarantined")
		if s := h.states[b.plugin]; s != nil && s.Generation == b.generation {
			s.State = "cleanup-blocked"
			s.Error = b.cleanupError.Error()
		}
		h.eventLocked(b.plugin, "cleanup-blocked", b.generation, b.cleanupError.Error())
		h.mu.Unlock()
		return errors.New("cleanup-blocked; callback/Apply has not proved exit")
	}
}

// update is the sole desired-revision writer. RPC ACK means plan admission, NOT
// Apply success. Unknown ACK never activates a legacy Go fallback.
func (h *CordisLifecycleHost) update(id string, enabled *bool, config map[string]any, persist bool) error {
	h.mu.Lock()
	k := h.kernel
	if h.closed || h.startupError != nil || h.worker == nil {
		err := h.startupError
		if err == nil {
			err = errors.New("lifecycle host unavailable/closed")
		}
		h.mu.Unlock()
		return err
	}
	k.mu.Lock()
	rec := k.records[id]
	if rec == nil {
		k.mu.Unlock()
		h.mu.Unlock()
		return errors.New("plugin not found")
	}
	if enabled != nil {
		rec.enabled = *enabled
	}
	if config != nil {
		rec.config = config
	}
	h.nextRevision++
	revision := strconv.FormatUint(h.nextRevision, 10)
	s := h.states[id]
	s.Desired = revision
	s.Error = ""
	s.State = "waiting-deps"
	if !rec.enabled {
		s.State = "disabled"
	}
	plan := cordisPlan{id, revision, rec.enabled, append([]string{}, rec.plugin.Meta().Requires...)}
	k.mu.Unlock()
	for _, b := range h.attempts {
		if b.plugin == id {
			h.revokeLocked(b, "intent-superseded")
		}
	}
	// revoke can mark draining; user intent state remains distinct from drain events.
	s.State = "waiting-deps"
	if !plan.Enabled {
		s.State = "disabled"
	}
	h.signalLocked()
	w := h.worker
	h.mu.Unlock()
	err := w.control("plan", map[string]any{"entries": []cordisPlan{plan}}, nil)
	if err != nil {
		h.failHost(err)
	}
	var savedErr error
	if persist {
		savedErr = k.savePersistedConfig()
	}
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), h.opts.OperationTimeout)
		err = h.WaitRevision(ctx, id, revision)
		cancel()
	}
	k.reconcileDependents()
	k.notifyChange()
	if savedErr != nil {
		return fmt.Errorf("配置保存失败（不是已保存）: %w", errors.Join(err, savedErr))
	}
	if config != nil && err != nil {
		return fmt.Errorf("已保存/激活失败 (F03无自动回退): %w", errors.Join(err, savedErr))
	}
	return errors.Join(err, savedErr)
}
func (h *CordisLifecycleHost) WaitRevision(ctx context.Context, id, revision string) error {
	return h.waitRevision(ctx, id, revision, true)
}
func (h *CordisLifecycleHost) waitRevision(ctx context.Context, id, revision string, allowDisabled bool) error {
	for {
		h.mu.Lock()
		s := h.states[id]
		if s == nil {
			h.mu.Unlock()
			return errors.New("unknown plugin")
		}
		state := *s
		changed := h.changed
		if revision != "" && state.Desired != revision {
			h.mu.Unlock()
			return errors.New("intent superseded")
		}
		if state.State == "active" && (revision == "" || state.Effective == revision) {
			h.mu.Unlock()
			return nil
		}
		if state.State == "disabled" && allowDisabled {
			h.mu.Unlock()
			return nil
		}
		if state.State == "failed" || state.State == "cleanup-blocked" || state.State == "host-unavailable" {
			h.mu.Unlock()
			return fmt.Errorf("%s: %s", state.State, state.Error)
		}
		h.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return fmt.Errorf("activation pending; no automatic retry/fallback: %w", ctx.Err())
		}
	}
}
func (h *CordisLifecycleHost) WaitActive(ctx context.Context, ids ...string) error {
	for _, id := range ids {
		if err := h.waitRevision(ctx, id, "", false); err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
	}
	return nil
}
func (h *CordisLifecycleHost) NodeState() (json.RawMessage, error) {
	h.mu.Lock()
	w := h.worker
	h.mu.Unlock()
	if w == nil {
		return nil, errors.New("no host")
	}
	var reply cordisReply
	err := w.control("state", nil, &reply)
	return reply.Data, err
}
func (h *CordisLifecycleHost) Close(ctx context.Context) error {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		h.mu.Unlock()
		go func() {
			deadline, cancel := context.WithTimeout(context.Background(), h.opts.OperationTimeout+time.Second)
			defer cancel()
			h.closeErr = h.closeHost(deadline)
			close(h.closeDone)
		}()
	})
	select {
	case <-h.closeDone:
		return h.closeErr
	case <-ctx.Done():
		return fmt.Errorf("host close not observed: %w", ctx.Err())
	}
}
func (h *CordisLifecycleHost) closeHost(ctx context.Context) (result error) {
	defer func() {
		if result == nil {
			return
		}
		h.mu.Lock()
		w := h.worker
		h.mu.Unlock()
		if w == nil {
			return
		}
		w.abort()
		select {
		case <-w.exited:
		case <-time.After(200 * time.Millisecond):
			result = errors.Join(result, errors.New("direct Node process exit not observed"))
		}
	}()
	h.mu.Lock()
	h.closed = true
	for _, b := range h.attempts {
		h.revokeLocked(b, "shutdown")
	}
	batches := []*cordisScope{}
	for _, b := range h.attempts {
		batches = append(batches, b)
	}
	w := h.worker
	h.mu.Unlock()
	for _, b := range batches {
		select {
		case <-b.cleanupDone:
			h.mu.Lock()
			err := b.cleanupError
			h.mu.Unlock()
			if err != nil {
				if w != nil {
					w.abort()
				}
				return err
			}
		case <-ctx.Done():
			if w != nil {
				w.abort()
			}
			return ctx.Err()
		}
	}
	if w == nil {
		return nil
	}
	err := w.control("shutdown", nil, nil)
	if err != nil {
		w.abort()
	}
	select {
	case <-w.exited:
		return err
	case <-ctx.Done():
		w.abort()
		return ctx.Err()
	}
}
