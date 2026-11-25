package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
)

func cloneCordisConfig(c map[string]any) map[string]any {
	v, _ := DeepCloneValue(c).(map[string]any)
	return v
}
func rejectCordisUnknownFields(schema *ConfigSchema, raw map[string]any) error {
	if schema == nil {
		if len(raw) > 0 {
			return errors.New("F03.1 schema-less config not supported")
		}
		return nil
	}
	return rejectCordisFieldKeys(schema.Fields, raw, "")
}
func rejectCordisFieldKeys(fields []FieldSchema, raw map[string]any, prefix string) error {
	known := map[string]bool{}
	for _, f := range fields {
		known[f.Key] = true
	}
	for key := range raw {
		if !known[key] {
			return fmt.Errorf("unknown field %q rejected; F03.1 migration not implemented", prefix+key)
		}
	}
	for _, f := range fields {
		if f.Type != FieldList {
			continue
		}
		items, _ := raw[f.Key].([]any)
		for _, item := range items {
			if child, ok := item.(map[string]any); ok {
				if err := rejectCordisFieldKeys(f.ItemFields, child, prefix+f.Key+"[]."); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type cordisConfigOperation struct {
	requestError                                                     string
	id, plugin, phase, revision, baseGeneration, activatedGeneration string
	base, target                                                     map[string]any
	deps                                                             map[string]string
	worker                                                           *cordisWorker
	epoch                                                            uint64
	oldDisk                                                          cordisDiskImage
	oldDiskEpoch, writtenDiskEpoch                                   uint64
	diskTouched                                                      bool
	observedDiskHash, diskError, activationError, compensationError  string
	terminal                                                         bool
	done                                                             chan struct{}
}
type CordisConfigOperationView struct {
	RequestedConfig          map[string]any `json:"requested_config"`
	RollbackConfig           map[string]any `json:"rollback_config"`
	LastSuccessfulGeneration string         `json:"last_successful_generation"`
	LastSuccessfulRevision   string         `json:"last_successful_revision"`
	RequestError             string         `json:"request_error,omitempty"`
	OperationID              string         `json:"operation_id"`
	Plugin                   string         `json:"plugin"`
	Phase                    string         `json:"phase"`
	Terminal                 bool           `json:"terminal"`
	OperationRevision        string         `json:"operation_revision"`
	DesiredRevision          string         `json:"desired_revision"`
	DesiredConfig            map[string]any `json:"desired_config"`
	RunningLive              bool           `json:"running_live"`
	RunningGeneration        string         `json:"running_generation"`
	RunningConfig            map[string]any `json:"running_config,omitempty"`
	LastSuccessfulConfig     map[string]any `json:"last_successful_config"`
	OriginalGeneration       string         `json:"original_generation"`
	ActivatedGeneration      string         `json:"activated_generation,omitempty"`
	OriginalDiskHash         string         `json:"original_disk_hash"`
	LastObservedDiskHash     string         `json:"last_observed_disk_hash"`
	DiskError                string         `json:"disk_error,omitempty"`
	ActivationError          string         `json:"activation_error,omitempty"`
	CompensationError        string         `json:"compensation_error,omitempty"`
}

// Active is a real owned, live scope, not Effective (a historical label).
func (h *CordisLifecycleHost) liveConfigScopeLocked(id string) *cordisScope {
	s := h.states[id]
	if s == nil || s.State != "active" {
		return nil
	}
	h.kernel.mu.RLock()
	defer h.kernel.mu.RUnlock()
	r := h.kernel.records[id]
	if r == nil || !r.active {
		return nil
	}
	for _, b := range h.attempts {
		if b.plugin == id && b.generation == s.Generation && !b.revoked && h.sourceValidLocked(b.host, b.hostIncarnation) && b.admissionEpoch == h.hostEpoch {
			return b
		}
	}
	return nil
}
func (h *CordisLifecycleHost) configViewLocked(op *cordisConfigOperation) CordisConfigOperationView {
	v := CordisConfigOperationView{RequestedConfig: cloneCordisConfig(op.target), RollbackConfig: cloneCordisConfig(op.base), RequestError: op.requestError, LastSuccessfulGeneration: h.configLastGeneration[op.plugin], LastSuccessfulRevision: h.configLastRevision[op.plugin], OperationID: op.id, Plugin: op.plugin, Phase: op.phase, Terminal: op.terminal, OperationRevision: op.revision, OriginalGeneration: op.baseGeneration, ActivatedGeneration: op.activatedGeneration, LastSuccessfulConfig: cloneCordisConfig(h.configAnchors[op.plugin]), OriginalDiskHash: diskImageHash(op.oldDisk), LastObservedDiskHash: op.observedDiskHash, DiskError: op.diskError, ActivationError: op.activationError, CompensationError: op.compensationError}
	if s := h.states[op.plugin]; s != nil {
		v.DesiredRevision = s.Desired
	}
	h.kernel.mu.RLock()
	if rec := h.kernel.records[op.plugin]; rec != nil {
		v.DesiredConfig = cloneCordisConfig(rec.config)
	}
	h.kernel.mu.RUnlock()
	if b := h.liveConfigScopeLocked(op.plugin); b != nil {
		v.RunningLive = true
		v.RunningGeneration = b.generation
		v.RunningConfig = cloneCordisConfig(b.config)
	}
	return v
}
func (h *CordisLifecycleHost) ConfigOperation(id string) (CordisConfigOperationView, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	op := h.configOperations[id]
	if op == nil {
		return CordisConfigOperationView{}, false
	}
	return h.configViewLocked(op), true
}
func (h *CordisLifecycleHost) configOperationCurrentLocked(op *cordisConfigOperation) bool {
	return !op.terminal && h.configCurrent[op.plugin] == op && (op.revision == "" || h.states[op.plugin].Desired == op.revision)
}
func (h *CordisLifecycleHost) configFinishLocked(op *cordisConfigOperation, phase string) {
	if op.terminal {
		return
	}
	op.phase = phase
	if phase == "recovery-required" {
		if b := h.liveConfigScopeLocked(op.plugin); b != nil && !reflect.DeepEqual(b.config, op.base) {
			h.revokeLocked(b, "config-recovery-required")
		}
	}
	op.terminal = true
	close(op.done)
	h.eventLocked(op.plugin, "config-"+phase, op.activatedGeneration, op.id)
}
func (h *CordisLifecycleHost) configure(ctx context.Context, id string, target map[string]any) error {
	if err := ctx.Err(); err != nil {
		return err
	} // cancellation before admission has zero side effects
	k := h.kernel
	k.persistMu.Lock()
	h.configFence.Lock()
	if err := ctx.Err(); err != nil {
		h.configFence.Unlock()
		k.persistMu.Unlock()
		return err
	}
	old, err := readCordisDisk(k.configPath)
	if err == nil {
		_, err = cordisConfigDocument(old, id, target)
		if err == nil && old.exists {
			var disk struct {
				Plugins map[string]struct {
					Config map[string]any `json:"config"`
				} `json:"plugins"`
			}
			if e := json.Unmarshal(old.bytes, &disk); e != nil {
				err = e
			} else {
				k.mu.RLock()
				rec := k.records[id]
				if rec != nil {
					err = rejectCordisUnknownFields(rec.plugin.Schema(), disk.Plugins[id].Config)
				}
				k.mu.RUnlock()
			}
		}
	}
	h.mu.Lock()
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && !h.sourceValidLocked(h.worker, func() string {
		if h.worker != nil {
			return h.worker.incarnation
		}
		return ""
	}()) {
		err = errors.New("host unavailable")
	}
	previous := h.configCurrent[id]
	if err == nil && previous != nil && (previous.phase == "recovery-required" || (!previous.terminal && previous.diskTouched)) {
		err = errors.New("recovery-required or file compensation pending; ordinary config/Reset refused")
	}
	live := h.liveConfigScopeLocked(id)
	if err == nil && live == nil && (previous == nil || previous.terminal) {
		err = errors.New("F03.0 requires a proven live enabled baseline; inactive/unknown baseline unsupported")
	}
	if err != nil {
		h.mu.Unlock()
		h.configFence.Unlock()
		k.persistMu.Unlock()
		return fmt.Errorf("F03 preflight rejected: %w", err)
	}
	base := cloneCordisConfig(h.configAnchors[id])
	gen := ""
	deps := map[string]string{}
	if base == nil && live != nil {
		base = cloneCordisConfig(live.config)
		h.configAnchors[id] = cloneCordisConfig(base)
		h.configLastGeneration[id] = live.generation
		h.configLastRevision[id] = live.revision
	}
	if live != nil {
		gen = live.generation
		deps = cloneCordisDeps(live.deps)
	}
	if previous != nil && !previous.terminal {
		base = cloneCordisConfig(previous.base)
		gen = previous.baseGeneration
		deps = cloneCordisDeps(previous.deps)
	}
	h.configSequence++
	op := &cordisConfigOperation{id: h.incarnation + "/config/" + strconv.FormatUint(h.configSequence, 10), plugin: id, phase: "admitted", base: base, target: cloneCordisConfig(target), baseGeneration: gen, deps: deps, worker: h.worker, epoch: h.hostEpoch, oldDisk: old, oldDiskEpoch: k.configDiskRevision, observedDiskHash: diskImageHash(old), done: make(chan struct{})}
	h.configCurrent[id] = op
	if previous != nil && !previous.terminal {
		previous.activationError = "superseded by " + op.id
		h.configFinishLocked(previous, "superseded")
	}
	h.configOperations[op.id] = op
	h.eventLocked(id, "config-admitted", gen, op.id)
	h.mu.Unlock()
	h.configFence.Unlock()
	k.persistMu.Unlock()
	go h.runConfigOperation(op)
	select {
	case <-op.done:
		h.mu.Lock()
		defer h.mu.Unlock()
		if op.phase == "committed" {
			return nil
		}
		return fmt.Errorf("config operation %s: %s: %s; compensation: %s", op.id, op.phase, op.requestError, op.compensationError)
	case <-ctx.Done():
		return fmt.Errorf("config operation %s: observation cancelled; query operation (no retry): %w", op.id, ctx.Err())
	}
}
func (h *CordisLifecycleHost) configActiveMatchesLocked(op *cordisConfigOperation, cfg map[string]any, generation string) bool {
	if !h.configOperationCurrentLocked(op) || !h.sourceValidLocked(op.worker, op.worker.incarnation) || h.hostEpoch != op.epoch {
		return false
	}
	b := h.liveConfigScopeLocked(op.plugin)
	if b != nil {
		h.kernel.mu.RLock()
		valid := h.depsMatchLocked(b)
		h.kernel.mu.RUnlock()
		if !valid {
			return false
		}
	}
	return b != nil && b.revision == op.revision && (generation == "" || b.generation == generation) && reflect.DeepEqual(b.config, cfg) && sameCordisDeps(b.deps, op.deps)
}
func (h *CordisLifecycleHost) runConfigOperation(op *cordisConfigOperation) {
	defer h.kernel.notifyChange()
	h.mu.Lock()
	if !h.configOperationCurrentLocked(op) {
		h.configFinishLocked(op, "superseded")
		h.mu.Unlock()
		return
	}
	op.phase = "activating"
	h.signalLocked()
	h.mu.Unlock()
	err := h.updateConfigGuarded(op.plugin, nil, op.target, false, op, false)
	if err != nil {
		h.mu.Lock()
		op.activationError = err.Error()
		h.mu.Unlock()
	}
	if err == nil {
		h.mu.Lock()
		if b := h.liveConfigScopeLocked(op.plugin); b != nil {
			op.activatedGeneration = b.generation
		}
		h.mu.Unlock()
		err = h.commitConfigOperation(op)
	}
	if err == nil {
		return
	}
	h.mu.Lock()
	op.requestError = err.Error()
	if !h.configOperationCurrentLocked(op) {
		h.configFinishLocked(op, "superseded")
		h.mu.Unlock()
		return
	}
	op.phase = "compensating"
	h.signalLocked()
	h.mu.Unlock()
	h.compensateConfigOperation(op)
}
func (h *CordisLifecycleHost) commitConfigOperation(op *cordisConfigOperation) error {
	k := h.kernel
	k.persistMu.Lock()
	defer k.persistMu.Unlock()
	h.configFence.Lock()
	defer h.configFence.Unlock()
	h.mu.Lock()
	valid := h.configActiveMatchesLocked(op, op.target, op.activatedGeneration)
	if valid {
		op.phase = "persisting"
		h.signalLocked()
	}
	h.mu.Unlock()
	if !valid {
		return errors.New("activation/source/dependency/generation fence changed before persistence")
	}
	if k.configDiskRevision != op.oldDiskEpoch {
		return errors.New("another config writer changed file epoch; old whole-file restore forbidden")
	}
	actual, err := readCordisDisk(k.configPath)
	if err != nil {
		return err
	}
	if !sameDiskImage(actual, op.oldDisk) {
		return errors.New("config bytes changed outside operation")
	}
	raw, err := cordisConfigDocument(op.oldDisk, op.plugin, op.target)
	if err != nil {
		return err
	}
	want := cordisDiskImage{raw, true, op.oldDisk.mode}
	writeErr := h.writeConfigImage(want, "commit")
	observed, readErr := readCordisDisk(k.configPath)
	h.mu.Lock()
	op.observedDiskHash = diskImageHash(observed)
	if readErr != nil || writeErr != nil {
		op.diskError = fmt.Sprint(errors.Join(writeErr, readErr))
	}
	if readErr == nil && !sameDiskImage(observed, op.oldDisk) {
		k.configDiskRevision++
		op.writtenDiskEpoch = k.configDiskRevision
		op.diskTouched = true
	}
	valid = h.configActiveMatchesLocked(op, op.target, op.activatedGeneration)
	if writeErr == nil && readErr == nil && sameDiskImage(observed, want) && valid {
		h.configAnchors[op.plugin] = cloneCordisConfig(op.target)
		h.configLastGeneration[op.plugin] = op.activatedGeneration
		h.configLastRevision[op.plugin] = op.revision
		h.configFinishLocked(op, "committed")
		h.mu.Unlock()
		return nil
	}
	h.mu.Unlock()
	if writeErr != nil {
		return writeErr
	}
	if readErr != nil {
		return readErr
	}
	return errors.New("post-write active/source fence failed or disk outcome differs")
}
func (h *CordisLifecycleHost) drainConfigScopes(op *cordisConfigOperation) error {
	ctx, cancel := context.WithTimeout(context.Background(), h.opts.OperationTimeout+h.opts.CleanupTimeout+h.opts.CleanupExecutionTimeout)
	defer cancel()
	h.mu.Lock()
	scopes := []*cordisScope{}
	for _, b := range h.attempts {
		if b.plugin == op.plugin && b.revoked {
			scopes = append(scopes, b)
		}
	}
	h.mu.Unlock()
	for _, b := range scopes {
		select {
		case <-b.cleanupDone:
			h.mu.Lock()
			ok, e := b.cleanupOK, b.cleanupError
			h.mu.Unlock()
			if !ok {
				return fmt.Errorf("prior cleanup failed; no compensation admission: %v", e)
			}
		case <-ctx.Done():
			return errors.New("prior cleanup still pending; compensation not dispatched")
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.configOperationCurrentLocked(op) {
		return errors.New("config operation superseded while draining")
	}
	if !h.sourceValidLocked(op.worker, op.worker.incarnation) {
		return errors.New("host unavailable while draining")
	}
	return nil
}
func (h *CordisLifecycleHost) compensateConfigOperation(op *cordisConfigOperation) {
	h.mu.Lock()
	source := h.sourceValidLocked(op.worker, op.worker.incarnation) && h.hostEpoch == op.epoch
	deps := true
	h.kernel.mu.RLock()
	for name, token := range op.deps {
		actual, _, _, ok := h.resolveLocked(name)
		if !ok || actual != token {
			deps = false
		}
	}
	h.kernel.mu.RUnlock()
	h.mu.Unlock()
	var activationErr error
	if !source || !deps {
		activationErr = errors.New("source/dependency baseline invalid; automatic A reactivation refused")
	} else {
		activationErr = h.updateConfigGuarded(op.plugin, nil, op.base, false, op, true)
	}
	diskErr := h.restoreConfigDisk(op)
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.configOperationCurrentLocked(op) {
		h.configFinishLocked(op, "superseded")
		return
	}
	recovered := activationErr == nil && diskErr == nil && h.configActiveMatchesLocked(op, op.base, "")
	if b := h.liveConfigScopeLocked(op.plugin); b == nil || b.generation == op.baseGeneration {
		recovered = false
	}
	if recovered {
		if b := h.liveConfigScopeLocked(op.plugin); b != nil {
			h.configLastGeneration[op.plugin] = b.generation
			h.configLastRevision[op.plugin] = b.revision
		}
		h.configFinishLocked(op, "recovered")
	} else {
		op.compensationError = fmt.Sprint(errors.Join(activationErr, diskErr))
		h.configFinishLocked(op, "recovery-required")
	}
}
func (h *CordisLifecycleHost) restoreConfigDisk(op *cordisConfigOperation) error {
	k := h.kernel
	k.persistMu.Lock()
	defer k.persistMu.Unlock()
	h.configFence.Lock()
	defer h.configFence.Unlock()
	h.mu.Lock()
	current := h.configOperationCurrentLocked(op)
	h.mu.Unlock()
	if !current {
		return errors.New("superseded; no old disk restore")
	}
	expected := op.oldDiskEpoch
	if op.diskTouched {
		expected = op.writtenDiskEpoch
	}
	if k.configDiskRevision != expected {
		return errors.New("another file writer committed; raw rollback refused")
	}
	actual, err := readCordisDisk(k.configPath)
	if err != nil {
		return err
	}
	if !sameDiskImage(actual, op.oldDisk) {
		if !op.diskTouched {
			return errors.New("unowned disk change; raw rollback refused")
		}
		raw, e := cordisConfigDocument(op.oldDisk, op.plugin, op.target)
		if e != nil {
			return e
		}
		if !sameDiskImage(actual, cordisDiskImage{raw, true, op.oldDisk.mode}) {
			return errors.New("unowned post-write disk state; restore refused")
		}
		err = h.writeConfigImage(op.oldDisk, "restore")
		k.configDiskRevision++
	}
	observed, e := readCordisDisk(k.configPath)
	h.mu.Lock()
	op.observedDiskHash = diskImageHash(observed)
	if err != nil || e != nil {
		op.diskError = fmt.Sprint(errors.Join(err, e))
	}
	h.mu.Unlock()
	if err != nil || e != nil {
		return errors.Join(err, e)
	}
	if !sameDiskImage(observed, op.oldDisk) {
		return errors.New("original disk bytes/absence not restored")
	}
	return nil
}
