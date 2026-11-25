package kernel

import (
	"errors"
	"fmt"
	"strconv"
)

// One bounded dependency-driven retry, never a general Apply retry loop.
type cordisRecovery struct {
	old                        *cordisScope
	host                       *cordisWorker
	incarnation                string
	epoch                      uint64
	plugin, revision, recovery string
	deps                       map[string]string
}

func cloneCordisDeps(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func sameCordisDeps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Called under h.mu only after Apply AND every cleanup callback actually returned.
func (h *CordisLifecycleHost) cleanupFinishedLocked(b *cordisScope) *cordisRecovery {
	state := h.states[b.plugin]
	ticket := h.recoveries[b.plugin]
	if ticket != nil && ticket.old == b {
		delete(h.recoveries, b.plugin)
	} else {
		ticket = nil
	}
	if !b.cleanupOK {
		if state != nil && state.Generation == b.generation && h.sourceValidLocked(b.host, b.hostIncarnation) {
			state.State = "cleanup-failed"
			state.Error = b.cleanupError.Error()
			state.Recovery = "explicit-recovery-required"
		}
		h.eventLocked(b.plugin, "cleanup-failed", b.generation, b.cleanupError.Error())
		return nil
	}
	h.eventLocked(b.plugin, "disposed", b.generation, "")
	if state == nil || state.Generation != b.generation || !h.sourceValidLocked(b.host, b.hostIncarnation) || b.admissionEpoch != h.hostEpoch {
		return nil
	}
	h.kernel.mu.RLock()
	recNow := h.kernel.records[b.plugin]
	enabledNow := recNow != nil && recNow.enabled
	h.kernel.mu.RUnlock()
	if !enabledNow {
		state.State = "disabled"
		state.Error = ""
		state.Recovery = ""
		return nil
	}
	if ticket != nil {
		k := h.kernel
		k.mu.RLock()
		rec := k.records[b.plugin]
		valid := rec != nil && rec.enabled && state.Desired == ticket.revision && ticket.host == h.worker && ticket.epoch == h.hostEpoch && ticket.incarnation == h.worker.incarnation
		for name, expected := range ticket.deps {
			actual, _, _, ok := h.resolveLocked(name)
			if !ok || actual != expected {
				valid = false
			}
		}
		k.mu.RUnlock()
		if valid {
			h.nextRecovery++
			ticket.recovery = strconv.FormatUint(h.nextRecovery, 10)
			state.State = "recovery-scheduled"
			state.Error = ""
			state.Recovery = "one-dependency-retry-consumed"
			h.eventLocked(b.plugin, "recovery-scheduled", b.generation, ticket.recovery)
			return ticket
		}
	}
	if b.cleanupTimedOut {
		state.State = "cleanup-ready-explicit-reload"
		state.Error = "actual cleanup succeeded; explicit new intent required"
		state.Recovery = "explicit-reload"
		h.signalLocked()
	}
	return nil
}
func (h *CordisLifecycleHost) resumeAfterDrain(ticket *cordisRecovery) {
	// Revalidate just before sending; all hooks/RPC occur outside owner/kernel locks.
	h.mu.Lock()
	state := h.states[ticket.plugin]
	valid := h.sourceValidLocked(ticket.host, ticket.incarnation) && h.hostEpoch == ticket.epoch && state != nil && state.Desired == ticket.revision && state.Generation == ticket.old.generation
	h.mu.Unlock()
	if !valid {
		return
	}
	err := ticket.host.control("resume", map[string]any{"plugin": ticket.plugin, "revision": ticket.revision, "deps": ticket.deps, "recovery": ticket.recovery}, nil)
	if err == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	state = h.states[ticket.plugin]
	if !h.sourceValidLocked(ticket.host, ticket.incarnation) || state == nil || state.Desired != ticket.revision || state.Generation != ticket.old.generation {
		return
	}
	state.State = "cleanup-ready-explicit-reload"
	state.Error = fmt.Sprint(errors.New("one-shot dependency recovery rejected; no automatic repeat"), ": ", err)
	state.Recovery = "explicit-reload"
	h.eventLocked(ticket.plugin, "recovery-rejected", ticket.old.generation, state.Error)
}
