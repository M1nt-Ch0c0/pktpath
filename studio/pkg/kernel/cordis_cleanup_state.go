package kernel

// Cleanup lifecycle diagnostics contain no Go values, function pointers or data
// plane payloads. Every field is protected by the lifecycle owner's mutex.
type CordisCleanupView struct {
	Plugin                   string `json:"plugin"`
	Generation               string `json:"generation"`
	Phase                    string `json:"phase"`
	Cause                    string `json:"cause"`
	ApplyExitObserved        bool   `json:"apply_exit_observed"`
	ApplyWaitTimedOut        bool   `json:"apply_wait_timed_out"`
	ObservationTimedOut      bool   `json:"observation_timed_out"`
	HooksStarted             bool   `json:"hooks_started"`
	HooksReturned            bool   `json:"hooks_returned"`
	ExecutionTimedOut        bool   `json:"execution_timed_out"`
	CompletionObserved       bool   `json:"completion_observed"`
	CleanupOK                bool   `json:"cleanup_ok"`
	ResourceHeld             bool   `json:"resource_held"`
	CloseObservationTimedOut bool   `json:"close_observation_timed_out"`
	WaitStarted              string `json:"wait_started,omitempty"`
	CleanupStarted           string `json:"cleanup_started,omitempty"`
	CleanupDeadline          string `json:"cleanup_deadline,omitempty"`
	Error                    string `json:"error,omitempty"`
}

func (h *CordisLifecycleHost) cleanupViewLocked(b *cordisScope) CordisCleanupView {
	v := CordisCleanupView{Plugin: b.plugin, Generation: b.generation, Phase: b.cleanupPhase, Cause: b.disposeCause, ApplyExitObserved: b.applyExitObserved, ApplyWaitTimedOut: b.applyWaitTimedOut, ObservationTimedOut: b.cleanupTimedOut, HooksStarted: b.cleanupHooksStarted, HooksReturned: b.cleanupHooksReturned, ExecutionTimedOut: b.cleanupExecutionTimedOut, CompletionObserved: b.cleanupCompletionObserved, CleanupOK: b.cleanupOK, ResourceHeld: !b.cleanupOK, CloseObservationTimedOut: b.closeObservationTimedOut}
	if !b.cleanupWaitStarted.IsZero() {
		v.WaitStarted = b.cleanupWaitStarted.Format("2006-01-02T15:04:05.999999999Z07:00")
	}
	if !b.cleanupStarted.IsZero() {
		v.CleanupStarted = b.cleanupStarted.Format("2006-01-02T15:04:05.999999999Z07:00")
	}
	if !b.cleanupDeadline.IsZero() {
		v.CleanupDeadline = b.cleanupDeadline.Format("2006-01-02T15:04:05.999999999Z07:00")
	}
	if b.cleanupError != nil {
		v.Error = b.cleanupError.Error()
	}
	return v
}
func (h *CordisLifecycleHost) cleanupPhaseLocked(b *cordisScope, phase, err string) {
	b.cleanupPhase = phase
	if s := h.states[b.plugin]; s != nil && s.Generation == b.generation {
		s.CleanupPhase = phase
		if h.sourceValidLocked(b.host, b.hostIncarnation) {
			if phase == "apply-exit-timeout-pending" {
				s.State = "cleanup-timeout-pending"
				s.Error = err
			}
			if phase == "cleanup-execution-timeout-pending" {
				s.State = phase
				s.Error = err
				s.Recovery = "explicit-recovery-required"
			}
		}
	}
	h.eventLocked(b.plugin, phase, b.generation, err)
}
