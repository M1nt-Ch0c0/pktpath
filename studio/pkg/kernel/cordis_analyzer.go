package kernel

// F01 is an opt-in, development-only Cordis3 control host. Go remains the
// task/config owner and the sole executor of the original stdio hook.
import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const cordisProtocol = "pktpath.cordis3.analyzer/1"

var ErrAnalyzerStale = errors.New("analyzer activation superseded; old result not committed")
var ErrAnalyzerBundleBusy = errors.New("analyzer package leased by in-flight task; retry after drain")

// CordisAnalyzerOptions explicitly enables the candidate. Empty options are
// never inferred from PATH/environment by the default Go implementation.
type CordisAnalyzerOptions struct{ NodePath, HostPath string }

// AnalyzerTaskRecord is a Go-owned, single-terminal task record. No analysis
// payload crosses JS: u64 values stay in original Go/raw-JSON representations.
type AnalyzerTaskRecord struct {
	NodeVersion, CoreVersion, Protocol                  string
	Backend, ConfigRevision, Admission                  string
	TerminalCommits                                     uint32
	Output                                              *AnalyzeOutput `json:"-"`
	TaskID, Generation, PluginID, AnalyzerID, SessionID string
	ConfigDigest, PackageIdentity                       string
	State, Diagnostic                                   string
	HookExited, ResultAccepted                          bool
}

type CordisAnalyzerHost struct {
	opts        CordisAnalyzerOptions
	mu          sync.Mutex
	seq         uint64
	closed      bool
	current     map[string]*cordisActivation
	activations []*cordisActivation
	tasks       []AnalyzerTaskRecord
	// Package leases and replacement state share mu. No lock spans hook I/O.
	leases      int
	mutating    bool
	incarnation string
	bootErr     error
}

type cordisActivation struct {
	ready                                               chan struct{}
	revoked                                             bool
	startErr                                            error
	host                                                *CordisAnalyzerHost
	pluginID, generation, configDigest, packageIdentity string
	worker                                              *cordisWorker
	active                                              bool // protected by host.mu
	pending                                             int
	idle                                                chan struct{}
	retired                                             sync.Once
	done                                                chan struct{}
	drainErr                                            error // published before done closes
}

func NewCordisAnalyzerHost(opts CordisAnalyzerOptions) *CordisAnalyzerHost {
	var seed [16]byte
	_, err := rand.Read(seed[:])
	return &CordisAnalyzerHost{opts: opts, current: map[string]*cordisActivation{}, incarnation: hex.EncodeToString(seed[:]), bootErr: err}
}

func digestJSON(value any) string {
	b, _ := json.Marshal(value)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (h *CordisAnalyzerHost) activate(pluginID, packageIdentity string, config any, analyzers []string) (*cordisActivation, error) {
	h.mu.Lock()
	if h.bootErr != nil {
		h.mu.Unlock()
		return nil, h.bootErr
	}
	if h.closed {
		h.mu.Unlock()
		return nil, errors.New("Cordis analyzer host closed")
	}
	h.seq++
	a := &cordisActivation{host: h, pluginID: pluginID, generation: h.incarnation + "/" + strconv.FormatUint(h.seq, 10), ready: make(chan struct{}), configDigest: digestJSON(config), packageIdentity: packageIdentity, idle: make(chan struct{}), done: make(chan struct{})}
	close(a.idle)
	old := h.current[pluginID]
	h.current[pluginID] = a
	h.activations = append(h.activations, a)
	h.mu.Unlock()
	if old != nil {
		old.revoke()
	}
	w, err := startCordisWorker(h.opts)
	if err == nil {
		a.worker = w
		var reply cordisReply
		err = w.control("activate", map[string]any{"generation": a.generation, "analyzers": analyzers}, &reply)
		if err == nil && reply.Generation != a.generation {
			err = errors.New("Cordis activation acknowledgement mismatch")
		}
	}
	h.mu.Lock()
	if err == nil && !h.closed && !a.revoked && h.current[pluginID] == a {
		a.active = true
	} else if err == nil {
		err = ErrAnalyzerStale
	}
	h.mu.Unlock()
	a.startErr = err
	close(a.ready)
	if err != nil {
		a.revoke()
		<-a.done
		return nil, fmt.Errorf("Cordis analyzer activation: %w", err)
	}
	return a, nil
}

func (a *cordisActivation) revoke() {
	a.host.mu.Lock()
	a.active = false
	a.revoked = true
	a.host.mu.Unlock()
	a.retired.Do(func() { go a.retire() })
}

func (a *cordisActivation) retire() {
	defer close(a.done)
	<-a.ready
	if a.startErr != nil {
		if a.worker != nil {
			a.worker.abort()
			<-a.worker.exited
		}
		a.drainErr = a.startErr
		return
	}
	if a.worker == nil {
		return
	}
	var errs []error
	if err := a.worker.control("deactivate", nil, nil); err != nil {
		errs = append(errs, err)
	}
	a.host.mu.Lock()
	idle := a.idle
	a.host.mu.Unlock()
	<-idle // Explicit application drain, NOT Cordis3's synchronous dispose return.
	var reply cordisReply
	if err := a.worker.control("drain", nil, &reply); err != nil {
		errs = append(errs, err)
	} else if !reply.Drained || !reply.CleanupDone {
		errs = append(errs, errors.New("Cordis cleanup not observed"))
	}
	if err := a.worker.control("shutdown", nil, nil); err != nil {
		errs = append(errs, err)
		a.worker.abort()
	}
	select {
	case <-a.worker.exited:
	case <-time.After(3 * time.Second):
		errs = append(errs, errors.New("Cordis host did not exit after drain"))
		a.worker.abort()
		<-a.worker.exited
	}
	if a.worker.waitErr != nil {
		errs = append(errs, a.worker.waitErr)
	}
	a.drainErr = errors.Join(errs...)
}

// Drain observes completion/errors for revoked activations. Active generations
// remain admitted. Close revokes every generation before observing drain.
func (h *CordisAnalyzerHost) Drain(ctx context.Context) error {
	h.mu.Lock()
	var retired []*cordisActivation
	for _, a := range h.activations {
		if !a.active {
			retired = append(retired, a)
		}
	}
	h.mu.Unlock()
	var errs []error
	for _, a := range retired {
		select {
		case <-ctx.Done():
			return errors.Join(append(errs, ctx.Err())...)
		case <-a.done:
			errs = append(errs, a.drainErr)
		}
	}
	return errors.Join(errs...)
}

func (h *CordisAnalyzerHost) Close(ctx context.Context) error {
	h.mu.Lock()
	h.closed = true
	all := append([]*cordisActivation(nil), h.activations...)
	h.mu.Unlock()
	for _, a := range all {
		a.revoke()
	}
	err := h.Drain(ctx)
	if ctx.Err() != nil {
		for _, a := range all {
			<-a.ready
			if a.worker != nil {
				a.worker.abort()
			}
		}
	}
	return err
}

func (h *CordisAnalyzerHost) Tasks() []AnalyzerTaskRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := append([]AnalyzerTaskRecord(nil), h.tasks...)
	for i := range out {
		out[i].Output = cloneAnalyzerOutput(out[i].Output)
	}
	return out
}

// ProtectPackageMutation guards ALL current and legacy package write/delete
// entry points. A task lease and mutation admission are one atomic decision.
func (h *CordisAnalyzerHost) ProtectPackageMutation() (func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mutating || h.leases > 0 {
		return nil, ErrAnalyzerBundleBusy
	}
	h.mutating = true
	return func() { h.mu.Lock(); h.mutating = false; h.mu.Unlock() }, nil
}
func (h *CordisAnalyzerHost) acquirePackage() (func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mutating {
		return nil, ErrAnalyzerBundleBusy
	}
	h.leases++
	return func() { h.mu.Lock(); h.leases--; h.mu.Unlock() }, nil
}
func cloneAnalyzerOutput(out *AnalyzeOutput) *AnalyzeOutput {
	if out == nil {
		return nil
	}
	raw, _ := json.Marshal(out)
	var copy AnalyzeOutput
	_ = json.Unmarshal(raw, &copy)
	return &copy
}

func (a *cordisActivation) run(ctx context.Context, analyzer, session string, current func() bool, runner func() (*AnalyzeOutput, error)) (*AnalyzeOutput, error) {
	h := a.host
	release, leaseErr := h.acquirePackage()
	if leaseErr != nil {
		return nil, leaseErr
	}
	leaseHeld := true
	defer func() {
		if leaseHeld {
			release()
		}
	}() // early rejection still releases its lease.
	h.mu.Lock()
	if !a.active || h.current[a.pluginID] != a || !current() {
		h.mu.Unlock()
		return nil, ErrAnalyzerStale
	}
	if a.pending == 0 {
		a.idle = make(chan struct{})
	}
	a.pending++
	h.seq++
	task := h.incarnation + "/task/" + strconv.FormatUint(h.seq, 10)
	index := len(h.tasks)
	h.tasks = append(h.tasks, AnalyzerTaskRecord{TaskID: task, Generation: a.generation, PluginID: a.pluginID, AnalyzerID: analyzer, SessionID: session, ConfigDigest: a.configDigest, PackageIdentity: a.packageIdentity, State: "admitting", Backend: "cordis3-go-runner", NodeVersion: a.worker.nodeVersion, CoreVersion: "3.18.1", Protocol: cordisProtocol, ConfigRevision: a.generation})
	h.mu.Unlock()
	var out *AnalyzeOutput
	var err error
	var begin cordisReply
	err = a.worker.control("begin", map[string]any{"task": task, "generation": a.generation, "analyzer": analyzer}, &begin)
	hookExited := false
	unknown := err != nil
	h.mu.Lock()
	if err == nil && begin.Accepted {
		h.tasks[index].Admission = "acknowledged"
		h.tasks[index].State = "running"
	} else {
		h.tasks[index].Admission = "unknown"
	}
	h.mu.Unlock()
	if err == nil && !begin.Accepted {
		err = errors.New("Cordis begin not acknowledged")
	}
	if err == nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		} else {
			out, err = runner()
			hookExited = true
		}
		var finish cordisReply
		finishErr := a.worker.control("finish", map[string]any{"task": task, "generation": a.generation}, &finish)
		if finishErr != nil {
			unknown = true
			err = errors.Join(err, fmt.Errorf("Cordis finish/commit unknown: %w", finishErr))
		} else if !finish.Accepted {
			err = errors.Join(err, ErrAnalyzerStale)
		}
	}
	// The Go ledger has exactly one terminal transition. Cancellation observed at
	// this commit point wins over success; no retry/fallback after missing ACK.
	h.mu.Lock()
	if ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	if !a.active || h.current[a.pluginID] != a || !current() {
		err = errors.Join(err, ErrAnalyzerStale)
	}
	rec := &h.tasks[index]
	rec.HookExited = hookExited
	rec.TerminalCommits = 1
	rec.Output = cloneAnalyzerOutput(out)
	rec.State = "succeeded"
	rec.ResultAccepted = err == nil
	if err != nil {
		rec.State = "failed"
		rec.Diagnostic = err.Error()
		if unknown {
			rec.State = "unknown"
		} else if errors.Is(err, context.DeadlineExceeded) {
			rec.State = "timed-out"
		} else if errors.Is(err, context.Canceled) {
			rec.State = "cancelled"
		} else if errors.Is(err, ErrAnalyzerStale) && hookExited {
			rec.State = "completed-stale"
		}
	}
	// Publish package release before waking drain observers.
	h.leases--
	leaseHeld = false
	a.pending--
	if a.pending == 0 {
		close(a.idle)
	}
	if len(h.tasks) > 256 {
		busy := false
		for _, activation := range h.activations {
			busy = busy || activation.pending > 0
		}
		if !busy {
			h.tasks = append([]AnalyzerTaskRecord(nil), h.tasks[len(h.tasks)-256:]...)
		}
	}
	h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Control messages contain only strings/booleans/metadata, never evidence JSON.
type cordisReply struct {
	Incarnation string          `json:"incarnation,omitempty"`
	Kind        string          `json:"kind,omitempty"`
	Data        json.RawMessage `json:"data,omitempty"`
	ID          string          `json:"id"`
	Protocol    string          `json:"protocol"`
	OK          bool            `json:"ok"`
	Error       string          `json:"error"`
	Core        string          `json:"core"`
	Node        string          `json:"node"`
	Generation  string          `json:"generation"`
	Accepted    bool            `json:"accepted"`
	Drained     bool            `json:"drained"`
	CleanupDone bool            `json:"cleanupDone"`
}

type cordisWorker struct {
	incarnation string
	dead        atomic.Bool
	onFailure   func(*cordisWorker, error)
	protocol    string
	onRequest   func(*cordisWorker, []byte)
	nodeVersion string
	stderr      cordisStderr
	cmd         *exec.Cmd
	input       io.WriteCloser
	writeMu     sync.Mutex
	mu          sync.Mutex
	next        uint64
	pending     map[string]chan cordisReply
	failed      chan struct{}
	failOnce    sync.Once
	failure     error
	exited      chan struct{}
	waitErr     error
}

func startCordisWorker(opts CordisAnalyzerOptions) (*cordisWorker, error) {
	return startCordisWorkerMode(opts, cordisProtocol, nil)
}

func startCordisWorkerMode(opts CordisAnalyzerOptions, protocol string, handler func(*cordisWorker, []byte), observers ...func(*cordisWorker, error)) (*cordisWorker, error) {
	if opts.HostPath == "" {
		return nil, errors.New("missing Cordis host module path")
	}
	node := opts.NodePath
	if node == "" {
		node = "node"
	}
	args := []string{opts.HostPath}
	if protocol == cordisLifecycleProtocol {
		args = append(args, "--lifecycle")
	}
	cmd := exec.Command(node, args...)
	// No shell; no dynamic npm install; script and runtime are explicit trusted code.
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, err
	}
	// Keep stderr out of the protocol. Errors are returned through framed replies.

	w := &cordisWorker{protocol: protocol, onRequest: handler, cmd: cmd, input: input, pending: map[string]chan cordisReply{}, failed: make(chan struct{}), exited: make(chan struct{})}
	if protocol == cordisLifecycleProtocol {
		var nonce [16]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			input.Close()
			output.Close()
			return nil, err
		}
		w.incarnation = hex.EncodeToString(nonce[:])
	}
	if len(observers) > 0 {
		w.onFailure = observers[0]
	}
	cmd.Stderr = &w.stderr
	if err = cmd.Start(); err != nil {
		input.Close()
		output.Close()
		return nil, err
	}
	go w.read(output)
	go func() { w.waitErr = cmd.Wait(); w.fail(errors.New("Cordis host exited")); close(w.exited) }()
	var hello cordisReply
	helloFields := map[string]any{}
	if protocol == cordisLifecycleProtocol {
		helloFields["incarnation"] = w.incarnation
	}
	if err = w.control("hello", helloFields, &hello); err != nil || hello.Core != "3.18.1" || (protocol == cordisLifecycleProtocol && hello.Incarnation != w.incarnation) {
		w.abort()
		<-w.exited
		if err == nil {
			err = fmt.Errorf("unexpected Cordis core/session handshake: %q", hello.Core)
		}
		return nil, err
	}
	w.nodeVersion = hello.Node
	return w, nil
}
func (w *cordisWorker) abort() {
	_ = w.input.Close()
	if w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
	}
}
func (w *cordisWorker) fail(err error) {
	w.dead.Store(true) // fast rejection even before the owner admission lock is acquired
	w.failOnce.Do(func() {
		// No worker mutex is held here. Lifecycle revocation uses the same owner
		// mutex as scope admission/commit, before failure becomes externally settled.
		if w.onFailure != nil {
			w.onFailure(w, err)
		}
		w.mu.Lock()
		w.failure = err
		w.mu.Unlock()
		close(w.failed)
	})
}
func (w *cordisWorker) read(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 65536)
	for scanner.Scan() {
		var reply cordisReply
		if err := json.Unmarshal(scanner.Bytes(), &reply); err != nil || reply.Protocol != w.protocol || reply.ID == "" {
			w.fail(fmt.Errorf("invalid Cordis control response: json=%v protocol=%q id=%q", err, reply.Protocol, reply.ID))
			w.abort()
			return
		}
		if w.protocol == cordisLifecycleProtocol {
			if reply.Incarnation != w.incarnation {
				w.fail(errors.New("invalid host incarnation"))
				w.abort()
				return
			}
			if reply.Kind == "request" && strings.HasPrefix(reply.ID, "node/") && w.onRequest != nil {
				data := append([]byte(nil), scanner.Bytes()...)
				go w.onRequest(w, data) // never block read loop on Apply/dispose/RPC
				continue
			}
			if reply.Kind != "response" || !strings.HasPrefix(reply.ID, "go/") {
				w.fail(errors.New("invalid duplex ID namespace/kind"))
				w.abort()
				return
			}
		}
		w.mu.Lock()
		ch := w.pending[reply.ID]
		w.mu.Unlock()
		if ch != nil {
			select {
			case ch <- reply:
			default:
			}
		}
	}
	if err := scanner.Err(); err != nil {
		w.fail(err)
	} else {
		w.fail(io.EOF)
	}
}
func (w *cordisWorker) control(op string, fields map[string]any, out *cordisReply) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	w.mu.Lock()
	w.next++
	id := strconv.FormatUint(w.next, 10)
	if w.protocol == cordisLifecycleProtocol {
		id = "go/" + id
	}
	ch := make(chan cordisReply, 1)
	w.pending[id] = ch
	w.mu.Unlock()
	defer func() { w.mu.Lock(); delete(w.pending, id); w.mu.Unlock() }()
	req := map[string]any{"id": id, "op": op, "protocol": w.protocol}
	if w.protocol == cordisLifecycleProtocol {
		req["kind"] = "request"
		req["incarnation"] = w.incarnation
	}
	for k, v := range fields {
		req[k] = v
	}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if len(data) > 65535 {
		return errors.New("Cordis control message too large")
	}
	// A stuck pipe must not make the bounded control request unbounded.
	stopKill := context.AfterFunc(ctx, w.abort)
	defer stopKill()
	w.writeMu.Lock()
	_, err = w.input.Write(append(data, '\n'))
	w.writeMu.Unlock()
	if err != nil {
		return fmt.Errorf("Cordis %s write: %w", op, err)
	}
	select {
	case reply := <-ch:
		if !reply.OK {
			return fmt.Errorf("Cordis %s: %s", op, reply.Error)
		}
		if out != nil {
			*out = reply
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("Cordis %s acknowledgement unknown: %w", op, ctx.Err())
	case <-w.failed:
		// Prefer an already-buffered final response over normal EOF after shutdown.
		select {
		case reply := <-ch:
			if reply.OK {
				if out != nil {
					*out = reply
				}
				return nil
			}
		default:
		}
		w.mu.Lock()
		err = w.failure
		w.mu.Unlock()
		return fmt.Errorf("Cordis %s acknowledgement unknown: %w; stderr=%s", op, err, w.stderr.String())
	}
}

// Bounded diagnostics: startup/module errors must not disappear into EOF.
type cordisStderr struct {
	mu   sync.Mutex
	data []byte
}

func (b *cordisStderr) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if len(b.data) < 8192 {
		take := 8192 - len(b.data)
		if take > len(p) {
			take = len(p)
		}
		b.data = append(b.data, p[:take]...)
	}
	return n, nil
}
func (b *cordisStderr) String() string { b.mu.Lock(); defer b.mu.Unlock(); return string(b.data) }

// AnalyzerHostSnapshot is transient diagnostic state, not a config writer.
type AnalyzerHostSnapshot struct {
	Backend     string               `json:"backend"`
	Incarnation string               `json:"incarnation"`
	Leases      int                  `json:"leases"`
	Mutating    bool                 `json:"mutating"`
	Tasks       []AnalyzerTaskRecord `json:"tasks"`
}

func (h *CordisAnalyzerHost) Snapshot() *AnalyzerHostSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := &AnalyzerHostSnapshot{Backend: "cordis3-candidate", Incarnation: h.incarnation, Leases: h.leases, Mutating: h.mutating, Tasks: append([]AnalyzerTaskRecord(nil), h.tasks...)}
	for i := range out.Tasks {
		out.Tasks[i].Output = nil
	}
	return out
}
