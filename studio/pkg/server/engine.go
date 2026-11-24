package server

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"

	"pktpath/studio/pkg/export"
	"pktpath/studio/pkg/reconstruct"
)

// engine bridges the pure-Go reconstruction/export engine (owned by
// studio-engine) so the rest of the server stays decoupled from its types.

type loadedSession struct {
	sess     *reconstruct.Session
	overview json.RawMessage
	samples  int
}

func engineLoad(id, dir string) (*loadedSession, error) {
	s, err := reconstruct.Open(dir)
	if err != nil {
		return nil, err
	}
	ov := reconstruct.BuildOverview(s)
	n := countSamples(ov)
	raw, err := marshalOverviewWithPath(ov, id, dir)
	if err != nil {
		return nil, err
	}
	return &loadedSession{sess: s, overview: raw, samples: n}, nil
}

func marshalOverviewWithPath(ov any, id, dir string) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ov); err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(buf.Bytes())
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return json.RawMessage(trimmed), nil
	}
	meta, _ := json.Marshal(struct {
		SessionID   string `json:"session_id"`
		SessionPath string `json:"session_path"`
	}{SessionID: id, SessionPath: dir})
	// Prepend {"session_id":...,"session_path":..., to existing object fields.
	inner := bytes.TrimSpace(trimmed[1 : len(trimmed)-1])
	var out bytes.Buffer
	out.Grow(len(meta) + len(trimmed) + 2)
	out.Write(meta[:len(meta)-1])
	if len(inner) > 0 {
		out.WriteByte(',')
		out.Write(inner)
	}
	out.WriteByte('}')
	return json.RawMessage(out.Bytes()), nil
}

func engineSample(ls *loadedSession, sampleID uint64) (any, error) {
	return reconstruct.BuildSampleDetail(ls.sess, sampleID)
}

func enginePcapngBytes(ls *loadedSession, redact bool, key string) ([]byte, int, error) {
	var buf bytes.Buffer
	n, err := export.WritePcapng(ls.sess, io.Writer(&buf), redact, key)
	return buf.Bytes(), n, err
}

func engineExportFile(dir, out string, redact bool, key string) (int, error) {
	return export.ExportPcapng(dir, out, redact, key)
}

func engineRedact(in, out, key string) error {
	return export.RedactSession(in, out, key)
}

// countSamples reads len(overview.Samples) without hard-coding the struct type.
func countSamples(ov any) int {
	v := reflect.ValueOf(ov)
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return 0
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return 0
	}
	f := v.FieldByName("Samples")
	if f.IsValid() && (f.Kind() == reflect.Slice || f.Kind() == reflect.Array) {
		return f.Len()
	}
	return 0
}
