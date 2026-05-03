package signeraudit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type Event struct {
	OccurredAt time.Time         `json:"occurred_at"`
	Action     string            `json:"action"`
	Outcome    string            `json:"outcome"`
	Actor      string            `json:"actor,omitempty"`
	ClientID   string            `json:"client_id,omitempty"`
	RequestID  string            `json:"request_id,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type Recorder interface {
	Record(Event) error
	Close() error
}

type NopRecorder struct{}

func (NopRecorder) Record(Event) error { return nil }
func (NopRecorder) Close() error       { return nil }

type JSONLRecorder struct {
	mu   sync.Mutex
	file *os.File
}

func NewJSONLRecorder(path string) (*JSONLRecorder, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &JSONLRecorder{file: file}, nil
}

func (r *JSONLRecorder) Record(event Event) error {
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := r.file.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return r.file.Sync()
}

func (r *JSONLRecorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.file.Close()
}
