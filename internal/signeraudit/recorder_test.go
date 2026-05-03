package signeraudit

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestJSONLRecorderWritesEvent(t *testing.T) {
	path := t.TempDir() + "/signer-audit.jsonl"
	recorder, err := NewJSONLRecorder(path)
	if err != nil {
		t.Fatalf("NewJSONLRecorder() error = %v", err)
	}
	defer recorder.Close()
	if err := recorder.Record(Event{Action: "certificate.sign", Outcome: "success", Actor: "admin", ClientID: "client_alice", RequestID: "trace-1"}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.HasSuffix(payload, []byte("\n")) {
		t.Fatalf("expected JSONL newline, got %q", string(payload))
	}
	var event Event
	if err := json.Unmarshal(bytes.TrimSpace(payload), &event); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if event.Action != "certificate.sign" || event.Outcome != "success" || event.RequestID != "trace-1" {
		t.Fatalf("unexpected event: %+v", event)
	}
	if event.OccurredAt.IsZero() {
		t.Fatal("expected occurred_at to be set")
	}
}
