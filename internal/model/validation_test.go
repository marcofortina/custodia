package model

import "testing"

func TestValidClientID(t *testing.T) {
	for _, value := range []string{"client_alice", "tenant-1.client:prod", "A09"} {
		if !ValidClientID(value) {
			t.Fatalf("expected %q to be valid", value)
		}
	}
	for _, value := range []string{"", "client alice", "client/alice", "client\n"} {
		if ValidClientID(value) {
			t.Fatalf("expected %q to be invalid", value)
		}
	}
}
