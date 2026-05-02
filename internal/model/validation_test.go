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

func TestNormalizeSecretName(t *testing.T) {
	if got := NormalizeSecretName("  db password  "); got != "db password" {
		t.Fatalf("unexpected normalized secret name: %q", got)
	}
}

func TestValidSecretName(t *testing.T) {
	for _, value := range []string{"db password", "tenant/prod/api-key"} {
		if !ValidSecretName(value) {
			t.Fatalf("expected %q to be valid", value)
		}
	}
	for _, value := range []string{"", "   ", "secret\nname"} {
		if ValidSecretName(value) {
			t.Fatalf("expected %q to be invalid", value)
		}
	}
}

func TestValidCryptoMetadata(t *testing.T) {
	if !ValidCryptoMetadata(make([]byte, MaxCryptoMetadataBytes)) {
		t.Fatal("expected max-sized crypto metadata to be valid")
	}
	if ValidCryptoMetadata(make([]byte, MaxCryptoMetadataBytes+1)) {
		t.Fatal("expected oversized crypto metadata to be invalid")
	}
}

func TestValidMTLSSubject(t *testing.T) {
	for _, value := range []string{"client_alice", "spiffe://custodia/client/alice", "CN=client_alice"} {
		if !ValidMTLSSubject(value) {
			t.Fatalf("expected %q to be valid", value)
		}
	}
	for _, value := range []string{"", "   ", "client\nsubject"} {
		if ValidMTLSSubject(value) {
			t.Fatalf("expected %q to be invalid", value)
		}
	}
}
