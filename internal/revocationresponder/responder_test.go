package revocationresponder

import (
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestCheckCRLReturnsRevoked(t *testing.T) {
	revokedAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	status, err := CheckCRL(&x509.RevocationList{
		ThisUpdate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NextUpdate: time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   big.NewInt(0xCAFE),
			RevocationTime: revokedAt,
		}},
	}, "0xCAFE")
	if err != nil {
		t.Fatalf("CheckCRL() error = %v", err)
	}
	if status.Status != StatusRevoked || status.RevokedAt == nil || !status.RevokedAt.Equal(revokedAt) {
		t.Fatalf("unexpected status: %+v", status)
	}
	if status.SerialHex != "cafe" || status.RevokedCount != 1 {
		t.Fatalf("unexpected metadata: %+v", status)
	}
}

func TestCheckCRLReturnsGood(t *testing.T) {
	status, err := CheckCRL(&x509.RevocationList{RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(1)}}}, "02")
	if err != nil {
		t.Fatalf("CheckCRL() error = %v", err)
	}
	if status.Status != StatusGood || status.RevokedAt != nil {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestCheckCRLRejectsInvalidSerial(t *testing.T) {
	_, err := CheckCRL(&x509.RevocationList{}, "not hex")
	if !errors.Is(err, ErrInvalidSerial) {
		t.Fatalf("CheckCRL() error = %v, want %v", err, ErrInvalidSerial)
	}
}
