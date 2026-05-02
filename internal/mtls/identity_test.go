package mtls

import (
	"crypto/x509"
	"net/url"
	"testing"

	"crypto/x509/pkix"
)

func TestClientIDFromCertificatePrefersSAN(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames: []string{"client_alice"},
		Subject:  pkix.Name{CommonName: "ignored"},
	}
	clientID, err := ClientIDFromCertificate(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clientID != "client_alice" {
		t.Fatalf("expected SAN client id, got %q", clientID)
	}
}

func TestClientIDFromCertificateFallsBackToURIAndCN(t *testing.T) {
	clientURI, _ := url.Parse("spiffe://custodia/client_bob")
	clientID, err := ClientIDFromCertificate(&x509.Certificate{URIs: []*url.URL{clientURI}})
	if err != nil || clientID != "spiffe://custodia/client_bob" {
		t.Fatalf("expected URI client id, got %q, err=%v", clientID, err)
	}

	clientID, err = ClientIDFromCertificate(&x509.Certificate{Subject: pkix.Name{CommonName: "client_charlie"}})
	if err != nil || clientID != "client_charlie" {
		t.Fatalf("expected CN client id, got %q, err=%v", clientID, err)
	}
}
