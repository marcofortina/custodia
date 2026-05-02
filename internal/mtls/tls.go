package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func ServerTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	return ServerTLSConfigWithClientCRL(certFile, keyFile, clientCAFile, "")
}

func ServerTLSConfigWithClientCRL(certFile, keyFile, clientCAFile, clientCRLFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("client CA file does not contain a valid PEM certificate")
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	if clientCRLFile != "" {
		revoked, err := LoadRevokedClientSerials(clientCRLFile, caPEM)
		if err != nil {
			return nil, err
		}
		tlsConfig.VerifyPeerCertificate = revokedClientVerifier(revoked)
	}
	return tlsConfig, nil
}

func ClientTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read server CA: %w", err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("server CA file does not contain a valid PEM certificate")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAs,
	}, nil
}
