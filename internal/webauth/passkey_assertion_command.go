package webauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"time"
)

var ErrPasskeyAssertionVerificationFailed = errors.New("passkey assertion verification failed")

type PasskeyAssertionVerificationRequest struct {
	CredentialID      string `json:"credential_id"`
	ClientID          string `json:"client_id"`
	RPID              string `json:"rp_id"`
	Origin            string `json:"origin"`
	Type              string `json:"type"`
	ClientDataJSON    string `json:"client_data_json"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
	CredentialKeyCOSE string `json:"credential_key_cose"`
	SignCount         uint32 `json:"sign_count"`
}

type passkeyAssertionVerificationResponse struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

func VerifyPasskeyAssertionWithCommand(ctx context.Context, command string, request PasskeyAssertionVerificationRequest) error {
	command = strings.TrimSpace(command)
	if command == "" || strings.TrimSpace(request.CredentialID) == "" || strings.TrimSpace(request.ClientID) == "" || strings.TrimSpace(request.ClientDataJSON) == "" || strings.TrimSpace(request.AuthenticatorData) == "" || strings.TrimSpace(request.Signature) == "" || strings.TrimSpace(request.CredentialKeyCOSE) == "" {
		return ErrPasskeyAssertionVerificationFailed
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(verifyCtx, command)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return ErrPasskeyAssertionVerificationFailed
	}
	var response passkeyAssertionVerificationResponse
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil || !response.Valid {
		return ErrPasskeyAssertionVerificationFailed
	}
	return nil
}
