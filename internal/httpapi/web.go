// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package httpapi

import (
	"context"
	"custodia/internal/audit"
	"custodia/internal/build"
	"custodia/internal/model"
	"custodia/internal/webauth"
	"encoding/base64"
	"encoding/json"

	"html"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// handleWebLogin unlocks only the metadata console; it never receives or displays secret plaintext.
func (s *Server) handleWebLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		body := "<h1>Web MFA</h1>" +
			webParagraph("Enter your TOTP code to unlock the metadata console for this mTLS admin session.") +
			`<form method="post" action="/web/login"><label for="totp">TOTP code</label><input id="totp" name="totp" inputmode="numeric" autocomplete="one-time-code" required><button type="submit">Unlock console</button></form>`
		writeWebLoginPage(w, "Web MFA", body)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if s.webSessionManager == nil || strings.TrimSpace(s.webTOTPSecret) == "" {
		s.auditFailure(r, "web.login", "system", "", map[string]string{"reason": "mfa_not_configured"})
		writeError(w, http.StatusServiceUnavailable, "mfa_not_configured")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.auditFailure(r, "web.login", "system", "", map[string]string{"reason": "invalid_form"})
		writeError(w, http.StatusBadRequest, "invalid_form")
		return
	}
	code := r.FormValue("totp")
	if !webauth.VerifyTOTP(s.webTOTPSecret, code, time.Now().UTC(), 1) {
		s.auditFailure(r, "web.login", "system", "", map[string]string{"reason": "invalid_totp"})
		writeError(w, http.StatusUnauthorized, "invalid_totp")
		return
	}
	clientID := clientIDFromContext(r)
	token, expires := s.webSessionManager.Issue(clientID, time.Now().UTC())
	w.Header().Add("Set-Cookie", webauth.CookieHeaderValue(token, expires, s.webSessionSecure))
	s.audit(r, "web.login", "system", "", "success", nil)
	http.Redirect(w, r, "/web/", http.StatusSeeOther)
}

func (s *Server) handleWebLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Set-Cookie", webauth.ExpiredCookieHeaderValue(s.webSessionSecure))
	s.audit(r, "web.logout", "system", "", "success", nil)
	http.Redirect(w, r, "/web/login", http.StatusSeeOther)
}

func writeWebLoginPage(w http.ResponseWriter, title string, body string) {
	writeWebPageWithOptions(w, title, body, false)
}

func writeWebPage(w http.ResponseWriter, title string, body string) {
	writeWebPageWithOptions(w, title, body, true)
}

func writeWebPageWithOptions(w http.ResponseWriter, title string, body string, authenticatedNav bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	nav := `<p class="console-kicker">Admin metadata console</p>`
	if authenticatedNav {
		nav = `<header class="console-topbar">
<a class="console-brand" href="/web/" aria-label="Custodia overview"><span class="console-brand-mark" aria-hidden="true">C</span><span>Custodia</span></a>
<nav class="console-nav" aria-label="Console navigation">
<a href="/web/">Overview</a>
<a href="/web/status">Status</a>
<a href="/web/diagnostics">Diagnostics</a>
<a href="/web/clients">Clients</a>
<a href="/web/access-requests">Access requests</a>
<a href="/web/audit">Audit</a>
<a href="/web/audit/verify">Verify audit</a>
</nav>
<form class="console-logout" method="post" action="/web/logout"><button type="submit">Logout</button></form>
</header>`
	}
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + html.EscapeString(title) + ` – Custodia</title>
<style>` + webConsoleCSS + `</style>
</head>
<body>
<div class="console-shell">
` + nav + `
<main class="console-card">
` + body + `
</main>
</div>
</body>
</html>`))
}

const webConsoleCSS = `
:root {
  color-scheme: light dark;
  --bg: #f5f7fb;
  --surface: #ffffff;
  --surface-soft: #f8fafc;
  --border: #d8dee8;
  --text: #111827;
  --muted: #5b6472;
  --accent: #2354d5;
  --accent-strong: #173ea5;
  --danger: #b42318;
  --shadow: 0 18px 45px rgba(15, 23, 42, 0.10);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f172a;
    --surface: #111827;
    --surface-soft: #182235;
    --border: #334155;
    --text: #f8fafc;
    --muted: #a6b0c0;
    --accent: #7aa2ff;
    --accent-strong: #adc4ff;
    --danger: #ffb4a8;
    --shadow: 0 18px 45px rgba(0, 0, 0, 0.35);
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background: radial-gradient(circle at top left, rgba(35, 84, 213, 0.14), transparent 34rem), var(--bg);
  color: var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.5;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.console-shell { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 24px 0 48px; }
.console-topbar {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
  margin-bottom: 18px;
  padding: 14px;
  border: 1px solid var(--border);
  border-radius: 20px;
  background: color-mix(in srgb, var(--surface) 92%, transparent);
  box-shadow: var(--shadow);
}
.console-brand { display: inline-flex; align-items: center; gap: 10px; color: var(--text); font-weight: 800; letter-spacing: -0.02em; }
.console-brand-mark { display: grid; place-items: center; width: 32px; height: 32px; border-radius: 10px; background: var(--accent); color: white; }
.console-nav { display: flex; align-items: center; gap: 6px; flex: 1 1 480px; flex-wrap: wrap; }
.console-nav a { padding: 8px 10px; border-radius: 10px; color: var(--muted); font-weight: 650; }
.console-nav a:hover { background: var(--surface-soft); color: var(--text); text-decoration: none; }
.console-logout { margin: 0; }
.console-card { padding: 28px; border: 1px solid var(--border); border-radius: 24px; background: var(--surface); box-shadow: var(--shadow); overflow-x: auto; }
.console-kicker { margin: 0 0 12px; color: var(--muted); font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; }
h1 { margin: 0 0 12px; font-size: clamp(1.9rem, 4vw, 3rem); line-height: 1.05; letter-spacing: -0.04em; }
h2 { margin-top: 28px; }
p { color: var(--muted); max-width: 78ch; }
form { display: grid; gap: 10px; max-width: 420px; margin-top: 18px; }
label { color: var(--muted); font-weight: 700; }
input { width: 100%; padding: 11px 12px; border: 1px solid var(--border); border-radius: 12px; background: var(--surface-soft); color: var(--text); font: inherit; }
button { display: inline-flex; justify-content: center; align-items: center; min-height: 38px; padding: 8px 14px; border: 0; border-radius: 12px; background: var(--accent); color: white; font: inherit; font-weight: 800; cursor: pointer; }
button:hover { background: var(--accent-strong); }
.console-logout button { background: transparent; color: var(--danger); border: 1px solid var(--border); }
.console-logout button:hover { background: color-mix(in srgb, var(--danger) 11%, transparent); }
table { width: 100%; min-width: 680px; border-collapse: collapse; margin-top: 18px; overflow: hidden; border-radius: 16px; border: 1px solid var(--border); }
th, td { padding: 12px 14px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }
th { background: var(--surface-soft); color: var(--muted); font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.05em; }
tr:last-child td { border-bottom: 0; }
dl { display: grid; grid-template-columns: minmax(180px, 260px) 1fr; gap: 0; border: 1px solid var(--border); border-radius: 16px; overflow: hidden; }
dt, dd { margin: 0; padding: 12px 14px; border-bottom: 1px solid var(--border); }
dt { background: var(--surface-soft); color: var(--muted); font-weight: 800; }
dd { overflow-wrap: anywhere; }
dt:last-of-type, dd:last-of-type { border-bottom: 0; }
pre { padding: 16px; border: 1px solid var(--border); border-radius: 16px; background: var(--surface-soft); overflow: auto; }
@media (max-width: 720px) {
  .console-shell { width: min(100% - 20px, 1180px); padding-top: 10px; }
  .console-card { padding: 18px; }
  .console-nav { flex-basis: 100%; }
  dl { grid-template-columns: 1fr; }
}
`

func webParagraph(text string) string {
	return "<p>" + html.EscapeString(text) + "</p>"
}

func (s *Server) webOptionalLimit(w http.ResponseWriter, r *http.Request, action, resourceType, resourceID string, fallback int) (int, bool) {
	limit := fallback
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 || parsed > 500 {
			s.auditFailure(r, action, resourceType, resourceID, map[string]string{"reason": "invalid_limit"})
			writeError(w, http.StatusBadRequest, "invalid_limit")
			return 0, false
		}
		limit = parsed
	}
	return limit, true
}

type passkeyVerifyRequest struct {
	ClientDataJSON    string `json:"client_data_json"`
	CredentialID      string `json:"credential_id"`
	AuthenticatorData string `json:"authenticator_data"`
	CredentialKeyCOSE string `json:"credential_key_cose"`
	Signature         string `json:"signature"`
}

type passkeyVerifyResponse struct {
	Status                  string `json:"status"`
	Challenge               string `json:"challenge"`
	Origin                  string `json:"origin"`
	Type                    string `json:"type"`
	CredentialID            string `json:"credential_id,omitempty"`
	SignCount               uint32 `json:"sign_count,omitempty"`
	CredentialKeyCOSEStored bool   `json:"credential_key_cose_stored"`
}

func (s *Server) handleWebPasskeyRegisterVerify(w http.ResponseWriter, r *http.Request) {
	s.handleWebPasskeyVerify(w, r, "register", "webauthn.create", "web.passkey_register_verify")
}

func (s *Server) handleWebPasskeyAuthenticateVerify(w http.ResponseWriter, r *http.Request) {
	s.handleWebPasskeyVerify(w, r, "authenticate", "webauthn.get", "web.passkey_authenticate_verify")
}

func (s *Server) handleWebPasskeyVerify(w http.ResponseWriter, r *http.Request, purpose, clientDataType, action string) {
	if !s.webPasskeyEnabled {
		writeError(w, http.StatusNotFound, "passkey_disabled")
		return
	}
	var payload passkeyVerifyRequest
	if !decodeJSON(w, r, &payload) {
		return
	}
	rawClientData, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(payload.ClientDataJSON))
	if err != nil {
		s.auditFailure(r, action, "system", "", map[string]string{"reason": "invalid_client_data_json"})
		writeError(w, http.StatusBadRequest, "invalid_client_data_json")
		return
	}
	var clientData webauth.PasskeyClientData
	if err := json.Unmarshal(rawClientData, &clientData); err != nil || strings.TrimSpace(clientData.Challenge) == "" {
		s.auditFailure(r, action, "system", "", map[string]string{"reason": "invalid_client_data"})
		writeError(w, http.StatusBadRequest, "invalid_client_data")
		return
	}
	clientID := clientIDFromContext(r)
	record, err := s.webPasskeyChallenges.Consume(clientData.Challenge, clientID, purpose, time.Now().UTC())
	if err != nil {
		s.auditFailure(r, action, "system", "", map[string]string{"reason": "invalid_or_replayed_challenge"})
		writeError(w, http.StatusUnauthorized, "invalid_or_replayed_challenge")
		return
	}
	verified, err := webauth.VerifyPasskeyClientDataJSON(rawClientData, clientDataType, record.Challenge, s.expectedPasskeyOrigin(r))
	if err != nil {
		s.auditFailure(r, action, "system", "", map[string]string{"reason": "invalid_client_data"})
		writeError(w, http.StatusUnauthorized, "invalid_client_data")
		return
	}
	credentialID := strings.TrimSpace(payload.CredentialID)
	var authenticatorData *webauth.PasskeyAuthenticatorData
	if strings.TrimSpace(payload.AuthenticatorData) != "" {
		var err error
		authenticatorData, err = webauth.ParsePasskeyAuthenticatorDataBase64URL(strings.TrimSpace(payload.AuthenticatorData))
		if err != nil {
			s.auditFailure(r, action, "system", "", map[string]string{"reason": "invalid_authenticator_data"})
			writeError(w, http.StatusBadRequest, "invalid_authenticator_data")
			return
		}
		if err := webauth.ValidatePasskeyAuthenticatorData(authenticatorData, s.webPasskeyRPID, true); err != nil {
			s.auditFailure(r, action, "system", "", map[string]string{"reason": "invalid_authenticator_data"})
			writeError(w, http.StatusUnauthorized, "invalid_authenticator_data")
			return
		}
	}
	signCount := uint32(0)
	if authenticatorData != nil {
		signCount = authenticatorData.SignCount
	}
	credentialKeyCOSEStored := false
	if purpose == "register" {
		if credentialID == "" {
			s.auditFailure(r, action, "system", "", map[string]string{"reason": "missing_credential_id"})
			writeError(w, http.StatusBadRequest, "missing_credential_id")
			return
		}
		credentialKeyCOSE, err := decodePasskeyCredentialKeyCOSE(payload.CredentialKeyCOSE)
		if err != nil {
			s.auditFailure(r, action, "system", "", map[string]string{"reason": "invalid_credential_key_cose"})
			writeError(w, http.StatusBadRequest, "invalid_credential_key_cose")
			return
		}
		credentialKeyCOSEStored = true
		if !s.webPasskeyCredentials.Register(webauth.PasskeyCredentialRecord{CredentialID: credentialID, ClientID: clientID, CreatedAt: time.Now().UTC(), SignCount: signCount, CredentialKeyCOSE: credentialKeyCOSE}) {
			s.auditFailure(r, action, "system", "", map[string]string{"reason": "invalid_credential"})
			writeError(w, http.StatusBadRequest, "invalid_credential")
			return
		}
	} else {
		if credentialID == "" {
			s.auditFailure(r, action, "system", "", map[string]string{"reason": "missing_credential_id"})
			writeError(w, http.StatusBadRequest, "missing_credential_id")
			return
		}
		record, err := s.webPasskeyCredentials.Get(credentialID, clientID)
		if err != nil {
			s.auditFailure(r, action, "system", "", map[string]string{"reason": "unknown_credential"})
			writeError(w, http.StatusUnauthorized, "unknown_credential")
			return
		}
		if len(record.CredentialKeyCOSE) == 0 {
			s.auditFailure(r, action, "system", "", map[string]string{"reason": "missing_credential_key_cose"})
			writeError(w, http.StatusUnauthorized, "missing_credential_key_cose")
			return
		}
		credentialKeyCOSEStored = true
		if strings.TrimSpace(s.webPasskeyAssertionVerifyCommand) != "" {
			if authenticatorData == nil || strings.TrimSpace(payload.Signature) == "" {
				s.auditFailure(r, action, "system", "", map[string]string{"reason": "missing_assertion_signature_material"})
				writeError(w, http.StatusUnauthorized, "missing_assertion_signature_material")
				return
			}
			if err := webauth.VerifyPasskeyAssertionWithCommand(r.Context(), s.webPasskeyAssertionVerifyCommand, webauth.PasskeyAssertionVerificationRequest{
				CredentialID:      credentialID,
				ClientID:          clientID,
				RPID:              s.webPasskeyRPID,
				Origin:            verified.Origin,
				Type:              verified.Type,
				ClientDataJSON:    strings.TrimSpace(payload.ClientDataJSON),
				AuthenticatorData: strings.TrimSpace(payload.AuthenticatorData),
				Signature:         strings.TrimSpace(payload.Signature),
				CredentialKeyCOSE: base64.RawURLEncoding.EncodeToString(record.CredentialKeyCOSE),
				SignCount:         signCount,
			}); err != nil {
				s.auditFailure(r, action, "system", "", map[string]string{"reason": "invalid_assertion_signature"})
				writeError(w, http.StatusUnauthorized, "invalid_assertion_signature")
				return
			}
		}
		if authenticatorData != nil {
			if _, err := s.webPasskeyCredentials.TouchWithSignCount(credentialID, clientID, authenticatorData.SignCount, time.Now().UTC()); err != nil {
				s.auditFailure(r, action, "system", "", map[string]string{"reason": "invalid_sign_count"})
				writeError(w, http.StatusUnauthorized, "invalid_sign_count")
				return
			}
		} else if _, err := s.webPasskeyCredentials.Touch(credentialID, clientID, time.Now().UTC()); err != nil {
			s.auditFailure(r, action, "system", "", map[string]string{"reason": "unknown_credential"})
			writeError(w, http.StatusUnauthorized, "unknown_credential")
			return
		}
	}
	s.audit(r, action, "system", "", "success", nil)
	writeJSON(w, http.StatusOK, passkeyVerifyResponse{Status: "verified_challenge", Challenge: verified.Challenge, Origin: verified.Origin, Type: verified.Type, CredentialID: credentialID, SignCount: signCount, CredentialKeyCOSEStored: credentialKeyCOSEStored})
}

func decodePasskeyCredentialKeyCOSE(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, webauth.ErrPasskeyCredentialCredentialKeyMissing
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > 4096 {
		return nil, webauth.ErrPasskeyCredentialCredentialKeyMissing
	}
	if _, err := webauth.ParsePasskeyCredentialKeyCOSE(decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func passkeyAssertionVerifierStatus(command string) string {
	if strings.TrimSpace(command) == "" {
		return "preverify_only"
	}
	return "external_command"
}

func (s *Server) expectedPasskeyOrigin(r *http.Request) string {
	scheme := "https"
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		scheme = forwarded
	} else if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

func (s *Server) handleWebPasskeyRegisterOptions(w http.ResponseWriter, r *http.Request) {
	if !s.webPasskeyEnabled {
		writeError(w, http.StatusNotFound, "passkey_disabled")
		return
	}
	clientID := clientIDFromContext(r)
	options, err := webauth.NewPasskeyOptions(s.webPasskeyRPID, s.webPasskeyRPName, clientID, clientID, s.webPasskeyChallengeTTL, true)
	if err != nil {
		s.auditFailure(r, "web.passkey_register_options", "system", "", map[string]string{"reason": "invalid_passkey_config"})
		writeError(w, http.StatusServiceUnavailable, "invalid_passkey_config")
		return
	}
	s.webPasskeyChallenges.Prune(time.Now().UTC())
	s.webPasskeyChallenges.Store(webauth.PasskeyChallengeRecord{Challenge: options.Challenge, ClientID: clientID, Purpose: "register", ExpiresAt: time.Now().UTC().Add(s.webPasskeyChallengeTTL)})
	s.audit(r, "web.passkey_register_options", "system", "", "success", nil)
	writeJSON(w, http.StatusOK, options)
}

func (s *Server) handleWebPasskeyAuthenticateOptions(w http.ResponseWriter, r *http.Request) {
	if !s.webPasskeyEnabled {
		writeError(w, http.StatusNotFound, "passkey_disabled")
		return
	}
	clientID := clientIDFromContext(r)
	options, err := webauth.NewPasskeyOptions(s.webPasskeyRPID, s.webPasskeyRPName, clientID, clientID, s.webPasskeyChallengeTTL, false)
	if err != nil {
		s.auditFailure(r, "web.passkey_authenticate_options", "system", "", map[string]string{"reason": "invalid_passkey_config"})
		writeError(w, http.StatusServiceUnavailable, "invalid_passkey_config")
		return
	}
	s.webPasskeyChallenges.Prune(time.Now().UTC())
	s.webPasskeyChallenges.Store(webauth.PasskeyChallengeRecord{Challenge: options.Challenge, ClientID: clientID, Purpose: "authenticate", ExpiresAt: time.Now().UTC().Add(s.webPasskeyChallengeTTL)})
	s.audit(r, "web.passkey_authenticate_options", "system", "", "success", nil)
	writeJSON(w, http.StatusOK, options)
}

// handleWebStatus renders operational metadata for the admin console without exposing secret payload material.
func (s *Server) handleWebStatus(w http.ResponseWriter, r *http.Request) {
	storeStatus := "ok"
	if err := s.store.Health(r.Context()); err != nil {
		storeStatus = "unavailable"
	}
	rateLimiterStatus := "ok"
	if checker, ok := s.limiter.(interface{ Health(context.Context) error }); ok {
		if err := checker.Health(r.Context()); err != nil {
			rateLimiterStatus = "unavailable"
		}
	}
	info := build.Current()
	body := "<h1>Operational status</h1>" +
		"<dl>" +
		"<dt>Status</dt><dd>" + html.EscapeString(statusOutcome(storeStatus, rateLimiterStatus)) + "</dd>" +
		"<dt>Store</dt><dd>" + html.EscapeString(storeStatus) + " (" + html.EscapeString(s.storeBackend) + ")</dd>" +
		"<dt>Rate limiter</dt><dd>" + html.EscapeString(rateLimiterStatus) + " (" + html.EscapeString(s.rateLimitBackend) + ")</dd>" +
		"<dt>Max envelopes per secret</dt><dd>" + html.EscapeString(strconv.Itoa(s.maxEnvelopesPerSecret)) + "</dd>" +
		"<dt>Build version</dt><dd>" + html.EscapeString(info.Version) + "</dd>" +
		"<dt>Build commit</dt><dd>" + html.EscapeString(info.Commit) + "</dd>" +
		"<dt>Web MFA required</dt><dd>" + html.EscapeString(strconv.FormatBool(s.webMFARequired)) + "</dd>" +
		"<dt>Web passkey enabled</dt><dd>" + html.EscapeString(strconv.FormatBool(s.webPasskeyEnabled)) + "</dd>" +
		"</dl>"
	s.audit(r, "web.status", "system", "", statusOutcome(storeStatus, rateLimiterStatus), nil)
	writeWebPage(w, "Operational status", body)
}

func (s *Server) handleWebDiagnostics(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	body := "<h1>Runtime diagnostics</h1>" +
		"<p>Operational runtime metadata only; secret payloads are never rendered.</p>" +
		"<dl>" +
		"<dt>Started at</dt><dd>" + html.EscapeString(s.startedAt.Format(time.RFC3339)) + "</dd>" +
		"<dt>Uptime seconds</dt><dd>" + html.EscapeString(strconv.FormatInt(int64(time.Since(s.startedAt).Seconds()), 10)) + "</dd>" +
		"<dt>Goroutines</dt><dd>" + html.EscapeString(strconv.Itoa(runtime.NumGoroutine())) + "</dd>" +
		"<dt>Alloc bytes</dt><dd>" + html.EscapeString(strconv.FormatUint(mem.Alloc, 10)) + "</dd>" +
		"</dl>"
	s.audit(r, "web.diagnostics", "system", "", "success", nil)
	writeWebPage(w, "Runtime diagnostics", body)
}

func statusOutcome(storeStatus, rateLimiterStatus string) string {
	if storeStatus != "ok" || rateLimiterStatus != "ok" {
		return "degraded"
	}
	return "success"
}

func (s *Server) handleWebClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.store.ListClients(r.Context())
	if err != nil {
		s.auditStoreFailure(r, "web.client_list", "client", "", err)
		writeMappedError(w, err)
		return
	}
	if rawActive := strings.TrimSpace(r.URL.Query().Get("active")); rawActive != "" {
		active, ok := parseBoolQuery(rawActive)
		if !ok {
			s.auditFailure(r, "web.client_list", "client", "", map[string]string{"reason": "invalid_active_filter"})
			writeError(w, http.StatusBadRequest, "invalid_active_filter")
			return
		}
		filtered := clients[:0]
		for _, client := range clients {
			if client.IsActive == active {
				filtered = append(filtered, client)
			}
		}
		clients = filtered
	}
	rows := ""
	for _, client := range clients {
		state := "active"
		if !client.IsActive {
			state = "revoked"
		}
		rows += "<tr><td>" + html.EscapeString(client.ClientID) + "</td><td>" + html.EscapeString(client.MTLSSubject) + "</td><td>" + html.EscapeString(state) + "</td></tr>"
	}
	if rows == "" {
		rows = `<tr><td colspan="3">No clients found.</td></tr>`
	}
	body := "<h1>Clients</h1><table><thead><tr><th>Client ID</th><th>mTLS subject</th><th>Status</th></tr></thead><tbody>" + rows + "</tbody></table>"
	s.audit(r, "web.client_list", "client", "", "success", nil)
	writeWebPage(w, "Clients", body)
}

func (s *Server) handleWebAudit(w http.ResponseWriter, r *http.Request) {
	limit, ok := s.webOptionalLimit(w, r, "web.audit_list", "audit_event", "", 100)
	if !ok {
		return
	}
	events, err := s.store.ListAuditEvents(r.Context(), limit)
	if err != nil {
		s.auditStoreFailure(r, "web.audit_list", "audit_event", "", err)
		writeMappedError(w, err)
		return
	}
	filtered, ok := s.filterAuditEventsForRequest(w, r, "web.audit_list", events)
	if !ok {
		return
	}
	events = filtered
	rows := ""
	for _, event := range events {
		rows += "<tr><td>" + html.EscapeString(event.OccurredAt.Format(time.RFC3339)) + "</td><td>" + html.EscapeString(event.Action) + "</td><td>" + html.EscapeString(event.ActorClientID) + "</td><td>" + html.EscapeString(event.Outcome) + "</td></tr>"
	}
	if rows == "" {
		rows = `<tr><td colspan="4">No audit events found.</td></tr>`
	}
	body := "<h1>Audit events</h1><p>Latest 100 events. Export remains available as JSONL from the API.</p><table><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Outcome</th></tr></thead><tbody>" + rows + "</tbody></table>"
	s.audit(r, "web.audit_list", "audit_event", "", "success", nil)
	writeWebPage(w, "Audit events", body)
}

func (s *Server) handleWebAccessRequests(w http.ResponseWriter, r *http.Request) {
	limit, ok := s.webOptionalLimit(w, r, "web.access_request_list", "secret", "", 100)
	if !ok {
		return
	}
	secretID := strings.TrimSpace(r.URL.Query().Get("secret_id"))
	if secretID != "" && !model.ValidUUIDID(secretID) {
		s.auditFailure(r, "web.access_request_list", "secret", secretID, map[string]string{"reason": "invalid_secret_id_filter"})
		writeError(w, http.StatusBadRequest, "invalid_secret_id_filter")
		return
	}
	requests, err := s.store.ListAccessGrantRequests(r.Context(), secretID)
	if err != nil {
		s.auditStoreFailure(r, "web.access_request_list", "secret", "", err)
		writeMappedError(w, err)
		return
	}
	if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" {
		if !model.ValidAccessRequestStatus(status) {
			s.auditFailure(r, "web.access_request_list", "secret", "", map[string]string{"reason": "invalid_status_filter"})
			writeError(w, http.StatusBadRequest, "invalid_status_filter")
			return
		}
		filtered := requests[:0]
		for _, request := range requests {
			if request.Status == status {
				filtered = append(filtered, request)
			}
		}
		requests = filtered
	}
	if targetClientID := strings.TrimSpace(r.URL.Query().Get("client_id")); targetClientID != "" {
		if !model.ValidClientID(targetClientID) {
			s.auditFailure(r, "web.access_request_list", "secret", secretID, map[string]string{"reason": "invalid_client_id_filter"})
			writeError(w, http.StatusBadRequest, "invalid_client_id_filter")
			return
		}
		filtered := requests[:0]
		for _, request := range requests {
			if request.ClientID == targetClientID {
				filtered = append(filtered, request)
			}
		}
		requests = filtered
	}
	if requestedBy := strings.TrimSpace(r.URL.Query().Get("requested_by_client_id")); requestedBy != "" {
		if !model.ValidClientID(requestedBy) {
			s.auditFailure(r, "web.access_request_list", "secret", secretID, map[string]string{"reason": "invalid_requested_by_filter"})
			writeError(w, http.StatusBadRequest, "invalid_requested_by_filter")
			return
		}
		filtered := requests[:0]
		for _, request := range requests {
			if request.RequestedByClientID == requestedBy {
				filtered = append(filtered, request)
			}
		}
		requests = filtered
	}
	if len(requests) > limit {
		requests = requests[:limit]
	}
	rows := ""
	for _, request := range requests {
		rows += "<tr><td>" + html.EscapeString(request.SecretID) + "</td><td>" + html.EscapeString(request.VersionID) + "</td><td>" + html.EscapeString(request.ClientID) + "</td><td>" + html.EscapeString(request.RequestedByClientID) + "</td><td>" + html.EscapeString(request.Status) + "</td></tr>"
	}
	if rows == "" {
		rows = `<tr><td colspan="5">No access requests found.</td></tr>`
	}
	body := "<h1>Access requests</h1><p>Metadata-only pending grant workflow. Envelopes are never rendered here.</p><table><thead><tr><th>Secret</th><th>Version</th><th>Target client</th><th>Requested by</th><th>Status</th></tr></thead><tbody>" + rows + "</tbody></table>"
	s.audit(r, "web.access_request_list", "secret", "", "success", nil)
	writeWebPage(w, "Access requests", body)
}

func (s *Server) handleWebAuditVerify(w http.ResponseWriter, r *http.Request) {
	limit, ok := s.webOptionalLimit(w, r, "web.audit_verify", "audit_event", "", 500)
	if !ok {
		return
	}
	events, err := s.store.ListAuditEvents(r.Context(), limit)
	if err != nil {
		s.auditStoreFailure(r, "web.audit_verify", "audit_event", "", err)
		writeMappedError(w, err)
		return
	}
	result := audit.VerifyChain(events)
	outcome := "success"
	if !result.Valid {
		outcome = "failure"
	}
	body := "<h1>Audit chain verification</h1><dl>" +
		"<dt>Valid</dt><dd>" + html.EscapeString(strconv.FormatBool(result.Valid)) + "</dd>" +
		"<dt>Verified events</dt><dd>" + html.EscapeString(strconv.Itoa(result.VerifiedEvents)) + "</dd>" +
		"<dt>Failure index</dt><dd>" + html.EscapeString(strconv.Itoa(result.FailureIndex)) + "</dd>" +
		"</dl>"
	s.audit(r, "web.audit_verify", "audit_event", "", outcome, nil)
	writeWebPage(w, "Audit verification", body)
}
