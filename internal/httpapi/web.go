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
	"custodia/internal/mtls"
	"custodia/internal/revocationresponder"
	"custodia/internal/store"
	"custodia/internal/webauth"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"

	"html"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

//go:embed web_assets/console.js
var webConsoleJS string

//go:embed web_assets/console.css
var webConsoleCSS string

//go:embed web_assets/favicon.svg
var webConsoleFaviconSVG string

// handleWebLogin unlocks only the Custodia Console; it never receives or displays secret plaintext.
func (s *Server) handleWebLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		body := `<h1 id="auth-title">Verify Access</h1>` +
			webParagraph("Enter your TOTP code to unlock the Custodia Console for this mTLS admin session.") +
			`<form class="console-auth-form" method="post" action="/web/login"><label for="totp">TOTP code</label><input id="totp" name="totp" type="password" inputmode="numeric" autocomplete="one-time-code" required><div class="console-auth-actions"><button type="submit">Unlock console</button></div></form>`
		writeWebLoginPage(w, "Verify Access", body)
		return
	}
	if r.Method != http.MethodPost {
		writeWebStatusError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if s.webSessionManager == nil || strings.TrimSpace(s.webTOTPSecret) == "" {
		s.auditFailure(r, "web.login", "system", "", map[string]string{"reason": "mfa_not_configured"})
		writeWebStatusError(w, http.StatusServiceUnavailable, "mfa_not_configured")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.auditFailure(r, "web.login", "system", "", map[string]string{"reason": "invalid_form"})
		writeWebStatusError(w, http.StatusBadRequest, "invalid_form")
		return
	}
	code := r.FormValue("totp")
	if !webauth.VerifyTOTP(s.webTOTPSecret, code, time.Now().UTC(), 1) {
		s.auditFailure(r, "web.login", "system", "", map[string]string{"reason": "invalid_totp"})
		writeWebStatusError(w, http.StatusUnauthorized, "invalid_totp")
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
	setSecurityHeaders(w, true)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + html.EscapeString(title) + ` – Custodia</title>
<link rel="icon" href="/web/assets/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/web/assets/console.css">
</head>
<body>
<main id="console-main" class="console-auth-shell" tabindex="-1">
<section class="console-auth-card" aria-labelledby="auth-title">
<div class="console-brand"><span class="console-logo" aria-hidden="true">C</span><span>Custodia</span></div>
<p class="console-kicker">Custodia Console</p>
` + body + `
</section>
</main>
</body>
</html>`))
}

func writeWebPage(w http.ResponseWriter, title string, body string) {
	writeWebPageWithOptions(w, title, body, true)
}

func writeWebNotFoundPage(w http.ResponseWriter, authenticatedNav bool) {
	_ = authenticatedNav
	writeWebErrorPage(w, http.StatusNotFound, "Page not found", "The requested Custodia Console page does not exist.")
}

func writeWebStatusError(w http.ResponseWriter, statusCode int, code string) {
	writeWebErrorPage(w, statusCode, webErrorTitle(statusCode), webErrorDescription(statusCode, code))
}

func writeWebMappedError(w http.ResponseWriter, err error) {
	statusCode, code := mapStoreError(err)
	writeWebStatusError(w, statusCode, code)
}

func writeWebErrorPage(w http.ResponseWriter, statusCode int, title string, description string) {
	if title == "" {
		title = webErrorTitle(statusCode)
	}
	if description == "" {
		description = webErrorDescription(statusCode, "")
	}
	setSecurityHeaders(w, true)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + html.EscapeString(title) + ` – Custodia</title>
<link rel="icon" href="/web/assets/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/web/assets/console.css">
</head>
<body>
<main id="console-main" class="console-error-shell" tabindex="-1">
<section class="console-error-card" aria-labelledby="web-error-title" aria-label="` + html.EscapeString(title) + `">
<div class="console-brand"><span class="console-logo" aria-hidden="true">C</span><span>Custodia</span></div>
<p class="console-kicker">Custodia Console</p>
<h1 id="web-error-title">` + html.EscapeString(strconv.Itoa(statusCode)) + `</h1>
<p>` + html.EscapeString(description) + `</p>
<div class="console-error-actions"><a class="console-button" href="/web/">Back to home</a></div>
</section>
</main>
</body>
</html>`))
}

func webErrorTitle(statusCode int) string {
	switch statusCode {
	case http.StatusBadRequest:
		return "Bad request"
	case http.StatusUnauthorized:
		return "Authentication required"
	case http.StatusForbidden:
		return "Access denied"
	case http.StatusNotFound:
		return "Page not found"
	case http.StatusMethodNotAllowed:
		return "Method not allowed"
	case http.StatusConflict:
		return "Conflict"
	case http.StatusRequestEntityTooLarge:
		return "Payload too large"
	case http.StatusUnsupportedMediaType:
		return "Unsupported media type"
	case http.StatusTooManyRequests:
		return "Rate limit exceeded"
	case http.StatusServiceUnavailable:
		return "Service unavailable"
	case http.StatusInternalServerError:
		return "Internal server error"
	default:
		if text := http.StatusText(statusCode); text != "" {
			return text
		}
		return "Console error"
	}
}

func webErrorDescription(statusCode int, code string) string {
	switch statusCode {
	case http.StatusBadRequest:
		return "The Custodia Console could not process this request. Check the submitted values and try again."
	case http.StatusUnauthorized:
		return "Authentication is required before this Custodia Console page can be displayed."
	case http.StatusForbidden:
		return "Your current mTLS identity is not allowed to access this Custodia Console page."
	case http.StatusNotFound:
		return "The requested Custodia Console page does not exist."
	case http.StatusMethodNotAllowed:
		return "The requested method is not allowed for this Custodia Console page."
	case http.StatusConflict:
		return "The Custodia Console could not complete this request because the resource changed or already exists."
	case http.StatusRequestEntityTooLarge:
		return "The submitted request is too large for this Custodia Console operation."
	case http.StatusUnsupportedMediaType:
		return "The submitted content type is not supported by this Custodia Console operation."
	case http.StatusTooManyRequests:
		return "Too many Custodia Console requests were sent in a short time. Wait briefly and try again."
	case http.StatusServiceUnavailable:
		return "A required Custodia service is currently unavailable. Check operational status and try again."
	case http.StatusInternalServerError:
		return "The Custodia Console could not complete this request because an internal error occurred."
	default:
		if code != "" {
			return "The Custodia Console could not complete this request: " + code + "."
		}
		return "The Custodia Console could not complete this request."
	}
}

func writeWebPageWithOptions(w http.ResponseWriter, title string, body string, authenticatedNav bool) {
	writeWebPageStatusWithOptions(w, http.StatusOK, title, body, authenticatedNav)
}

func webRefreshControls() string {
	return `<section class="console-refresh-controls" data-console-refresh-control aria-label="Console refresh controls">` +
		`<div><p class="console-panel-label">Live refresh</p><p class="console-refresh-status" data-refresh-status aria-live="polite">Refresh in 10s</p><p class="console-refresh-updated" data-refresh-updated>Last updated just now</p></div>` +
		`<label>Interval<select data-refresh-interval aria-label="Refresh interval"><option value="5">5 seconds</option><option value="10" selected>10 seconds</option><option value="15">15 seconds</option><option value="30">30 seconds</option></select></label>` +
		`<button type="button" data-refresh-now aria-label="Refresh current console view"><span aria-hidden="true">↻</span><span>Refresh</span></button>` +
		`</section>`
}

func writeWebPageStatusWithOptions(w http.ResponseWriter, statusCode int, title string, body string, authenticatedNav bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	layoutClass := "console-app-shell"
	mainClass := "console-main"
	pageBody := body
	nav := ""
	refreshControls := ""
	if authenticatedNav {
		nav = `<aside class="console-sidebar" aria-label="Console sidebar">
<a class="console-brand" href="/web/" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true" aria-label="Custodia overview"><span class="console-logo" aria-hidden="true">C</span><span>Custodia</span></a>
<nav class="console-nav" aria-label="Console navigation" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true">
<a href="/web/">Overview</a>
<a href="/web/status">Status</a>
<a href="/web/diagnostics">Diagnostics</a>
<a href="/web/clients">Clients</a>
<a href="/web/client-enrollments">Client Enrollments</a>
<a href="/web/revocation">Revocation</a>
<a href="/web/secret-metadata">Secret Metadata</a>
<a href="/web/access-requests">Access Requests</a>
<a href="/web/audit">Audit</a>
<a href="/web/audit/verify">Verify Audit</a>
</nav>
<form class="console-logout" method="post" action="/web/logout"><button type="submit">Logout</button></form>
</aside>
<header class="console-mobile-nav" aria-label="Console mobile navigation">
<a class="console-brand" href="/web/" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true" aria-label="Custodia overview"><span class="console-logo" aria-hidden="true">C</span><span>Custodia</span></a>
<nav aria-label="Console mobile sections" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true">
<a href="/web/status">Status</a><a href="/web/clients">Clients</a><a href="/web/client-enrollments">Enrollments</a><a href="/web/secret-metadata">Secrets</a><a href="/web/audit">Audit</a>
</nav>
</header>`
		refreshControls = webRefreshControls()
	}
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + html.EscapeString(title) + ` – Custodia</title>
<link rel="icon" href="/web/assets/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/web/assets/console.css">
<script src="/web/assets/console.js" defer></script>
</head>
<body>
<div class="` + layoutClass + `">
` + nav + `
<main id="console-main" class="` + mainClass + `" tabindex="-1">
` + refreshControls + `
` + pageBody + `
</main>
</div>
</body>
</html>`))
}

func (s *Server) handleWebFavicon(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/favicon.ico" && r.URL.Path != "/web/assets/favicon.svg" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte(webConsoleFaviconSVG))
}

func (s *Server) handleWebConsoleAsset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/web/assets/console.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write([]byte(webConsoleJS))
	case "/web/assets/console.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write([]byte(webConsoleCSS))
	default:
		http.NotFound(w, r)
	}
}

func webHero(title string, description string) string {
	return `<section class="console-hero"><p class="console-kicker">Custodia console</p><h1>` + html.EscapeString(title) + `</h1><p>` + html.EscapeString(description) + `</p></section>`
}

func webBadge(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "_", "-")
	normalized = strings.ReplaceAll(normalized, " ", "-")
	if normalized == "" {
		normalized = "unknown"
	}
	return `<span class="console-badge console-badge--` + html.EscapeString(normalized) + `">` + html.EscapeString(value) + `</span>`
}

func webOptionalString(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = fallback
	}
	return html.EscapeString(value)
}

func webReadinessBadge(deploymentMode, databaseHATarget, auditShipmentSink string) string {
	if strings.TrimSpace(deploymentMode) == "" && strings.TrimSpace(databaseHATarget) == "" && strings.TrimSpace(auditShipmentSink) == "" {
		return webBadge("not configured")
	}
	if strings.TrimSpace(databaseHATarget) == "" || strings.TrimSpace(auditShipmentSink) == "" {
		return webBadge("incomplete")
	}
	return webBadge("configured")
}

func webKeyspace(namespace, key string) string {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		namespace = model.DefaultSecretNamespace
	}
	return `<span class="console-keyspace"><span class="console-keyspace__namespace">` + html.EscapeString(namespace) + `</span><code>` + html.EscapeString(key) + `</code></span>`
}

func webSecretMetadataHref(namespace, key, ownerClientID string) string {
	query := url.Values{}
	query.Set("namespace", model.NormalizeSecretNamespace(namespace))
	query.Set("key", model.NormalizeSecretKey(key))
	if strings.TrimSpace(ownerClientID) != "" {
		query.Set("owner_client_id", strings.TrimSpace(ownerClientID))
	}
	return "/web/secret-metadata?" + query.Encode()
}

func webKeyspaceMetadataLink(namespace, key, ownerClientID string) string {
	return `<a href="` + html.EscapeString(webSecretMetadataHref(namespace, key, ownerClientID)) + `" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true">` + webKeyspace(namespace, key) + `</a>`
}

func webPermissions(bits int) string {
	labels := make([]string, 0, 3)
	if model.HasPermission(bits, model.PermissionRead) {
		labels = append(labels, "read")
	}
	if model.HasPermission(bits, model.PermissionWrite) {
		labels = append(labels, "update")
	}
	if model.HasPermission(bits, model.PermissionShare) {
		labels = append(labels, "share")
	}
	if len(labels) == 0 {
		return "none"
	}
	return strings.Join(labels, ", ")
}

func webOptionalTime(value *time.Time) string {
	if value == nil {
		return "-"
	}
	return html.EscapeString(value.Format(time.RFC3339))
}

func webTable(columns []string, rows string, emptyColspan int, emptyMessage string) string {
	return webTableWithAttributes(columns, rows, emptyColspan, emptyMessage, "")
}

func webPaginatedTable(columns []string, rows string, emptyColspan int, emptyMessage string, pageSize int, label string) string {
	if rows == "" {
		return webTable(columns, rows, emptyColspan, emptyMessage)
	}
	attributes := ` data-console-pagination="true" data-page-size="` + html.EscapeString(strconv.Itoa(pageSize)) + `" data-pagination-label="` + html.EscapeString(label) + `"`
	return webTableWithAttributes(columns, rows, emptyColspan, emptyMessage, attributes)
}

func webTableWithAttributes(columns []string, rows string, emptyColspan int, emptyMessage string, attributes string) string {
	headers := ""
	for _, column := range columns {
		headers += "<th>" + html.EscapeString(column) + "</th>"
	}
	if rows == "" {
		rows = `<tr><td colspan="` + html.EscapeString(strconv.Itoa(emptyColspan)) + `">` + html.EscapeString(emptyMessage) + `</td></tr>`
	}
	return `<div class="console-table-wrap"` + attributes + `><table><thead><tr>` + headers + `</tr></thead><tbody>` + rows + `</tbody></table></div>`
}

func webParagraph(text string) string {
	return "<p>" + html.EscapeString(text) + "</p>"
}

func webInputValueAttr(r *http.Request, key string) string {
	value := strings.TrimSpace(r.URL.Query().Get(key))
	if value == "" {
		return ""
	}
	return ` value="` + html.EscapeString(value) + `"`
}

func webSelectOption(value, label, current string) string {
	selected := ""
	if value == current {
		selected = " selected"
	}
	return `<option value="` + html.EscapeString(value) + `"` + selected + `>` + html.EscapeString(label) + `</option>`
}

type webSecretMetadataRecord struct {
	Secret   model.SecretMetadata
	Versions []model.SecretVersionMetadata
	Access   []model.SecretAccessMetadata
}

func (s *Server) webSecretMetadataRecords(ctx context.Context, namespace, key, ownerClientID string, limit int) ([]webSecretMetadataRecord, error) {
	clients, err := s.store.ListClients(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	records := []webSecretMetadataRecord{}
	for _, client := range clients {
		if !client.IsActive {
			continue
		}
		if ownerClientID != "" && client.ClientID != ownerClientID {
			continue
		}
		secrets, err := s.store.ListSecrets(ctx, client.ClientID)
		if err != nil {
			return nil, err
		}
		for _, secret := range secrets {
			if seen[secret.SecretID] || secret.CreatedByClientID != client.ClientID || secret.Namespace != namespace || secret.Key != key {
				continue
			}
			versions, err := s.store.ListSecretVersions(ctx, client.ClientID, secret.SecretID)
			if err != nil {
				return nil, err
			}
			access, err := s.store.ListSecretAccess(ctx, client.ClientID, secret.SecretID)
			if err != nil {
				return nil, err
			}
			if limit > 0 && len(versions) > limit {
				versions = versions[:limit]
			}
			if limit > 0 && len(access) > limit {
				access = access[:limit]
			}
			records = append(records, webSecretMetadataRecord{Secret: secret, Versions: versions, Access: access})
			seen[secret.SecretID] = true
		}
	}
	return records, nil
}

func webSecretMetadataForm(r *http.Request) string {
	return `<form class="console-toolbar" method="get" action="/web/secret-metadata" hx-get="/web/secret-metadata" hx-target="#console-main" hx-select="#console-main" hx-push-url="true">` +
		`<label>Namespace<input name="namespace" placeholder="default"` + webInputValueAttr(r, "namespace") + `></label>` +
		`<label>Key<input name="key" placeholder="alice-bob-demo"` + webInputValueAttr(r, "key") + `></label>` +
		`<label>Owner client<input name="owner_client_id" placeholder="client_alice"` + webInputValueAttr(r, "owner_client_id") + `></label>` +
		`<label>Limit<input name="limit" inputmode="numeric" placeholder="100"` + webInputValueAttr(r, "limit") + `></label>` +
		`<button type="submit">Inspect metadata</button><a class="console-button console-button--ghost" href="/web/secret-metadata" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true">Reset</a></form>`
}

func webSecretAccessRevokeForm(namespace, key, ownerClientID, targetClientID string) string {
	if targetClientID == ownerClientID {
		return `<span class="console-muted">owner</span>`
	}
	return `<form class="console-inline-form" method="post" action="/web/secret-metadata/revoke">` +
		`<input type="hidden" name="namespace" value="` + html.EscapeString(namespace) + `">` +
		`<input type="hidden" name="key" value="` + html.EscapeString(key) + `">` +
		`<input type="hidden" name="owner_client_id" value="` + html.EscapeString(ownerClientID) + `">` +
		`<input type="hidden" name="target_client_id" value="` + html.EscapeString(targetClientID) + `">` +
		`<label class="console-checkbox"><input type="checkbox" name="confirm" value="yes"> Confirm</label>` +
		`<button type="submit">Revoke</button></form>`
}

func webSecretMetadataResults(records []webSecretMetadataRecord, revokedClientID string) string {
	if len(records) == 0 {
		return `<section class="console-panel"><p class="console-panel-label">Lookup result</p><p>No active owned secret metadata matched this namespace/key.</p></section>`
	}
	body := `<section class="console-panel console-security-boundary"><p class="console-panel-label">Strong revocation guidance</p><p>Server-side access revocation removes future reads only. Strong cryptographic revocation requires a new encrypted version excluding the revoked client.</p></section>`
	if revokedClientID != "" {
		body += `<section class="console-panel" role="status"><p class="console-panel-label">Access revocation</p><p>Access revoked for <code>` + html.EscapeString(revokedClientID) + `</code>. Already obtained material cannot be clawed back; create a new encrypted version excluding the revoked client for strong rotation.</p></section>`
	}
	for _, record := range records {
		secret := record.Secret
		versionsRows := ""
		for _, version := range record.Versions {
			versionsRows += `<tr><td>` + html.EscapeString(version.VersionID) + `</td><td>` + html.EscapeString(version.CreatedByClientID) + `</td><td>` + html.EscapeString(version.CreatedAt.Format(time.RFC3339)) + `</td><td>` + webOptionalTime(version.RevokedAt) + `</td></tr>`
		}
		accessRows := ""
		for _, access := range record.Access {
			accessRows += `<tr><td>` + html.EscapeString(secret.CreatedByClientID) + `</td><td>` + html.EscapeString(access.ClientID) + `</td><td>` + html.EscapeString(access.VersionID) + `</td><td>` + html.EscapeString(webPermissions(access.Permissions)) + `</td><td>` + html.EscapeString(access.GrantedAt.Format(time.RFC3339)) + `</td><td>` + webOptionalTime(access.ExpiresAt) + `</td><td>` + webSecretAccessRevokeForm(secret.Namespace, secret.Key, secret.CreatedByClientID, access.ClientID) + `</td></tr>`
		}
		body += `<section class="console-panel"><p class="console-panel-label">Secret record</p><dl class="console-detail">` +
			`<dt>Keyspace</dt><dd>` + webKeyspace(secret.Namespace, secret.Key) + `</dd>` +
			`<dt>Owner</dt><dd>` + html.EscapeString(secret.CreatedByClientID) + `</dd>` +
			`<dt>Secret ID</dt><dd><code>` + html.EscapeString(secret.SecretID) + `</code></dd>` +
			`<dt>Current version</dt><dd><code>` + html.EscapeString(secret.VersionID) + `</code></dd>` +
			`<dt>Created at</dt><dd>` + html.EscapeString(secret.CreatedAt.Format(time.RFC3339)) + `</dd></dl>` +
			`<h2>Versions</h2>` + webPaginatedTable([]string{"Version", "Created by", "Created", "Revoked"}, versionsRows, 4, "No versions found.", 10, "Secret versions pagination") +
			`<h2>Access Grants</h2><p class="console-muted">Future access revocation removes active grants only. Strong cryptographic revocation requires a new encrypted version excluding the revoked client.</p>` +
			webPaginatedTable([]string{"Owner client", "Target client", "Version", "Permissions", "Granted", "Expires", "Action"}, accessRows, 7, "No active access grants found.", 10, "Secret access pagination") + `</section>`
	}
	return body
}

func (s *Server) handleWebSecretMetadata(w http.ResponseWriter, r *http.Request) {
	limit, ok := s.webOptionalLimit(w, r, "web.secret_metadata", "secret", "", 100)
	if !ok {
		return
	}
	namespace := model.NormalizeSecretNamespace(strings.TrimSpace(r.URL.Query().Get("namespace")))
	key := model.NormalizeSecretKey(strings.TrimSpace(r.URL.Query().Get("key")))
	ownerClientID := strings.TrimSpace(r.URL.Query().Get("owner_client_id"))
	if namespace == "" {
		namespace = model.DefaultSecretNamespace
	}
	if r.URL.Query().Get("namespace") != "" && !model.ValidSecretNamespace(namespace) {
		s.auditFailure(r, "web.secret_metadata", "secret_key", namespace, map[string]string{"reason": "invalid_namespace_filter"})
		writeWebStatusError(w, http.StatusBadRequest, "invalid_namespace_filter")
		return
	}
	if key != "" && !model.ValidSecretKey(key) {
		s.auditFailure(r, "web.secret_metadata", "secret_key", key, map[string]string{"reason": "invalid_key_filter"})
		writeWebStatusError(w, http.StatusBadRequest, "invalid_key_filter")
		return
	}
	if ownerClientID != "" && !model.ValidClientID(ownerClientID) {
		s.auditFailure(r, "web.secret_metadata", "client", ownerClientID, map[string]string{"reason": "invalid_owner_filter"})
		writeWebStatusError(w, http.StatusBadRequest, "invalid_owner_filter")
		return
	}
	body := webHero("Secret Metadata", "Inspect secret versions and active access grants by namespace/key without exposing client cryptographic payloads.") + webSecretMetadataForm(r)
	if key != "" {
		records, err := s.webSecretMetadataRecords(r.Context(), namespace, key, ownerClientID, limit)
		if err != nil {
			s.auditStoreFailure(r, "web.secret_metadata", "secret_key", secretKeyspaceResource(namespace, key), err)
			writeWebMappedError(w, err)
			return
		}
		body += webSecretMetadataResults(records, strings.TrimSpace(r.URL.Query().Get("revoked_client_id")))
	}
	s.audit(r, "web.secret_metadata", "secret", "", "success", nil)
	writeWebPage(w, "Secret Metadata", body)
}

func (s *Server) handleWebSecretAccessRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.auditFailure(r, "web.secret_access_revoke", "secret", "", map[string]string{"reason": "invalid_form"})
		writeWebStatusError(w, http.StatusBadRequest, "invalid_form")
		return
	}
	namespace := model.NormalizeSecretNamespace(strings.TrimSpace(r.FormValue("namespace")))
	key := model.NormalizeSecretKey(strings.TrimSpace(r.FormValue("key")))
	ownerClientID := strings.TrimSpace(r.FormValue("owner_client_id"))
	targetClientID := strings.TrimSpace(r.FormValue("target_client_id"))
	if namespace == "" {
		namespace = model.DefaultSecretNamespace
	}
	if !model.ValidSecretNamespace(namespace) || !model.ValidSecretKey(key) || !model.ValidClientID(ownerClientID) || !model.ValidClientID(targetClientID) {
		s.auditFailure(r, "web.secret_access_revoke", "secret_key", secretKeyspaceResource(namespace, key), map[string]string{"reason": "invalid_form"})
		writeWebStatusError(w, http.StatusBadRequest, "invalid_form")
		return
	}
	if r.FormValue("confirm") != "yes" {
		s.auditFailure(r, "web.secret_access_revoke", "secret_key", secretKeyspaceResource(namespace, key), map[string]string{"reason": "confirmation_required"})
		writeWebStatusError(w, http.StatusBadRequest, "confirmation_required")
		return
	}
	records, err := s.webSecretMetadataRecords(r.Context(), namespace, key, ownerClientID, 1)
	if err != nil {
		s.auditStoreFailure(r, "web.secret_access_revoke", "secret_key", secretKeyspaceResource(namespace, key), err)
		writeWebMappedError(w, err)
		return
	}
	if len(records) != 1 {
		s.auditFailure(r, "web.secret_access_revoke", "secret_key", secretKeyspaceResource(namespace, key), map[string]string{"reason": "secret_not_found"})
		writeWebStatusError(w, http.StatusNotFound, "secret_not_found")
		return
	}
	if err := s.store.RevokeAccess(r.Context(), ownerClientID, records[0].Secret.SecretID, targetClientID); err != nil {
		s.auditStoreFailure(r, "web.secret_access_revoke", "secret", records[0].Secret.SecretID, err)
		writeWebMappedError(w, err)
		return
	}
	s.audit(r, "web.secret_access_revoke", "secret", records[0].Secret.SecretID, "success", nil)
	redirect := "/web/secret-metadata?namespace=" + url.QueryEscape(namespace) + "&key=" + url.QueryEscape(key) + "&owner_client_id=" + url.QueryEscape(ownerClientID) + "&revoked_client_id=" + url.QueryEscape(targetClientID)
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func (s *Server) webOptionalLimit(w http.ResponseWriter, r *http.Request, action, resourceType, resourceID string, fallback int) (int, bool) {
	limit := fallback
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 || parsed > 500 {
			s.auditFailure(r, action, resourceType, resourceID, map[string]string{"reason": "invalid_limit"})
			writeWebStatusError(w, http.StatusBadRequest, "invalid_limit")
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
	body := webHero("Operational Status", "Live metadata about service health, build identity and web authentication posture.") +
		`<section class="console-grid console-grid--two" aria-label="Operational snapshot">` +
		`<dl class="console-panel console-stat"><dt>Overall status</dt><dd>` + webBadge(statusOutcome(storeStatus, rateLimiterStatus)) + `</dd></dl>` +
		`<dl class="console-panel console-stat"><dt>Store</dt><dd>` + webBadge(storeStatus) + `</dd></dl>` +
		`<dl class="console-panel console-stat"><dt>Rate limiter</dt><dd>` + webBadge(rateLimiterStatus) + `</dd></dl>` +
		`<dl class="console-panel console-stat"><dt>Max envelopes</dt><dd>` + html.EscapeString(strconv.Itoa(s.maxEnvelopesPerSecret)) + `</dd></dl>` +
		`</section>` +
		`<h2>Configuration</h2><dl class="console-detail">` +
		"<dt>Store backend</dt><dd>" + html.EscapeString(s.storeBackend) + "</dd>" +
		"<dt>Rate limiter backend</dt><dd>" + html.EscapeString(s.rateLimitBackend) + "</dd>" +
		"<dt>Build version</dt><dd>" + html.EscapeString(info.Version) + "</dd>" +
		"<dt>Build commit</dt><dd>" + html.EscapeString(info.Commit) + "</dd>" +
		"<dt>Web MFA required</dt><dd>" + html.EscapeString(strconv.FormatBool(s.webMFARequired)) + "</dd>" +
		"<dt>Web passkey enabled</dt><dd>" + html.EscapeString(strconv.FormatBool(s.webPasskeyEnabled)) + "</dd>" +
		"</dl>"
	s.audit(r, "web.status", "system", "", statusOutcome(storeStatus, rateLimiterStatus), nil)
	writeWebPage(w, "Operational Status", body)
}

func (s *Server) handleWebDiagnostics(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	body := webHero("Runtime Diagnostics", "Operational runtime metadata only; secret payloads are never rendered.") +
		`<dl class="console-detail">` +
		"<dt>Started at</dt><dd>" + html.EscapeString(s.startedAt.Format(time.RFC3339)) + "</dd>" +
		"<dt>Uptime seconds</dt><dd>" + html.EscapeString(strconv.FormatInt(int64(time.Since(s.startedAt).Seconds()), 10)) + "</dd>" +
		"<dt>Goroutines</dt><dd>" + html.EscapeString(strconv.Itoa(runtime.NumGoroutine())) + "</dd>" +
		"<dt>Alloc bytes</dt><dd>" + html.EscapeString(strconv.FormatUint(mem.Alloc, 10)) + "</dd>" +
		"</dl>"
	s.audit(r, "web.diagnostics", "system", "", "success", nil)
	writeWebPage(w, "Runtime Diagnostics", body)
}

func statusOutcome(storeStatus, rateLimiterStatus string) string {
	if storeStatus != "ok" || rateLimiterStatus != "ok" {
		return "degraded"
	}
	return "success"
}

func (s *Server) handleWebClientEnrollments(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.renderWebClientEnrollmentForm(w, http.StatusOK, "", "", "")
		return
	}
	if r.Method != http.MethodPost {
		writeWebStatusError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.auditFailure(r, "web.client_enrollment_create", "client_enrollment", "", map[string]string{"reason": "invalid_form"})
		s.renderWebClientEnrollmentForm(w, http.StatusBadRequest, "", "invalid_form", "The submitted enrollment form could not be parsed. Check the values and try again.")
		return
	}
	ttlText := strings.TrimSpace(r.Form.Get("ttl"))
	ttl := defaultEnrollmentTTL
	if ttlText != "" {
		parsed, err := time.ParseDuration(ttlText)
		if err != nil || parsed <= 0 {
			s.auditFailure(r, "web.client_enrollment_create", "client_enrollment", "", map[string]string{"reason": "invalid_ttl"})
			s.renderWebClientEnrollmentForm(w, http.StatusBadRequest, ttlText, "invalid_ttl", "TTL must be a positive Go duration, for example 15m, 1h or 24h.")
			return
		}
		ttl = parsed
	}
	response, status, code := s.createClientEnrollment(r, ttl, "web.client_enrollment_create")
	if code != "" {
		if code == "invalid_ttl" {
			s.renderWebClientEnrollmentForm(w, status, ttlText, code, "TTL must not exceed 24h for one-shot enrollment tokens.")
			return
		}
		writeWebStatusError(w, status, code)
		return
	}
	serverURL := html.EscapeString(response.ServerURL)
	enrollmentToken := html.EscapeString(response.EnrollmentToken)
	body := webHero("Client Enrollments", "Create one-shot client onboarding tokens without shell access to a server or Kubernetes pod.") +
		webClientEnrollmentForm(ttlText) +
		`<section class="console-panel" aria-label="New enrollment token"><p class="console-panel-label">Enrollment token</p>` +
		`<dl class="console-detail"><dt>Server URL</dt><dd><code id="enrollment-server-url">` + serverURL + `</code> <button type="button" class="console-button console-button--ghost" data-copy-target="enrollment-server-url" data-copy-value="` + serverURL + `">Copy server URL</button></dd>` +
		`<dt>Enrollment token</dt><dd><code id="enrollment-token">` + enrollmentToken + `</code> <button type="button" class="console-button console-button--ghost" data-copy-target="enrollment-token" data-copy-value="` + enrollmentToken + `">Copy token</button></dd>` +
		`<dt>Expires at</dt><dd>` + html.EscapeString(response.ExpiresAt.Format(time.RFC3339)) + `</dd></dl>` +
		`<p class="console-muted">The token is shown only in this response. Treat it as sensitive and transfer it to the client host through your normal trusted channel.</p>` +
		`<pre><code>custodia-client mtls enroll --client-id client_alice --server-url ` + serverURL + ` --enrollment-token ` + enrollmentToken + `</code></pre>` +
		`<p class="console-muted">If this is a disposable lab using the bootstrap CA before the client trusts it, add <code>--insecure</code>. Do not use <code>--insecure</code> for real remote clients.</p></section>`
	writeWebPage(w, "Client Enrollments", body)
}

func (s *Server) renderWebClientEnrollmentForm(w http.ResponseWriter, statusCode int, ttlText string, errorCode string, errorMessage string) {
	body := webHero("Client Enrollments", "Create one-shot client onboarding tokens without shell access to a server or Kubernetes pod.") + webClientEnrollmentNotice(errorCode, errorMessage) + webClientEnrollmentForm(ttlText)
	writeWebPageStatusWithOptions(w, statusCode, "Client Enrollments", body, true)
}

func webClientEnrollmentNotice(errorCode string, errorMessage string) string {
	errorCode = strings.TrimSpace(errorCode)
	errorMessage = strings.TrimSpace(errorMessage)
	if errorCode == "" && errorMessage == "" {
		return ""
	}
	if errorMessage == "" {
		errorMessage = "The enrollment token request could not be processed."
	}
	body := `<section class="console-panel" role="alert" aria-label="Enrollment error"><p class="console-panel-label">Enrollment error</p><p>` + html.EscapeString(errorMessage) + `</p>`
	if errorCode != "" {
		body += `<p class="console-muted">Error code: <code>` + html.EscapeString(errorCode) + `</code></p>`
	}
	return body + `</section>`
}

func webClientEnrollmentForm(ttlText string) string {
	if strings.TrimSpace(ttlText) == "" {
		ttlText = "15m"
	}
	return `<section class="console-panel"><p class="console-panel-label">Create token</p><p class="console-muted">Tokens are one-shot bootstrap secrets. The server receives only the client CSR and token during enrollment; client mTLS private keys remain client-side.</p>` +
		`<form class="console-toolbar" method="post" action="/web/client-enrollments">` +
		`<label>TTL<input name="ttl" value="` + html.EscapeString(ttlText) + `" placeholder="15m"></label>` +
		`<button type="submit">Create enrollment token</button></form></section>`
}

func (s *Server) handleWebRevocationStatus(w http.ResponseWriter, r *http.Request) {
	status, statusCode, failureReason := s.clientRevocationStatus()
	if failureReason != "" {
		s.auditFailure(r, "web.revocation_status", "system", "", map[string]string{"reason": failureReason})
	} else {
		s.audit(r, "web.revocation_status", "system", "", "success", nil)
	}
	body := webHero("Revocation Status", "Client certificate revocation metadata visible without entering a server or Kubernetes pod.") + webRevocationStatusPanel(status) + webRevocationSerialCheckForm("")
	writeWebPageStatusWithOptions(w, statusCode, "Revocation Status", body, true)
}

func (s *Server) handleWebClientCRLDownload(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.clientCRLFile) == "" {
		s.auditFailure(r, "web.revocation_crl_download", "system", "", map[string]string{"reason": "crl_not_configured"})
		writeWebStatusError(w, http.StatusNotFound, "crl_not_configured")
		return
	}
	caPEM, err := os.ReadFile(s.clientCAFile)
	if err != nil {
		s.auditFailure(r, "web.revocation_crl_download", "system", "", map[string]string{"reason": "client_ca_unavailable"})
		writeWebStatusError(w, http.StatusServiceUnavailable, "client_ca_unavailable")
		return
	}
	if _, err := mtls.LoadClientRevocationLists(s.clientCRLFile, caPEM); err != nil {
		s.auditFailure(r, "web.revocation_crl_download", "system", "", map[string]string{"reason": "client_crl_invalid"})
		writeWebStatusError(w, http.StatusServiceUnavailable, "client_crl_invalid")
		return
	}
	payload, err := os.ReadFile(s.clientCRLFile)
	if err != nil {
		s.auditFailure(r, "web.revocation_crl_download", "system", "", map[string]string{"reason": "client_crl_unavailable"})
		writeWebStatusError(w, http.StatusServiceUnavailable, "client_crl_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", `attachment; filename="custodia-client.crl.pem"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
	s.audit(r, "web.revocation_crl_download", "system", "", "success", nil)
}

func (s *Server) handleWebRevocationCheckSerial(w http.ResponseWriter, r *http.Request) {
	serialHex := strings.TrimSpace(r.URL.Query().Get("serial_hex"))
	if serialHex == "" {
		s.auditFailure(r, "web.revocation_check_serial", "system", "", map[string]string{"reason": "missing_serial_hex"})
		s.renderWebRevocationSerialResult(w, http.StatusBadRequest, "missing_serial_hex", serialHex, nil)
		return
	}
	if strings.TrimSpace(s.clientCRLFile) == "" {
		s.auditFailure(r, "web.revocation_check_serial", "system", serialHex, map[string]string{"reason": "crl_not_configured"})
		s.renderWebRevocationSerialResult(w, http.StatusNotFound, "crl_not_configured", serialHex, nil)
		return
	}
	caPEM, err := os.ReadFile(s.clientCAFile)
	if err != nil {
		s.auditFailure(r, "web.revocation_check_serial", "system", serialHex, map[string]string{"reason": "client_ca_unavailable"})
		s.renderWebRevocationSerialResult(w, http.StatusServiceUnavailable, "client_ca_unavailable", serialHex, nil)
		return
	}
	lists, err := mtls.LoadClientRevocationLists(s.clientCRLFile, caPEM)
	if err != nil {
		s.auditFailure(r, "web.revocation_check_serial", "system", serialHex, map[string]string{"reason": "client_crl_invalid"})
		s.renderWebRevocationSerialResult(w, http.StatusServiceUnavailable, "client_crl_invalid", serialHex, nil)
		return
	}
	serialStatus, err := revocationresponder.CheckCRLs(lists, serialHex)
	if err != nil {
		s.auditFailure(r, "web.revocation_check_serial", "system", serialHex, map[string]string{"reason": "invalid_serial_hex"})
		s.renderWebRevocationSerialResult(w, http.StatusBadRequest, "invalid_serial_hex", serialHex, nil)
		return
	}
	metadata, _ := json.Marshal(map[string]string{"status": serialStatus.Status})
	s.audit(r, "web.revocation_check_serial", "system", serialStatus.SerialHex, "success", metadata)
	s.renderWebRevocationSerialResult(w, http.StatusOK, "", serialHex, serialStatus)
}

func (s *Server) renderWebRevocationSerialResult(w http.ResponseWriter, statusCode int, errorCode string, serialHex string, serialStatus *revocationresponder.Status) {
	status, _, _ := s.clientRevocationStatus()
	body := webHero("Revocation Status", "Client certificate revocation metadata visible without entering a server or Kubernetes pod.") + webRevocationStatusPanel(status) + webRevocationSerialCheckForm(serialHex) + webRevocationSerialResultPanel(errorCode, serialStatus)
	writeWebPageStatusWithOptions(w, statusCode, "Revocation Status", body, true)
}

func webRevocationStatusPanel(status model.RevocationStatus) string {
	configured := webBadge("not configured")
	if status.Configured {
		configured = webBadge("configured")
	}
	valid := webBadge("ok")
	if !status.Valid {
		valid = webBadge("unavailable")
	}
	body := `<section class="console-panel"><p class="console-panel-label">Client CRL</p>` +
		`<dl class="console-detail"><dt>Configured</dt><dd>` + configured + `</dd>` +
		`<dt>Valid</dt><dd>` + valid + `</dd>` +
		`<dt>Source</dt><dd>` + webOptionalText(status.Source) + `</dd>` +
		`<dt>Issuer</dt><dd>` + webOptionalText(status.Issuer) + `</dd>` +
		`<dt>This update</dt><dd>` + webOptionalTimeValue(status.ThisUpdate) + `</dd>` +
		`<dt>Next update</dt><dd>` + webOptionalTimeValue(status.NextUpdate) + `</dd>` +
		`<dt>Revoked certificates</dt><dd>` + html.EscapeString(strconv.Itoa(status.RevokedCount)) + `</dd>` +
		`<dt>Expires in seconds</dt><dd>` + html.EscapeString(strconv.FormatInt(status.ExpiresInSeconds, 10)) + `</dd>` +
		`<dt>Error</dt><dd>` + webOptionalText(status.Error) + `</dd></dl>`
	if status.Configured && status.Valid {
		body += `<p><a class="console-button" href="/web/revocation/client.crl.pem">Download client CRL PEM</a></p>`
	}
	return body + `<p class="console-muted">This page reports certificate revocation distribution health only. Secret access revocation is future-only; strong revocation still requires creating a new encrypted version without the revoked recipient.</p></section>`
}

func webRevocationSerialCheckForm(serialHex string) string {
	return `<section class="console-panel"><p class="console-panel-label">Check serial</p><p class="console-muted">Check a certificate serial number against the configured, CA-verified client CRL without entering a server or Kubernetes pod.</p>` +
		`<form class="console-toolbar" method="get" action="/web/revocation/check-serial">` +
		`<label>Serial hex<input name="serial_hex" value="` + html.EscapeString(strings.TrimSpace(serialHex)) + `" placeholder="64"></label>` +
		`<button type="submit">Check serial</button></form></section>`
}

func webRevocationSerialResultPanel(errorCode string, serialStatus *revocationresponder.Status) string {
	if serialStatus == nil {
		if strings.TrimSpace(errorCode) == "" {
			return ""
		}
		return `<section class="console-panel" role="alert"><p class="console-panel-label">Serial check error</p><p>Error code: <code>` + html.EscapeString(errorCode) + `</code></p></section>`
	}
	return `<section class="console-panel"><p class="console-panel-label">Serial result</p>` +
		`<dl class="console-detail"><dt>Serial</dt><dd><code>` + html.EscapeString(serialStatus.SerialHex) + `</code></dd>` +
		`<dt>Status</dt><dd>` + webBadge(serialStatus.Status) + `</dd>` +
		`<dt>Revoked at</dt><dd>` + webOptionalTime(serialStatus.RevokedAt) + `</dd>` +
		`<dt>This update</dt><dd>` + webOptionalTimeValue(serialStatus.ThisUpdate) + `</dd>` +
		`<dt>Next update</dt><dd>` + webOptionalTimeValue(serialStatus.NextUpdate) + `</dd>` +
		`<dt>CRL revoked certificates</dt><dd>` + html.EscapeString(strconv.Itoa(serialStatus.RevokedCount)) + `</dd></dl>` +
		`<p class="console-muted">This is CRL evidence only. Certificate revocation blocks future mTLS use after the CRL is enforced by the receiving component.</p></section>`
}

func webOptionalText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return `<span class="console-muted">not set</span>`
	}
	return html.EscapeString(value)
}

func webOptionalTimeValue(value time.Time) string {
	if value.IsZero() {
		return `<span class="console-muted">not set</span>`
	}
	return html.EscapeString(value.Format(time.RFC3339))
}

type webClientPublicKeySummary struct {
	status      string
	fingerprint string
	scheme      string
	publishedAt time.Time
}

func (s *Server) webClientPublicKeySummary(ctx context.Context, client model.Client) (webClientPublicKeySummary, error) {
	if !client.IsActive {
		return webClientPublicKeySummary{status: "unavailable for revoked client"}, nil
	}
	publicKey, err := s.store.GetClientPublicKey(ctx, client.ClientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrForbidden) {
			return webClientPublicKeySummary{status: "not published"}, nil
		}
		return webClientPublicKeySummary{}, err
	}
	return webClientPublicKeySummary{status: "published", fingerprint: publicKey.Fingerprint, scheme: publicKey.Scheme, publishedAt: publicKey.PublishedAt}, nil
}

func (summary webClientPublicKeySummary) ListHTML() string {
	if summary.status != "published" {
		return `<span class="console-muted">` + html.EscapeString(summary.status) + `</span>`
	}
	return webBadge("published")
}

func (summary webClientPublicKeySummary) DetailHTML() string {
	if summary.status != "published" {
		return `<dt>Public key</dt><dd><span class="console-muted">` + html.EscapeString(summary.status) + `</span></dd><dt>Public key fingerprint</dt><dd><span class="console-muted">not available</span></dd><dt>Public key published at</dt><dd><span class="console-muted">not available</span></dd>`
	}
	return `<dt>Public key</dt><dd>` + webBadge("published") + ` <span class="console-muted">` + html.EscapeString(summary.scheme) + `</span></dd><dt>Public key fingerprint</dt><dd><code>` + html.EscapeString(summary.fingerprint) + `</code></dd><dt>Public key published at</dt><dd>` + webOptionalTimeValue(summary.publishedAt) + `</dd>`
}

func (s *Server) handleWebClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.store.ListClients(r.Context())
	if err != nil {
		s.auditStoreFailure(r, "web.client_list", "client", "", err)
		writeWebMappedError(w, err)
		return
	}
	activeFilter := strings.TrimSpace(r.URL.Query().Get("active"))
	if activeFilter != "" {
		active, ok := parseBoolQuery(activeFilter)
		if !ok {
			s.auditFailure(r, "web.client_list", "client", "", map[string]string{"reason": "invalid_active_filter"})
			writeWebStatusError(w, http.StatusBadRequest, "invalid_active_filter")
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
		publicKey, err := s.webClientPublicKeySummary(r.Context(), client)
		if err != nil {
			s.auditStoreFailure(r, "web.client_list", "client_public_key", client.ClientID, err)
			writeWebMappedError(w, err)
			return
		}
		rows += `<tr><td><a href="/web/clients/` + url.PathEscape(client.ClientID) + `" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true">` + html.EscapeString(client.ClientID) + `</a></td><td>` + html.EscapeString(client.MTLSSubject) + `</td><td>` + webBadge(state) + `</td><td>` + publicKey.ListHTML() + `</td></tr>`
	}
	body := webHero("Clients", "mTLS client identities visible to the admin console.") +
		`<form class="console-toolbar" method="get" action="/web/clients" hx-get="/web/clients" hx-target="#console-main" hx-select="#console-main" hx-push-url="true">` +
		`<label>Status<select name="active">` + webSelectOption("", "All", activeFilter) + webSelectOption("true", "Active", activeFilter) + webSelectOption("false", "Revoked", activeFilter) + `</select></label>` +
		`<button type="submit">Apply filter</button><a class="console-button console-button--ghost" href="/web/clients" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true">Reset</a></form>` +
		webPaginatedTable([]string{"Client ID", "mTLS subject", "Status", "Public key"}, rows, 4, "No clients found.", 10, "Clients pagination")
	s.audit(r, "web.client_list", "client", "", "success", nil)
	writeWebPage(w, "Clients", body)
}

func (s *Server) handleWebClientDetail(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimSpace(r.PathValue("client_id"))
	if !model.ValidClientID(clientID) {
		s.auditFailure(r, "web.client_detail", "client", clientID, map[string]string{"reason": "invalid_client_id"})
		writeWebStatusError(w, http.StatusBadRequest, "invalid_client_id")
		return
	}
	client, err := s.store.GetClient(r.Context(), clientID)
	if err != nil {
		s.auditStoreFailure(r, "web.client_detail", "client", clientID, err)
		writeWebMappedError(w, err)
		return
	}
	secrets := []model.SecretMetadata{}
	if client.IsActive {
		var err error
		secrets, err = s.store.ListSecrets(r.Context(), clientID)
		if err != nil {
			s.auditStoreFailure(r, "web.client_detail", "client", clientID, err)
			writeWebMappedError(w, err)
			return
		}
	}

	visibleRows := ""
	shareRows := ""
	for _, secret := range secrets {
		relationship := "shared with this client"
		if secret.CreatedByClientID == clientID {
			relationship = "owned by this client"
		}
		visibleRows += "<tr><td>" + webKeyspaceMetadataLink(secret.Namespace, secret.Key, secret.CreatedByClientID) + "</td><td>" + webBadge(relationship) + "</td><td>" + html.EscapeString(secret.CreatedByClientID) + "</td><td>" + html.EscapeString(webPermissions(secret.Permissions)) + "</td><td>" + html.EscapeString(secret.VersionID) + "</td><td>" + webOptionalTime(secret.AccessExpiresAt) + "</td></tr>"
		if secret.CreatedByClientID != clientID || !model.HasPermission(secret.Permissions, model.PermissionShare) {
			continue
		}
		accesses, err := s.store.ListSecretAccess(r.Context(), clientID, secret.SecretID)
		if err != nil {
			s.auditStoreFailure(r, "web.client_detail", "secret", secret.SecretID, err)
			writeWebMappedError(w, err)
			return
		}
		for _, access := range accesses {
			if access.ClientID == clientID {
				continue
			}
			shareRows += "<tr><td>" + webKeyspaceMetadataLink(secret.Namespace, secret.Key, secret.CreatedByClientID) + "</td><td>" + html.EscapeString(access.ClientID) + "</td><td>" + html.EscapeString(webPermissions(access.Permissions)) + "</td><td>" + webOptionalTime(access.ExpiresAt) + "</td></tr>"
		}
	}

	state := "active"
	if !client.IsActive {
		state = "revoked"
	}
	publicKey, err := s.webClientPublicKeySummary(r.Context(), client)
	if err != nil {
		s.auditStoreFailure(r, "web.client_detail", "client_public_key", client.ClientID, err)
		writeWebMappedError(w, err)
		return
	}
	revokePanel := webClientRevokePanel(client, r.URL.Query().Get("revoked") == "1")
	body := webHero("Client Detail", "Metadata-only view of one client visible keyspace, ownership and shares.") +
		`<p><a class="console-button console-button--ghost" href="/web/clients" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true">Back to clients</a></p>` +
		`<dl class="console-panel console-stat"><dt>Client ID</dt><dd>` + html.EscapeString(client.ClientID) + `</dd><dt>mTLS subject</dt><dd>` + html.EscapeString(client.MTLSSubject) + `</dd><dt>Status</dt><dd>` + webBadge(state) + `</dd><dt>Created at</dt><dd>` + webOptionalTimeValue(client.CreatedAt) + `</dd><dt>Revoked at</dt><dd>` + webOptionalTime(client.RevokedAt) + `</dd>` + publicKey.DetailHTML() + `<dt>Certificate serial</dt><dd><span class="console-muted">not stored in the client registry; use Revocation Status to check a serial from the certificate or CRL evidence.</span></dd><dt>Revocation status</dt><dd><a href="/web/revocation" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true">Open CRL status and serial check</a></dd></dl>` +
		revokePanel +
		`<h2>Visible Keyspace</h2><p class="console-muted">Secrets this client can resolve by namespace/key. Secret plaintext, ciphertext, envelopes and DEKs are never rendered.</p>` +
		webPaginatedTable([]string{"Keyspace", "Relationship", "Owner", "Permissions", "Current version", "Access expires"}, visibleRows, 6, "No visible keyspace entries found for this client.", 10, "Client visible keyspace pagination") +
		`<h2>Shares From This Client</h2><p class="console-muted">Active metadata-only shares for secrets owned by this client.</p>` +
		webPaginatedTable([]string{"Keyspace", "Shared with", "Permissions", "Expires"}, shareRows, 4, "No active shares from this client.", 10, "Client shares pagination")
	s.audit(r, "web.client_detail", "client", clientID, "success", nil)
	writeWebPage(w, "Client Detail", body)
}

func webClientRevokePanel(client model.Client, justRevoked bool) string {
	if !client.IsActive {
		message := "This client is already revoked."
		if justRevoked {
			message = "Client revoked successfully."
		}
		return `<section class="console-panel" role="status" aria-label="Client revocation status"><p class="console-panel-label">Client revocation</p><p>` + html.EscapeString(message) + `</p><p class="console-muted">Certificate and access revocation are future-only. Already downloaded material cannot be clawed back; strong secret revocation requires a new encrypted version excluding the revoked client.</p></section>`
	}
	clientPath := url.PathEscape(client.ClientID)
	return `<section class="console-panel" aria-label="Revoke client"><p class="console-panel-label">Danger zone</p><h2>Revoke Client</h2><p class="console-muted">Revoking a client disables future server-side use of this mTLS identity. It does not erase already downloaded ciphertext, envelopes or plaintext; strong revocation requires a new encrypted version without this client.</p>` +
		`<form class="console-toolbar" method="post" action="/web/clients/` + clientPath + `/revoke">` +
		`<label>Reason<input name="reason" maxlength="512" placeholder="lost device, decommissioned host, compromised certificate"></label>` +
		`<label class="console-checkbox"><input type="checkbox" name="confirm" value="yes"> Confirm future access revocation</label>` +
		`<button type="submit">Revoke client</button></form></section>`
}

func (s *Server) handleWebClientRevoke(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimSpace(r.PathValue("client_id"))
	if !model.ValidClientID(clientID) {
		s.auditFailure(r, "web.client_revoke", "client", clientID, map[string]string{"reason": "invalid_client_id"})
		writeWebStatusError(w, http.StatusBadRequest, "invalid_client_id")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.auditFailure(r, "web.client_revoke", "client", clientID, map[string]string{"reason": "invalid_form"})
		writeWebStatusError(w, http.StatusBadRequest, "invalid_form")
		return
	}
	if r.FormValue("confirm") != "yes" {
		s.auditFailure(r, "web.client_revoke", "client", clientID, map[string]string{"reason": "missing_confirmation"})
		writeWebStatusError(w, http.StatusBadRequest, "missing_confirmation")
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if !model.ValidRevocationReason(reason) {
		s.auditFailure(r, "web.client_revoke", "client", clientID, map[string]string{"reason": "invalid_revoke_reason"})
		writeWebStatusError(w, http.StatusBadRequest, "invalid_revoke_reason")
		return
	}
	if err := s.store.RevokeClient(r.Context(), clientID); err != nil {
		s.auditStoreFailure(r, "web.client_revoke", "client", clientID, err)
		writeWebMappedError(w, err)
		return
	}
	metadata, _ := json.Marshal(map[string]string{"reason": reason})
	s.audit(r, "web.client_revoke", "client", clientID, "success", metadata)
	http.Redirect(w, r, "/web/clients/"+url.PathEscape(clientID)+"?revoked=1", http.StatusSeeOther)
}

func (s *Server) handleWebAudit(w http.ResponseWriter, r *http.Request) {
	limit, ok := s.webOptionalLimit(w, r, "web.audit_list", "audit_event", "", 100)
	if !ok {
		return
	}
	events, err := s.store.ListAuditEvents(r.Context(), limit)
	if err != nil {
		s.auditStoreFailure(r, "web.audit_list", "audit_event", "", err)
		writeWebMappedError(w, err)
		return
	}
	filtered, ok := s.filterAuditEventsForRequest(w, r, "web.audit_list", events)
	if !ok {
		return
	}
	events = filtered
	rows := ""
	for _, event := range events {
		rows += "<tr><td>" + html.EscapeString(event.OccurredAt.Format(time.RFC3339)) + "</td><td>" + html.EscapeString(event.Action) + "</td><td>" + html.EscapeString(event.ActorClientID) + "</td><td>" + webBadge(event.Outcome) + "</td></tr>"
	}
	auditOutcomeFilter := strings.TrimSpace(r.URL.Query().Get("outcome"))
	exportHref := webAuditExportHref(r)
	body := webHero("Audit Events", "Latest bounded audit metadata with a browser-downloadable JSONL export. Exports include SHA-256 and event-count headers for downstream evidence capture.") +
		`<form class="console-toolbar" method="get" action="/web/audit" hx-get="/web/audit" hx-target="#console-main" hx-select="#console-main" hx-push-url="true">` +
		`<label>Limit<input name="limit" inputmode="numeric" placeholder="100"` + webInputValueAttr(r, "limit") + `></label>` +
		`<label>Action<input name="action" placeholder="secret.read"` + webInputValueAttr(r, "action") + `></label>` +
		`<label>Actor<input name="actor_client_id" placeholder="client_alice"` + webInputValueAttr(r, "actor_client_id") + `></label>` +
		`<label>Resource type<input name="resource_type" placeholder="secret"` + webInputValueAttr(r, "resource_type") + `></label>` +
		`<label>Resource ID<input name="resource_id" placeholder="client_alice"` + webInputValueAttr(r, "resource_id") + `></label>` +
		`<label>Outcome<select name="outcome">` + webSelectOption("", "Any", auditOutcomeFilter) + webSelectOption("success", "Success", auditOutcomeFilter) + webSelectOption("failure", "Failure", auditOutcomeFilter) + webSelectOption("degraded", "Degraded", auditOutcomeFilter) + `</select></label>` +
		`<button type="submit">Apply filter</button><a class="console-button console-button--ghost" href="/web/audit" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true">Reset</a><a class="console-button console-button--secondary" href="` + exportHref + `">Download JSONL</a></form>` +
		webPaginatedTable([]string{"Time", "Action", "Actor", "Outcome"}, rows, 4, "No audit events found.", 10, "Audit Events pagination")
	s.audit(r, "web.audit_list", "audit_event", "", "success", nil)
	writeWebPage(w, "Audit Events", body)
}

func webAuditExportHref(r *http.Request) string {
	query := r.URL.Query()
	encoded := query.Encode()
	if encoded == "" {
		return "/web/audit/export"
	}
	return "/web/audit/export?" + html.EscapeString(encoded)
}

func (s *Server) handleWebAuditExport(w http.ResponseWriter, r *http.Request) {
	limit, ok := s.webOptionalLimit(w, r, "web.audit_export", "audit_event", "", 500)
	if !ok {
		return
	}
	events, err := s.store.ListAuditEvents(r.Context(), limit)
	if err != nil {
		s.auditStoreFailure(r, "web.audit_export", "audit_event", "", err)
		writeWebMappedError(w, err)
		return
	}
	filtered, ok := s.filterAuditEventsForRequest(w, r, "web.audit_export", events)
	if !ok {
		return
	}
	body, digest, count, err := encodeAuditEventsExport(filtered)
	if err != nil {
		s.auditFailure(r, "web.audit_export", "audit_event", "", map[string]string{"reason": "encode_failed"})
		writeWebStatusError(w, http.StatusInternalServerError, "export_failed")
		return
	}
	writeAuditExportResponse(w, "custodia-web-audit.jsonl", body, digest, count)
	s.audit(r, "web.audit_export", "audit_event", "", "success", nil)
}

func (s *Server) handleWebAccessRequests(w http.ResponseWriter, r *http.Request) {
	limit, ok := s.webOptionalLimit(w, r, "web.access_request_list", "secret", "", 100)
	if !ok {
		return
	}
	requests, err := s.store.ListAccessGrantRequests(r.Context(), "")
	if err != nil {
		s.auditStoreFailure(r, "web.access_request_list", "secret", "", err)
		writeWebMappedError(w, err)
		return
	}
	namespaceFilter := strings.TrimSpace(r.URL.Query().Get("namespace"))
	if namespaceFilter != "" && !model.ValidSecretNamespace(namespaceFilter) {
		s.auditFailure(r, "web.access_request_list", "secret_key", namespaceFilter, map[string]string{"reason": "invalid_namespace_filter"})
		writeWebStatusError(w, http.StatusBadRequest, "invalid_namespace_filter")
		return
	}
	keyFilter := strings.TrimSpace(r.URL.Query().Get("key"))
	if keyFilter != "" && !model.ValidSecretKey(keyFilter) {
		s.auditFailure(r, "web.access_request_list", "secret_key", keyFilter, map[string]string{"reason": "invalid_key_filter"})
		writeWebStatusError(w, http.StatusBadRequest, "invalid_key_filter")
		return
	}
	if namespaceFilter != "" || keyFilter != "" {
		filtered := requests[:0]
		for _, request := range requests {
			if namespaceFilter != "" && request.Namespace != namespaceFilter {
				continue
			}
			if keyFilter != "" && request.Key != keyFilter {
				continue
			}
			filtered = append(filtered, request)
		}
		requests = filtered
	}
	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
	if statusFilter != "" {
		if !model.ValidAccessRequestStatus(statusFilter) {
			s.auditFailure(r, "web.access_request_list", "secret", "", map[string]string{"reason": "invalid_status_filter"})
			writeWebStatusError(w, http.StatusBadRequest, "invalid_status_filter")
			return
		}
		filtered := requests[:0]
		for _, request := range requests {
			if request.Status == statusFilter {
				filtered = append(filtered, request)
			}
		}
		requests = filtered
	}
	if targetClientID := strings.TrimSpace(r.URL.Query().Get("client_id")); targetClientID != "" {
		if !model.ValidClientID(targetClientID) {
			s.auditFailure(r, "web.access_request_list", "secret", "", map[string]string{"reason": "invalid_client_id_filter"})
			writeWebStatusError(w, http.StatusBadRequest, "invalid_client_id_filter")
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
			s.auditFailure(r, "web.access_request_list", "secret", "", map[string]string{"reason": "invalid_requested_by_filter"})
			writeWebStatusError(w, http.StatusBadRequest, "invalid_requested_by_filter")
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
		rows += "<tr><td>" + webKeyspaceMetadataLink(request.Namespace, request.Key, "") + "</td><td>" + html.EscapeString(request.ClientID) + "</td><td>" + html.EscapeString(request.RequestedByClientID) + "</td><td>" + webBadge(request.Status) + "</td></tr>"
	}
	body := webHero("Access Requests", "Metadata-only pending grant workflow filtered by namespace/key. Envelopes are never rendered here.") +
		`<p class="console-muted console-filter-note">Filter grants by the public keyspace tuple used by clients. Internal secret identifiers are intentionally not part of this workflow.</p>` +
		`<form class="console-toolbar" method="get" action="/web/access-requests" hx-get="/web/access-requests" hx-target="#console-main" hx-select="#console-main" hx-push-url="true">` +
		`<label>Limit<input name="limit" inputmode="numeric" placeholder="100"` + webInputValueAttr(r, "limit") + `></label>` +
		`<label>Namespace<input name="namespace" placeholder="default"` + webInputValueAttr(r, "namespace") + `></label>` +
		`<label>Key<input name="key" placeholder="user:sys"` + webInputValueAttr(r, "key") + `></label>` +
		`<label>Status<select name="status">` + webSelectOption("", "Any", statusFilter) + webSelectOption("pending", "Pending", statusFilter) + webSelectOption("activated", "Activated", statusFilter) + webSelectOption("revoked", "Revoked", statusFilter) + webSelectOption("expired", "Expired", statusFilter) + `</select></label>` +
		`<label>Target<input name="client_id" placeholder="client_bob"` + webInputValueAttr(r, "client_id") + `></label>` +
		`<label>Requester<input name="requested_by_client_id" placeholder="admin"` + webInputValueAttr(r, "requested_by_client_id") + `></label>` +
		`<button type="submit">Apply filter</button><a class="console-button console-button--ghost" href="/web/access-requests" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true">Reset</a></form>` +
		webPaginatedTable([]string{"Keyspace", "Target client", "Requested by", "Status"}, rows, 4, "No access requests found for this keyspace filter.", 10, "Access Requests pagination")
	s.audit(r, "web.access_request_list", "secret", "", "success", nil)
	writeWebPage(w, "Access Requests", body)
}

func (s *Server) handleWebAuditVerify(w http.ResponseWriter, r *http.Request) {
	limit, ok := s.webOptionalLimit(w, r, "web.audit_verify", "audit_event", "", 500)
	if !ok {
		return
	}
	events, err := s.store.ListAuditEvents(r.Context(), limit)
	if err != nil {
		s.auditStoreFailure(r, "web.audit_verify", "audit_event", "", err)
		writeWebMappedError(w, err)
		return
	}
	result := audit.VerifyChain(events)
	outcome := "success"
	if !result.Valid {
		outcome = "failure"
	}
	body := webHero("Audit Chain Verification", "Hash-chain integrity summary for the latest bounded audit events.") +
		`<form class="console-toolbar" method="get" action="/web/audit/verify" hx-get="/web/audit/verify" hx-target="#console-main" hx-select="#console-main" hx-push-url="true">` +
		`<label>Limit<input name="limit" inputmode="numeric" placeholder="500"` + webInputValueAttr(r, "limit") + `></label><button type="submit">Verify</button></form>` +
		`<dl class="console-detail">` +
		"<dt>Valid</dt><dd>" + webBadge(strconv.FormatBool(result.Valid)) + "</dd>" +
		"<dt>Verified events</dt><dd>" + html.EscapeString(strconv.Itoa(result.VerifiedEvents)) + "</dd>" +
		"<dt>Failure index</dt><dd>" + html.EscapeString(strconv.Itoa(result.FailureIndex)) + "</dd>" +
		"</dl>"
	s.audit(r, "web.audit_verify", "audit_event", "", outcome, nil)
	writeWebPage(w, "Audit verification", body)
}
