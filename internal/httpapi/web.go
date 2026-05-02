package httpapi

import (
	"context"
	"custodia/internal/audit"
	"custodia/internal/build"

	"html"
	"net/http"
	"strconv"
	"time"
)

func writeWebPage(w http.ResponseWriter, title string, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>` + html.EscapeString(title) + ` – Custodia</title></head>
<body>
<nav>
<a href="/web/">Overview</a> |
<a href="/web/status">Status</a> |
<a href="/web/clients">Clients</a> |
<a href="/web/access-requests">Access requests</a> |
<a href="/web/audit">Audit</a> |
<a href="/web/audit/verify">Verify audit</a>
</nav>
<hr>
` + body + `
</body>
</html>`))
}

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
		"</dl>"
	s.audit(r, "web.status", "system", "", statusOutcome(storeStatus, rateLimiterStatus), nil)
	writeWebPage(w, "Operational status", body)
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
	requests, err := s.store.ListAccessGrantRequests(r.Context(), "")
	if err != nil {
		s.auditStoreFailure(r, "web.access_request_list", "secret", "", err)
		writeMappedError(w, err)
		return
	}
	if len(requests) > 100 {
		requests = requests[:100]
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
	events, err := s.store.ListAuditEvents(r.Context(), 500)
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
