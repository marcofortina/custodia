package httpapi

import (
	"context"
	"html"
	"net/http"
	"strconv"
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
<a href="/web/audit">Audit</a>
</nav>
<hr>
` + body + `
</body>
</html>`))
}

func webParagraph(text string) string {
	return "<p>" + html.EscapeString(text) + "</p>"
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
	body := "<h1>Operational status</h1>" +
		"<dl>" +
		"<dt>Status</dt><dd>" + html.EscapeString(statusOutcome(storeStatus, rateLimiterStatus)) + "</dd>" +
		"<dt>Store</dt><dd>" + html.EscapeString(storeStatus) + " (" + html.EscapeString(s.storeBackend) + ")</dd>" +
		"<dt>Rate limiter</dt><dd>" + html.EscapeString(rateLimiterStatus) + " (" + html.EscapeString(s.rateLimitBackend) + ")</dd>" +
		"<dt>Max envelopes per secret</dt><dd>" + html.EscapeString(strconv.Itoa(s.maxEnvelopesPerSecret)) + "</dd>" +
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
