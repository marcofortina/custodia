package httpapi

import (
	"html"
	"net/http"
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
