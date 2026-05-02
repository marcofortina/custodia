package httpapi

import (
	"encoding/json"
	"net/http"

	"custodia/internal/model"
)

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Health(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleWeb(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Custodia</title></head>
<body>
<h1>Custodia metadata console</h1>
<p>Phase 1 web surface is metadata-only. The vault never decrypts or manages client-side encryption keys.</p>
</body>
</html>`))
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.store.ListClients(r.Context())
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

func (s *Server) handleRevokeClient(w http.ResponseWriter, r *http.Request) {
	var req model.RevokeClientRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.store.RevokeClient(r.Context(), req.ClientID); err != nil {
		writeMappedError(w, err)
		return
	}
	s.audit(r, "client.revoke", "client", req.ClientID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	var req model.CreateSecretRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Envelopes) > s.maxEnvelopesPerSecret {
		writeError(w, http.StatusRequestEntityTooLarge, "too_many_envelopes")
		return
	}
	ref, err := s.store.CreateSecret(r.Context(), clientIDFromContext(r), req)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.create", "secret", ref.SecretID, "success", nil)
	writeJSON(w, http.StatusCreated, ref)
}

func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("secret_id")
	response, err := s.store.GetSecret(r.Context(), clientIDFromContext(r), secretID)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.read", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("secret_id")
	if err := s.store.DeleteSecret(r.Context(), clientIDFromContext(r), secretID); err != nil {
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.delete", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleShareSecret(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("secret_id")
	var req model.ShareSecretRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.store.ShareSecret(r.Context(), clientIDFromContext(r), secretID, req); err != nil {
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.share", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "shared"})
}

func (s *Server) handleRevokeAccess(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("secret_id")
	targetClientID := r.PathValue("client_id")
	if err := s.store.RevokeAccess(r.Context(), clientIDFromContext(r), secretID, targetClientID); err != nil {
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.access_revoke", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleCreateSecretVersion(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("secret_id")
	var req model.CreateSecretVersionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Envelopes) > s.maxEnvelopesPerSecret {
		writeError(w, http.StatusRequestEntityTooLarge, "too_many_envelopes")
		return
	}
	ref, err := s.store.CreateSecretVersion(r.Context(), clientIDFromContext(r), secretID, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.version_create", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusCreated, ref)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}
