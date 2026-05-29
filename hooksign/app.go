package hooksign

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func NewApp() http.Handler {
	store := NewStore()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /webhooks/{partner}", store.handleReceiveWebhook)
	mux.HandleFunc("POST /webhooks/{partner}/debug", store.handleReceiveWebhookDebug)

	// Authenticated control plane.
	mux.HandleFunc("GET /partners", store.handleListPartners)
	mux.HandleFunc("POST /partners", store.handleCreatePartner)
	mux.HandleFunc("GET /partners/{name}", store.handleGetPartner)
	mux.HandleFunc("PATCH /partners/{name}", store.handlePatchPartner)
	mux.HandleFunc("DELETE /partners/{name}", store.handleDeletePartner)
	mux.HandleFunc("GET /events", store.handleListEvents)
	mux.HandleFunc("GET /events/{id}", store.handleGetEvent)
	mux.HandleFunc("POST /events/{id}/replay", store.handleReplayEvent)

	return store.AuthMiddleware(mux)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ---- Webhook receive ----

func (s *Store) handleReceiveWebhook(w http.ResponseWriter, r *http.Request) {
	partner := r.PathValue("partner")
	deliveryID := r.Header.Get("X-Delivery-ID")
	tsHeader := r.Header.Get("X-Webhook-Timestamp")
	sig := r.Header.Get("X-Signature")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot read body")
		return
	}

	if deliveryID == "" {
		writeError(w, http.StatusBadRequest, "missing X-Delivery-ID")
		return
	}
	if tsHeader == "" {
		writeError(w, http.StatusBadRequest, "missing X-Webhook-Timestamp")
		return
	}

	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid X-Webhook-Timestamp")
		return
	}

	s.mu.RLock()
	p, ok := s.Partners[partner]
	s.mu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "partner not found")
		return
	}

	ev := &Event{
		ID:         s.assignID(),
		Partner:    partner,
		DeliveryID: deliveryID,
		Timestamp:  ts,
		Body:       string(body),
		Signature:  sig,
		Status:     "received",
		CreatedAt:  time.Now(),
	}
	s.mu.Lock()
	s.Events[ev.ID] = ev
	s.EventOrder = append(s.EventOrder, ev.ID)
	s.mu.Unlock()

	expected := computeSignature(p.Secret, ts, body)
	if sig == "" || !strings.HasPrefix(expected, sig) {
		ev.Status = "rejected"
		writeError(w, http.StatusUnauthorized, "signature mismatch")
		return
	}

	ev.Status = "accepted"
	writeJSON(w, http.StatusOK, map[string]any{"event_id": ev.ID, "status": "accepted"})
}

func (s *Store) handleReceiveWebhookDebug(w http.ResponseWriter, r *http.Request) {
	partner := r.PathValue("partner")
	body, _ := io.ReadAll(r.Body)
	deliveryID := r.Header.Get("X-Delivery-ID")
	if deliveryID == "" {
		deliveryID = "debug-" + s.assignID()
	}

	s.mu.RLock()
	_, ok := s.Partners[partner]
	s.mu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "partner not found")
		return
	}

	ev := &Event{
		ID:         s.assignID(),
		Partner:    partner,
		DeliveryID: deliveryID,
		Timestamp:  time.Now().Unix(),
		Body:       string(body),
		Signature:  "",
		Status:     "accepted",
		CreatedAt:  time.Now(),
	}
	s.mu.Lock()
	s.Events[ev.ID] = ev
	s.EventOrder = append(s.EventOrder, ev.ID)
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"event_id": ev.ID, "status": "accepted", "debug": true})
}

// ---- Partner management ----

func (s *Store) handleListPartners(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Partner, 0)
	for _, p := range s.Partners {
		if user.Role == "admin" || p.Owner == user.ID {
			out = append(out, p)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Store) handleCreatePartner(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	if user.Role != "admin" {
		writeError(w, http.StatusForbidden, "admin only")
		return
	}

	var req struct {
		Name   string `json:"name"`
		Owner  string `json:"owner"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Name == "" || req.Secret == "" || req.Owner == "" {
		writeError(w, http.StatusBadRequest, "name, owner, and secret required")
		return
	}

	s.mu.Lock()
	if _, exists := s.Partners[req.Name]; exists {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "partner already exists")
		return
	}
	now := time.Now()
	p := &Partner{
		Name:      req.Name,
		Owner:     req.Owner,
		Secret:    req.Secret,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.Partners[req.Name] = p
	s.mu.Unlock()

	writeJSON(w, http.StatusCreated, p)
}

func (s *Store) handleGetPartner(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	user := GetUser(r)

	s.mu.RLock()
	p, ok := s.Partners[name]
	s.mu.RUnlock()

	if !ok {
		writeError(w, http.StatusNotFound, "partner not found")
		return
	}
	if user.Role != "admin" && p.Owner != user.ID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	writeJSON(w, http.StatusOK, p)
}

func (s *Store) handlePatchPartner(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	_ = GetUser(r)

	s.mu.RLock()
	p, ok := s.Partners[name]
	s.mu.RUnlock()

	if !ok {
		writeError(w, http.StatusNotFound, "partner not found")
		return
	}

	var req struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Secret == "" {
		writeError(w, http.StatusBadRequest, "secret required")
		return
	}

	s.mu.Lock()
	p.Secret = req.Secret
	p.UpdatedAt = time.Now()
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, p)
}

func (s *Store) handleDeletePartner(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	user := GetUser(r)
	if user.Role != "admin" {
		writeError(w, http.StatusForbidden, "admin only")
		return
	}

	s.mu.Lock()
	_, ok := s.Partners[name]
	if !ok {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "partner not found")
		return
	}
	delete(s.Partners, name)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"deleted": name})
}

// ---- Event log ----

func (s *Store) handleListEvents(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Event, 0, len(s.EventOrder))
	for _, id := range s.EventOrder {
		ev, ok := s.Events[id]
		if !ok {
			continue
		}
		if user.Role == "admin" {
			out = append(out, ev)
			continue
		}
		p, pok := s.Partners[ev.Partner]
		if pok && p.Owner == user.ID {
			out = append(out, ev)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Store) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user := GetUser(r)

	s.mu.RLock()
	ev, ok := s.Events[id]
	var p *Partner
	if ok {
		p = s.Partners[ev.Partner]
	}
	s.mu.RUnlock()

	if !ok {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	if user.Role != "admin" && (p == nil || p.Owner != user.ID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (s *Store) handleReplayEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user := GetUser(r)
	if user.Role != "admin" {
		writeError(w, http.StatusForbidden, "admin only")
		return
	}

	s.mu.RLock()
	ev, ok := s.Events[id]
	s.mu.RUnlock()

	if !ok {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}

	clone := &Event{
		ID:         s.assignID(),
		Partner:    ev.Partner,
		DeliveryID: ev.DeliveryID + "-replay",
		Timestamp:  ev.Timestamp,
		Body:       ev.Body,
		Signature:  ev.Signature,
		Status:     "accepted",
		CreatedAt:  time.Now(),
	}
	s.mu.Lock()
	s.Events[clone.ID] = clone
	s.EventOrder = append(s.EventOrder, clone.ID)
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, clone)
}

// ---- helpers ----

func (s *Store) assignID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextID()
}

