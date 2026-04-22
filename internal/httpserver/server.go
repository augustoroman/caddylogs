// Package httpserver wires the caddylogs HTTP API and embedded UI. It serves
// the dashboard SPA, dispatches backend queries over JSON, and fans out
// live-tail events through a websocket hub.
package httpserver

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"sync"
	"time"

	"github.com/augustoroman/caddylogs/internal/backend"
)

// DefaultFilter is applied to every request before the client-supplied filter.
// It enforces the server-operator's baseline preferences (hide bots, hide
// local IPs) without hiding them from the UI's filter chips.
type DefaultFilter struct {
	ExcludeBots  bool
	ExcludeLocal bool
}

// Server owns the routes, the backend Store, and the live-tail broadcast hub.
type Server struct {
	store            backend.Store
	defaults         DefaultFilter
	hub              *hub
	assets           fs.FS
	ingestMu         sync.RWMutex
	ingestBusy       bool
	classificationFn ClassificationFunc // optional; when set, /api/classification is available
	tagFn            TagFunc            // optional; when set, POST /api/tag is available
	tagListFn        TagListFunc        // optional; when set, GET /api/tags is available
	tagRemoveFn      TagRemoveFunc      // optional; when set, DELETE /api/tag is available
}

// ClassificationFunc computes the 6-cell breakdown for the header strip.
// It is passed explicitly because the backend.Store interface does not
// expose it (it's SQLite-specific today).
type ClassificationFunc func(ctx context.Context, fromNs, toNs int64) (any, error)

// SetClassificationFn registers the function used by /api/classification.
// Passing nil disables the endpoint.
func (s *Server) SetClassificationFn(fn ClassificationFunc) {
	s.classificationFn = fn
}

// TagFunc applies a user-supplied per-IP override. Tag is one of
// "real" | "local" | "bot" | "malicious". Implementations are expected to
// persist the tag, update existing rows in the store, and teach the
// classifier so subsequent events from the same IP are routed the same way.
type TagFunc func(ctx context.Context, ip, tag string) error

// SetTagFn registers the function used by /api/tag. Passing nil disables
// the endpoint.
func (s *Server) SetTagFn(fn TagFunc) {
	s.tagFn = fn
}

// TagListFunc returns the currently persisted tag set as a JSON-
// serializable value. Used by /api/tags to let the UI inspect and manage
// overrides.
type TagListFunc func(ctx context.Context) (any, error)

// SetTagListFn registers the /api/tags GET handler.
func (s *Server) SetTagListFn(fn TagListFunc) {
	s.tagListFn = fn
}

// TagRemoveFunc clears the manual tag for ip from both the persistent
// store and the in-memory classifier. It does not revert already-
// classified rows — callers handle that separately.
type TagRemoveFunc func(ctx context.Context, ip string) error

// SetTagRemoveFn registers the /api/tag DELETE handler.
func (s *Server) SetTagRemoveFn(fn TagRemoveFunc) {
	s.tagRemoveFn = fn
}

// New builds a Server. assets is the filesystem of UI assets; pass the
// embedded fs.FS from the assets package.
func New(store backend.Store, assets fs.FS, defaults DefaultFilter) *Server {
	return &Server{
		store:    store,
		defaults: defaults,
		hub:      newHub(),
		assets:   assets,
	}
}

// Routes returns the http.Handler for all caddylogs endpoints.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/dashboard", s.handleDashboard)
	mux.HandleFunc("/api/query", s.handleQuery)
	mux.HandleFunc("/api/static", s.handleStatic)
	mux.HandleFunc("/api/panel", s.handlePanel)
	mux.HandleFunc("/api/rows", s.handleRows)
	mux.HandleFunc("/api/dimensions", s.handleDimensions)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/classification", s.handleClassification)
	mux.HandleFunc("/api/tag", s.handleTag)
	mux.HandleFunc("/api/tags", s.handleTagList)
	mux.HandleFunc("/ws", s.handleWS)
	mux.Handle("/", http.FileServer(http.FS(s.assets)))
	return mux
}

// Start runs the server until ctx is canceled or ListenAndServe returns an
// error. It closes the hub on shutdown.
func (s *Server) Start(ctx context.Context, listen string) error {
	srv := &http.Server{
		Addr:              listen,
		Handler:           s.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		s.hub.closeAll()
	}()
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Broadcast sends a newly-classified row to all websocket clients.
func (s *Server) Broadcast(row backend.EventRow) {
	s.hub.broadcast(row)
}

// SetIngestBusy lets the live tailer tell the UI whether a re-ingest is in
// progress so it can show a spinner.
func (s *Server) SetIngestBusy(busy bool) {
	s.ingestMu.Lock()
	s.ingestBusy = busy
	s.ingestMu.Unlock()
}

// --- handlers ---

func (s *Server) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func (s *Server) writeError(w http.ResponseWriter, code int, msg string) {
	s.writeJSON(w, code, map[string]string{"error": msg})
}

// handleQuery runs a single backend.Query.
func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var q backend.Query
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.applyDefaults(&q.Filter, q.Table)
	res, err := s.store.Query(r.Context(), q)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, res)
}

// handleDimensions returns the list of queryable dimensions.
func (s *Server) handleDimensions(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, backend.AllowedDimensions)
}

// handleClassification returns the real/bot/malicious × static/dynamic
// breakdown for the current time-range filter (other dimensions are ignored
// — this panel summarizes the whole traffic mix).
func (s *Server) handleClassification(w http.ResponseWriter, r *http.Request) {
	if s.classificationFn == nil {
		s.writeError(w, http.StatusNotFound, "classification endpoint not configured")
		return
	}
	var req DashboardRequest
	if r.Method == http.MethodPost && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	var fromNs, toNs int64
	if !req.Filter.TimeFrom.IsZero() {
		fromNs = req.Filter.TimeFrom.UnixNano()
	}
	if !req.Filter.TimeTo.IsZero() {
		toNs = req.Filter.TimeTo.UnixNano()
	}
	result, err := s.classificationFn(r.Context(), fromNs, toNs)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

// handleTag applies or removes a manual per-IP override.
//
//	POST   /api/tag          {"ip": "1.2.3.4", "tag": "real|local|bot|malicious"}
//	DELETE /api/tag?ip=1.2.3.4
//
// POST persists the tag and updates existing rows; DELETE clears the tag
// from the persistent file and classifier but leaves already-classified
// rows where they are (the UI surfaces this caveat).
func (s *Server) handleTag(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleTagSet(w, r)
	case http.MethodDelete:
		s.handleTagDelete(w, r)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "POST or DELETE only")
	}
}

func (s *Server) handleTagSet(w http.ResponseWriter, r *http.Request) {
	if s.tagFn == nil {
		s.writeError(w, http.StatusNotFound, "tag endpoint not configured")
		return
	}
	var req struct {
		IP  string `json:"ip"`
		Tag string `json:"tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.IP == "" || req.Tag == "" {
		s.writeError(w, http.StatusBadRequest, "ip and tag are required")
		return
	}
	if err := s.tagFn(r.Context(), req.IP, req.Tag); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": req.IP, "tag": req.Tag})
}

func (s *Server) handleTagDelete(w http.ResponseWriter, r *http.Request) {
	if s.tagRemoveFn == nil {
		s.writeError(w, http.StatusNotFound, "tag endpoint not configured")
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		s.writeError(w, http.StatusBadRequest, "ip is required")
		return
	}
	if err := s.tagRemoveFn(r.Context(), ip); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": ip})
}

// handleTagList returns every currently-persisted manual tag so the
// dashboard can surface the override list. GET only.
func (s *Server) handleTagList(w http.ResponseWriter, r *http.Request) {
	if s.tagListFn == nil {
		s.writeError(w, http.StatusNotFound, "tag endpoint not configured")
		return
	}
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	out, err := s.tagListFn(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, out)
}

// handleStatus reports ingest status + server info.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.ingestMu.RLock()
	busy := s.ingestBusy
	s.ingestMu.RUnlock()
	s.writeJSON(w, http.StatusOK, map[string]any{
		"ingest_busy": busy,
		"clients":     s.hub.count(),
		"version":     "0.1.0-dev",
	})
}

// applyDefaults merges server-configured baseline exclusions into the
// client's filter without letting the client accidentally remove them.
// The malicious table intentionally bypasses these defaults because
// "hide bots" would hide nearly all of its rows and defeat the point of
// the view.
func (s *Server) applyDefaults(f *backend.Filter, table backend.Table) {
	if table == backend.TableMalicious {
		return
	}
	if f.Exclude == nil {
		f.Exclude = map[backend.Dimension][]string{}
	}
	if s.defaults.ExcludeBots {
		if !containsStr(f.Exclude[backend.DimIsBot], "true") &&
			!containsStr(f.Include[backend.DimIsBot], "true") {
			f.Exclude[backend.DimIsBot] = append(f.Exclude[backend.DimIsBot], "true")
		}
	}
	if s.defaults.ExcludeLocal {
		if !containsStr(f.Exclude[backend.DimIsLocal], "true") &&
			!containsStr(f.Include[backend.DimIsLocal], "true") {
			f.Exclude[backend.DimIsLocal] = append(f.Exclude[backend.DimIsLocal], "true")
		}
	}
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
