package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/augustoroman/caddylogs/internal/backend"
)

// DashboardRequest is what the UI POSTs to /api/dashboard. Table defaults to
// Dynamic; static-asset summaries live behind /api/static.
type DashboardRequest struct {
	Filter  backend.Filter `json:"filter"`
	Table   backend.Table  `json:"table,omitempty"`
	TopN    int            `json:"topn,omitempty"`
	Bucket  time.Duration  `json:"bucket,omitempty"`
	OrderBy string         `json:"order_by,omitempty"` // "hits" (default), "bytes", "visitors"
}

// DashboardResponse is the parallel fanout of every dashboard panel plus the
// shared overview/timeline/status-class results.
type DashboardResponse struct {
	Overview    backend.Overview                 `json:"overview"`
	StatusClass map[string]int64                 `json:"status_class"`
	Timeline    []backend.Bucket                 `json:"timeline"`
	Panels      map[string][]backend.Group       `json:"panels"`
	Elapsed     map[string]int64                 `json:"elapsed_ms"`
	Errors      map[string]string                `json:"errors,omitempty"`
}

// panelSpec declares one top-N fanout.
type panelSpec struct {
	Name    string
	GroupBy backend.Dimension
	Extra   backend.Filter // merged on top of the request filter
	Order   string         // passes through to Query.OrderBy
}

// dashboardPanels is the canonical list for the main UI. The "not_found"
// and "server_error" panels are GroupBy=URI with extra status filters; the
// "slow" panel is GroupBy=URI with OrderBy=max_dur.
var dashboardPanels = []panelSpec{
	{Name: "ip", GroupBy: backend.DimIP},
	{Name: "uri", GroupBy: backend.DimURI},
	{Name: "country", GroupBy: backend.DimCountry},
	{Name: "city", GroupBy: backend.DimCity},
	{Name: "referer", GroupBy: backend.DimReferrer},
	{Name: "browser", GroupBy: backend.DimBrowser},
	{Name: "os", GroupBy: backend.DimOS},
	{Name: "device", GroupBy: backend.DimDevice},
	{Name: "host", GroupBy: backend.DimHost},
	{Name: "method", GroupBy: backend.DimMethod},
	{Name: "status", GroupBy: backend.DimStatus},
	{
		Name: "not_found", GroupBy: backend.DimURI,
		Extra: backend.Filter{Include: map[backend.Dimension][]string{backend.DimStatus: {"404"}}},
	},
	{
		Name: "server_error", GroupBy: backend.DimURI,
		Extra: backend.Filter{Include: map[backend.Dimension][]string{backend.DimStatusClass: {"5xx"}}},
	},
	{Name: "slow", GroupBy: backend.DimURI, Order: "max_dur"},
}

// maliciousPanels is the panel set used when Table == malicious. It focuses
// on who and why (top attacker IPs, top reasons, top URIs being probed)
// rather than the real-traffic breakdown.
var maliciousPanels = []panelSpec{
	{Name: "ip", GroupBy: backend.DimIP},
	{Name: "malicious_reason", GroupBy: backend.DimMalReason},
	{Name: "uri", GroupBy: backend.DimURI},
	{Name: "country", GroupBy: backend.DimCountry},
	{Name: "city", GroupBy: backend.DimCity},
	{Name: "browser", GroupBy: backend.DimBrowser},
	{Name: "os", GroupBy: backend.DimOS},
	{Name: "host", GroupBy: backend.DimHost},
	{Name: "method", GroupBy: backend.DimMethod},
	{Name: "status", GroupBy: backend.DimStatus},
	{Name: "referer", GroupBy: backend.DimReferrer},
}

// staticPanels is the panel set used by /api/static and by handlePanel when
// Table == static. Kept aligned with the server-side slice used in
// handleStatic so /api/panel can resolve any name shown on the Static view.
var staticPanels = []panelSpec{
	{Name: "uri", GroupBy: backend.DimURI},
	{Name: "ip", GroupBy: backend.DimIP},
	{Name: "referer", GroupBy: backend.DimReferrer},
	{Name: "host", GroupBy: backend.DimHost},
	{Name: "country", GroupBy: backend.DimCountry},
}

// panelsFor returns the panel spec list used for a given table.
func panelsFor(t backend.Table) []panelSpec {
	switch t {
	case backend.TableStatic:
		return staticPanels
	case backend.TableMalicious:
		return maliciousPanels
	default:
		return dashboardPanels
	}
}

// findPanelSpec resolves a panel by name within a table's list.
func findPanelSpec(t backend.Table, name string) *panelSpec {
	for _, p := range panelsFor(t) {
		if p.Name == name {
			return &p
		}
	}
	return nil
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	req, err := decodeDashboardRequest(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Table == "" {
		req.Table = backend.TableDynamic
	}
	s.applyDefaults(&req.Filter, req.Table)
	if req.TopN <= 0 {
		req.TopN = 10
	}
	panels := dashboardPanels
	if req.Table == backend.TableMalicious {
		panels = maliciousPanels
	}
	resp, err := s.runDashboard(r.Context(), req, panels)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleStatic answers the "Load static asset stats" button. It runs the
// dashboard fanout against the static table; the UI renders a smaller panel
// set for it.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	req, err := decodeDashboardRequest(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Table = backend.TableStatic
	s.applyDefaults(&req.Filter, req.Table)
	if req.TopN <= 0 {
		req.TopN = 10
	}
	resp, err := s.runDashboard(r.Context(), req, staticPanels)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handlePanel returns a single panel's next page of rows. The client uses
// this for its "Show more" button without refetching the whole dashboard.
// Request body:
//   { filter, table, panel, offset, limit, order_by }
// Response body:
//   { panel, rows, total, has_more }
func (s *Server) handlePanel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DashboardRequest
		Panel   string `json:"panel"`
		Offset  int    `json:"offset"`
		Limit   int    `json:"limit"`
		OrderBy string `json:"order_by"`
	}
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.Table == "" {
		req.Table = backend.TableDynamic
	}
	s.applyDefaults(&req.Filter, req.Table)

	spec := findPanelSpec(req.Table, req.Panel)
	if spec == nil {
		s.writeError(w, http.StatusNotFound, "unknown panel "+req.Panel)
		return
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 25
	}
	// Panel-specific order wins (e.g. slow = max_dur) so the Slow panel
	// keeps sorting by duration even when the global toggle is on
	// "bytes" or "hits".
	order := spec.Order
	if order == "" {
		order = req.OrderBy
	}
	filter := mergeFilters(req.Filter, spec.Extra)
	res, err := s.store.Query(r.Context(), backend.Query{
		Table:   req.Table,
		Kind:    backend.KindTopN,
		Filter:  filter,
		GroupBy: spec.GroupBy,
		Limit:   limit,
		Offset:  req.Offset,
		OrderBy: order,
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows := res.TopN
	if rows == nil {
		rows = []backend.Group{} // keep the wire shape an array, never null
	}
	out := map[string]any{
		"panel":    req.Panel,
		"rows":     rows,
		"offset":   req.Offset,
		"has_more": len(rows) == limit, // heuristic: a full page implies more
	}
	s.writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRows(w http.ResponseWriter, r *http.Request) {
	req, err := decodeDashboardRequest(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Table == "" {
		req.Table = backend.TableDynamic
	}
	s.applyDefaults(&req.Filter, req.Table)
	q := backend.Query{
		Table: req.Table, Kind: backend.KindRows,
		Filter: req.Filter, Limit: 50, OrderBy: "ts desc",
	}
	// Optional pagination via "offset" query param
	if o := r.URL.Query().Get("offset"); o != "" {
		off, _ := strconv.Atoi(o)
		if off > 0 {
			q.Offset = off
		}
	}
	res, err := s.store.Query(r.Context(), q)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, res)
}

func decodeDashboardRequest(r *http.Request) (DashboardRequest, error) {
	var req DashboardRequest
	if r.Method == http.MethodPost && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return req, err
		}
	}
	return req, nil
}

// runDashboard fans out overview + status-class + timeline + panels in
// parallel. Individual panel failures are reported under Errors rather than
// failing the whole response — this keeps a slow/broken panel from blacking
// out the UI.
func (s *Server) runDashboard(ctx context.Context, req DashboardRequest, panels []panelSpec) (*DashboardResponse, error) {
	resp := &DashboardResponse{
		Panels:  map[string][]backend.Group{},
		Elapsed: map[string]int64{},
	}
	var mu sync.Mutex
	var wg sync.WaitGroup

	track := func(name string, fn func(ctx context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			err := fn(ctx)
			mu.Lock()
			resp.Elapsed[name] = time.Since(start).Milliseconds()
			if err != nil {
				if resp.Errors == nil {
					resp.Errors = map[string]string{}
				}
				resp.Errors[name] = err.Error()
			}
			mu.Unlock()
		}()
	}

	track("overview", func(ctx context.Context) error {
		out, err := s.store.Query(ctx, backend.Query{
			Table: req.Table, Kind: backend.KindOverview, Filter: req.Filter,
		})
		if err == nil {
			mu.Lock()
			resp.Overview = out.Overview
			mu.Unlock()
		}
		return err
	})
	track("status_class", func(ctx context.Context) error {
		out, err := s.store.Query(ctx, backend.Query{
			Table: req.Table, Kind: backend.KindStatusClass, Filter: req.Filter,
		})
		if err == nil {
			mu.Lock()
			resp.StatusClass = out.Statuses
			mu.Unlock()
		}
		return err
	})
	track("timeline", func(ctx context.Context) error {
		out, err := s.store.Query(ctx, backend.Query{
			Table: req.Table, Kind: backend.KindTimeline, Filter: req.Filter, Bucket: req.Bucket,
		})
		if err == nil {
			mu.Lock()
			resp.Timeline = out.Timeline
			mu.Unlock()
		}
		return err
	})
	for _, p := range panels {
		p := p
		track(p.Name, func(ctx context.Context) error {
			filter := mergeFilters(req.Filter, p.Extra)
			// Panel-specific order (e.g. slow requests always use max_dur)
			// wins; otherwise fall back to the request-level order, then the
			// backend default of "hits".
			order := p.Order
			if order == "" {
				order = req.OrderBy
			}
			out, err := s.store.Query(ctx, backend.Query{
				Table:   req.Table,
				Kind:    backend.KindTopN,
				Filter:  filter,
				GroupBy: p.GroupBy,
				Limit:   req.TopN,
				OrderBy: order,
			})
			if err == nil {
				mu.Lock()
				resp.Panels[p.Name] = out.TopN
				mu.Unlock()
			}
			return err
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return resp, nil
}

// mergeFilters AND-merges two filters. For include sets, same dim means OR
// within the resulting list. For our use case (base filter + per-panel
// extra) we just concatenate.
func mergeFilters(base, extra backend.Filter) backend.Filter {
	out := backend.Filter{
		Include:  map[backend.Dimension][]string{},
		Exclude:  map[backend.Dimension][]string{},
		Contains: map[backend.Dimension][]string{},
		TimeFrom: base.TimeFrom,
		TimeTo:   base.TimeTo,
	}
	for d, v := range base.Include {
		out.Include[d] = append(out.Include[d], v...)
	}
	for d, v := range base.Exclude {
		out.Exclude[d] = append(out.Exclude[d], v...)
	}
	for d, v := range base.Contains {
		out.Contains[d] = append(out.Contains[d], v...)
	}
	for d, v := range extra.Include {
		out.Include[d] = append(out.Include[d], v...)
	}
	for d, v := range extra.Exclude {
		out.Exclude[d] = append(out.Exclude[d], v...)
	}
	for d, v := range extra.Contains {
		out.Contains[d] = append(out.Contains[d], v...)
	}
	if !extra.TimeFrom.IsZero() && (base.TimeFrom.IsZero() || extra.TimeFrom.After(base.TimeFrom)) {
		out.TimeFrom = extra.TimeFrom
	}
	if !extra.TimeTo.IsZero() && (base.TimeTo.IsZero() || extra.TimeTo.Before(base.TimeTo)) {
		out.TimeTo = extra.TimeTo
	}
	return out
}
