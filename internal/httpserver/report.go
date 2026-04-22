package httpserver

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/augustoroman/caddylogs/internal/backend"
)

//go:embed assets/report.html assets/app.css
var reportFS embed.FS

// ReportOptions controls the static snapshot renderer.
type ReportOptions struct {
	Inputs      []string
	Filter      backend.Filter
	TopN        int
	IncludeStatic bool
	Version     string
}

// RenderReport writes a self-contained HTML snapshot of the dashboard, with
// CSS inlined and all data resolved server-side. No JS, no websocket.
func RenderReport(ctx context.Context, store backend.Store, defaults DefaultFilter, out io.Writer, opts ReportOptions) error {
	f := opts.Filter
	// Apply the same default exclusions the server applies.
	if defaults.ExcludeBots {
		if f.Exclude == nil {
			f.Exclude = map[backend.Dimension][]string{}
		}
		if !containsStr(f.Exclude[backend.DimIsBot], "true") &&
			!containsStr(f.Include[backend.DimIsBot], "true") {
			f.Exclude[backend.DimIsBot] = append(f.Exclude[backend.DimIsBot], "true")
		}
	}
	if defaults.ExcludeLocal {
		if f.Exclude == nil {
			f.Exclude = map[backend.Dimension][]string{}
		}
		if !containsStr(f.Exclude[backend.DimIsLocal], "true") &&
			!containsStr(f.Include[backend.DimIsLocal], "true") {
			f.Exclude[backend.DimIsLocal] = append(f.Exclude[backend.DimIsLocal], "true")
		}
	}
	topN := opts.TopN
	if topN <= 0 {
		topN = 10
	}

	// Reuse the server's parallel fanout to gather every panel.
	srv := &Server{store: store}
	dyn, err := srv.runDashboard(ctx, DashboardRequest{
		Filter: f, Table: backend.TableDynamic, TopN: topN,
	}, dashboardPanels)
	if err != nil {
		return err
	}

	var stat *DashboardResponse
	if opts.IncludeStatic {
		staticPanels := []panelSpec{
			{Name: "uri", GroupBy: backend.DimURI},
			{Name: "ip", GroupBy: backend.DimIP},
			{Name: "referer", GroupBy: backend.DimReferrer},
			{Name: "host", GroupBy: backend.DimHost},
			{Name: "country", GroupBy: backend.DimCountry},
		}
		stat, err = srv.runDashboard(ctx, DashboardRequest{
			Filter: f, Table: backend.TableStatic, TopN: topN,
		}, staticPanels)
		if err != nil {
			return err
		}
	}

	css, err := reportFS.ReadFile("assets/app.css")
	if err != nil {
		return err
	}
	raw, err := reportFS.ReadFile("assets/report.html")
	if err != nil {
		return err
	}
	tmpl, err := template.New("report").Parse(string(raw))
	if err != nil {
		return err
	}
	data := buildReportData(dyn, stat, opts, string(css))
	return tmpl.Execute(out, data)
}

// --- template data shaping ---

type reportData struct {
	GeneratedAt         string
	Inputs              string
	Version             string
	CSS                 template.CSS
	Overview            overviewView
	Static              *overviewView
	StatusBars          []statusBar
	TimelineBars        []timelineBar
	Panels              []panelView
	StaticPanels        []panelView
	IncludeFilterLines  []filterLine
	ExcludeFilterLines  []filterLine
}

type overviewView struct {
	HitsFmt, VisitorsFmt, BytesFmt, Span string
}
type statusBar struct {
	Class    string
	Label    string
	Count    int64
	CountFmt string
}
type timelineBar struct {
	X, Y, W, H float64
	Title      string
}
type panelView struct {
	Title, Dim string
	HasMax     bool
	Rows       []panelRowView
}
type panelRowView struct {
	Key, KeyTrunc string
	HitsFmt       string
	BytesFmt      string
	MaxMs         int64
	ShowMax       bool
	BarPct        float64
}
type filterLine struct{ Dim, Val string }

var reportPanelTitles = map[string]string{
	"ip":           "Top IPs",
	"uri":          "Top URIs",
	"country":      "Top Countries",
	"city":         "Top Cities",
	"referer":      "Top Referrers",
	"browser":      "Top Browsers",
	"os":           "Top OS",
	"device":       "Top Devices",
	"host":         "Top Hosts",
	"method":       "Methods",
	"not_found":    "404s — Not Found",
	"server_error": "5xx Errors",
	"slow":         "Slow Requests (max)",
}

func buildReportData(dyn, stat *DashboardResponse, opts ReportOptions, css string) reportData {
	d := reportData{
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05Z"),
		Inputs:      strings.Join(opts.Inputs, " "),
		Version:     opts.Version,
		CSS:         template.CSS(css),
		Overview:    overviewViewFrom(dyn.Overview),
		StatusBars:  buildStatusBars(dyn.StatusClass),
		TimelineBars: buildTimelineBars(dyn.Timeline),
	}
	for _, p := range dashboardPanels {
		rows := dyn.Panels[p.Name]
		maxHits := int64(0)
		for _, r := range rows {
			if r.Hits > maxHits {
				maxHits = r.Hits
			}
		}
		pv := panelView{Title: reportPanelTitles[p.Name], Dim: string(p.GroupBy), HasMax: p.Name == "slow"}
		if pv.Title == "" {
			pv.Title = p.Name
		}
		for _, r := range rows {
			pct := 0.0
			if maxHits > 0 {
				pct = float64(r.Hits) / float64(maxHits) * 100
			}
			pv.Rows = append(pv.Rows, panelRowView{
				Key:      r.Key,
				KeyTrunc: truncate(r.Key, 80),
				HitsFmt:  fmtInt(r.Hits),
				BytesFmt: fmtBytes(r.Bytes),
				MaxMs:    r.MaxMs,
				ShowMax:  p.Name == "slow",
				BarPct:   pct,
			})
		}
		d.Panels = append(d.Panels, pv)
	}
	for dim, vals := range opts.Filter.Include {
		for _, v := range vals {
			d.IncludeFilterLines = append(d.IncludeFilterLines, filterLine{Dim: string(dim), Val: v})
		}
	}
	for dim, vals := range opts.Filter.Exclude {
		for _, v := range vals {
			d.ExcludeFilterLines = append(d.ExcludeFilterLines, filterLine{Dim: string(dim), Val: v})
		}
	}
	if stat != nil {
		ov := overviewViewFrom(stat.Overview)
		d.Static = &ov
		staticPanelOrder := []string{"uri", "ip", "referer", "host", "country"}
		staticTitles := map[string]string{
			"uri": "Top static files", "ip": "Top IPs (static)",
			"referer": "Top referrers (static)", "host": "Top hosts (static)",
			"country": "Top countries (static)",
		}
		for _, name := range staticPanelOrder {
			rows := stat.Panels[name]
			maxHits := int64(0)
			for _, r := range rows {
				if r.Hits > maxHits {
					maxHits = r.Hits
				}
			}
			pv := panelView{Title: staticTitles[name], Dim: name}
			for _, r := range rows {
				pct := 0.0
				if maxHits > 0 {
					pct = float64(r.Hits) / float64(maxHits) * 100
				}
				pv.Rows = append(pv.Rows, panelRowView{
					Key: r.Key, KeyTrunc: truncate(r.Key, 80),
					HitsFmt: fmtInt(r.Hits), BytesFmt: fmtBytes(r.Bytes),
					BarPct: pct,
				})
			}
			d.StaticPanels = append(d.StaticPanels, pv)
		}
	}
	return d
}

func overviewViewFrom(o backend.Overview) overviewView {
	span := ""
	if !o.First.IsZero() && !o.Last.IsZero() {
		span = o.First.Format("2006-01-02 15:04") + " → " + o.Last.Format("2006-01-02 15:04")
	}
	return overviewView{
		HitsFmt:     fmtInt(o.Hits),
		VisitorsFmt: fmtInt(o.Visitors),
		BytesFmt:    fmtBytes(o.Bytes),
		Span:        span,
	}
}

func buildStatusBars(sc map[string]int64) []statusBar {
	order := []string{"2xx", "3xx", "4xx", "5xx", "1xx", "other"}
	var out []statusBar
	total := int64(0)
	for _, n := range sc {
		total += n
	}
	for _, k := range order {
		n := sc[k]
		if n == 0 {
			continue
		}
		label := ""
		if total > 0 && float64(n)/float64(total) >= 0.04 {
			label = k + " " + fmtInt(n)
		}
		out = append(out, statusBar{Class: k, Label: label, Count: n, CountFmt: fmtInt(n)})
	}
	return out
}

func buildTimelineBars(buckets []backend.Bucket) []timelineBar {
	if len(buckets) == 0 {
		return nil
	}
	var maxHits int64
	for _, b := range buckets {
		if b.Hits > maxHits {
			maxHits = b.Hits
		}
	}
	barW := 1000.0 / float64(len(buckets))
	out := make([]timelineBar, 0, len(buckets))
	for i, b := range buckets {
		h := 0.0
		if maxHits > 0 {
			h = float64(b.Hits) / float64(maxHits) * 140
		}
		out = append(out, timelineBar{
			X: float64(i) * barW, Y: 160 - h, W: barW - 0.5, H: h,
			Title: fmt.Sprintf("%s: %s hits", b.Start.Format("2006-01-02 15:04"), fmtInt(b.Hits)),
		})
	}
	return out
}

func fmtInt(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
		if len(s) > pre {
			b.WriteByte(',')
		}
	}
	for i := pre; i < len(s); i += 3 {
		b.WriteString(s[i : i+3])
		if i+3 < len(s) {
			b.WriteByte(',')
		}
	}
	return b.String()
}

func fmtBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	v := float64(n) / 1024
	u := 0
	for v >= 1024 && u < len(units)-1 {
		v /= 1024
		u++
	}
	if v < 10 {
		return fmt.Sprintf("%.1f %s", v, units[u])
	}
	return fmt.Sprintf("%.0f %s", v, units[u])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
