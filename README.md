# caddylogs

Interactive analyzer for Caddy's JSON access logs. Parses historical
`.log.gz` files plus the live `.log`, indexes every event in a local SQLite
database, and serves a goaccess-style dashboard with click-to-drill
filtering across IP, host, URI, status, country, city, referrer, browser,
OS, device, and time range.

Traffic is split into four categories end-to-end — **real**, **bot**,
**local**, **malicious** — with a header strip showing the breakdown by
both request count and bytes served. Static assets are ingested into a
cold table so the hot path stays fast. Suspected-malicious clients
(matched by attack URI patterns or flagged behaviorally) are quarantined
in their own table with a dedicated drill-down view.

## Build

```
go build -o caddylogs ./cmd/caddylogs
```

No CGO required — the SQLite driver is `modernc.org/sqlite`.

## Run

```
./caddylogs serve /var/log/caddy/access.log /var/log/caddy/access-*.log.gz
```

Open http://127.0.0.1:8080. Drop a `GeoLite2-City.mmdb` next to the binary
(or pass `--geoip path/to/it.mmdb`) to populate country and city panels.

Positional paths accept shell globs (either pre-expanded by the shell or
quoted so Go's `filepath.Glob` handles them). Paths ending in `.gz` are
decompressed transparently; plain `.log` files are tailed for live updates
with rotation detection (inode change / truncation triggers a reopen).

### Static HTML snapshot

```
./caddylogs report /var/log/caddy/access.log /var/log/caddy/access-*.log.gz \
    --out report.html
```

Single self-contained HTML file with no JS and no websocket. Applies the
same default filters (hide bots, hide local IPs) that the live dashboard
uses so a shared report won't silently disagree with the live view.

## Dashboard

### Views

Four top-level view switches at the top of the page:

| View | Table | Default filters |
| --- | --- | --- |
| **Real** | `requests_dynamic` | `is_bot=false`, `is_local=false` |
| **Static** | `requests_static` | `is_bot=false`, `is_local=false` |
| **Local** | `requests_dynamic` | include `is_local=true` |
| **Malicious** | `requests_malicious` | none — bots are exactly what you want to see here |

### Classification breakdown

The header strip shows two stacked bars — one sized by request count and
one by bytes served — split into eight segments:

```
real doc · real static · bot doc · bot static · local doc · local static · mal doc · mal static
```

Hover any segment for both metrics; click to jump to the matching view.
The bytes bar reveals traffic that hit count alone obscures — e.g.
"malicious is 66% of requests but 0.4% of bandwidth" (scanner 404s return
empty bodies) while "real is 28% of requests and 77% of bandwidth".

### Malicious classification

Requests are flagged as malicious in two ways:

1. **URI pattern match at ingest** — the embedded `attacks.list` covers
   WordPress scans (`wp-login.php`, `xmlrpc.php`), env-file fishing
   (`/.env`, `/.git/`, `/.aws/`), admin panels (`phpmyadmin`, `adminer`),
   server-info leaks, web shells, router/IoT exploits (`GponForm`,
   `boaform`, `HNAP1`), Exchange/OWA paths, cloud metadata fetches,
   backup probes, and any `.php` / `.asp` / `.jsp` / `.cgi` extension via
   regex. A URI hit tags both the row and its client IP.

2. **Behavioral promotion after bulk ingest** — an IP with ≥ N attack-URI
   hits (default 2) or ≥ M requests at ≥ X% 4xx rate (default 15 / 70%)
   has **every one of its rows** (including earlier benign-looking ones)
   relocated to the malicious table via a single JOIN per source table.

Local IPs (RFC1918, loopback, link-local, CGNAT) are never classified as
malicious — a home router or internal scanner shouldn't land in the
attacker view. They live in the dynamic/static tables and are surfaced
via the Local view.

The Malicious view swaps in its own panel set: top attacker IPs, top
flag reasons, top probed URIs, target hosts, source countries.

### Drill-down filtering

Click any row in any panel (or any status segment, country, etc.) to add
an `include` filter for that value. Shift-click to add an `exclude`
filter. Filter chips along the top show the active set; each has an `×`
to remove it. Drag on the timeline to brush a time range; the drag keeps
tracking when your cursor leaves the chart, so "from some time ago
through now" is a single gesture. Dragging to the rightmost bucket leaves
the upper bound open so freshly-arriving live events still appear.

### Panels

Panels show top-10 by default with a **show 25 more** button beneath each
one that appends the next page without refetching the dashboard. Every
column header has a drag handle on its right edge — widths persist per
panel in `localStorage`. Every cell has a hover tooltip with the full
value plus a hits/visitors/bytes summary.

A top-bar `sort [hits] [data]` toggle swaps every panel's primary column
between hit count and total bytes. URIs by hits tend to be landing pages;
URIs by data expose the actual bandwidth drivers (firmware downloads,
video, wasm bundles). The Slow Requests panel keeps ordering by max
duration regardless of the toggle.

### Live tail

Plain `.log` files (not the `.gz` archives) are tailed from their current
EOF after bulk ingest. Each new row is classified and streamed over a
`/ws` websocket to every connected client; a small "live · N" badge
flashes in the corner as events arrive. Known-attacker IPs (URI-flagged
or behaviorally promoted) route directly to the malicious table so the
live-feed categorization matches the bulk ingest.

### Progress reporting

Every long-running phase (ingest, index build, behavioral scan,
malicious promotion, ANALYZE) reports progress through a throttled
callback — the CLI surfaces a line at least every 5s, well under any
reasonable "did it hang?" threshold:

```
[ingest] big-access.log 480,000
[index] idx_dyn_ip 0/3 (0%)
[behavioral] rule B: IPs with high 4xx rate
[promote] relocating rows from requests_dynamic
[promote] relocated 17,328 rows from requests_static
[index] done 14/14 (100%)
```

On a 1M-event synthetic log: ~66s for ingest, ~4s for promotion, ~5s for
post-ingest indexes + ANALYZE. The cached DB under
`$XDG_CACHE_HOME/caddylogs/<key>.db` is keyed by input paths + mtimes +
sizes, so unchanged inputs skip ingest on the next run (startup drops to
under a second).

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--listen` | `127.0.0.1:8080` | HTTP listen address |
| `--geoip` | `./GeoLite2-City.mmdb` | MaxMind mmdb for country/city (optional, soft fallback if missing) |
| `--cache-dir` | `$XDG_CACHE_HOME/caddylogs` | Where to keep ingested DBs |
| `--no-cache` | | Ingest into a tempfile, never reuse |
| `--open` | off | Launch the dashboard in the default browser |
| `--no-tail` | off | Exit after initial ingest; no live tailing |
| `--include-bots` | off | Stop auto-excluding bot traffic in the Real view |
| `--include-local` | off | Stop auto-excluding RFC1918 / loopback / link-local |
| `--bot-list PATH` | | Replace the embedded crawler list with this file |
| `--bot-pattern STRING` | | Add extra substrings to the bot matcher (repeatable) |
| `--static-ext EXT` | built-in list | Override static-asset extension list (repeatable) |
| `--attack-list PATH` | | Replace the embedded attack-URI pattern list |
| `--attack-pattern STRING` | | Add an attack-URI pattern (substring or `re:<regex>`, repeatable) |
| `--no-attack-detection` | off | Disable both URI and behavioral attack detection |
| `--attack-min-hits` | 15 | Behavioral threshold: minimum total requests to flag an IP |
| `--attack-err-rate` | 0.70 | Behavioral threshold: 4xx rate (0..1) to flag an IP |
| `--attack-min-uri-hits` | 2 | Behavioral threshold: IPs with ≥ N attack-URI hits flagged |

## Architecture

| Package | Purpose |
| --- | --- |
| `internal/parser` | Caddy JSON → normalized Event; handles `.gz`, tails plain files with rotation detection |
| `internal/classify` | Bot / static / local-IP / UA / GeoIP labeling; embeds goaccess's `browsers.list` and a curated `attacks.list` |
| `internal/progress` | Throttled progress-callback type shared by every long phase |
| `internal/backend` | Narrow `Store` interface. One parameterized `Query` method dispatches Overview / TopN / Timeline / Rows / StatusClass |
| `internal/sqlitestore` | SQLite-backed Store. Three physical tables (`requests_dynamic`, `requests_static`, `requests_malicious`); URI match + behavioral promotion move rows into malicious |
| `internal/ingest` | Drives parser → store in batches; `CacheKey` fingerprints inputs; `FinalizeAttacks` runs the promotion pass |
| `internal/livetail` | Tails live logs, classifies, writes to the store, broadcasts non-static rows to websocket clients |
| `internal/httpserver` | REST API (`/api/dashboard`, `/api/static`, `/api/panel`, `/api/rows`, `/api/classification`, `/api/query`, `/ws`), embedded UI, static-HTML report renderer |
| `cmd/caddylogs` | kingpin CLI, `serve` and `report` subcommands |

The `Store` interface is deliberately narrow — one `Query` method with a
parameterized `Query` struct — so a non-SQLite backend (e.g. a
stream-re-parse implementation for memory-constrained environments) can
be swapped in without changing any callers.

## Status

Working: parser, classifier, SQLite ingest with cached reuse, panel
queries with pagination, filter drill-down, timeline brush, live tail
with rotation handling, websocket broadcasts, embedded dashboard with
view switches and sort toggle, static-asset view, malicious
classification with URI + behavioral flagging, 8-cell request/data
breakdown, static HTML snapshot, throttled progress reporting.

Not yet wired: per-panel search/filter-within (paging is implemented;
substring search on a panel's group column is a natural next step);
server-side UA bucketing into coarser buckets than `mileusna/useragent`
returns.
