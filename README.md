# caddylogs

Interactive analyzer for Caddy's JSON access logs. Parses historical
`.log.gz` files plus the live `.log`, indexes every event in a local SQLite
database, and serves a goaccess-style dashboard with click-to-drill
filtering across IP, host, URI, status, country, city, referrer, browser,
OS, device, and time range.

Traffic is split end-to-end into **real**, **bot**, **local**, and
**malicious** categories, with a header strip showing the breakdown by
both request count and bytes served. Static assets are ingested into a
cold table so the hot path stays fast. Suspected-malicious clients
(matched by attack URI patterns or flagged behaviorally) are quarantined
in their own table with a dedicated drill-down view. A pluggable
heuristic classifier framework reclassifies IPs whose UA looks benign
but whose behavior is bot-like (root-only probing, regular polling,
HEAD-only liveness checks, HTTP/1.0-only clients), and operators can
manually tag any IP from the dashboard with overrides that survive
cache rebuilds.

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

### Subcommands

| Command | Purpose |
| --- | --- |
| `serve` | Ingest, serve the live dashboard, tail new events. Default. |
| `report` | Render a static HTML snapshot to `--out` (default `report.html`) and exit. |
| `clear-cache` | Delete cached ingest DBs and exit. With paths, targets just those files' cache; with `--all`, empties the cache dir. |

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

Five top-level view switches at the top of the page:

| View | Table | Default filters |
| --- | --- | --- |
| **Real** | `requests_dynamic` | `is_bot=false`, `is_local=false` |
| **Static** | `requests_static` | `is_bot=false`, `is_local=false` |
| **Local** | `requests_dynamic` | include `is_local=true` |
| **Bots** | `requests_dynamic` | include `is_bot=true` |
| **Malicious** | `requests_malicious` | none — bots are exactly what you want to see here |

### Classification breakdown

The header strip shows two stacked bars — one sized by request count and
one by bytes served — split into eight segments:

```
real doc · real static · bot doc · bot static · local doc · local static · mal doc · mal static
```

Hover any segment for both metrics; click to jump to the matching view
(bot segments land in the Bots view). The bytes bar reveals traffic that
hit count alone obscures — e.g. "malicious is 66% of requests but 0.4%
of bandwidth" (scanner 404s return empty bodies) while "real is 28% of
requests and 77% of bandwidth".

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
via the Local view. Manual operator tags and non-malicious classifier
tags also preempt behavioral promotion: an IP explicitly tagged `real`
will not be relocated to the malicious table even if its 4xx rate
crosses the threshold.

The Malicious view swaps in its own panel set: top attacker IPs, top
flag reasons, top probed URIs, target hosts, source countries.

### Heuristic classifiers

A pluggable framework reclassifies IPs whose behavior looks bot-like
even when UA-based detection missed them. Classifiers ship with
caddylogs, run automatically after ingest, and can be re-run on demand
from a panel in the dashboard. Each rule owns a `source` name; tags it
applies carry that name so the operator can tell which rule fired (and
with what reason — e.g. "3 / hit(s) across 3 UTC day(s); no static").

The built-in rules:

| Name | Pattern |
| --- | --- |
| `root-only-burst` | 4+ hits to `/` in a UTC day OR `/` hits across 2+ distinct days, and no static-asset requests (favicon, robots.txt, and social-card previews don't count). |
| `cadence-polling` | 7+ inter-request intervals whose coefficient of variation is under 25% with a mean interval ≥ 60s — uptime monitors, cron scrapers, status-page pollers. |
| `head-only` | 4+ requests, all `HEAD`. |
| `http10-only` | 4+ requests, all `HTTP/1.0`. |
| `no-static-ever` | 6+ dynamic requests and no static hits ever. The generalization of `root-only-burst` — HTML scrapers and deep-link crawlers that don't only hit `/`. |

Re-running a classifier reconciles against the tags it previously
applied: IPs newly matching its rule are tagged, IPs that no longer
match are reverted, and IPs already tagged by the operator or by
another classifier are left alone (shown in a `skipped` count on the
Run button's response). Registration order sets priority when two
rules overlap (e.g. `root-only-burst` ⊂ `no-static-ever`): the first
registered wins, so more specific rules apply before general ones.

Disable the automatic startup run with `--no-classifiers`; the Run
button in the UI stays available either way.

### Manual IP tagging

Right-click any IP — in a top-IPs panel, the raw events list, a
live-tail row, or an IP filter chip — to open a four-option menu:
**Real / Local / Bot / Malicious**. The server persists the tag, moves
existing rows between the dynamic / static / malicious tables, flips
`is_bot` / `is_local` flags to match, and teaches the classifier so
future live-tail events for that IP are classified the same way.

Tags are stored in a JSON file outside the cache dir (default
`$XDG_CONFIG_HOME/caddylogs/tags.json`, override with `--tags-file`)
so they survive cache-key invalidation — changing the size or mtime
of any input file would otherwise rebuild the ingest DB and lose any
in-DB tags.

The dashboard has a collapsible **Manual IP tags** panel listing
every override with its IP, tag, source (`manual` or a classifier
name), and timestamp; each row has an Untag button. Manual tags
always win over classifier rules, so an IP explicitly tagged `real`
stays `real` across every subsequent classifier run.

### Drill-down filtering

Click any row in any panel (or any status segment, country, etc.) to
add an `include` filter for that value. Clicking a new IP replaces any
previous IP filter (they're almost always "switch to this one", not
"union with the previous"); other dimensions stay additive so unions
like "both 4xx and 5xx" still work. Shift-click on most rows to add an
`exclude` filter.

Filter chips along the top show the active set; each has an `×` to
remove it. Two free-text inputs next to the chips let you filter by
exact IP or by URL substring (shown as a green `uri ∋ …` chip).

Drag on the timeline to brush a time range; the drag keeps tracking
when your cursor leaves the chart, so "from some time ago through now"
is a single gesture. Dragging to the rightmost bucket leaves the upper
bound open so freshly-arriving live events still appear. Six preset
buttons in the timeline title (**7d / 30d / 3mo / 6mo / 1y / all**) jump
to "last N days ending at the freshest known timestamp" — useful for
historical logs where wall-clock "last 7 days" would be empty.

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

Live events that don't match the current view's filter still appear in
Recent requests, rendered with a muted italic style and a left-border
marker, so you see new activity without the feed misleadingly
contradicting the panels above it.

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
caddylogs: classifier root-only-burst: +12 / -0 / skipped 0 (18ms)
caddylogs: classifier cadence-polling: +3 / -0 / skipped 2 (22ms)
```

On a 1M-event synthetic log: ~66s for ingest, ~4s for promotion, ~5s for
post-ingest indexes + ANALYZE. The cached DB under
`$XDG_CACHE_HOME/caddylogs/<key>.db` is keyed by input paths + mtimes +
sizes, so unchanged inputs skip ingest on the next run (startup drops to
under a second). Manual tags live outside the cache and are replayed
into whichever DB is active, so they survive cache invalidation.

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--listen` | `127.0.0.1:8080` | HTTP listen address |
| `--geoip` | `./GeoLite2-City.mmdb` | MaxMind mmdb for country/city (optional, soft fallback if missing) |
| `--cache-dir` | `$XDG_CACHE_HOME/caddylogs` | Where to keep ingested DBs |
| `--no-cache` | | Ingest into a tempfile, never reuse |
| `--tags-file` | `$XDG_CONFIG_HOME/caddylogs/tags.json` | Persistent manual-tag store (lives outside the cache) |
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
| `--no-classifiers` | off | Skip the built-in heuristic classifiers at startup (Run buttons in the UI still work) |
| `--all` | | `clear-cache` only: delete every cached DB in the cache dir |
| `--out` | `report.html` | `report` only: output path for the static HTML snapshot |

## Architecture

| Package | Purpose |
| --- | --- |
| `internal/parser` | Caddy JSON → normalized Event; handles `.gz`, tails plain files with rotation detection |
| `internal/classify` | Bot / static / local-IP / UA / GeoIP labeling; embeds goaccess's `browsers.list` and a curated `attacks.list`. Also holds the manual-tag set (`ManualTagSet`) consulted at classification time |
| `internal/classifier` | Pluggable heuristic-rule framework. A `Classifier` interface (`Name`, `Description`, `Run(ctx, RunEnv)`) plus a `Runner` that diffs new candidates against the rule's last tag set, respects manual overrides and other classifiers' claims, and applies add/remove deltas |
| `internal/progress` | Throttled progress-callback type shared by every long phase |
| `internal/backend` | Narrow `Store` interface. One parameterized `Query` method dispatches Overview / TopN / Timeline / Rows / StatusClass. Filters are `Include` / `Exclude` / `Contains` maps plus a time window |
| `internal/sqlitestore` | SQLite-backed Store. Three physical tables (`requests_dynamic`, `requests_static`, `requests_malicious`); URI match + behavioral promotion move rows into malicious. Exposes `ApplyManualTag` / `RemoveManualTag` for tag-driven row relocation, and `DB()` for classifier SQL |
| `internal/ingest` | Drives parser → store in batches; `CacheKey` fingerprints inputs; `FinalizeAttacks` runs the promotion pass (and skips manually-tagged non-malicious IPs) |
| `internal/livetail` | Tails live logs, classifies, writes to the store, broadcasts non-static rows to websocket clients |
| `internal/httpserver` | REST API (`/api/dashboard`, `/api/static`, `/api/panel`, `/api/rows`, `/api/classification`, `/api/query`, `/api/tag`, `/api/tags`, `/api/classifiers`, `/api/classifiers/run`, `/ws`), embedded UI, static-HTML report renderer |
| `cmd/caddylogs` | kingpin CLI: `serve`, `report`, `clear-cache` subcommands |

The `Store` interface is deliberately narrow — one `Query` method with a
parameterized `Query` struct — so a non-SQLite backend (e.g. a
stream-re-parse implementation for memory-constrained environments) can
be swapped in without changing any callers.

The `Classifier` interface is equally narrow — the rule writes whatever
SQL it wants against the raw `*sql.DB`, and everything tag-related
(persistence, diff, UI plumbing) is handled by the runner — so new rules
plug in without touching the dashboard.
