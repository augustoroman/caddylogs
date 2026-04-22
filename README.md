# caddylogs

Interactive analyzer for Caddy's JSON access logs. Parses historical
`.log.gz` files and the live `.log`, indexes every event in a local SQLite
database, and serves a goaccess-style dashboard with click-to-drill
filtering across IP, host, URI, status, country, city, referrer, browser,
OS, device, and time range.

Static-asset requests are ingested but kept in a separate cold table so the
hot path is not dragged down by them. A **Load static asset stats** button
computes static summaries on demand against whichever filters are currently
applied.

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

### Useful flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--listen` | `127.0.0.1:8080` | HTTP listen address |
| `--geoip` | `./GeoLite2-City.mmdb` | MaxMind mmdb for country/city (optional) |
| `--cache-dir` | `$XDG_CACHE_HOME/caddylogs` | Where to keep ingested DBs |
| `--no-cache` | | Ingest into a tempfile, do not reuse |
| `--include-bots` | off | Stop auto-excluding bot traffic |
| `--include-local` | off | Stop auto-excluding RFC1918 / loopback |
| `--bot-list PATH` | | Replace the embedded crawler list with this file |
| `--bot-pattern STRING` | | Add extra substrings to the bot matcher (repeatable) |
| `--static-ext EXT` | built-in list | Override static-asset extension list (repeatable) |
| `--open` | off | Launch the dashboard in the default browser |
| `--no-tail` | off | Exit after initial ingest; no live tailing |

The input paths accept shell globs (either pre-expanded by the shell or
quoted so `filepath.Glob` handles them).

### Static HTML snapshot

```
./caddylogs report /var/log/caddy/access.log /var/log/caddy/access-*.log.gz \
    --out report.html
```

Produces a single self-contained HTML file with no JS and no websocket. The
same default filters (hide bots, hide local IPs) that the live dashboard
applies are baked into the snapshot so a shared report will not silently
disagree with the live view.

## Architecture

| Package | Purpose |
| --- | --- |
| `internal/parser` | Caddy JSON → normalized Event; handles `.gz`, tails plain files with rotation detection |
| `internal/classify` | Bot/static/local-IP/UA/GeoIP labeling; embeds goaccess's `browsers.list` |
| `internal/backend` | Narrow `Store` interface. One parameterized `Query` method dispatches Overview / TopN / Timeline / Rows / StatusClass |
| `internal/sqlitestore` | SQLite-backed Store. Splits rows into `requests_dynamic` and `requests_static`; indices created at `MarkIngestComplete` |
| `internal/ingest` | Drives parser → store in batches; computes a path+mtime+size cache key |
| `internal/livetail` | Tails live logs, classifies, writes to the store, broadcasts to websocket clients |
| `internal/httpserver` | REST API, websocket hub, embedded UI (HTML/CSS/JS), static-HTML report renderer |
| `cmd/caddylogs` | kingpin CLI, `serve` and `report` subcommands |

The `Store` interface is deliberately narrow so a non-SQLite backend (e.g.
stream-re-parse for memory-constrained environments) can be swapped in
without changing call sites.

## Status

Working: parser, classifier, SQLite ingest, panel queries, filter
drill-down, live tail, websocket, embedded dashboard, static-asset panel on
demand, static HTML snapshot, cache reuse across runs.

Not yet: UA-parser is pass-through from `mileusna/useragent`; some tuning
may help; server-side UA categorization into coarser buckets is on my list.
Per-panel "show all / paginate" modal is missing — currently top-10 only.
