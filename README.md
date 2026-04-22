# caddylogs

Interactive log analyzer for Caddy's JSON access logs. Parses rotated/gzipped
history plus the live current log, and exposes a goaccess-style web dashboard
with click-to-drill filtering across IP, host, URI, status, country, city,
referrer, browser, OS, device, and time range.

Static asset requests are ingested but kept in a separate cold table so they
don't bloat the interactive path; a "Load static asset stats" button computes
summaries on demand using the currently-applied filters.

## Status

Work in progress.

## Quick start

```
go build ./cmd/caddylogs
./caddylogs serve /path/to/caddy/access.log /path/to/caddy/access-*.log.gz
```

Open http://127.0.0.1:8080.

For a static HTML snapshot:

```
./caddylogs report --out report.html /path/to/caddy/access.log
```
