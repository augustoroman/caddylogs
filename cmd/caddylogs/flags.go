package main

import (
	"github.com/alecthomas/kingpin/v2"
)

// commonFlags captures flags used by both serve and report.
type commonFlags struct {
	Paths             []string
	GeoIPPath         string
	CacheDir          string
	NoCache           bool
	BotList           string
	BotPatterns       []string
	StaticExts        []string
	IncludeLocal      bool
	IncludeBots       bool
	AttackList        string
	AttackPatterns    []string
	NoAttackDetection bool
	AttackMinHits     int
	AttackErrRate     float64
	AttackMinURIHits  int
}

// serveFlags extends commonFlags with server-specific options.
type serveFlags struct {
	commonFlags
	Listen       string
	NoTail       bool
	OpenBrowser  bool
}

// reportFlags extends commonFlags with report-specific options.
type reportFlags struct {
	commonFlags
	Out string
}

func bindCommon(cmd *kingpin.CmdClause, c *commonFlags) {
	cmd.Arg("paths", "Caddy log files (.log or .log.gz); supports shell globs.").
		Required().StringsVar(&c.Paths)
	cmd.Flag("geoip", "Path to a MaxMind GeoLite2-City.mmdb for country/city lookup.").
		Default("./GeoLite2-City.mmdb").StringVar(&c.GeoIPPath)
	cmd.Flag("cache-dir", "Where to keep ingested SQLite DBs. Empty means the OS cache dir.").
		StringVar(&c.CacheDir)
	cmd.Flag("no-cache", "Ingest into an ephemeral tempfile; never reuse a prior DB.").
		BoolVar(&c.NoCache)
	cmd.Flag("bot-list", "Override the embedded bot pattern list with a file (one pattern per line).").
		StringVar(&c.BotList)
	cmd.Flag("bot-pattern", "Additional case-insensitive substring pattern to treat as a bot. Repeatable.").
		StringsVar(&c.BotPatterns)
	cmd.Flag("static-ext", "Treat URIs ending in this extension as static assets. Repeatable; overrides defaults when given.").
		StringsVar(&c.StaticExts)
	cmd.Flag("include-local", "Do not auto-exclude RFC1918 / loopback / link-local IPs.").
		BoolVar(&c.IncludeLocal)
	cmd.Flag("include-bots", "Do not auto-exclude requests whose UA matches a bot pattern.").
		BoolVar(&c.IncludeBots)
	cmd.Flag("attack-list", "Replace the embedded attack-URI pattern list with a file.").
		StringVar(&c.AttackList)
	cmd.Flag("attack-pattern", "Additional attack-URI pattern (substring, or re:<regex>). Repeatable.").
		StringsVar(&c.AttackPatterns)
	cmd.Flag("no-attack-detection", "Disable URI-pattern and behavioral attack detection entirely.").
		BoolVar(&c.NoAttackDetection)
	cmd.Flag("attack-min-hits", "Behavioral threshold: ignore IPs with fewer than N total requests.").
		Default("15").IntVar(&c.AttackMinHits)
	cmd.Flag("attack-err-rate", "Behavioral threshold: fraction of 4xx responses (0..1) required to flag an IP.").
		Default("0.70").Float64Var(&c.AttackErrRate)
	cmd.Flag("attack-min-uri-hits", "Behavioral threshold: IPs with at least N attack-URI hits are flagged.").
		Default("2").IntVar(&c.AttackMinURIHits)
}

func bindServeFlags(cmd *kingpin.CmdClause) *serveFlags {
	s := &serveFlags{}
	bindCommon(cmd, &s.commonFlags)
	cmd.Flag("listen", "HTTP listen address for the dashboard.").
		Default("127.0.0.1:8080").StringVar(&s.Listen)
	cmd.Flag("no-tail", "Skip live tailing; exit after the interactive session would normally remain open.").
		BoolVar(&s.NoTail)
	cmd.Flag("open", "Open the dashboard in the default browser once it's listening.").
		BoolVar(&s.OpenBrowser)
	return s
}

func bindReportFlags(cmd *kingpin.CmdClause) *reportFlags {
	r := &reportFlags{}
	bindCommon(cmd, &r.commonFlags)
	cmd.Flag("out", "Path to write the static HTML report to.").
		Default("report.html").StringVar(&r.Out)
	return r
}
