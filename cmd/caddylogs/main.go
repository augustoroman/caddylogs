// caddylogs is an interactive dashboard for Caddy's JSON access logs. It
// ingests rotated .gz and live .log files into a SQLite database, classifies
// each event (bot/static/local, browser/os/device, country/city), and serves
// a goaccess-style drill-down UI backed by a websocket for live updates.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
)

func main() {
	app := kingpin.New("caddylogs", "Interactive analyzer for Caddy JSON access logs.")
	app.HelpFlag.Short('h')
	app.Version("caddylogs 0.1.0-dev")

	// Shared flags used by both subcommands live here.
	serveCmd := app.Command("serve", "Ingest logs and run the interactive web dashboard with live tail.").Default()
	serveOpts := bindServeFlags(serveCmd)

	reportCmd := app.Command("report", "Render a static HTML snapshot of the current filter set.")
	reportOpts := bindReportFlags(reportCmd)

	chosen, err := app.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	switch chosen {
	case serveCmd.FullCommand():
		if err := runServe(ctx, serveOpts); err != nil {
			fmt.Fprintln(os.Stderr, "serve:", err)
			os.Exit(1)
		}
	case reportCmd.FullCommand():
		if err := runReport(ctx, reportOpts); err != nil {
			fmt.Fprintln(os.Stderr, "report:", err)
			os.Exit(1)
		}
	}
}
