package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/augustoroman/caddylogs/internal/classifier"
	"github.com/augustoroman/caddylogs/internal/classify"
)

// classifierEval holds one classifier's independent-run metrics against
// the ground-truth tag set.
type classifierEval struct {
	name      string
	elapsed   time.Duration
	cands     int             // total candidates the rule produced
	caughtSet map[string]bool // candidates that are in the bad ground-truth set
	newCount  int             // candidates in neither the bad nor good ground-truth sets
	fpSet     []string        // candidates that are in the good (real/local) set
}

// runAnalyze evaluates each heuristic classifier in isolation against the
// current tag set ("ground truth") and reports, per classifier: how much
// of the currently-flagged set it recovers on its own, how long it takes,
// how many flags are unique to it, how many untagged IPs it would newly
// flag, and how many known-good (manually real/local) IPs it wrongly
// flags. It also surfaces the inverse signal the operator asked for —
// currently-flagged IPs that NO classifier corroborates, which are either
// coverage gaps or candidates for mis-tagged ground truth.
//
// The evaluation runs against a fresh, tag-free baseline: a no-cache
// ingest with the automatic attack-detection/behavioral promotion applied
// but WITHOUT any manual or heuristic tags written to the DB. Each rule is
// thus judged on what it independently recovers from the raw data rather
// than on a DB already shaped by the tags it's being scored against.
func runAnalyze(ctx context.Context, opts *analyzeFlags) error {
	paths, err := expandPaths(opts.Paths)
	if err != nil {
		return err
	}
	cls, err := buildClassifier(opts.commonFlags)
	if err != nil {
		return err
	}
	defer cls.Close()

	opts.NoCache = true // always evaluate on a clean, tag-free ingest
	store, cached, err := openStore(ctx, opts.commonFlags, cls, paths)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := initialIngest(ctx, store, cls, paths, cached, opts.commonFlags); err != nil {
		return err
	}

	// Ground truth: the current tag set, read-only — never applied to the DB.
	gtPath, err := resolveTagsFile(opts.TagsFile)
	if err != nil {
		return err
	}
	gt, err := classify.LoadManualTagSet(gtPath)
	if err != nil {
		return err
	}

	badGT := map[string]classify.ManualTagListEntry{}  // tagged malicious|bot
	goodGT := map[string]classify.ManualTagListEntry{} // tagged real|local
	manualBad := map[string]bool{}                     // bad set the operator set by hand
	for _, e := range gt.List() {
		switch e.Tag {
		case classify.ManualTagMalicious, classify.ManualTagBot:
			badGT[e.IP] = e
			if e.Source == "" || e.Source == classify.SourceManual {
				manualBad[e.IP] = true
			}
		case classify.ManualTagReal, classify.ManualTagLocal:
			goodGT[e.IP] = e
		}
	}

	classifiers, err := buildClassifiers(opts.commonFlags)
	if err != nil {
		return err
	}

	var results []classifierEval
	caughtCount := map[string]int{} // bad IP -> # classifiers that caught it
	fpByIP := map[string][]string{} // good IP -> classifiers that flagged it

	for _, c := range classifiers {
		t0 := time.Now()
		decs, err := c.Run(ctx, classifier.RunEnv{DB: store.DB()})
		el := time.Since(t0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "analyze: classifier %s failed: %v\n", c.Name(), err)
			continue
		}
		r := classifierEval{name: c.Name(), elapsed: el, cands: len(decs), caughtSet: map[string]bool{}}
		for _, d := range decs {
			if _, ok := badGT[d.IP]; ok {
				r.caughtSet[d.IP] = true
				caughtCount[d.IP]++
			} else if _, ok := goodGT[d.IP]; ok {
				r.fpSet = append(r.fpSet, d.IP)
				fpByIP[d.IP] = append(fpByIP[d.IP], c.Name())
			} else {
				r.newCount++
			}
		}
		results = append(results, r)
	}

	printAnalysis(results, badGT, goodGT, manualBad, caughtCount, fpByIP, opts.ListAll)
	return nil
}

func printAnalysis(
	results []classifierEval,
	badGT, goodGT map[string]classify.ManualTagListEntry,
	manualBad map[string]bool,
	caughtCount map[string]int,
	fpByIP map[string][]string,
	listAll bool,
) {
	nBad := len(badGT)
	// Sort by recall (caught) desc, then by speed.
	sort.Slice(results, func(i, j int) bool {
		if len(results[i].caughtSet) != len(results[j].caughtSet) {
			return len(results[i].caughtSet) > len(results[j].caughtSet)
		}
		return results[i].elapsed < results[j].elapsed
	})

	fmt.Printf("Ground truth: %d flagged (bad) IP(s) — %d set manually, %d by classifiers; %d known-good (real/local).\n\n",
		nBad, len(manualBad), nBad-len(manualBad), len(goodGT))

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "classifier\trun\tcands\tcaught\tcov%\tuniq\tnew\tFP\tcaught/s")
	for _, r := range results {
		caught := len(r.caughtSet)
		uniq := 0
		for ip := range r.caughtSet {
			if caughtCount[ip] == 1 {
				uniq++
			}
		}
		perSec := "—"
		if s := r.elapsed.Seconds(); s > 0 {
			perSec = fmt.Sprintf("%.0f", float64(caught)/s)
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%.1f%%\t%d\t%d\t%d\t%s\n",
			r.name, r.elapsed.Round(time.Millisecond), r.cands, caught, pct(caught, nBad), uniq, r.newCount, len(r.fpSet), perSec)
	}
	w.Flush()
	fmt.Println("\n  caught = currently-flagged IPs this rule recovers alone · uniq = caught by only this rule")
	fmt.Println("  new    = untagged IPs it would newly flag · FP = known-good (real/local) IPs it flags")

	// Combined coverage across every classifier.
	fmt.Printf("\nUnion: %d/%d bad IP(s) caught by at least one classifier (%.1f%%).\n",
		len(caughtCount), nBad, pct(len(caughtCount), nBad))

	// Bad IPs no classifier caught: coverage gaps. Manual ones are the
	// operator's "all classifiers think this is OK" set — possible mis-tags.
	type miss struct{ ip, src, reason string }
	var misses, manualMisses []miss
	for ip, e := range badGT {
		if caughtCount[ip] == 0 {
			m := miss{ip: ip, src: srcOf(e), reason: e.Reason}
			misses = append(misses, m)
			if manualBad[ip] {
				manualMisses = append(manualMisses, m)
			}
		}
	}
	byIP := func(s []miss) { sort.Slice(s, func(i, j int) bool { return s[i].ip < s[j].ip }) }
	byIP(misses)
	byIP(manualMisses)

	fmt.Printf("\nCaught by NO classifier: %d bad IP(s) (%d of them manually tagged).\n",
		len(misses), len(manualMisses))
	fmt.Println("  Manually-tagged-bad IPs that every classifier thinks are OK (possible mis-tags):")
	if len(manualMisses) == 0 {
		fmt.Println("    (none)")
	} else {
		limit := len(manualMisses)
		if !listAll && limit > 20 {
			limit = 20
		}
		for _, m := range manualMisses[:limit] {
			line := fmt.Sprintf("    %-39s %s", m.ip, m.src)
			if m.reason != "" {
				line += "  — " + m.reason
			}
			fmt.Println(line)
		}
		if limit < len(manualMisses) {
			fmt.Printf("    … and %d more (use --list to show all)\n", len(manualMisses)-limit)
		}
	}

	// Known-good IPs that some classifier would flag: false positives.
	fmt.Printf("\nFalse positives: %d known-good IP(s) flagged by ≥1 classifier.\n", len(fpByIP))
	if len(fpByIP) > 0 {
		goodIPs := make([]string, 0, len(fpByIP))
		for ip := range fpByIP {
			goodIPs = append(goodIPs, ip)
		}
		sort.Strings(goodIPs)
		limit := len(goodIPs)
		if !listAll && limit > 20 {
			limit = 20
		}
		for _, ip := range goodIPs[:limit] {
			e := goodGT[ip]
			fmt.Printf("  %-39s %-9s by %s\n", ip, string(e.Tag), strings.Join(fpByIP[ip], ", "))
		}
		if limit < len(goodIPs) {
			fmt.Printf("  … and %d more (use --list to show all)\n", len(goodIPs)-limit)
		}
	}
}

func srcOf(e classify.ManualTagListEntry) string {
	if e.Source == "" {
		return classify.SourceManual
	}
	return e.Source
}

func pct(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d) * 100
}
