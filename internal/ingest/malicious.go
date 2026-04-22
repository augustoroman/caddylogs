package ingest

import (
	"context"

	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/progress"
	"github.com/augustoroman/caddylogs/internal/sqlitestore"
)

// FinalizeAttacks runs once after BulkFromFiles. It:
//   1. builds the ip indexes needed for fast promotion,
//   2. unions the classifier's URI-flagged IPs with the store's behavioral
//      attackers,
//   3. teaches the classifier the combined set so the live tail routes
//      subsequent rows directly to requests_malicious, and
//   4. moves every existing dynamic+static row belonging to a flagged IP
//      over to requests_malicious in a single JOIN-based pass per table.
//
// Returns the number of IPs flagged and rows relocated.
func FinalizeAttacks(ctx context.Context, store *sqlitestore.Store, cls *classify.Classifier, thresh sqlitestore.AttackerThresholds, prog progress.Func) (ips int, rowsMoved int64, err error) {
	if prog == nil {
		prog = progress.Nop
	}
	if err := store.BuildPreIngestIndexes(ctx, prog); err != nil {
		return 0, 0, err
	}
	all := map[string]string{}
	if cls != nil && cls.Attacks != nil {
		for ip, reason := range cls.Attacks.FlaggedIPs() {
			all[ip] = reason
		}
	}
	behavioral, err := store.ComputeBehavioralAttackers(ctx, thresh, prog)
	if err != nil {
		return 0, 0, err
	}
	for ip, reason := range behavioral {
		if _, ok := all[ip]; !ok {
			all[ip] = reason
		}
	}
	// Manual non-malicious tags win over every heuristic. Drop them from
	// the promote set so a user-declared "real"/"local"/"bot" IP is not
	// relocated to malicious by the behavioral rule.
	if cls != nil && cls.ManualTags != nil {
		for ip := range all {
			if t, ok := cls.ManualTags.Get(ip); ok && t != classify.ManualTagMalicious {
				delete(all, ip)
			}
		}
	}
	if cls != nil && cls.Attacks != nil {
		for ip, reason := range all {
			cls.Attacks.FlagIP(ip, reason)
		}
	}
	rowsMoved, err = store.PromoteFlaggedIPs(ctx, all, prog)
	return len(all), rowsMoved, err
}
