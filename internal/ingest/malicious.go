package ingest

import (
	"context"

	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/sqlitestore"
)

// FinalizeAttacks is called once after BulkFromFiles completes. It unions
// the IPs the classifier flagged via URI pattern match with the IPs a
// behavioral pass over the store turned up, teaches the classifier the
// combined set (so live tail routes them correctly), and moves all of
// their existing dynamic+static rows into the malicious table. Returns the
// number of IPs flagged and rows relocated.
func FinalizeAttacks(ctx context.Context, store *sqlitestore.Store, cls *classify.Classifier, thresh sqlitestore.AttackerThresholds) (ips int, rowsMoved int64, err error) {
	all := map[string]string{}
	if cls != nil && cls.Attacks != nil {
		for ip, reason := range cls.Attacks.FlaggedIPs() {
			all[ip] = reason
		}
	}
	behavioral, err := store.ComputeBehavioralAttackers(ctx, thresh)
	if err != nil {
		return 0, 0, err
	}
	for ip, reason := range behavioral {
		if _, ok := all[ip]; !ok {
			all[ip] = reason
		}
	}
	// Feed the combined set back into the classifier so new rows via live
	// tail are routed directly to malicious without waiting for another
	// promotion pass.
	if cls != nil && cls.Attacks != nil {
		for ip, reason := range all {
			cls.Attacks.FlagIP(ip, reason)
		}
	}
	rowsMoved, err = store.PromoteFlaggedIPs(ctx, all)
	return len(all), rowsMoved, err
}
