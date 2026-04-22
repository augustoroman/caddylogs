package classifier

import (
	"context"
	"fmt"
	"time"

	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/sqlitestore"
)

// RunResult summarizes what one classifier run changed. The UI surfaces
// these three counts; the JSON shape is also what the POST /api/
// classifiers/run endpoint returns verbatim.
type RunResult struct {
	Name    string     `json:"name"`
	Added   []Decision `json:"added,omitempty"`
	Removed []string   `json:"removed,omitempty"`
	Skipped []string   `json:"skipped,omitempty"`
	Elapsed int64      `json:"elapsed_ms"`
}

// Runner executes classifiers and reconciles their output with the
// persistent tag set. It owns the "manual wins, classifier edits only
// its own tags" policy so individual classifiers stay logic-only.
type Runner struct {
	store *sqlitestore.Store
	tags  *classify.ManualTagSet
}

// NewRunner binds a runner to the store and tag set the dashboard uses.
// The runner writes to both: Store.ApplyManualTag to move rows, and
// ManualTagSet.SetFrom/Delete to persist the tag record.
func NewRunner(store *sqlitestore.Store, tags *classify.ManualTagSet) *Runner {
	return &Runner{store: store, tags: tags}
}

// Run executes one classifier and applies the delta relative to the tag
// set the same classifier last produced. Semantics:
//
//   - If an IP appears in the classifier's new output AND has no tag
//     from this classifier yet AND is not manually overridden AND is
//     not already claimed by a DIFFERENT classifier, it is tagged now
//     (both the DB rows and the JSON).
//   - If an IP was tagged by this classifier previously but is not in
//     the new output, the tag is removed and the IP's rows are reverted
//     to the "real" state (is_bot/is_local flipped back, moved out of
//     the malicious table if applicable) — reverting is safe because
//     classifiers only ever tag IPs that were in the real pool.
//   - Manual tags always win: an IP the operator has tagged (Source =
//     SourceManual) appears in Skipped and is left alone.
//   - A classifier never steals another classifier's tags. With two
//     rules that overlap (e.g. root-only-burst ⊂ no-static-ever), the
//     first to tag an IP keeps it; the second sees the IP in Skipped.
//     Classifier order in BuiltIn() effectively sets priority:
//     specific rules register before general ones so the more
//     informative tag wins. To transfer ownership, the operator
//     untags manually (clears both the manual_tags row and the JSON
//     entry) and re-runs the target classifier.
//
// Returning early on any store/tag error leaves partial state in place;
// a subsequent run will re-apply the remainder.
func (r *Runner) Run(ctx context.Context, c Classifier) (*RunResult, error) {
	start := time.Now()

	prev := r.tags.ListBySource(c.Name())
	prevByIP := make(map[string]classify.ManualTagListEntry, len(prev))
	claimed := make([]string, 0, len(prev))
	for _, e := range prev {
		prevByIP[e.IP] = e
		claimed = append(claimed, e.IP)
	}

	decisions, err := c.Run(ctx, RunEnv{DB: r.store.DB(), Claimed: claimed})
	if err != nil {
		return nil, err
	}

	newByIP := make(map[string]Decision, len(decisions))
	for _, d := range decisions {
		newByIP[d.IP] = d
	}

	// Partition the full tag set into "manual" (always skip) and
	// "owned by a different classifier" (also skip) in a single pass.
	// Tags owned by THIS classifier are tracked separately in prev.
	ownedByOther := map[string]bool{}
	manualByIP := map[string]bool{}
	for _, e := range r.tags.List() {
		switch {
		case e.Source == classify.SourceManual:
			manualByIP[e.IP] = true
		case e.Source != "" && e.Source != c.Name():
			ownedByOther[e.IP] = true
		}
	}

	result := &RunResult{Name: c.Name()}

	for ip, d := range newByIP {
		if manualByIP[ip] || ownedByOther[ip] {
			result.Skipped = append(result.Skipped, ip)
			continue
		}
		if _, already := prevByIP[ip]; already {
			// Refresh the reason/timestamp so the UI reflects the
			// current rule output rather than the first-tag moment.
			if err := r.tags.SetFrom(ip, d.Tag, c.Name(), d.Reason); err != nil {
				return nil, fmt.Errorf("refresh tag %s: %w", ip, err)
			}
			continue
		}
		if err := r.store.ApplyManualTag(ctx, ip, d.Tag); err != nil {
			return nil, fmt.Errorf("apply tag %s=%s: %w", ip, d.Tag, err)
		}
		if err := r.tags.SetFrom(ip, d.Tag, c.Name(), d.Reason); err != nil {
			return nil, fmt.Errorf("persist tag %s: %w", ip, err)
		}
		result.Added = append(result.Added, d)
	}

	for ip := range prevByIP {
		if _, stillCandidate := newByIP[ip]; stillCandidate {
			continue
		}
		// Revert row classification: classifiers operate only on "real"
		// candidates, so returning them to real is the right undo.
		if err := r.store.ApplyManualTag(ctx, ip, classify.ManualTagReal); err != nil {
			return nil, fmt.Errorf("revert tag %s: %w", ip, err)
		}
		if err := r.store.RemoveManualTag(ctx, ip); err != nil {
			return nil, fmt.Errorf("remove DB tag %s: %w", ip, err)
		}
		if err := r.tags.Delete(ip); err != nil {
			return nil, fmt.Errorf("delete persisted tag %s: %w", ip, err)
		}
		result.Removed = append(result.Removed, ip)
	}

	result.Elapsed = time.Since(start).Milliseconds()
	return result, nil
}

// ByName looks up a classifier in cs by name. Returns nil when no match.
func ByName(cs []Classifier, name string) Classifier {
	for _, c := range cs {
		if c.Name() == name {
			return c
		}
	}
	return nil
}
