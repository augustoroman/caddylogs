// Package classifier provides a pluggable framework for heuristic IP
// classification. A Classifier scans the store's "real" pool
// (is_bot=0, is_local=0, not in requests_malicious) and returns a set
// of IPs that fit a pattern — today only bot patterns, but the type
// allows any ManualTag value so future rules can tag as local or
// malicious just as easily.
//
// The Runner handles persistence: classifier-applied tags live in the
// same external JSON file as operator-applied ones, distinguished by
// a Source field set to the classifier's name. Re-running a classifier
// diffs the new candidate set against the previously-applied set and
// applies only the delta, so changes to the rule are picked up without
// the operator needing to think about sync.
package classifier

import (
	"context"
	"database/sql"

	"github.com/augustoroman/caddylogs/internal/classify"
)

// Decision is a single "IP X should be tagged Tag because Reason" verdict
// produced by a classifier. The Runner applies the tag by calling
// store.ApplyManualTag and then recording the tag in the external set
// with Source = classifier.Name().
type Decision struct {
	IP     string             `json:"ip"`
	Tag    classify.ManualTag `json:"tag"`
	Reason string             `json:"reason,omitempty"`
}

// Classifier is the minimal contract every heuristic rule satisfies. The
// runner invokes Run with the store's raw *sql.DB so each rule is free
// to pick the SQL shape that matches its data access pattern — the
// alternative is a wider generic interface that ends up exposing almost
// everything in the store anyway.
//
// Run returns the COMPLETE current candidate set. The Runner is
// responsible for computing the add/remove delta vs. the tags this
// classifier applied last time; implementations should NOT try to be
// incremental themselves.
type Classifier interface {
	Name() string
	Description() string
	Run(ctx context.Context, db *sql.DB) ([]Decision, error)
}

// Info is the public-facing summary shown in the UI.
type Info struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// BuiltIn returns the set of classifiers that ship with caddylogs. New
// rules added to the binary register here. User-defined classifiers
// (e.g. SQL-template ones) would be registered at serve-time alongside
// these.
func BuiltIn() []Classifier {
	return []Classifier{
		NewRootOnly(),
	}
}

// InfoList is the JSON wrapper the UI fetches via GET /api/classifiers.
type InfoList struct {
	Classifiers []Info `json:"classifiers"`
}
