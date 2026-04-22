package backend

import (
	"context"

	"github.com/augustoroman/caddylogs/internal/parser"
	"github.com/augustoroman/caddylogs/internal/progress"
)

// Store is the narrow interface every backend must satisfy. All methods are
// expected to honor context cancellation; even when the underlying engine
// cannot truly abort mid-query, implementations should check ctx between
// units of work so a caller's Cancel eventually unblocks them.
type Store interface {
	// Ingest appends events to the store. Events may be classified and split
	// between the dynamic and static physical tables at the implementation's
	// discretion. Ingest is safe to call concurrently with Query.
	Ingest(ctx context.Context, events []parser.Event) error

	// Query runs a single parameterized request and returns the full Result.
	// The shape of Result depends on q.Kind. Implementations MUST check
	// ctx.Err() before doing any expensive work and SHOULD propagate
	// cancellation into the underlying engine where supported.
	Query(ctx context.Context, q Query) (*Result, error)

	// MarkIngestComplete signals that an initial bulk ingest has finished.
	// Implementations may use this to build secondary indices, analyze
	// statistics, or flip the store from an append-optimized state to a
	// query-optimized one. p is called with phase/detail/done/total updates
	// for any long-running sub-step.
	MarkIngestComplete(ctx context.Context, p progress.Func) error

	// Close releases resources.
	Close() error
}

// AllowedDimensions is the canonical list of dimensions the UI and query
// builders should recognize. Backends may reject unknown dimensions.
var AllowedDimensions = []Dimension{
	DimIP, DimHost, DimURI, DimStatus, DimStatusClass, DimMethod,
	DimReferrer, DimBrowser, DimOS, DimDevice, DimCountry, DimCity, DimProto,
	DimIsBot, DimIsLocal, DimIsStatic, DimMalReason,
}

// DimensionValid reports whether d is in AllowedDimensions.
func DimensionValid(d Dimension) bool {
	for _, a := range AllowedDimensions {
		if a == d {
			return true
		}
	}
	return false
}
