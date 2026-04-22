package parser

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestReadFile_PlainAndGzip(t *testing.T) {
	// Look for any of the example logs shipped in the working dir.
	paths, _ := filepath.Glob("../../*.access.log")
	gzPaths, _ := filepath.Glob("../../*.access-*.log.gz")
	paths = append(paths, gzPaths...)
	if len(paths) == 0 {
		t.Skip("no sample logs found in module root")
	}
	for _, p := range paths {
		p := p
		t.Run(filepath.Base(p), func(t *testing.T) {
			if _, err := os.Stat(p); err != nil {
				t.Skip(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ch, err := ReadFile(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			var events, errs int
			for r := range ch {
				if r.Err != nil {
					errs++
					continue
				}
				events++
				if events >= 100 {
					cancel()
				}
			}
			t.Logf("%s: %d events, %d errs", p, events, errs)
			if events == 0 {
				t.Fatal("no events parsed")
			}
		})
	}
}
