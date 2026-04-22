// Package ingest drives the parser → backend pipeline, including
// deterministic cache-key computation over the set of input files.
package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// CacheKey returns a deterministic fingerprint of the input files. Changing
// any file's size or mtime invalidates the key, which in turn invalidates the
// cached SQLite DB.
func CacheKey(paths []string) (string, error) {
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, p := range sorted {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", err
		}
		fi, err := os.Stat(abs)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\x00%d\x00%d\n", abs, fi.Size(), fi.ModTime().UnixNano())
	}
	return hex.EncodeToString(h.Sum(nil)[:12]), nil
}
