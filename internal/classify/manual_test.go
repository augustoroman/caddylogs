package classify

import (
	"os"
	"path/filepath"
	"testing"
)

// TestManualTagSet_Persistence verifies that Set writes to disk, Delete
// removes, and LoadManualTagSet restores the saved state. This is the
// contract the dashboard relies on so tags survive cache-key
// invalidation (which happens whenever a tailed log file's size or mtime
// changes).
func TestManualTagSet_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "tags.json")

	s, err := LoadManualTagSet(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Count() != 0 {
		t.Fatalf("fresh set has %d tags, want 0", s.Count())
	}
	if err := s.Set("8.8.8.8", ManualTagReal); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("1.1.1.1", ManualTagBot); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected tags file at %s: %v", path, err)
	}

	// Reopen: should see both tags.
	s2, err := LoadManualTagSet(path)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Count() != 2 {
		t.Fatalf("reopened set has %d tags, want 2", s2.Count())
	}
	if tag, ok := s2.Get("8.8.8.8"); !ok || tag != ManualTagReal {
		t.Errorf("reopen: 8.8.8.8 = %q/%v, want real/true", tag, ok)
	}
	if tag, ok := s2.Get("1.1.1.1"); !ok || tag != ManualTagBot {
		t.Errorf("reopen: 1.1.1.1 = %q/%v, want bot/true", tag, ok)
	}

	// Delete should persist too.
	if err := s2.Delete("8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	s3, err := LoadManualTagSet(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s3.Get("8.8.8.8"); ok {
		t.Errorf("deleted tag still present after reload")
	}
	if s3.Count() != 1 {
		t.Errorf("post-delete count = %d, want 1", s3.Count())
	}

	// List should be ordered most-recent-first.
	if err := s3.Set("9.9.9.9", ManualTagMalicious); err != nil {
		t.Fatal(err)
	}
	list := s3.List()
	if len(list) != 2 || list[0].IP != "9.9.9.9" {
		t.Errorf("list: %+v, want newest first", list)
	}
}

// TestManualTagSet_InMemory confirms the zero-path set still works for
// callers that don't want persistence.
func TestManualTagSet_InMemory(t *testing.T) {
	s := NewManualTagSet()
	if err := s.Set("8.8.8.8", ManualTagReal); err != nil {
		t.Fatal(err)
	}
	if tag, ok := s.Get("8.8.8.8"); !ok || tag != ManualTagReal {
		t.Errorf("in-memory get: %q/%v", tag, ok)
	}
	if s.Path() != "" {
		t.Errorf("in-memory Path = %q, want empty", s.Path())
	}
}
