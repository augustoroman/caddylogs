package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/augustoroman/caddylogs/internal/classify"
)

// resetTagsFlags configures the reset-tags subcommand. It clears entries from
// the persistent tags JSON so the classifier can re-derive them from scratch —
// useful after the attack-rule buckets or behavioral classifiers improve enough
// that hand-applied tags are redundant (or wrong). It is a dry run unless --yes.
type resetTagsFlags struct {
	TagsFile string
	Source   string
	Tag      string
	Apply    bool
	NoBackup bool
}

func bindResetTagsFlags(cmd *kingpin.CmdClause) *resetTagsFlags {
	c := &resetTagsFlags{}
	cmd.Flag("tags-file", "Path to the persistent tags JSON. Empty means the OS config dir.").
		StringVar(&c.TagsFile)
	cmd.Flag("source", "Which tag source to clear: manual, all, or a classifier name.").
		Default("manual").StringVar(&c.Source)
	cmd.Flag("tag", "Which tag value to clear: all, malicious, bot, real, local.").
		Default("all").StringVar(&c.Tag)
	cmd.Flag("yes", "Actually apply the reset (without this it is a dry run).").
		BoolVar(&c.Apply)
	cmd.Flag("no-backup", "Skip backing up the tags file before clearing.").
		BoolVar(&c.NoBackup)
	return c
}

// runResetTags removes matching entries from the tags JSON (default: every
// operator-applied tag). It reports the breakdown first and only mutates the
// file when --yes is given, backing it up beforehand unless --no-backup.
func runResetTags(ctx context.Context, opts *resetTagsFlags) error {
	if opts.Tag != "all" && !classify.ValidManualTag(classify.ManualTag(opts.Tag)) {
		return fmt.Errorf("invalid --tag %q (want all|malicious|bot|real|local)", opts.Tag)
	}
	path, err := resolveTagsFile(opts.TagsFile)
	if err != nil {
		return err
	}
	set, err := classify.LoadManualTagSet(path)
	if err != nil {
		return err
	}
	all := set.List()

	matches := func(e classify.ManualTagListEntry) bool {
		return (opts.Source == "all" || e.Source == opts.Source) &&
			(opts.Tag == "all" || string(e.Tag) == opts.Tag)
	}

	// Breakdown of the whole set by (source, tag), with how many each cell loses.
	type cell struct{ total, hit int }
	counts := map[string]*cell{}
	victims := 0
	for _, e := range all {
		k := e.Source + " / " + string(e.Tag)
		c := counts[k]
		if c == nil {
			c = &cell{}
			counts[k] = c
		}
		c.total++
		if matches(e) {
			c.hit++
			victims++
		}
	}

	fmt.Printf("tags file: %s\n", path)
	fmt.Printf("total tags: %d\n\n", len(all))
	fmt.Printf("%-28s %8s %8s\n", "source / tag", "count", "remove")
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%-28s %8d %8d\n", k, counts[k].total, counts[k].hit)
	}
	fmt.Printf("\nselector: source=%q tag=%q → %d tag(s) to remove, %d kept\n",
		opts.Source, opts.Tag, victims, len(all)-victims)

	if !opts.Apply {
		fmt.Println("\n(dry run — re-run with --yes to apply)")
		return nil
	}
	if victims == 0 {
		fmt.Println("\nnothing to remove.")
		return nil
	}
	if !opts.NoBackup {
		bak := fmt.Sprintf("%s.bak-%d", path, time.Now().Unix())
		if err := copyFile(path, bak); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		fmt.Printf("\nbacked up tags to %s\n", bak)
	}
	removed, err := set.DeleteWhere(matches)
	if err != nil {
		return fmt.Errorf("clear tags: %w", err)
	}
	fmt.Printf("removed %d tag(s); %d remain.\n", removed, set.Count())
	fmt.Println("\nThis only edits the tags file. To rebuild classification from the")
	fmt.Println("updated rules with no stale tags, drop the cached DB and re-serve:")
	fmt.Println("  caddylogs clear-cache <logs…>   # or --all")
	fmt.Println("  caddylogs serve <logs…>")
	return nil
}

// copyFile copies src to dst, creating/truncating dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
