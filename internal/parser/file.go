package parser

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync/atomic"
)

// Result is one event or a non-fatal per-line error emitted by a reader.
type Result struct {
	Event Event
	Err   error // parse/read error; Event is zero if Err != nil
}

// ByteCount accumulates how much data a ReadFileCounted stream has consumed.
// Raw is bytes read off disk; Uncompressed is bytes fed to the line scanner
// (equal to Raw for plain files, larger for .gz). Counts are updated with
// atomics and are final once the Result channel closes.
type ByteCount struct {
	raw, uncompressed atomic.Int64
}

// Raw returns the on-disk bytes read so far (compressed size for .gz files).
func (b *ByteCount) Raw() int64 { return b.raw.Load() }

// Uncompressed returns the decoded bytes scanned so far.
func (b *ByteCount) Uncompressed() int64 { return b.uncompressed.Load() }

// countingReader tallies bytes flowing through an io.Reader into n.
type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// ReadFile streams events from a file, transparently handling .gz. It closes
// the channel on EOF or when ctx is canceled.
func ReadFile(ctx context.Context, path string) (<-chan Result, error) {
	ch, _, err := ReadFileCounted(ctx, path)
	return ch, err
}

// ReadFileCounted is ReadFile plus a ByteCount that tracks the raw (on-disk)
// and uncompressed bytes consumed — used by ingest to record per-file size
// statistics without a second pass over the data.
func ReadFileCounted(ctx context.Context, path string) (<-chan Result, *ByteCount, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	bc := &ByteCount{}
	var r io.Reader = &countingReader{r: f, n: &bc.raw}
	var gz *gzip.Reader
	if strings.HasSuffix(path, ".gz") {
		gz, err = gzip.NewReader(r)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		r = gz
	}
	// The scanner-facing layer counts decoded bytes. For plain files the same
	// bytes pass through both counters, so Raw == Uncompressed by construction.
	r = &countingReader{r: r, n: &bc.uncompressed}
	out := make(chan Result, 256)
	go func() {
		defer close(out)
		defer f.Close()
		if gz != nil {
			defer gz.Close()
		}
		scan := bufio.NewScanner(r)
		scan.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scan.Scan() {
			if ctx.Err() != nil {
				return
			}
			line := scan.Bytes()
			if len(line) == 0 {
				continue
			}
			ev, err := Parse(line)
			if err != nil {
				if IsNotAccessLog(err) {
					continue
				}
				select {
				case <-ctx.Done():
					return
				case out <- Result{Err: err}:
				}
				continue
			}
			select {
			case <-ctx.Done():
				return
			case out <- Result{Event: ev}:
			}
		}
		if err := scan.Err(); err != nil && !errors.Is(err, io.EOF) {
			select {
			case <-ctx.Done():
			case out <- Result{Err: err}:
			}
		}
	}()
	return out, bc, nil
}
