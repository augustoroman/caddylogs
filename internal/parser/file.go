package parser

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"strings"
)

// Result is one event or a non-fatal per-line error emitted by a reader.
type Result struct {
	Event Event
	Err   error // parse/read error; Event is zero if Err != nil
}

// ReadFile streams events from a file, transparently handling .gz. It closes
// the channel on EOF or when ctx is canceled.
func ReadFile(ctx context.Context, path string) (<-chan Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var r io.Reader = f
	var gz *gzip.Reader
	if strings.HasSuffix(path, ".gz") {
		gz, err = gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		r = gz
	}
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
	return out, nil
}
