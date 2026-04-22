package parser

import (
	"bufio"
	"context"
	"io"
	"os"
	"time"
)

// TailOptions controls tail behavior.
type TailOptions struct {
	// FromStart reads the existing file from the beginning first, then tails.
	// When false, tail starts at current EOF.
	FromStart bool
	// Poll is the sleep between attempts to detect rotation / read more bytes.
	Poll time.Duration
}

// Tail follows a plain (non-gzipped) file, emitting parsed events as new lines
// are appended. It detects rotation (file shrink or inode change) and
// re-opens. Emits until ctx is canceled.
func Tail(ctx context.Context, path string, opts TailOptions) <-chan Result {
	if opts.Poll <= 0 {
		opts.Poll = 500 * time.Millisecond
	}
	out := make(chan Result, 256)
	go func() {
		defer close(out)
		var (
			f         *os.File
			reader    *bufio.Reader
			curInode  uint64
			curOffset int64
			partial   []byte
		)
		open := func(fromEnd bool) {
			if f != nil {
				f.Close()
			}
			var err error
			f, err = os.Open(path)
			if err != nil {
				f = nil
				reader = nil
				return
			}
			if fromEnd {
				offset, _ := f.Seek(0, io.SeekEnd)
				curOffset = offset
			} else {
				curOffset = 0
			}
			reader = bufio.NewReaderSize(f, 64*1024)
			curInode = statInode(path)
			partial = partial[:0]
		}

		open(!opts.FromStart)

		for {
			if ctx.Err() != nil {
				if f != nil {
					f.Close()
				}
				return
			}

			// Read as much as we can.
			if f != nil && reader != nil {
				for {
					line, err := reader.ReadBytes('\n')
					if len(line) > 0 {
						// Strip trailing newline; join with any saved partial.
						if line[len(line)-1] == '\n' {
							full := append(partial, line[:len(line)-1]...)
							partial = partial[:0]
							curOffset += int64(len(line))
							if len(full) > 0 {
								emit(ctx, out, full)
							}
						} else {
							// EOF mid-line; save for next round.
							partial = append(partial, line...)
							curOffset += int64(len(line))
							break
						}
					}
					if err == io.EOF || err == bufio.ErrBufferFull {
						break
					}
					if err != nil {
						break
					}
				}
			}

			// Check for rotation or truncation.
			fi, err := os.Stat(path)
			if err != nil {
				// File temporarily missing; wait and retry.
				sleep(ctx, opts.Poll)
				continue
			}
			inode := inodeOf(fi)
			if inode != curInode || fi.Size() < curOffset {
				open(false) // rotated or truncated: read the new file from start
				continue
			}

			sleep(ctx, opts.Poll)
		}
	}()
	return out
}

func emit(ctx context.Context, out chan<- Result, line []byte) {
	ev, err := Parse(line)
	if err != nil {
		if IsNotAccessLog(err) {
			return
		}
		select {
		case <-ctx.Done():
		case out <- Result{Err: err}:
		}
		return
	}
	select {
	case <-ctx.Done():
	case out <- Result{Event: ev}:
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
