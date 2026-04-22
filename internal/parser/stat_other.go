//go:build !unix

package parser

import "os"

// On non-unix platforms we fall back to mtime-based rotation detection.
func statInode(path string) uint64       { return 0 }
func inodeOf(_ os.FileInfo) uint64       { return 0 }
