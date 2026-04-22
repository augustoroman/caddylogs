//go:build unix

package parser

import (
	"os"
	"syscall"
)

func statInode(path string) uint64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return inodeOf(fi)
}

func inodeOf(fi os.FileInfo) uint64 {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return st.Ino
}
