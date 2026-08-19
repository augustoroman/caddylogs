package parser

import (
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func sampleLog(lines int) []byte {
	var b []byte
	for i := 0; i < lines; i++ {
		b = append(b, fmt.Sprintf(
			`{"ts":%d.5,"status":200,"size":123,"request":{"method":"GET","uri":"/p%d","host":"x","remote_ip":"1.2.3.4"}}`+"\n",
			1700000000+i, i)...)
	}
	// One malformed line that should surface as a Result.Err.
	b = append(b, "{not json\n"...)
	return b
}

func drain(t *testing.T, ch <-chan Result) (events, errs int) {
	t.Helper()
	for r := range ch {
		if r.Err != nil {
			errs++
		} else {
			events++
		}
	}
	return
}

func TestReadFileCounted_Plain(t *testing.T) {
	content := sampleLog(50)
	p := filepath.Join(t.TempDir(), "test.log")
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	ch, bc, err := ReadFileCounted(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	events, errs := drain(t, ch)
	if events != 50 || errs != 1 {
		t.Fatalf("got %d events, %d errs; want 50, 1", events, errs)
	}
	want := int64(len(content))
	if bc.Raw() != want || bc.Uncompressed() != want {
		t.Errorf("raw=%d uncompressed=%d; want both %d", bc.Raw(), bc.Uncompressed(), want)
	}
}

func TestReadFileCounted_Gzip(t *testing.T) {
	content := sampleLog(50)
	p := filepath.Join(t.TempDir(), "test.log.gz")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	if _, err := gz.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}

	ch, bc, err := ReadFileCounted(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	events, errs := drain(t, ch)
	if events != 50 || errs != 1 {
		t.Fatalf("got %d events, %d errs; want 50, 1", events, errs)
	}
	if bc.Raw() != fi.Size() {
		t.Errorf("raw=%d; want on-disk size %d", bc.Raw(), fi.Size())
	}
	if bc.Uncompressed() != int64(len(content)) {
		t.Errorf("uncompressed=%d; want %d", bc.Uncompressed(), len(content))
	}
}
