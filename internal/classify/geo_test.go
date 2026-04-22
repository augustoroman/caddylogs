package classify

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGeoLookup(t *testing.T) {
	paths, _ := filepath.Glob("../../GeoLite2-City.mmdb")
	if len(paths) == 0 {
		t.Skip("no GeoLite2-City.mmdb in module root")
	}
	if _, err := os.Stat(paths[0]); err != nil {
		t.Skip(err)
	}
	geo, err := OpenGeo(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer geo.Close()

	country, city := geo.Lookup("8.8.8.8")
	if country == "" {
		t.Errorf("expected country for 8.8.8.8")
	}
	_ = city

	// Nil receiver returns empties without crashing.
	var nilGeo *Geo
	c, ci := nilGeo.Lookup("1.1.1.1")
	if c != "" || ci != "" {
		t.Errorf("nil geo should return empty, got %q %q", c, ci)
	}
}
