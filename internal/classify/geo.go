package classify

import (
	"net"
	"net/netip"

	"github.com/oschwald/geoip2-golang/v2"
)

// Geo resolves IP addresses to country and city using a MaxMind GeoLite2-City
// mmdb file. A nil Geo returns empty strings for every lookup, which lets
// calling code treat geolocation as optional.
type Geo struct {
	db *geoip2.Reader
}

// OpenGeo opens the mmdb at path. A blank path returns (nil, nil).
func OpenGeo(path string) (*Geo, error) {
	if path == "" {
		return nil, nil
	}
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &Geo{db: db}, nil
}

// Close releases the underlying mmdb reader.
func (g *Geo) Close() error {
	if g == nil || g.db == nil {
		return nil
	}
	return g.db.Close()
}

// Lookup returns the English country name and city name for the given IP.
// Empty strings are returned for unknown IPs or on any error.
func (g *Geo) Lookup(ip string) (country, city string) {
	if g == nil || g.db == nil || ip == "" {
		return "", ""
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		// Fallback for odd inputs the parser might emit.
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return "", ""
		}
		addr, _ = netip.AddrFromSlice(parsed)
	}
	rec, err := g.db.City(addr)
	if err != nil || rec == nil {
		return "", ""
	}
	return rec.Country.Names.English, rec.City.Names.English
}
