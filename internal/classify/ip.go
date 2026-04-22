package classify

import "net/netip"

var privateV4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), // link-local
	netip.MustParsePrefix("0.0.0.0/8"),
}

var privateV6Prefixes = []netip.Prefix{
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),  // unique local
	netip.MustParsePrefix("fe80::/10"), // link-local
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::ffff:0:0/96"), // v4-mapped; final check below handles this
}

// IsLocalIP reports whether ip is a non-routable / local-network address. An
// invalid IP string returns false.
func IsLocalIP(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if addr.Is4() {
		for _, p := range privateV4Prefixes {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, p := range privateV6Prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
