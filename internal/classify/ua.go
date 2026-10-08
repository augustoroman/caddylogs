package classify

import (
	"strings"

	"github.com/mileusna/useragent"
)

// UAInfo is the parsed breakdown of a User-Agent string.
type UAInfo struct {
	Browser string
	OS      string
	Device  string
}

// ParseUA extracts browser, OS, and device class from a User-Agent. Unknown
// fields come back as empty strings.
func ParseUA(ua string) UAInfo {
	if ua == "" {
		return UAInfo{}
	}
	p := useragent.Parse(ua)
	// The library only recognises iOS via the "iPhone"/"iPad" tokens that
	// browsers emit. Native apps commonly send a bare platform name
	// instead, e.g. "myapp/1.2.3 (iOS; unit=unknown)", which leaves OS
	// empty and the device unclassified. Android gets no such gap because
	// the library flags any UA containing the "Android" token as Mobile.
	if p.OS == "" && hasToken(ua, "iOS") {
		p.OS = useragent.IOS
		p.Mobile = true
	}
	var dev string
	switch {
	case p.Mobile:
		dev = "Mobile"
	case p.Tablet:
		dev = "Tablet"
	case p.Desktop:
		dev = "Desktop"
	case p.Bot:
		dev = "Bot"
	default:
		dev = "Other"
	}
	return UAInfo{
		Browser: p.Name,
		OS:      p.OS,
		Device:  dev,
	}
}

// hasToken reports whether tok appears in s as a whole word, i.e. not as a
// substring of a longer alphanumeric run ("iOS" must not match "BiOS" or
// "iOSx"). Separators are anything other than ASCII letters and digits.
func hasToken(s, tok string) bool {
	for start := 0; ; {
		i := strings.Index(s[start:], tok)
		if i < 0 {
			return false
		}
		i += start
		end := i + len(tok)
		before := i == 0 || !isAlnum(s[i-1])
		after := end == len(s) || !isAlnum(s[end])
		if before && after {
			return true
		}
		start = i + 1
	}
}

func isAlnum(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')
}
