package classify

import "github.com/mileusna/useragent"

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
