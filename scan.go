package gonmap

import (
	"regexp"
	"log"
)

type Host string

type Scan struct {
	Type string
	Options string
	Hosts []Host
}

func HostCheck(h Host) bool {
	ipRegex := `^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
	domainRegex := `^[a-zA-Z0-9][a-zA-Z0-9-_]{0,61}[a-zA-Z0-9]{0,1}\.([a-zA-Z]{1,6}|[a-zA-Z0-9-]{1,30}\.[a-zA-Z]{2,3})$`

	ipMatched, err := regexp.MatchString(ipRegex, string(h))
	if (err != nil) {
		log.Fatal(err)
	}

	domainMatched, err := regexp.MatchString(domainRegex, string(h))
	if (err != nil) {
		log.Fatal(err)
	}

	return (ipMatched || domainMatched)
}

func (s Scan) AddHost(h Host) {
	s.Hosts = append(s.Hosts, h)
}

