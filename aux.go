package gonmap

import (
	"log"
	"regexp"
)

// IsHost gets a string and returns true if
// string represents a host false otherwise
func IsHost(h string) bool {
	ipRegex := `^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
	domainRegex := `^[a-zA-Z0-9][a-zA-Z0-9-_]{0,61}[a-zA-Z0-9]{0,1}\.([a-zA-Z]{1,6}|[a-zA-Z0-9-]{1,30}\.[a-zA-Z]{2,3})$`

	ipMatched, err := regexp.MatchString(ipRegex, h)
	if err != nil {
		log.Fatal(err)
	}

	domainMatched, err := regexp.MatchString(domainRegex, h)
	if err != nil {
		log.Fatal(err)
	}

	return (ipMatched || domainMatched)
}
