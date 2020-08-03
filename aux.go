package gonmap

import (
	"log"
	"regexp"
)

// IsValidHost gets a string and returns true if
// string represents a valid host false otherwise.
// Examples of valid hosts: 192.168.1.0, 192.0-100.0-3.8, 192.168.1.0/24, 192.0-100.0-3.8/19, 192.0-100.0-3.8,9,10,11/19 www.google.com, github.com/17
func IsValidHost(h string) bool {

	// Match examples:
	// - 192.168.1.0
	// - 192.0-100.0-3.8
	// - 192.168.1.0/24
	// - 192.0-100.0-3.8/19
	// - 192,193,194.0-100.0.1
	// - 192.168.0.1,2,3/23
	ipRegex := `^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)((,(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))*))\.){3}((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(/([0-9]|1[0-9]|2[0-9]|3[0-2]))?|(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)((,(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))*))$`

	// Match examples:
	// - google.com
	// - www.google.com
	// - github.com/17
	domainRegex := `^[a-zA-Z0-9][a-zA-Z0-9-_]{0,61}[a-zA-Z0-9]{0,1}\.([a-zA-Z]{1,6}|[a-zA-Z0-9-]{1,30}\.[a-zA-Z]{2,3})(/([0-9]|1[0-9]|2[0-9]|3[0-2]))?$`

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
