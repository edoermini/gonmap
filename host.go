package gonmap

import (
	"errors"
	"fmt"
	"log"
	"regexp"
)

// Host is a string corresponding to a domain or ip address
type Host string

// IsHost returns true if host is a valid host false otherwise
func IsHost(h Host) bool {
	ipRegex := `^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
	domainRegex := `^[a-zA-Z0-9][a-zA-Z0-9-_]{0,61}[a-zA-Z0-9]{0,1}\.([a-zA-Z]{1,6}|[a-zA-Z0-9-]{1,30}\.[a-zA-Z]{2,3})$`

	ipMatched, err := regexp.MatchString(ipRegex, string(h))
	if err != nil {
		log.Fatal(err)
	}

	domainMatched, err := regexp.MatchString(domainRegex, string(h))
	if err != nil {
		log.Fatal(err)
	}

	return (ipMatched || domainMatched)
}

// NewHost return Host if h is not null and if string correspond to an ipv4 address or a domain name
func NewHost(h string) (Host, error) {
	if h == "" {
		return Host(""), errors.New("parameter can't be nil")
	}

	if !IsHost(Host(h)) {
		return Host(""), errors.New("paramente must be an ipv4 address or a domain")
	}

	return Host(h), nil
}

func (h Host) String() string {
	return fmt.Sprintf("Host(%s)", string(h))
}
