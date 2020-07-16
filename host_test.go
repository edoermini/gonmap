package gonmap

import (
	"testing"
)

func TestIsHost(t *testing.T) {
	var result bool

	testSet := map[Host]bool{
		Host("192.168.1.1"):             true,
		Host("255.255.255.255"):         true,
		Host("888.888.888.888"):         false,
		Host("192.2.3"):                 false,
		Host("www.google.com"):          true,
		Host("google.com"):              true,
		Host("google.com.it.it"):        false,
		Host("g"):                       false,
		Host("https://www.gloogle.com"): false,
	}

	for test, expected := range testSet {
		result = IsHost(test)
		if result != expected {
			t.Errorf("Test: %s, expected: %t, got: %t", test, expected, result)
		}
	}
}

func TestNewHost(t *testing.T) {

	var result Host

	testSet := map[string]Host{
		"192.168.1.1":             Host("192.168.1.1"),
		"255.255.255.255":         Host("255.255.255.255"),
		"888.888.888.888":         Host(""),
		"192.2.3":                 Host(""),
		"www.google.com":          Host("www.google.com"),
		"google.com":              Host("google.com"),
		"google.com.it.it":        Host(""),
		"g":                       Host(""),
		"https://www.gloogle.com": Host(""),
	}

	for test, expected := range testSet {
		result, _ = NewHost(test)

		if result != expected {
			t.Errorf("Test: %s, expected: %s, got: %s", test, expected, result)
		}
	}
}
