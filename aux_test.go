package gonmap

import (
	"testing"
)

func TestIsValidHost(t *testing.T) {
	var result bool

	testSet := map[string]bool{
		"192.168.1.1":             true,
		"255.255.255.255":         true,
		"888.888.888.888":         false,
		"192.2.3":                 false,
		"www.google.com":          true,
		"google.com":              true,
		"google.com.it.it":        false,
		"g":                       false,
		"https://www.gloogle.com": false,
		"google.com/32":           true,
		"0-254.4.20.4-7":          true,
		"0-256.4.20.4-7":          false,
		"0-254.4.20.4-7/32":       true,
		"0-254.4.20.4-7/33":       false,
	}

	for test, expected := range testSet {
		result = IsValidHost(test)
		if result != expected {
			t.Errorf("Test: %s, expected: %t, got: %t", test, expected, result)
		}
	}
}
