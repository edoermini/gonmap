package gonmap

import "testing"

func TestIsHost(t *testing.T) {
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
	}

	for test, expected := range testSet {
		result = IsHost(test)
		if result != expected {
			t.Errorf("Test: %s, expected: %t, got: %t", test, expected, result)
		}
	}
}
