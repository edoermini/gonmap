package gonmap

import (
	"testing"
)

func TestHostCheck(t *testing.T) {
	var result bool;
	
	testSet := map[Host]bool{
		Host("192.168.1.1"):true,
		Host("255.255.255.255"):true,
		Host("888.888.888.888"):false,
		Host("192.2.3"):false,
		Host("www.google.com"):true,
		Host("google.com"):true,
		Host("google.com.it.it"):false,
		Host("g"):false,
		Host("https://www.gloogle.com"):false,
	}

	for test,expected := range testSet {
		result = HostCheck(test)
		if (result != expected) {
			t.Errorf("Test: %s expected %t, got: %t",test, expected, result)
		}
	}
}