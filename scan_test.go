package gonmap

import (
	"testing"
)

func TestIsEqual(t *testing.T) {
	var s1 Scan
	var s2 Scan

	s1 = Scan{[]Host{Host("192.168.1.1")}, []int{}}
	s2 = Scan{[]Host{Host("192.168.1.1"), Host("google.com")}, []int{}}
	s1, _ = s1.AddHost(Host("google.com"))

	if s1.IsEqual(s2) == false {
		t.Errorf("Test: %s == %s, expected: %t, got: %t", s1, s2, true, false)
	}

	s1 = Scan{[]Host{Host("192.168.1.1"), Host("google.com")}, []int{}}
	s2 = Scan{[]Host{Host("192.168.1.1"), Host("google.com")}, []int{80}}

	if s1.IsEqual(s2) == true {
		t.Errorf("Test: %s == %s, expected: %t, got: %t", s1, s2, false, true)
	}

}

func TestAddHost(t *testing.T) {
	result := NewScan(nil, nil)

	testSet := map[Host]Scan{
		Host("192.168.1.1"): Scan{[]Host{Host("192.168.1.1")}, []int{}},
		Host("google.com"):  Scan{[]Host{Host("192.168.1.1"), Host("google.com")}, []int{}},
	}

	for test, expected := range testSet {
		result, _ = result.AddHost(test)

		t.Log(result.IsEqual(expected))

		if !result.IsEqual(expected) {
			t.Errorf("Test: %s, expected: %s, got: %s", test, expected, result)
		}
	}
}
