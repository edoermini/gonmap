package gonmap

import (
	"testing"
)

func TestIsEqual(t *testing.T) {
	var s1 Scan
	var s2 Scan

	s1 = Scan{[]string{"192.168.1.1"}, []int{}, 0}
	s2 = Scan{[]string{"192.168.1.1", "google.com"}, []int{}, 0}
	s1, _ = s1.AddHost("google.com")

	if s1.IsEqual(s2) == false {
		t.Errorf("Test: %s == %s, expected: %t, got: %t", s1, s2, true, false)
	}

	s1 = Scan{[]string{"192.168.1.1", "google.com"}, []int{}, 0}
	s2 = Scan{[]string{"192.168.1.1", "google.com"}, []int{80}, 0}

	if s1.IsEqual(s2) == true {
		t.Errorf("Test: %s == %s, expected: %t, got: %t", s1, s2, false, true)
	}

}

func TestAddHost(t *testing.T) {
	result, _ := NewScan(nil, nil, 0)

	testSet := map[string]Scan{
		"192.168.1.1": Scan{[]string{"192.168.1.1"}, []int{}, 0},
		"google.com":  Scan{[]string{"192.168.1.1", "google.com"}, []int{}, 0},
	}

	for test, expected := range testSet {
		result, _ = result.AddHost(test)

		t.Log(result.IsEqual(expected))

		if !result.IsEqual(expected) {
			t.Errorf("Test: %s, expected: %s, got: %s", test, expected, result)
		}
	}
}
