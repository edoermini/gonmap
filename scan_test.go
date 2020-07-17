package gonmap

import (
	"testing"
)

func TestIsEqual(t *testing.T) {
	var s1 Scan
	var s2 Scan

	s1, _ = NewScan([]string{"192.168.1.1", "google.com"}, []int{}, 5)
	s2, _ = NewScan([]string{"192.168.1.1", "google.com"}, []int{}, 0)

	if s1.IsEqual(s2) == false {
		t.Errorf("Test: %s == %s, expected: %t, got: %t", s1, s2, true, false)
	}

	s1, _ = NewScan([]string{"192.168.1.1", "google.com"}, []int{}, 5)
	s2, _ = NewScan([]string{"192.168.1.1", "google.com"}, []int{80}, 0)

	if s1.IsEqual(s2) == true {
		t.Errorf("Test: %s == %s, expected: %t, got: %t", s1, s2, false, true)
	}

}

func TestAddHost(t *testing.T) {
	result, _ := NewScan(nil, nil, 5)

	s1, _ := NewScan([]string{"192.168.1.1"}, []int{}, 5)
	s2, _ := NewScan([]string{"192.168.1.1", "google.com"}, []int{}, 5)

	testSet := map[string]Scan{
		"192.168.1.1": s1,
		"google.com":  s2,
	}

	for test, expected := range testSet {
		result, _ = result.AddHost(test)

		t.Log(result.IsEqual(expected))

		if !result.IsEqual(expected) {
			t.Errorf("Test: %s, expected: %s, got: %s", test, expected, result)
		}
	}
}
