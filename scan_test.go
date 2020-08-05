package gonmap

import (
	"testing"
)

func TestIsEqual(t *testing.T) {
	var s1 Scan
	var s2 Scan

	s1 = NewScan()
	_ = s1.AddHosts([]string{"192.168.1.1", "google.com"})
	_ = s1.SetPerformance(5)
	s1.SetVersionScan(true)

	s2 = NewScan()
	_ = s2.AddHosts([]string{"192.168.1.1", "google.com"})
	_ = s2.SetPerformance(5)
	s2.SetVersionScan(true)

	if s1.IsEqual(s2) == false {
		t.Errorf("Test: %s == %s, expected: %t, got: %t", s1, s2, true, false)
	}

	s1 = NewScan()
	_ = s1.AddHosts([]string{"192.168.1.1", "google.com"})
	_ = s1.SetPerformance(5)
	s1.SetVersionScan(true)

	s2 = NewScan()
	_ = s2.AddHosts([]string{"192.168.1.1", "google.com"})
	_ = s2.SetPerformance(5)
	_ = s2.AddPort(80)
	s2.SetVersionScan(true)

	if s1.IsEqual(s2) == true {
		t.Errorf("Test: %s == %s, expected: %t, got: %t", s1, s2, false, true)
	}

}

func TestAddHost(t *testing.T) {
	result := NewScan()

	s1 := NewScan()
	_ = s1.AddHosts([]string{"192.168.1.1"})

	s2 := NewScan()
	_ = s2.AddHosts([]string{"192.168.1.1", "google.com"})

	testSet := map[string]Scan{
		"192.168.1.1": s1,
		"google.com":  s2,
	}

	for test, expected := range testSet {
		_ = result.AddHost(test)

		if !result.IsEqual(expected) {
			t.Errorf("Test: %s, expected: %s, got: %s", test, expected, result)
		}
	}
}

func TestAddTopPorts(t *testing.T) {
	scan := NewScan()

	testSet := []int{
		10,
		20,
	}

	for _, v := range testSet {
		scan.AddTopPorts(v)

		if len(scan.ports) != v {
			t.Errorf("Test: %d, expected: %d, got: %d", v, v, len(scan.ports))
		}
	}
}
