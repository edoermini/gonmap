package gonmap_test

import (
	"testing"

	. "github.com/MrRadix/gonmap"
)

func TestTCPScan(t *testing.T) {
	scan, _ := NewScan(nil, nil, 5)
	scan, _ = scan.AddHost("google.com")
	scan, _ = scan.AddPortRange(22, 80)

	out, err := scan.TCPScan()
	if err != nil {
		t.Log(err)
	} else {
		t.Log(out)
	}
}
