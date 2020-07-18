package gonmap

import (
	"fmt"
	"testing"
)

func ExampleTCPScan() {
	scan := NewInitScan()
	_ = scan.AddHost("google.com")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)
	scan.SetVersionScan(false)

	out, err := scan.TCPScan()
	if err != nil {
		return
	}
	fmt.Println(out)
}

func ExampleUDPScan(t *testing.T) {
	scan := NewInitScan()
	_ = scan.AddHost("google.com")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)
	scan.SetVersionScan(false)

	out, err := scan.UDPScan()
	if err != nil {
		return
	}
	fmt.Println(out)
}

func ExampleSYNScan(t *testing.T) {
	scan := NewInitScan()
	_ = scan.AddHost("google.com")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)
	scan.SetVersionScan(false)

	out, err := scan.SYNScan()
	if err != nil {
		return
	}
	fmt.Println(out)
}

func ExampleACKScan(t *testing.T) {
	scan := NewInitScan()
	_ = scan.AddHost("google.com")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)
	scan.SetVersionScan(false)

	out, err := scan.ACKScan()
	if err != nil {
		return
	}
	fmt.Println(out)
}

func ExampleFINScan(t *testing.T) {
	scan := NewInitScan()
	_ = scan.AddHost("google.com")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)
	scan.SetVersionScan(false)

	out, err := scan.FINScan()
	if err != nil {
		return
	}
	fmt.Println(out)
}

func ExampleNULLScan() {
	scan := NewInitScan()
	_ = scan.AddHost("google.com")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)
	scan.SetVersionScan(false)

	out, err := scan.NULLScan()
	if err != nil {
		return
	}
	fmt.Println(out)
}

func ExampleXMASScan(t *testing.T) {
	scan := NewInitScan()
	_ = scan.AddHost("google.com")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)
	scan.SetVersionScan(false)

	out, err := scan.XMASScan()
	if err != nil {
		return
	}
	fmt.Println(out)
}
