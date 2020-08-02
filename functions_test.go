package gonmap

import (
	"fmt"
)

func ExampleTCPScan() {
	scan := NewScan()
	_ = scan.AddHost("127.0.0.1")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)
	scan.AddScript("http-enum")

	out, err := scan.TCPScan()
	if err != nil {
		return
	}

	fmt.Println(out.Hosts[0].PortList.Port[0].ID)
	// Output: 80
}

func ExampleUDPScan() {
	scan := NewScan()
	_ = scan.AddHost("127.0.0.1")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)

	out, err := scan.UDPScan()
	if err != nil {
		return
	}

	fmt.Println(out.Hosts[0].PortList.Port[0].ID)
	// Output: 80
}

func ExampleSYNScan() {
	scan := NewScan()
	_ = scan.AddHost("127.0.0.1")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)

	out, err := scan.SYNScan()
	if err != nil {
		return
	}

	fmt.Println(out.Hosts[0].PortList.Port[0].ID)
	// Output: 80
}

func ExampleACKScan() {
	scan := NewScan()
	_ = scan.AddHost("127.0.0.1")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)

	out, err := scan.ACKScan()
	if err != nil {
		return
	}

	fmt.Println(out.Hosts[0].PortList.Port[0].ID)
	// Output: 80
}

func ExampleFINScan() {
	scan := NewScan()
	_ = scan.AddHost("127.0.0.1")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)

	out, err := scan.FINScan()
	if err != nil {
		return
	}

	fmt.Println(out.Hosts[0].PortList.Port[0].ID)
	// Output: 80
}

func ExampleNULLScan() {
	scan := NewScan()
	_ = scan.AddHost("127.0.0.1")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)

	out, err := scan.NULLScan()
	if err != nil {
		return
	}

	fmt.Println(out.Hosts[0].PortList.Port[0].ID)
	// Output: 80
}

func ExampleXmasScan() {
	scan := NewScan()
	_ = scan.AddHost("127.0.0.1")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)

	out, err := scan.XmasScan()
	if err != nil {
		return
	}

	fmt.Println(out.Hosts[0].PortList.Port[0].ID)
	// Output: 80
}

func ExampleAggressiveScan() {
	scan := NewScan()
	_ = scan.AddHost("127.0.0.1")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)

	out, err := scan.AggressiveScan()
	if err != nil {
		return
	}

	fmt.Println(out.Hosts[0].PortList.Port[0].ID)
	// Output: 80
}
