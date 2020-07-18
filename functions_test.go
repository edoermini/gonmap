package gonmap

import (
	"fmt"
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

	fmt.Println(out["hosts"].([]interface{})[0].(map[string]interface{})["ports"].(map[string]interface{})["ports"].([]interface{})[0].(map[string]interface{})["id"])
	// Output: 80
}

func ExampleUDPScan() {
	scan := NewInitScan()
	_ = scan.AddHost("google.com")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)
	scan.SetVersionScan(false)

	out, err := scan.UDPScan()
	if err != nil {
		return
	}

	fmt.Println(out["hosts"].([]interface{})[0].(map[string]interface{})["ports"].(map[string]interface{})["ports"].([]interface{})[0].(map[string]interface{})["id"])
	// Output: 80
}

func ExampleSYNScan() {
	scan := NewInitScan()
	_ = scan.AddHost("google.com")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)
	scan.SetVersionScan(false)

	out, err := scan.SYNScan()
	if err != nil {
		return
	}

	fmt.Println(out["hosts"].([]interface{})[0].(map[string]interface{})["ports"].(map[string]interface{})["ports"].([]interface{})[0].(map[string]interface{})["id"])
	// Output: 80
}

func ExampleACKScan() {
	scan := NewInitScan()
	_ = scan.AddHost("google.com")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)
	scan.SetVersionScan(false)

	out, err := scan.ACKScan()
	if err != nil {
		return
	}

	fmt.Println(out["hosts"].([]interface{})[0].(map[string]interface{})["ports"].(map[string]interface{})["ports"].([]interface{})[0].(map[string]interface{})["id"])
	// Output: 80
}

func ExampleFINScan() {
	scan := NewInitScan()
	_ = scan.AddHost("google.com")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)
	scan.SetVersionScan(false)

	out, err := scan.FINScan()
	if err != nil {
		return
	}

	fmt.Println(out["hosts"].([]interface{})[0].(map[string]interface{})["ports"].(map[string]interface{})["ports"].([]interface{})[0].(map[string]interface{})["id"])
	// Output: 80
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

	fmt.Println(out["hosts"].([]interface{})[0].(map[string]interface{})["ports"].(map[string]interface{})["ports"].([]interface{})[0].(map[string]interface{})["id"])
	// Output: 80
}

func ExampleXMASScan() {
	scan := NewInitScan()
	_ = scan.AddHost("google.com")
	_ = scan.AddPort(80)
	_ = scan.SetPerformance(5)
	scan.SetVersionScan(false)

	out, err := scan.XMASScan()
	if err != nil {
		return
	}

	fmt.Println(out["hosts"].([]interface{})[0].(map[string]interface{})["ports"].(map[string]interface{})["ports"].([]interface{})[0].(map[string]interface{})["id"])
	// Output: 80
}
