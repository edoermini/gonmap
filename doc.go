/*
Package gonmap provides an efficient API to interface go programs with nmap binary

For every scan it's necessary define a scan with:

	scan := NewInitScan()

and populate it with related functions or directly with:

	scan, err := NewScan([]string{"host1", "host2", ...}, []int{port1, port2, ...}, performance, vesionScan)


A simple main example:

	package main

	import (
		"log"
		"fmt"

		gonmap "github.com/MrRadix/gonmap"
	)

	func main() {
		scan := gonmap.NewInitScan()

		if err := scan.AddHost("github.com"); err != nil {
			log.Fatal(err)
		}

		if err := scan.AddPort(80); err != nil {
			log.Fatal(err)
		}

		ret, err := scan.TCPScan()
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(ret)
	}
*/
package gonmap
