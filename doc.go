/*
Package gonmap provides an efficient and simple API for nmap

For every scan it's necessary create a scan with:

	scan := NewScan()

and populate it with related functions.

A simple main example:

	package main

	import (
		"log"
		"fmt"

		gonmap "github.com/MrRadix/gonmap"
	)

	func main() {
		scan := gonmap.NewScan()

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

		fmt.Println(ret.Hosts[0].PortList.Port[0].ID)
	}
*/
package gonmap
