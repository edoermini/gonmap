package gonmap

import (
	"encoding/xml"
)

// NmapRun is the root of every scan result
type NmapRun struct {
	Info  ScanInfo `xml:"scaninfo" json:"scaninfo"`
	Hosts []Host   `xml:"host" json:"hosts"`
}

// ScanInfo contains info about the scan
type ScanInfo struct {
	Type        string `xml:"type,attr" json:"type"`
	Protocol    string `xml:"protocol,attr" json:"protocol"`
	Services    string `xml:"services,attr" json:"services"`
	NumServices int    `xml:"numservices,attr" json:"numservices"`
}

// Host contains all info about a specific host
type Host struct {
	Status   HostStatus `xml:"status" json:"status"`
	Address  Address    `xml:"address" json:"address"`
	PortList Port       `xml:"ports" json:"ports"`
	OsInfo   OsInfo     `xml:"os" json:"osinfo"`
}

// HostStatus contains status of specific host
type HostStatus struct {
	State  string `xml:"state,attr" json:"state"`
	Reason string `xml:"reason,attr" json:"reason"`
}

// Address contains info about address (ipv4, ipv6)
type Address struct {
	Value string `xml:"addr,attr" json:"value"`
	Type  string `xml:"addrtype,attr" json:"type"`
}

// Port contains all port checked in scan
type Port struct {
	Port []PortInfo `xml:"port" json:"ports"`
}

// PortInfo contains info about a specific port
type PortInfo struct {
	ID       int       `xml:"portid,attr" json:"id"`
	Protocol string    `xml:"protocol,attr" json:"protocol"`
	Status   PortState `xml:"state" json:"status"`
	Service  Service   `xml:"service" json:"service"`
	Scripts  []Script  `xml:"script" json:"scripts"`
}

// PortState contains status of specific port
type PortState struct {
	State  string `xml:"state,attr" json:"state"`
	Reason string `xml:"reason,attr" json:"reason"`
}

// Service contains info about service served in a specific port
type Service struct {
	Name    string `xml:"name,attr" json:"name"`
	Version string `xml:"product,attr" json:"version"`
}

// OsInfo contains all os detection matches
type OsInfo struct {
	OsMatch []OsMatch `xml:"osmatch" json:"osmatch"`
}

// OsMatch contains info about an os detection match
type OsMatch struct {
	Name     string `xml:"name,attr" json:"name"`
	Accuracy string `xml:"accuracy,attr" json:"accuracy"`
}

// Script contains info about a specific script launched against a specific port
type Script struct {
	ID     string  `xml:"id,attr" json:"id"`
	Output string  `xml:"output,attr" json:"output"`
	Elems  []Elem  `xml:"elem" json:"elems"`
	Tables []Table `xml:"table" json:"tables"`
}

// Table contains a group of elems of a specific script
type Table struct {
	Key   string `xml:"key,attr" json:"key"`
	Elems []Elem `xml:"elem" json:"elems"`
}

// Elem contains a part of script result
type Elem struct {
	Key   string `xml:"key,attr" json:"key"`
	Value string `xml:",chardata" json:"value"`
}

func nmapXMLParse(xmlData []byte) NmapRun {
	var data NmapRun

	xml.Unmarshal(xmlData, &data)

	return data
}
