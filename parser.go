package gonmap

import (
	"encoding/xml"
)

type NmapRun struct {
	Info  ScanInfo `xml:"scaninfo" json:"scaninfo"`
	Hosts []Host   `xml:"host" json:"hosts"`
}

type ScanInfo struct {
	Type     string `xml:"type,attr" json:"type"`
	Protocol string `xml:"protocol,attr" json:"protocol"`
}

type Host struct {
	Status   HostStatus `xml:"status" json:"status"`
	Address  Address    `xml:"address" json:"address"`
	PortList Port       `xml:"ports" json:"ports"`
	OsInfo   OsInfo     `xml:"os" json:"osinfo"`
}

type HostStatus struct {
	State  string `xml:"state,attr" json:"state"`
	Reason string `xml:"reason,attr" json:"reason"`
}

type Address struct {
	Addr string `xml:"addr,attr" json:"addr"`
	Type string `xml:"addrtype,attr" json:"type"`
}

type Port struct {
	Port []PortInfo `xml:"port" json:"ports"`
}

type PortInfo struct {
	ID       int       `xml:"portid,attr" json:"id"`
	Protocol string    `xml:"protocol,attr" json:"protocol"`
	Status   PortState `xml:"state" json:"status"`
	Service  Service   `xml:"service" json:"service"`
}

type PortState struct {
	State  string `xml:"state,attr" json:"state"`
	Reason string `xml:"reason,attr" json:"reason"`
}

type Service struct {
	Name    string `xml:"name,attr" json:"name"`
	Version string `xml:"product,attr" json:"version"`
}

type OsInfo struct {
	OsMatch []OsMatch `xml:"osmatch" json:"osmatch"`
}

type OsMatch struct {
	Name     string `xml:"name,attr" json:"name"`
	Accuracy string `xml:"accuracy,attr" json:"accuracy"`
}

// NmapXMLParse returns an NmapRun from xml nmap output
func NmapXMLParse(xmlData []byte) NmapRun {
	var data NmapRun

	xml.Unmarshal(xmlData, &data)

	return data
}
