package gonmap

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
)

type NmapRun struct {
	Info  ScanInfo `xml:"scaninfo" json:"info"`
	Hosts []Host   `xml:"host" json:"hosts"`
}

type ScanInfo struct {
	Type     string `xml:"type,attr" json:"type"`
	Protocol string `xml:"protocol,attr" json:"protocol"`
}

type Host struct {
	Status   HostStatus `xml:"status" json:"status"`
	Address  Address    `xml:"address" json:"address"`
	PortList Ports      `xml:"ports" json:"ports"`
}

type HostStatus struct {
	State  string `xml:"state,attr" json:"state"`
	Reason string `xml:"reason,attr" json:"reason"`
}

type Address struct {
	Addr string `xml:"addr,attr" json:"addr"`
	Type string `xml:"addrtype,attr" json:"type"`
}

type Ports struct {
	Ports []Port `xml:"port" json:"ports"`
}

type Port struct {
	Protocol string    `xml:"protocol,attr" json:"protocol"`
	ID       int       `xml:"portid,attr" json:"id"`
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

// NmapXMLParse return map from xml nmap output
func NmapXMLParse(xmlData []byte) map[string]interface{} {
	var data NmapRun
	mapData := make(map[string]interface{})

	xml.Unmarshal(xmlData, &data)

	fmt.Println(data.Hosts[0].PortList.Ports[0].Status.State)

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Fatal("Error json marshal")
	}

	fmt.Println(string(jsonData))

	if err := json.Unmarshal(jsonData, &mapData); err != nil {
		log.Fatal("Error json unmarshal")
	}

	fmt.Println()
	fmt.Println(mapData)

	return mapData
}
