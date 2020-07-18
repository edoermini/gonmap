package gonmap

import (
	"encoding/json"
	"encoding/xml"
	"log"
)

type nmapRun struct {
	Info  scanInfo `xml:"scaninfo" json:"scaninfo"`
	Hosts []host   `xml:"host" json:"hosts"`
}

type scanInfo struct {
	Type     string `xml:"type,attr" json:"type"`
	Protocol string `xml:"protocol,attr" json:"protocol"`
}

type host struct {
	Status   hostStatus `xml:"status" json:"status"`
	Address  address    `xml:"address" json:"address"`
	PortList ports      `xml:"ports" json:"ports"`
}

type hostStatus struct {
	State  string `xml:"state,attr" json:"state"`
	Reason string `xml:"reason,attr" json:"reason"`
}

type address struct {
	Addr string `xml:"addr,attr" json:"addr"`
	Type string `xml:"addrtype,attr" json:"type"`
}

type ports struct {
	Ports []port `xml:"port" json:"ports"`
}

type port struct {
	Protocol string    `xml:"protocol,attr" json:"protocol"`
	ID       int       `xml:"portid,attr" json:"id"`
	Status   portState `xml:"state" json:"status"`
	Service  service   `xml:"service" json:"service"`
}

type portState struct {
	State  string `xml:"state,attr" json:"state"`
	Reason string `xml:"reason,attr" json:"reason"`
}

type service struct {
	Name    string `xml:"name,attr" json:"name"`
	Version string `xml:"product,attr" json:"version"`
}

// NmapXMLParse return map from xml nmap output
func NmapXMLParse(xmlData []byte) map[string]interface{} {
	var data nmapRun
	mapData := make(map[string]interface{})

	xml.Unmarshal(xmlData, &data)

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Fatal("Error json marshal")
	}

	if err := json.Unmarshal(jsonData, &mapData); err != nil {
		log.Fatal("Error json unmarshal")
	}

	return mapData
}
