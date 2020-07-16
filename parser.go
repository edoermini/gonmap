package gonmap

import "encoding/xml"

type Port struct {
	XMLName  xml.Name `xml:"port"`
	Protocol string   `xml:"protocol,attr"`
	ID       int      `xml:"portid,attr"`
	//TODO ..
}
