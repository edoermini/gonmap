package gonmap

import (
	"errors"
	"fmt"
	"reflect"
)

// Scan contains basic scan information: hosts list and ports list
type Scan struct {
	Hosts []Host
	Ports []int
}

// AddHost add host h to Scan s
func (s Scan) AddHost(h Host) (Scan, error) {

	if h == Host("") {
		return s, errors.New("Parameter must be a created Host")
	}

	if !IsHost(h) {
		return s, errors.New("Parameter must be a valid Host")

	}

	s.Hosts = append(s.Hosts, h)
	return s, nil
}

// AddPort adds port p to Scan s
func (s Scan) AddPort(p int) (Scan, error) {
	if p < 0 || p > 65536 {
		return s, errors.New("Port parameter must be an integer between 0 and 65536")
	}

	s.Ports = append(s.Ports, p)
	return s, nil
}

// AddPortRange adds ports from min to max
func (s Scan) AddPortRange(min int, max int) (Scan, error) {
	if min < 0 || min > 65536 {
		return s, errors.New("Min parameter must be an integer between 0 and 65536")
	}

	if max < 0 || max > 65536 {
		return s, errors.New("Max parameter must be an integer between 0 and 65536")
	}

	for p := min; p <= max; p++ {
		s.Ports = append(s.Ports, p)
	}

	return s, nil
}

// NewScan return new Scan
func NewScan(hosts []Host, ports []int) Scan {

	if hosts == nil && ports == nil {
		return Scan{[]Host{}, []int{}}
	}
	if hosts == nil && ports != nil {
		return Scan{[]Host{}, ports}
	}
	if hosts != nil && ports == nil {
		return Scan{hosts, []int{}}
	}

	return Scan{hosts, ports}

}

func (s Scan) String() string {
	return fmt.Sprintf("Scan{%v, %v}", s.Hosts, s.Ports)
}

// IsEqual cheks if two scans are equal
func (s Scan) IsEqual(s1 Scan) bool {
	return reflect.DeepEqual(s.Hosts, s1.Hosts) && reflect.DeepEqual(s.Ports, s1.Ports)
}
