package gonmap

import (
	"errors"
	"fmt"
	"reflect"
)

// Scan contains basic scan information: hosts list and ports list
type Scan struct {
	hosts       []string
	ports       []int
	performance int
}

// NewScan return new Scan
func NewScan(hosts []string, ports []int, performance int) (Scan, error) {

	if performance < 0 || performance > 5 {
		return Scan{nil, nil, 0}, errors.New("Performance must be between 0 and 5")
	}

	if hosts == nil && ports == nil {
		return Scan{[]string{}, []int{}, performance}, nil
	}
	if hosts == nil && ports != nil {
		return Scan{[]string{}, ports, performance}, nil
	}
	if hosts != nil && ports == nil {
		return Scan{hosts, []int{}, performance}, nil
	}

	return Scan{hosts, ports, performance}, nil
}

// AddHost add host h to Scan s
func (s Scan) AddHost(h string) (Scan, error) {

	if h == "" {
		return s, errors.New("Parameter must be a created Host")
	}

	if !IsHost(h) {
		return s, errors.New("Parameter must be a valid Host")

	}

	s.hosts = append(s.hosts, h)
	return s, nil
}

// AddPort adds port p to Scan s
func (s Scan) AddPort(p int) (Scan, error) {
	if p < 0 || p > 65536 {
		return s, errors.New("Port parameter must be an integer between 0 and 65536")
	}

	s.ports = append(s.ports, p)
	return s, nil
} // TODO test

// AddPortRange adds ports from min to max
func (s Scan) AddPortRange(min int, max int) (Scan, error) {
	if min < 0 || min > 65536 {
		return s, errors.New("Min parameter must be an integer between 0 and 65536")
	}

	if max < 0 || max > 65536 {
		return s, errors.New("Max parameter must be an integer between 0 and 65536")
	}

	for p := min; p <= max; p++ {
		s.ports = append(s.ports, p)
	}

	return s, nil
} // TODO test

// SetPerformance ...
func (s Scan) SetPerformance(performance int) (Scan, error) {
	if performance < 0 || performance > 5 {
		return s, errors.New("Performance must be between 0 and 5")
	}

	s.performance = performance
	return s, nil
} // TODO test

// GetHosts return a copy of hosts slice
func (s Scan) GetHosts() []string {
	ret := make([]string, len(s.hosts))
	copy(ret, s.hosts)

	return ret
} // TODO

// GetPorts return a copy of ports slice
func (s Scan) GetPorts() []int {
	ret := make([]int, len(s.ports))
	copy(ret, s.ports)

	return ret
} // TODO test

// GetPerformance returns performance
func (s Scan) GetPerformance() int {
	return s.performance
}

func (s Scan) String() string {
	return fmt.Sprintf("Scan{%v, %v}", s.hosts, s.ports)
}

// IsEqual cheks if two scans are equal
func (s Scan) IsEqual(s1 Scan) bool {
	return reflect.DeepEqual(s.hosts, s1.hosts) && reflect.DeepEqual(s.ports, s1.ports)
}
