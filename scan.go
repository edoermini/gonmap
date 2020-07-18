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
	versionScan bool
}

// NewInitScan returns a Scan object with default values
func NewInitScan() Scan {
	return Scan{
		hosts:       []string{},
		ports:       []int{},
		performance: 4,
		versionScan: false,
	}
}

// NewScan return new Scan
func NewScan(hosts []string, ports []int, performance int, versionScan bool) (Scan, error) {

	if performance < 0 || performance > 5 {
		return Scan{nil, nil, 0, false}, errors.New("Performance must be between 0 and 5")
	}

	if hosts == nil && ports == nil {
		return Scan{[]string{}, []int{}, performance, versionScan}, nil
	}
	if hosts == nil && ports != nil {
		return Scan{[]string{}, ports, performance, versionScan}, nil
	}
	if hosts != nil && ports == nil {
		return Scan{hosts, []int{}, performance, versionScan}, nil
	}

	return Scan{hosts, ports, performance, versionScan}, nil
}

// HasPort checks if Scan s has port p
func (s Scan) HasPort(p int) bool {
	for _, v := range s.ports {
		if p == v {
			return true
		}
	}

	return false
}

// HasHost checks if Scan s has host h
func (s Scan) HasHost(h string) bool {

	if !IsHost(h) {
		return false
	}

	for _, v := range s.hosts {
		if h == v {
			return true
		}
	}

	return false
}

// AddHost add host h to Scan s
func (s *Scan) AddHost(h string) error {

	if h == "" {
		return errors.New("Parameter must be a created Host")
	}

	if !IsHost(h) {
		return errors.New("Parameter must be a valid Host")

	}

	if !s.HasHost(h) {
		s.hosts = append(s.hosts, h)
	}

	return nil
}

// AddHosts add hosts slice to Scan s
func (s *Scan) AddHosts(hosts []string) error {

	if hosts == nil {
		return errors.New("Parameter must be a initialized slice")
	}

	for _, h := range hosts {
		if !IsHost(h) {
			return errors.New("Hosts mus be all valid")
		}
	}

	for _, h := range hosts {
		if !s.HasHost(h) {
			s.hosts = append(s.hosts, h)
		}
	}

	return nil
}

// AddPort adds port p to Scan s
func (s *Scan) AddPort(p int) error {
	if p < 0 || p > 65536 {
		return errors.New("Port parameter must be an integer between 0 and 65536")
	}

	if !s.HasPort(p) {
		s.ports = append(s.ports, p)
	}

	return nil
} // TODO test

// AddPortRange adds ports from min to max
func (s *Scan) AddPortRange(min int, max int) error {
	if min < 0 || min > 65536 {
		return errors.New("Min parameter must be an integer between 0 and 65536")
	}

	if max < 0 || max > 65536 {
		return errors.New("Max parameter must be an integer between 0 and 65536")
	}

	for p := min; p <= max; p++ {

		if !s.HasPort(p) {
			s.ports = append(s.ports, p)
		}
	}

	return nil
} // TODO test

// AddPorts adds ports in ports slice to Scan s
func (s *Scan) AddPorts(ports []int) error {
	if ports == nil {
		return errors.New("Ports slice must be with with almost an element")
	}

	for _, p := range ports {
		if !s.HasPort(p) {
			s.ports = append(s.ports, p)
		}
	}

	return nil
}

// SetPerformance ...
func (s *Scan) SetPerformance(performance int) error {
	if performance < 0 || performance > 5 {
		return errors.New("Performance must be between 0 and 5")
	}

	s.performance = performance
	return nil
} // TODO test

// SetVersionScan sets service version scan to choise
func (s *Scan) SetVersionScan(choise bool) {
	s.versionScan = choise
}

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
