package gonmap

import (
	"errors"
	"fmt"
	"reflect"
)

// Scan contains basic scan information like hosts, ports, performance of scan
// and a flag for service version scan.
// Is the base for every scan type
type Scan struct {
	hosts       []string
	ports       []int
	performance int
	versionScan bool
}

// NewInitScan returns a new Scan with default values
func NewInitScan() Scan {
	return Scan{
		hosts:       []string{},
		ports:       []int{},
		performance: 4,
		versionScan: false,
	}
}

// NewScan return a new Scan with given settings if they are valid
// and returns error otherwise
func NewScan(hosts []string, ports []int, performance int, versionScan bool) (Scan, error) {

	if performance < 0 || performance > 5 {
		return Scan{nil, nil, 0, false}, errors.New("Performance must be between 0 and 5")
	}

	if hosts == nil && ports == nil {
		return Scan{[]string{}, []int{}, performance, versionScan}, nil
	}
	if hosts == nil && ports != nil {
		for _, p := range ports {
			if p < 1 && p > 65536 {
				return Scan{nil, nil, 0, false}, errors.New("Port parameter must be an integer between 0 and 65536")
			}
		}

		return Scan{[]string{}, ports, performance, versionScan}, nil
	}
	if hosts != nil && ports == nil {
		for _, h := range hosts {
			if !IsHost(h) {
				return Scan{nil, nil, 0, false}, errors.New("Hosts mus be all valid")
			}
		}

		return Scan{hosts, []int{}, performance, versionScan}, nil
	}

	for _, p := range ports {
		if p < 1 && p > 65536 {
			return Scan{nil, nil, 0, false}, errors.New("Port parameter must be an integer between 0 and 65536")
		}
	}

	for _, h := range hosts {
		if !IsHost(h) {
			return Scan{nil, nil, 0, false}, errors.New("Hosts mus be all valid")
		}
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

// AddHost adds host h to Scan s if it's a valid host
// and returns error otherwise
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

// AddHosts adds hosts slice to Scan if all hosts are valid
// and returns error otherwise
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

// AddPort adds port p to Scan s if p is a valid port
// and returns error otherwise
func (s *Scan) AddPort(p int) error {
	if p < 0 || p > 65536 {
		return errors.New("Port parameter must be an integer between 0 and 65536")
	}

	if !s.HasPort(p) {
		s.ports = append(s.ports, p)
	}

	return nil
}

// AddPortRange adds ports from min to max if min and max are valid bounds
// and returns error otherwise
func (s *Scan) AddPortRange(min int, max int) error {
	if min < 0 || min > 65536 {
		return errors.New("Min parameter must be an integer between 0 and 65536")
	}

	if max < 0 || max > 65536 {
		return errors.New("Max parameter must be an integer between 0 and 65536")
	}

	if min > max {
		return errors.New("Max parameter must be bigger or equal to min parameter")
	}

	for p := min; p <= max; p++ {

		if !s.HasPort(p) {
			s.ports = append(s.ports, p)
		}
	}

	return nil
}

// AddPorts adds ports in ports slice to Scan s if all ports are valid
// and returns error otherwise
func (s *Scan) AddPorts(ports []int) error {
	if ports == nil {
		return errors.New("Ports slice must be with almost an element")
	}

	for _, p := range ports {
		if p < 0 || p > 65536 {
			return errors.New("All ports must be an integer between 0 and 65536")
		}
	}

	for _, p := range ports {
		if !s.HasPort(p) {
			s.ports = append(s.ports, p)
		}
	}

	return nil
}

// SetPerformance sets scan performance if
// performance parameter is an integer between 0 and 5
func (s *Scan) SetPerformance(performance int) error {
	if performance < 0 || performance > 5 {
		return errors.New("Performance must be between 0 and 5")
	}

	s.performance = performance
	return nil
}

// SetVersionScan sets service version scan. Nmap flag: -sV
func (s *Scan) SetVersionScan(choise bool) {
	s.versionScan = choise
}

// GetHosts returns set hosts
func (s Scan) GetHosts() []string {
	ret := make([]string, len(s.hosts))
	copy(ret, s.hosts)

	return ret
}

// GetPorts returns set Ports
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
