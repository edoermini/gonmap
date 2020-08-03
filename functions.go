package gonmap

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"strings"
)

// ScanTecnique contains all methods that implement a scan tecnique
type ScanTecnique interface {
	TCPScan()
	UDPScan()
	SYNScan()
	ACKScan()
	FINScan()
	NULLScan()
	XmasScan()
	WindowScan()
	MaimonScan()
	IDLEScan()
}

// HostDiscovery contains all methods that implement an host discovery scan
type HostDiscovery interface {
	SYNDiscovery()
	ACKDiscovery()
	UDPDiscovery()
	SCTPDiscovery()
}

type settings struct {
	scanFlag    string
	portsFlag   string
	hosts       string
	performance string
	versionScan string
	osDetection string
	scripts     string
}

func arrayToString(a []int, delim string) string {
	return strings.Trim(strings.Replace(fmt.Sprint(a), " ", delim, -1), "[]")
}

func getSettings(s Scan) settings {

	configuration := settings{
		portsFlag:   "",
		hosts:       strings.Join(s.GetHosts(), " "),
		versionScan: "",
		osDetection: "",
	}

	// adds ports flag to configuration
	if len(s.ports) == 0 {
		configuration.portsFlag = ""
	} else {
		configuration.portsFlag = "-p" + arrayToString(s.ports, ",")
	}

	// adds performance flag to configuration
	switch s.performance {
	case 0:
		configuration.performance = "-T0"
	case 1:
		configuration.performance = "-T1"
	case 2:
		configuration.performance = "-T2"
	case 3:
		configuration.performance = "-T3"
	case 4:
		configuration.performance = "-T4"
	case 5:
		configuration.performance = "-T5"
	}

	// adds version scan flag to configuration
	if s.versionScan {
		configuration.versionScan = "-sV"
	}

	// adds os detection to configuration
	if s.osDetection {
		configuration.osDetection = "-O"
	}

	if s.runScripts {

		if len(s.scripts) == 0 {
			configuration.scripts = "-sC"
		} else {
			configuration.scripts = "--script=" + strings.Join(s.scripts, ",")
		}
	}

	return configuration
}

func runScan(config settings) ([]byte, error) {

	// Finds nmap binary path
	nmap, err := exec.LookPath("nmap")
	if err != nil {
		return nil, err
	}

	if config.hosts == "" {
		return nil, errors.New("Must be present at least one host")
	}

	cmd := exec.Command(
		nmap, "-oX", "-", "-vvvvv",
		config.performance,
		config.versionScan,
		config.osDetection,
		config.scanFlag,
		config.portsFlag,
		config.scripts,
		config.hosts,
	)

	// Configure output pipes
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	// Start command
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	stdout, err := ioutil.ReadAll(outPipe)
	if err != nil {
		return nil, err
	}

	stderr, err := ioutil.ReadAll(errPipe)
	if err != nil {
		return nil, err
	}

	// Waits nmap command
	if err := cmd.Wait(); err != nil {
		return nil, errors.New(err.Error() + "\n" + string(stderr))
	}

	return stdout, nil
}

// TCPScan is generally used to check and complete a three-way handshake
// between you and a chosen target system. Flag: -sT
func (s Scan) TCPScan() (NmapRun, error) {

	config := getSettings(s)
	config.scanFlag = "-sT"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return nmapXMLParse(xml), nil

}

// UDPScan are used to check whether there is any UDP port up and
// listening for incoming requests on the target machine. Flag: -sU
func (s Scan) UDPScan() (NmapRun, error) {

	config := getSettings(s)
	config.scanFlag = "-sU"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return nmapXMLParse(xml), nil
}

// SYNScan is another form of TCP scan. The difference is unlike a normal TCP scan, nmap itself crafts a syn packet,
// which is the first packet that is sent to establish a TCP connection. Flag: -sS
func (s Scan) SYNScan() (NmapRun, error) {

	config := getSettings(s)
	config.scanFlag = "-sS"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return nmapXMLParse(xml), nil

}

// ACKScan are used to determine whether a particular port is filtered or not. Flag: -sA
func (s Scan) ACKScan() (NmapRun, error) {

	config := getSettings(s)
	config.scanFlag = "-sA"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return nmapXMLParse(xml), nil
}

// FINScan is like SYN scan, but sends a TCP FIN packet instead. Flag: -sF
func (s Scan) FINScan() (NmapRun, error) {

	config := getSettings(s)
	config.scanFlag = "-sF"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return nmapXMLParse(xml), nil
}

// NULLScan are extremely stealthy scan and what they do
// is as the name suggests — they set all the header fields to null. Flag: -sN
func (s Scan) NULLScan() (NmapRun, error) {

	config := getSettings(s)
	config.scanFlag = "-sN"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return nmapXMLParse(xml), nil
}

// XmasScan is just like null scans, these are also stealthy in nature. Flag -sX
func (s Scan) XmasScan() (NmapRun, error) {

	config := getSettings(s)
	config.scanFlag = "-sX"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return nmapXMLParse(xml), nil
}

// WindowScan is exactly the same as ACK scan except that it exploits
// an implementation detail of certain systems to differentiate open ports
// from closed ones, rather than always printing unfiltered when a RST is returned. Flag: -sW
func (s Scan) WindowScan() (NmapRun, error) {

	config := getSettings(s)
	config.scanFlag = "-sW"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return nmapXMLParse(xml), nil
}

// MaimonScan is exactly the same as NULL, FIN, and Xmas scan, except that the probe is FIN/ACK.
// Flag: -sM
func (s Scan) MaimonScan() (NmapRun, error) {

	config := getSettings(s)
	config.scanFlag = "-sW"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return nmapXMLParse(xml), nil
}

// IDLEScan is the stealthiest of all scans as the packets are bounced off an external host.
// Flag: -sI
func (s Scan) IDLEScan(zombie string) (NmapRun, error) {

	if !IsValidHost(zombie) {
		return NmapRun{}, errors.New("Zombie target must be a valid host")
	}

	config := getSettings(s)
	config.scanFlag = "-sI"

	// Finds nmap binary path
	nmap, err := exec.LookPath("nmap")
	if err != nil {
		return NmapRun{}, err
	}

	if config.hosts == "" {
		return NmapRun{}, errors.New("Must be present at least one host")
	}

	cmd := exec.Command(nmap, "-oX", "-", "-vvvvv", config.performance, config.scanFlag, zombie, config.portsFlag, config.versionScan, config.hosts)

	// Configure output pipes
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return NmapRun{}, err
	}

	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return NmapRun{}, err
	}

	// Start command
	if err := cmd.Start(); err != nil {
		return NmapRun{}, err
	}

	stdout, err := ioutil.ReadAll(outPipe)
	if err != nil {
		return NmapRun{}, err
	}

	stderr, err := ioutil.ReadAll(errPipe)
	if err != nil {
		return NmapRun{}, err
	}

	// Waits nmap command
	if err := cmd.Wait(); err != nil {
		return NmapRun{}, errors.New(err.Error() + "\n" + string(stderr))
	}

	return nmapXMLParse(stdout), nil
}

// AggressiveScan makes a scan with version scan (-sV), os detection (-O), script scanning (-sC) and traceroute
func (s Scan) AggressiveScan() (NmapRun, error) {
	config := getSettings(s)
	config.scanFlag = "-A"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return nmapXMLParse(xml), nil
}

// SYNDiscovery makes a TCP SYN discovery
func (s Scan) SYNDiscovery() (NmapRun, error) {
	config := getSettings(s)
	config.scanFlag = "-PS"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return nmapXMLParse(xml), nil
}

// ACKDiscovery makes a TCP ACK discovery
func (s Scan) ACKDiscovery() (NmapRun, error) {
	config := getSettings(s)
	config.scanFlag = "-PA"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return nmapXMLParse(xml), nil
}

// UDPDiscovery makes an UDP discovery
func (s Scan) UDPDiscovery() (NmapRun, error) {
	config := getSettings(s)
	config.scanFlag = "-PU"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return nmapXMLParse(xml), nil
}

// SCTPDiscovery makes an SCTP discovery
func (s Scan) SCTPDiscovery() (NmapRun, error) {
	config := getSettings(s)
	config.scanFlag = "-PY"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return nmapXMLParse(xml), nil
}
