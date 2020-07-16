package gonmap

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os/exec"
	"strings"
)

type settings struct {
	scanFlag    string
	portsFlag   string
	hosts       string
	performance string
}

func arrayToString(a []int, delim string) string {
	return strings.Trim(strings.Replace(fmt.Sprint(a), " ", delim, -1), "[]")
}

func getSettings(scanFlag string, s Scan) settings {
	configuration := settings{
		scanFlag:  scanFlag,
		portsFlag: "-p" + arrayToString(s.GetPorts(), ","),
		hosts:     strings.Join(s.GetHosts(), " "),
	}

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

	return configuration
}

// TCPScan makes a tcp scan; command: nmap -sT ...
func (s Scan) TCPScan() ([]byte, error) {

	config := getSettings("-sT", s)

	// Finds nmap binary path
	nmap, err := exec.LookPath("nmap")
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(nmap, "-oX", "-", "-vvv", config.performance, config.scanFlag, config.portsFlag, config.hosts)
	//fmt.Println(cmd)

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

	fmt.Println(string(stdout))

	return nil, nil

}
func UDPScan()  {}
func SYNScan()  {}
func ACKScan()  {}
func FINScan()  {}
func NULLScan() {}
func XMASScan() {}
func RPCScan()  {}
func IDLEScan() {}
