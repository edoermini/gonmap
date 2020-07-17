package gonmap

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"strings"
)

type settings struct {
	scanFlag    string
	portsFlag   string
	hosts       string
	performance string
	versionScan string
}

func arrayToString(a []int, delim string) string {
	return strings.Trim(strings.Replace(fmt.Sprint(a), " ", delim, -1), "[]")
}

func getSettings(s Scan) settings {
	configuration := settings{
		portsFlag:   "-p" + arrayToString(s.GetPorts(), ","),
		hosts:       strings.Join(s.GetHosts(), " "),
		versionScan: "",
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

	if s.versionScan {
		configuration.versionScan = "-sV"
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

	cmd := exec.Command(nmap, "-oX", "-", "-vvvvv", config.performance, config.scanFlag, config.portsFlag, config.versionScan, config.hosts)

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

// TCPScan makes a tcp scan; command: nmap -sT ...
func (s Scan) TCPScan() (map[string]interface{}, error) {

	config := getSettings(s)
	config.scanFlag = "-sT"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return NmapXMLParse(xml), nil

}

func (s Scan) UDPScan() (map[string]interface{}, error) {
	config := getSettings(s)
	config.scanFlag = "-sU"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return NmapXMLParse(xml), nil
}

func (s Scan) SYNScan() (map[string]interface{}, error) {
	config := getSettings(s)
	config.scanFlag = "-sS"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return NmapXMLParse(xml), nil

}

func (s Scan) ACKScan() (map[string]interface{}, error) {
	config := getSettings(s)
	config.scanFlag = "-sA"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return NmapXMLParse(xml), nil
}

func (s Scan) FINScan() (map[string]interface{}, error) {
	config := getSettings(s)
	config.scanFlag = "-sF"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return NmapXMLParse(xml), nil
}

func (s Scan) NULLScan() (map[string]interface{}, error) {
	config := getSettings(s)
	config.scanFlag = "-sN"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return NmapXMLParse(xml), nil
}

func (s Scan) XMASScan() (map[string]interface{}, error) {
	config := getSettings(s)
	config.scanFlag = "-sX"

	xml, err := runScan(config)
	if err != nil {
		log.Fatal(err)
	}

	return NmapXMLParse(xml), nil
}

func (s Scan) IDLEScan(zombie string) (map[string]interface{}, error) {
	if !IsHost(zombie) {
		return nil, errors.New("Zombie target must be a valid host")
	}

	config := getSettings(s)
	config.scanFlag = "-sI"

	// Finds nmap binary path
	nmap, err := exec.LookPath("nmap")
	if err != nil {
		return nil, err
	}

	if config.hosts == "" {
		return nil, errors.New("Must be present at least one host")
	}

	cmd := exec.Command(nmap, "-oX", "-", "-vvvvv", config.performance, config.scanFlag, zombie, config.portsFlag, config.versionScan, config.hosts)

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

	return NmapXMLParse(stdout), nil
} // Without examples
