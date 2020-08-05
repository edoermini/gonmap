package gonmap

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

var openedPipes = 0
var maxOpenedPipes = sync.NewCond(new(sync.Mutex))

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
	performance string
	versionScan string
	osDetection string
	zombie      string // IDLE scan argument only
	scripts     string
}

func arrayToString(a []int, delim string) string {
	return strings.Trim(strings.Replace(fmt.Sprint(a), " ", delim, -1), "[]")
}

func getSettings(s Scan) settings {

	configuration := settings{}

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
		configuration.osDetection = ""
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

func getTopPorts(n int) ([]int, error) {

	res := []int{}

	// Finds nmap binary path
	nmap, err := exec.LookPath("nmap")
	if err != nil {
		return nil, err
	}

	args := []string{
		"-v",
		"-oX",
		"-",
		"--top-ports",
		fmt.Sprintf("%d", n),
	}

	cmd := exec.Cmd{
		Path: nmap,
		Args: args,
	}

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

	data := nmapXMLParse(stdout).Info.Services
	splitData := strings.Split(data, ",")

	for _, v := range splitData {
		if strings.Contains(v, "-") {
			bounds := strings.Split(v, "-")

			min, err := strconv.Atoi(bounds[0])
			if err != nil {
				return nil, err
			}

			max, err := strconv.Atoi(bounds[1])
			if err != nil {
				return nil, err
			}

			for j := min; j <= max; j++ {
				res = append(res, j)
			}

		} else {
			intVal, err := strconv.Atoi(v)
			if err != nil {
				return nil, err
			}

			res = append(res, intVal)
		}
	}

	return res, nil
}

// makes a simple port scan with given configuration
func portScan(config settings, scanFlag, host string, ports []int, dataChan chan NmapRun) {

	// Finds nmap binary path
	nmap, err := exec.LookPath("nmap")
	if err != nil {
		log.Fatal(err)
	}

	args := []string{
		config.performance,
		config.versionScan,
		config.osDetection,
		scanFlag,
		config.zombie,
		fmt.Sprintf("-p%s", arrayToString(ports, ",")),
		config.scripts,
		"-oX",
		"-",
		"-vvvvv",
		host,
	}

	cmd := exec.Cmd{
		Path: nmap,
		Args: args,
	}

	// checks if there are already 400 opened pipes
	maxOpenedPipes.L.Lock()

	// waits for at least 2 close on pipes
	for openedPipes > 400 {
		maxOpenedPipes.Wait()
	}

	openedPipes += 2
	maxOpenedPipes.L.Unlock()

	// Configure output pipes
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		log.Fatal(err)
	}

	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}

	// Start command
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	stdout, err := ioutil.ReadAll(outPipe)
	if err != nil {
		log.Fatal(err)
	}

	stderr, err := ioutil.ReadAll(errPipe)
	if err != nil {
		log.Fatal(err)
	}

	// Waits nmap command
	if err := cmd.Wait(); err != nil {
		log.Fatal(errors.New(err.Error() + "\n" + string(stderr)))
	}

	// signals waiting goroutines
	maxOpenedPipes.L.Lock()
	openedPipes -= 2
	maxOpenedPipes.Signal()
	maxOpenedPipes.L.Unlock()

	dataChan <- nmapXMLParse(stdout)
}

func osDetection(ports []int, host string, dataChan chan Host) {

	// Finds nmap binary path
	nmap, err := exec.LookPath("nmap")
	if err != nil {
		log.Fatal(err)
	}

	args := []string{
		fmt.Sprintf("-p%s", arrayToString(ports, ",")),
		"-O",
		"-oX",
		"-",
		host,
	}

	cmd := exec.Cmd{
		Path: nmap,
		Args: args,
	}

	// checks if there are already 400 opened pipes
	maxOpenedPipes.L.Lock()

	// waits for at least 2 close on pipes
	for openedPipes > 400 {
		maxOpenedPipes.Wait()
	}

	openedPipes += 2
	maxOpenedPipes.L.Unlock()

	// Configure output pipes
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		log.Fatal(err)
	}

	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}

	// Start command
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	stdout, err := ioutil.ReadAll(outPipe)
	if err != nil {
		log.Fatal(err)
	}

	stderr, err := ioutil.ReadAll(errPipe)
	if err != nil {
		log.Fatal(err)
	}

	// Waits nmap command
	if err := cmd.Wait(); err != nil {
		log.Fatal(errors.New(err.Error() + "\n" + string(stderr)))
	}

	// signals waiting goroutines
	maxOpenedPipes.L.Lock()
	openedPipes -= 2
	maxOpenedPipes.Signal()
	maxOpenedPipes.L.Unlock()

	data := nmapXMLParse(stdout)

	dataChan <- data.Hosts[0]
}

// merge run NmapRun with new NmapRun
func mergeRuns(run, new NmapRun) NmapRun {

	if run.Hosts == nil {
		return new
	}

	res := NmapRun{}

	// ScanInfo merge
	res.Info.Type = new.Info.Type
	res.Info.Protocol = new.Info.Protocol

	if !strings.Contains(run.Info.Services, new.Info.Services) {
		res.Info.NumServices = run.Info.NumServices + new.Info.NumServices
		res.Info.Services = run.Info.Services + "," + new.Info.Services
	} else {
		res.Info.NumServices = run.Info.NumServices
		res.Info.Services = run.Info.Services
	}

	// Hosts merge
	res.Hosts = run.Hosts

	if run.Hosts[len(run.Hosts)-1].Address.Value == new.Hosts[0].Address.Value {
		res.Hosts[len(res.Hosts)-1].PortList.Port = append(res.Hosts[len(res.Hosts)-1].PortList.Port, new.Hosts[0].PortList.Port...)
	} else {

		res.Hosts = append(res.Hosts, new.Hosts[0])
	}

	return res

}

// runs scan with given configuration
func runScan(config settings, ports []int, hosts []string, osDet bool, scanFlag string) NmapRun {

	counter := 0
	chunkSize := 0
	nChunks := 0
	res := NmapRun{}
	osData := map[string]OsInfo{}

	// calculates number and size of chunks
	if len(ports)/10 < 1 {
		chunkSize = 1
		nChunks = len(ports)

	} else {
		chunkSize = len(ports) / 10

		tmp := float64(len(ports)) / float64(chunkSize)

		if tmp-float64(int(tmp)) > 0 {
			nChunks = int(tmp) + 1
		} else {
			nChunks = int(tmp)
		}
	}

	runResults := make([]chan NmapRun, nChunks*len(hosts))
	osResults := make([]chan Host, len(hosts))

	// initializing runResult
	for i := range runResults {
		runResults[i] = make(chan NmapRun)
	}

	// initializing osResult
	for i := range osResults {
		osResults[i] = make(chan Host)
	}

	// launching goroutines:
	// one go routines every chunkSize port for every host
	for i, host := range hosts {

		if osDet {
			go osDetection(ports, host, osResults[i])
		}

		for _, group := range chunkBy(ports, chunkSize) {

			go portScan(config, scanFlag, host, group, runResults[counter])
			counter++
		}
	}

	// waiting for os discovery routines end
	if osDet {

		for _, c := range osResults {
			data := <-c
			osData[data.Address.Value] = data.OsInfo
		}
	}

	// waiting for scan routines end
	for _, c := range runResults {
		data := <-c
		res = mergeRuns(res, data)
	}

	// adding os discovery info to res
	for i, h := range res.Hosts {
		res.Hosts[i].OsInfo = osData[h.Address.Value]
	}

	return res
}

// TCPScan is generally used to check and complete a three-way handshake
// between you and a chosen target system. Flag: -sT
func (s Scan) TCPScan() (NmapRun, error) {

	config := getSettings(s)

	if (len(s.ports)) == 0 {
		ports, err := getTopPorts(1000)
		if err != nil {
			return NmapRun{}, err
		}

		s.ports = ports
	}

	data := runScan(config, s.ports, s.hosts, s.osDetection, "-sT")

	return data, nil

}

// UDPScan are used to check whether there is any UDP port up and
// listening for incoming requests on the target machine. Flag: -sU
func (s Scan) UDPScan() (NmapRun, error) {

	config := getSettings(s)

	if (len(s.ports)) == 0 {
		ports, err := getTopPorts(1000)
		if err != nil {
			return NmapRun{}, err
		}

		s.ports = ports
	}

	data := runScan(config, s.ports, s.hosts, s.osDetection, "-sU")

	return data, nil
}

// SYNScan is another form of TCP scan. The difference is unlike a normal TCP scan, nmap itself crafts a syn packet,
// which is the first packet that is sent to establish a TCP connection. Flag: -sS
func (s Scan) SYNScan() (NmapRun, error) {

	config := getSettings(s)

	if (len(s.ports)) == 0 {
		ports, err := getTopPorts(1000)
		if err != nil {
			return NmapRun{}, err
		}

		s.ports = ports
	}

	data := runScan(config, s.ports, s.hosts, s.osDetection, "-sS")

	return data, nil

}

// ACKScan are used to determine whether a particular port is filtered or not. Flag: -sA
func (s Scan) ACKScan() (NmapRun, error) {

	config := getSettings(s)

	if (len(s.ports)) == 0 {
		ports, err := getTopPorts(1000)
		if err != nil {
			return NmapRun{}, err
		}

		s.ports = ports
	}

	data := runScan(config, s.ports, s.hosts, s.osDetection, "-sA")

	return data, nil
}

// FINScan is like SYN scan, but sends a TCP FIN packet instead. Flag: -sF
func (s Scan) FINScan() (NmapRun, error) {

	config := getSettings(s)

	if (len(s.ports)) == 0 {
		ports, err := getTopPorts(1000)
		if err != nil {
			return NmapRun{}, err
		}

		s.ports = ports
	}

	data := runScan(config, s.ports, s.hosts, s.osDetection, "-sF")

	return data, nil
}

// NULLScan are extremely stealthy scan and what they do
// is as the name suggests — they set all the header fields to null. Flag: -sN
func (s Scan) NULLScan() (NmapRun, error) {

	config := getSettings(s)

	if (len(s.ports)) == 0 {
		ports, err := getTopPorts(1000)
		if err != nil {
			return NmapRun{}, err
		}

		s.ports = ports
	}

	data := runScan(config, s.ports, s.hosts, s.osDetection, "-sN")

	return data, nil
}

// XmasScan is just like null scans, these are also stealthy in nature. Flag -sX
func (s Scan) XmasScan() (NmapRun, error) {

	config := getSettings(s)

	if (len(s.ports)) == 0 {
		ports, err := getTopPorts(1000)
		if err != nil {
			return NmapRun{}, err
		}

		s.ports = ports
	}

	data := runScan(config, s.ports, s.hosts, s.osDetection, "-sX")

	return data, nil
}

// WindowScan is exactly the same as ACK scan except that it exploits
// an implementation detail of certain systems to differentiate open ports
// from closed ones, rather than always printing unfiltered when a RST is returned. Flag: -sW
func (s Scan) WindowScan() (NmapRun, error) {

	config := getSettings(s)

	if (len(s.ports)) == 0 {
		ports, err := getTopPorts(1000)
		if err != nil {
			return NmapRun{}, err
		}

		s.ports = ports
	}

	data := runScan(config, s.ports, s.hosts, s.osDetection, "-sW")

	return data, nil
}

// MaimonScan is exactly the same as NULL, FIN, and Xmas scan, except that the probe is FIN/ACK.
// Flag: -sM
func (s Scan) MaimonScan() (NmapRun, error) {

	config := getSettings(s)

	if (len(s.ports)) == 0 {
		ports, err := getTopPorts(1000)
		if err != nil {
			return NmapRun{}, err
		}

		s.ports = ports
	}

	data := runScan(config, s.ports, s.hosts, s.osDetection, "-sM")

	return data, nil
}

// IDLEScan is the stealthiest of all scans as the packets are bounced off an external host.
// Flag: -sI
// IDLEScan is the stealthiest of all scans as the packets are bounced off an external host.
// Flag: -sI
func (s Scan) IDLEScan(zombie string) (NmapRun, error) {

	if !isValidHost(zombie) {
		return NmapRun{}, errors.New("Zombie target must be a valid host")
	}

	config := getSettings(s)
	config.zombie = zombie

	if (len(s.ports)) == 0 {
		ports, err := getTopPorts(1000)
		if err != nil {
			return NmapRun{}, err
		}

		s.ports = ports
	}

	data := runScan(config, s.ports, s.hosts, s.osDetection, "-sI")

	return data, nil
}

// AggressiveScan makes a scan with version scan (-sV), os detection (-O), script scanning (-sC) and traceroute
func (s Scan) AggressiveScan() (NmapRun, error) {

	config := getSettings(s)

	if (len(s.ports)) == 0 {
		ports, err := getTopPorts(1000)
		if err != nil {
			return NmapRun{}, err
		}

		s.ports = ports
	}

	data := runScan(config, s.ports, s.hosts, true, "-A")

	return data, nil
}

// SYNDiscovery makes a TCP SYN discovery
func (s Scan) SYNDiscovery() (NmapRun, error) {

	config := getSettings(s)

	if (len(s.ports)) == 0 {
		ports, err := getTopPorts(1000)
		if err != nil {
			return NmapRun{}, err
		}

		s.ports = ports
	}

	data := runScan(config, s.ports, s.hosts, s.osDetection, "-PS")

	return data, nil
}

// ACKDiscovery makes a TCP ACK discovery
func (s Scan) ACKDiscovery() (NmapRun, error) {

	config := getSettings(s)

	if (len(s.ports)) == 0 {
		ports, err := getTopPorts(1000)
		if err != nil {
			return NmapRun{}, err
		}

		s.ports = ports
	}

	data := runScan(config, s.ports, s.hosts, s.osDetection, "-PA")

	return data, nil
}

// UDPDiscovery makes an UDP discovery
func (s Scan) UDPDiscovery() (NmapRun, error) {

	config := getSettings(s)

	if (len(s.ports)) == 0 {
		ports, err := getTopPorts(1000)
		if err != nil {
			return NmapRun{}, err
		}

		s.ports = ports
	}

	data := runScan(config, s.ports, s.hosts, s.osDetection, "-PU")

	return data, nil
}

// SCTPDiscovery makes an SCTP discovery
func (s Scan) SCTPDiscovery() (NmapRun, error) {

	config := getSettings(s)

	if (len(s.ports)) == 0 {
		ports, err := getTopPorts(1000)
		if err != nil {
			return NmapRun{}, err
		}

		s.ports = ports
	}

	data := runScan(config, s.ports, s.hosts, s.osDetection, "-PY")

	return data, nil
}
