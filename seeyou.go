package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const BANNER = `
 ___  ___  ___ _   _  ___  _   _ 
/ __|/ _ \/ _ \ | | |/ _ \| | | |
\__ \  __/  __/ |_| | (_) | |_| |
|___/\___|\___|\__, |\___/ \__,_|
                __/ |            
               |___/             v2.0

[*] SeeYou Advanced Port Scanner & Service Detector
[*] Created for Offensive Security Operations
`

type ScanResult struct {
	Port        int      `json:"port"`
	Protocol    string   `json:"protocol"`
	State       string   `json:"state"`
	Service     string   `json:"service"`
	Version     string   `json:"version,omitempty"`
	Banner      string   `json:"banner,omitempty"`
	TTL         int      `json:"ttl,omitempty"`
	Fingerprint []string `json:"fingerprint,omitempty"`
	CVEs        []string `json:"cves,omitempty"`
}

type ScanConfig struct {
	Target       string
	StartPort    int
	EndPort      int
	Timeout      time.Duration
	Threads      int
	ScanTCP      bool
	ScanUDP      bool
	GrabBanner   bool
	Stealth      bool
	RandomPorts  bool
	OutputFile   string
	OutputJSON   bool
	Verbose      bool
	PingFirst    bool
	ServiceScan  bool
	Fingerprint  bool
	CVECheck     bool
	WaitTime     time.Duration
	MaxRetries   int
	FragmentSize int
	PortRange    string
	ScanAll      bool
}

func main() {
	fmt.Print(BANNER)
	fmt.Println("[*] Starting SeeYou Port Scanner...")

	rand.Seed(time.Now().UnixNano())
	config := parseFlags()
	validateConfig(&config)

	fmt.Printf("[*] Target: %s\n", config.Target)
	fmt.Printf("[*] Port Range: %d-%d\n", config.StartPort, config.EndPort)

	if config.ScanTCP {
		fmt.Println("[*] TCP scan active")
	}
	if config.ScanUDP {
		fmt.Println("[*] UDP scan active")
	}
	if config.Stealth {
		fmt.Println("[*] Stealth mode active")
	}
	if config.ServiceScan {
		fmt.Println("[*] Service scan active")
	}
	if config.CVECheck {
		fmt.Println("[*] CVE check active")
	}
	fmt.Println()

	startTime := time.Now()

	if strings.Contains(config.Target, "/") {
		fmt.Printf("[*] Starting network scan: %s\n", config.Target)
		scanNetwork(config)
	} else {
		fmt.Printf("[*] Starting host scan: %s\n", config.Target)
		scanSingleHost(config)
	}

	duration := time.Since(startTime)
	fmt.Printf("\n[*] Scan completed! Time: %s\n", duration.Round(time.Second))
}

func parseFlags() ScanConfig {
	config := ScanConfig{}

	flag.StringVar(&config.Target, "host", "", "Target host/network")
	flag.IntVar(&config.StartPort, "start", 1, "Start port")
	flag.IntVar(&config.EndPort, "end", 1024, "End port")
	flag.StringVar(&config.PortRange, "p", "", "Port range (e.g., 80,443 or 1-1000)")
	flag.BoolVar(&config.ScanAll, "all", false, "Scan all ports (1-65535)")
	flag.DurationVar(&config.Timeout, "timeout", 2*time.Second, "Timeout")
	flag.IntVar(&config.Threads, "threads", 100, "Threads")
	flag.BoolVar(&config.ScanTCP, "tcp", true, "TCP scan")
	flag.BoolVar(&config.ScanUDP, "udp", false, "UDP scan")
	flag.BoolVar(&config.GrabBanner, "banner", false, "Banner grab")
	flag.BoolVar(&config.Stealth, "stealth", false, "Stealth scan")
	flag.BoolVar(&config.RandomPorts, "random", false, "Random port order")
	flag.StringVar(&config.OutputFile, "out", "", "Output file")
	flag.BoolVar(&config.OutputJSON, "json", false, "JSON output")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose")
	flag.BoolVar(&config.PingFirst, "ping", false, "Ping sweep")
	flag.BoolVar(&config.ServiceScan, "sV", false, "Service scan")
	flag.BoolVar(&config.Fingerprint, "fp", false, "OS/Service fingerprint")
	flag.BoolVar(&config.CVECheck, "cve", false, "CVE check")
	flag.DurationVar(&config.WaitTime, "wait", 100*time.Millisecond, "Wait between probes")
	flag.IntVar(&config.MaxRetries, "retry", 2, "Max retries")
	flag.IntVar(&config.FragmentSize, "frag", 0, "Fragment size")

	flag.Parse()
	return config
}

func validateConfig(config *ScanConfig) {
	if config.Target == "" {
		fmt.Println("[-] Error: Target required")
		os.Exit(1)
	}

	if config.ScanAll {
		config.StartPort = 1
		config.EndPort = 65535
	} else if config.PortRange != "" {
		if strings.Contains(config.PortRange, "-") {
			parts := strings.Split(config.PortRange, "-")
			if len(parts) == 2 {
				start, err1 := strconv.Atoi(parts[0])
				end, err2 := strconv.Atoi(parts[1])
				if err1 == nil && err2 == nil && start > 0 && end <= 65535 && start <= end {
					config.StartPort = start
					config.EndPort = end
				}
			}
		} else if strings.Contains(config.PortRange, ",") {
			ports := strings.Split(config.PortRange, ",")
			minPort := 65535
			maxPort := 1
			for _, p := range ports {
				if port, err := strconv.Atoi(p); err == nil && port > 0 && port <= 65535 {
					if port < minPort {
						minPort = port
					}
					if port > maxPort {
						maxPort = port
					}
				}
			}
			if minPort <= maxPort {
				config.StartPort = minPort
				config.EndPort = maxPort
			}
		}
	}

	if config.EndPort < config.StartPort {
		config.EndPort = config.StartPort
	}

	if config.Threads < 1 {
		config.Threads = 1
	} else if config.Threads > 1000 {
		config.Threads = 1000
	}

	if config.FragmentSize > 0 && config.FragmentSize < 8 {
		config.FragmentSize = 8
	}
}

func scanNetwork(config ScanConfig) {
	ip, ipNet, err := net.ParseCIDR(config.Target)
	if err != nil {
		fmt.Printf("[-] Invalid CIDR: %v\n", err)
		os.Exit(1)
	}

	var hosts []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		hosts = append(hosts, ip.String())
	}

	if config.RandomPorts {
		rand.Shuffle(len(hosts), func(i, j int) {
			hosts[i], hosts[j] = hosts[j], hosts[i]
		})
	}

	var allResults []ScanResult
	resultChan := make(chan []ScanResult, len(hosts))
	sem := make(chan bool, config.Threads)

	var wg sync.WaitGroup
	for _, host := range hosts {
		wg.Add(1)
		sem <- true
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			if config.PingFirst && !isHostAlive(h) {
				return
			}

			hostConfig := config
			hostConfig.Target = h
			results := scanHost(hostConfig)
			if len(results) > 0 {
				resultChan <- results
			}
		}(host)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for results := range resultChan {
		allResults = append(allResults, results...)
	}

	outputResults(allResults, config)
}

func scanSingleHost(config ScanConfig) {
	ips, err := net.LookupIP(config.Target)
	if err != nil || len(ips) == 0 {
		fmt.Printf("[-] Could not resolve host: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Resolved %s to %s\n", config.Target, ips[0].String())

	if config.PingFirst {
		fmt.Printf("[*] Checking if host is alive: %s\n", config.Target)
		if !isHostAlive(ips[0].String()) {
			fmt.Printf("[-] Host is not responding: %s\n", config.Target)
			os.Exit(1)
		}
		fmt.Printf("[+] Host is up: %s (%s)\n", config.Target, ips[0].String())
	}

	fmt.Printf("[*] Starting port scan (%d-%d)\n", config.StartPort, config.EndPort)
	results := scanHost(config)
	if len(results) == 0 {
		fmt.Println("[-] No open ports found")
		return
	}

	fmt.Printf("\n[+] Open ports found (%d):\n\n", len(results))
	fmt.Printf("PORT\t\tPROTO\tSTATE\t\tSERVICE\tVERSION\n")
	fmt.Println("------------------------------------------------------------")

	outputResults(results, config)
}

func scanHost(config ScanConfig) []ScanResult {
	var results []ScanResult
	totalPorts := config.EndPort - config.StartPort + 1

	resultChan := make(chan ScanResult, config.Threads*2)
	done := make(chan bool)

	var wg sync.WaitGroup
	var mu sync.Mutex // For thread-safe printing

	// Port scanning worker pool
	workerCount := config.Threads
	if workerCount > totalPorts {
		workerCount = totalPorts
	}

	// Fast port queue
	portChan := make(chan int, workerCount*4)
	go func() {
		defer close(portChan)
		commonPorts := []int{80, 443, 22, 21, 25, 3389, 3306, 1433, 8080, 8443, 445, 139, 135, 5900}
		// First scan common ports
		for _, port := range commonPorts {
			if port >= config.StartPort && port <= config.EndPort {
				portChan <- port
			}
		}
		// Then scan remaining ports
		if config.RandomPorts {
			ports := make([]int, 0, totalPorts)
			for port := config.StartPort; port <= config.EndPort; port++ {
				if !contains(commonPorts, port) {
					ports = append(ports, port)
				}
			}
			rand.Shuffle(len(ports), func(i, j int) {
				ports[i], ports[j] = ports[j], ports[i]
			})
			for _, port := range ports {
				portChan <- port
			}
		} else {
			for port := config.StartPort; port <= config.EndPort; port++ {
				if !contains(commonPorts, port) {
					portChan <- port
				}
			}
		}
	}()

	// Launch workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				if config.ScanTCP {
					result := scanTCPPort(config.Target, port, config)
					if result.State != "closed" {
						mu.Lock()
						fmt.Printf("[+] Found open port: %d/%s - %s\n",
							port, result.Protocol, result.Service)
						mu.Unlock()
						resultChan <- result
					}
				}

				if config.ScanUDP {
					result := scanUDPPort(config.Target, port, config)
					if result.State != "closed" {
						mu.Lock()
						fmt.Printf("[+] Found open UDP port: %d - %s\n",
							port, result.Service)
						mu.Unlock()
						resultChan <- result
					}
				}
			}
		}()
	}

	// Result collector
	go func() {
		wg.Wait()
		close(resultChan)
		close(done)
	}()

	// Collect results with timeout
	timeout := time.After(config.Timeout * time.Duration(totalPorts/config.Threads))
	for {
		select {
		case result, ok := <-resultChan:
			if !ok {
				if config.ServiceScan {
					fmt.Println("\n[*] Starting service detection...")
					return enhanceResults(results, config)
				}
				return results
			}
			results = append(results, result)
		case <-timeout:
			fmt.Println("\n[-] Scan timeout reached")
			return results
		}
	}
}

func contains(slice []int, item int) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func scanTCPPort(target string, port int, config ScanConfig) ScanResult {
	result := ScanResult{
		Port:     port,
		Protocol: "tcp",
		State:    "closed",
		Service:  getServiceName(port, "tcp"),
	}

	if config.Stealth {
		return stealthScanPort(target, port)
	}

	// Use very short timeout for initial connection
	timeout := 200 * time.Millisecond
	if config.ServiceScan {
		timeout = config.Timeout
	}

	addr := fmt.Sprintf("%s:%d", target, port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return result
	}
	defer conn.Close()

	result.State = "open"

	if config.GrabBanner {
		banner := grabBannerInfo(conn, port)
		if banner != "" {
			result.Banner = banner
			result.Version = detectVersion(banner, port)
		}
	}

	return result
}

func stealthScanPort(target string, port int) ScanResult {
	result := ScanResult{
		Port:     port,
		Protocol: "tcp",
		State:    "closed",
		Service:  getServiceName(port, "tcp"),
	}

	srcPort := 12345 + rand.Intn(53000)
	ipAddr, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return result
	}

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return result
	}
	defer conn.Close()

	synPacket := craftTCPSYNPacket(srcPort, port)
	_, err = conn.WriteTo(synPacket, ipAddr)
	if err != nil {
		return result
	}

	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		return result
	}

	if n > 0 && buffer[13] == 0x12 {
		result.State = "open"
	}

	return result
}

func scanUDPPort(target string, port int, config ScanConfig) ScanResult {
	result := ScanResult{
		Port:     port,
		Protocol: "udp",
		State:    "closed",
		Service:  getServiceName(port, "udp"),
	}

	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("udp", addr, config.Timeout)
	if err != nil {
		return result
	}
	defer conn.Close()

	probe := getUDPProbe(port)
	_, err = conn.Write(probe)
	if err != nil {
		return result
	}

	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(config.Timeout))
	_, err = conn.Read(buffer)

	if err == nil {
		result.State = "open"
	} else {
		result.State = "open|filtered"
	}

	return result
}

func getUDPProbe(port int) []byte {
	probes := map[int][]byte{
		53:    {0x00, 0x00, 0x10, 0x00, 0x00},             // DNS
		161:   {0x30, 0x26, 0x02, 0x01, 0x01},             // SNMP
		137:   {0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00}, // NetBIOS
		123:   {0x1b, 0x00, 0x00, 0x00},                   // NTP
		27015: {0xff, 0xff, 0xff, 0xff},                   // Source Engine
	}

	if probe, ok := probes[port]; ok {
		return probe
	}
	return []byte{0x00}
}

func craftTCPSYNPacket(srcPort, dstPort int) []byte {
	packet := make([]byte, 20)
	binary.BigEndian.PutUint16(packet[0:], uint16(srcPort))
	binary.BigEndian.PutUint16(packet[2:], uint16(dstPort))
	packet[13] = 0x02
	return packet
}

func enhanceResults(results []ScanResult, config ScanConfig) []ScanResult {
	for i := range results {
		if results[i].State == "open" {
			if config.Fingerprint {
				results[i].Fingerprint = fingerprint(results[i])
			}
			if config.CVECheck {
				results[i].CVEs = checkCVEs(results[i])
			}
		}
	}
	return results
}

func fingerprint(result ScanResult) []string {
	var fingerprints []string
	if result.Banner != "" {
		if strings.Contains(strings.ToLower(result.Banner), "apache") {
			fingerprints = append(fingerprints, "Apache")
		}
		if strings.Contains(strings.ToLower(result.Banner), "nginx") {
			fingerprints = append(fingerprints, "Nginx")
		}
		if strings.Contains(strings.ToLower(result.Banner), "microsoft") {
			fingerprints = append(fingerprints, "Microsoft")
		}
	}
	return fingerprints
}

func checkCVEs(result ScanResult) []string {
	var cves []string
	if result.Version != "" {
		switch {
		case strings.Contains(result.Service, "apache") && strings.Contains(result.Version, "2.4.49"):
			cves = append(cves, "CVE-2021-41773")
		case strings.Contains(result.Service, "openssh") && strings.Contains(result.Version, "7.2p1"):
			cves = append(cves, "CVE-2016-6515")
		}
	}
	return cves
}

func isHostAlive(ip string) bool {
	for _, port := range []int{80, 443, 22, 445} {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

func outputResults(results []ScanResult, config ScanConfig) {
	if len(results) == 0 {
		fmt.Println("\n[-] No open ports found")
		return
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Protocol != results[j].Protocol {
			return results[i].Protocol < results[j].Protocol
		}
		return results[i].Port < results[j].Port
	})

	// JSON output handling
	if config.OutputJSON {
		jsonData, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Printf("\n[-] Error creating JSON output: %v\n", err)
			return
		}

		// If output file is specified, save to file
		if config.OutputFile != "" {
			if err := ioutil.WriteFile(config.OutputFile, jsonData, 0644); err != nil {
				fmt.Printf("\n[-] Error saving JSON to file: %v\n", err)
			} else {
				fmt.Printf("\n[+] JSON results saved to: %s\n", config.OutputFile)
			}
		} else {
			// If no output file, print JSON to console
			fmt.Println(string(jsonData))
		}
		return
	}

	// Normal text output
	fmt.Printf("\n[+] Found %d open ports:\n\n", len(results))
	fmt.Printf("PORT\t\tPROTO\tSTATE\t\tSERVICE\tVERSION\n")
	fmt.Println("------------------------------------------------------------")

	for _, r := range results {
		fmt.Printf("%d/%s\t%-10s\t%-10s\t%s",
			r.Port,
			r.Protocol,
			r.State,
			r.Service,
			r.Version)

		if len(r.CVEs) > 0 {
			fmt.Printf("\t[CVE: %s]", strings.Join(r.CVEs, ", "))
		}
		fmt.Println()
	}

	// Save normal output to file if specified
	if config.OutputFile != "" {
		var output strings.Builder
		for _, r := range results {
			fmt.Fprintf(&output, "%d/%s\t%-10s\t%s", r.Port, r.Protocol, r.State, r.Service)
			if r.Version != "" {
				fmt.Fprintf(&output, "\t%s", r.Version)
			}
			if len(r.CVEs) > 0 {
				fmt.Fprintf(&output, "\tCVEs: %s", strings.Join(r.CVEs, ", "))
			}
			output.WriteString("\n")
		}

		if err := ioutil.WriteFile(config.OutputFile, []byte(output.String()), 0644); err != nil {
			fmt.Printf("\n[-] Error saving results to file: %v\n", err)
		} else {
			fmt.Printf("\n[+] Results saved to: %s\n", config.OutputFile)
		}
	}
}

func getServiceName(port int, protocol string) string {
	tcpServices := map[int]string{
		20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
		53: "domain", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
		139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
		587: "submission", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
		1521: "oracle", 3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
		5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
		9090: "zeus-admin", 9200: "elasticsearch", 27017: "mongodb",
	}

	udpServices := map[int]string{
		53: "domain", 67: "dhcps", 68: "dhcpc", 69: "tftp", 123: "ntp",
		161: "snmp", 162: "snmptrap", 500: "isakmp", 514: "syslog",
		520: "route", 631: "ipp", 1434: "ms-sql-m", 1900: "upnp",
		5353: "mdns", 11211: "memcache",
	}

	if protocol == "udp" {
		if service, ok := udpServices[port]; ok {
			return service
		}
	} else {
		if service, ok := tcpServices[port]; ok {
			return service
		}
	}
	return "unknown"
}

func grabBannerInfo(conn net.Conn, port int) string {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	switch port {
	case 80, 8080, 443:
		_, err := conn.Write([]byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"))
		if err != nil {
			return ""
		}
	case 25, 587:
		_, err := conn.Write([]byte("EHLO seeyou.scanner\r\n"))
		if err != nil {
			return ""
		}
	case 21:
	case 22:
	}

	reader := bufio.NewReader(conn)
	banner := ""

	for i := 0; i < 5; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		banner += line
	}

	return strings.TrimSpace(banner)
}

func detectVersion(banner string, port int) string {
	if banner == "" {
		return ""
	}

	lowerBanner := strings.ToLower(banner)

	switch port {
	case 22:
		if strings.Contains(lowerBanner, "openssh") {
			parts := strings.Split(banner, " ")
			for _, part := range parts {
				if strings.HasPrefix(part, "OpenSSH_") {
					return part
				}
			}
		}
	case 80, 443, 8080:
		if strings.Contains(lowerBanner, "server:") {
			lines := strings.Split(banner, "\n")
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "server:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) > 1 {
						return strings.TrimSpace(parts[1])
					}
				}
			}
		}
	case 21:
		if strings.Contains(lowerBanner, "ftp") {
			return strings.Split(banner, "\n")[0]
		}
	}

	return ""
}
