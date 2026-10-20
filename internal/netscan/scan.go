package netscan

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/iac"
)

var netRules = []Rule{
	{"DG-NET-001", "HIGH", "A database, cache or message broker answers on the network"},
	{"DG-NET-002", "CRITICAL", "The Docker API answers without TLS"},
	{"DG-NET-003", "HIGH", "A Kubernetes node or etcd port answers on the network"},
	{"DG-NET-004", "HIGH", "A cleartext remote-access service answers"},
	{"DG-NET-005", "MEDIUM", "Windows file sharing or Remote Desktop answers"},
}

// Rules lists the network and TLS rules.
func Rules() []Rule { return append(append([]Rule{}, netRules...), tlsRules...) }

// services names well-known ports, and says which rule an open one fails.
var services = map[int]struct{ name, rule string }{
	21: {"FTP", "DG-NET-004"}, 22: {"SSH", ""}, 23: {"Telnet", "DG-NET-004"}, 25: {"SMTP", ""}, 53: {"DNS", ""},
	80: {"HTTP", ""}, 110: {"POP3", ""}, 111: {"RPC portmapper", ""}, 135: {"Windows RPC", ""}, 139: {"NetBIOS", "DG-NET-005"},
	143: {"IMAP", ""}, 389: {"LDAP", ""}, 443: {"HTTPS", ""}, 445: {"SMB", "DG-NET-005"}, 465: {"SMTPS", ""},
	512: {"rexec", "DG-NET-004"}, 513: {"rlogin", "DG-NET-004"}, 514: {"rsh", "DG-NET-004"}, 587: {"SMTP submission", ""},
	636: {"LDAPS", ""}, 873: {"rsync", ""}, 993: {"IMAPS", ""}, 995: {"POP3S", ""}, 1433: {"SQL Server", "DG-NET-001"},
	1521: {"Oracle", "DG-NET-001"}, 1883: {"MQTT", "DG-NET-001"}, 2049: {"NFS", ""}, 2181: {"ZooKeeper", "DG-NET-001"},
	2375: {"Docker API", "DG-NET-002"}, 2376: {"Docker API (TLS)", ""}, 2379: {"etcd", "DG-NET-003"}, 2380: {"etcd peer", "DG-NET-003"},
	3000: {"HTTP (app)", ""}, 3306: {"MySQL", "DG-NET-001"}, 3389: {"Remote Desktop", "DG-NET-005"}, 4369: {"Erlang EPMD", "DG-NET-001"},
	5000: {"HTTP (app)", ""}, 5432: {"PostgreSQL", "DG-NET-001"}, 5601: {"Kibana", ""}, 5672: {"AMQP", "DG-NET-001"},
	5900: {"VNC", "DG-NET-004"}, 5984: {"CouchDB", "DG-NET-001"}, 5985: {"WinRM", ""}, 5986: {"WinRM (TLS)", ""},
	6379: {"Redis", "DG-NET-001"}, 6443: {"Kubernetes API", ""}, 7001: {"WebLogic", ""}, 8000: {"HTTP (alt)", ""},
	8080: {"HTTP (alt)", ""}, 8081: {"HTTP (alt)", ""}, 8086: {"InfluxDB", "DG-NET-001"}, 8443: {"HTTPS (alt)", ""},
	8500: {"Consul", ""}, 8888: {"HTTP (alt)", ""}, 9000: {"HTTP (alt)", ""}, 9042: {"Cassandra", "DG-NET-001"},
	9090: {"HTTP (Prometheus)", ""}, 9092: {"Kafka", "DG-NET-001"}, 9100: {"Node exporter", ""}, 9200: {"Elasticsearch", "DG-NET-001"},
	9300: {"Elasticsearch transport", "DG-NET-001"}, 9443: {"HTTPS (alt)", ""}, 10250: {"Kubelet", "DG-NET-003"},
	10255: {"Kubelet (read-only)", "DG-NET-003"}, 11211: {"Memcached", "DG-NET-001"}, 15672: {"RabbitMQ management", "DG-NET-001"},
	27017: {"MongoDB", "DG-NET-001"},
}

// tlsPorts usually speak TLS from the first byte.
var tlsPorts = map[int]bool{443: true, 465: true, 636: true, 993: true, 995: true, 2376: true, 5986: true, 6443: true, 8443: true, 9443: true, 10250: true}

// httpPorts usually speak plain HTTP.
var httpPorts = map[int]bool{80: true, 3000: true, 5000: true, 5601: true, 8000: true, 8080: true, 8081: true, 8086: true, 8500: true, 8888: true, 9000: true, 9090: true, 9100: true, 15672: true}

// DefaultPorts are the well-known ports, checked unless others are given.
func DefaultPorts() []int {
	ports := make([]int, 0, len(services))
	for port := range services {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

// ParsePorts reads "22,80,443" and ranges such as "8000-8100"; "" or
// "default" is DefaultPorts.
func ParsePorts(spec string) ([]int, error) {
	if spec == "" || spec == "default" {
		return DefaultPorts(), nil
	}
	seen := map[int]bool{}
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		low, high, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(low)
		b := a
		if err == nil && isRange {
			b, err = strconv.Atoi(high)
		}
		if err != nil || a < 1 || b > 65535 || a > b {
			return nil, fmt.Errorf("%q is not a port or range of ports (1-65535)", part)
		}
		for port := a; port <= b; port++ {
			if !seen[port] {
				seen[port] = true
				ports = append(ports, port)
			}
		}
	}
	sort.Ints(ports)
	return ports, nil
}

// Target is one address to scan, with the name it was given by, if any.
type Target struct {
	Address netip.Addr
	Name    string
}

// ParseTargets reads addresses, CIDR ranges and host names. A range gives
// its usable addresses; a name resolves to its addresses. More than max
// addresses in all is refused.
func ParseTargets(ctx context.Context, arguments []string, max int) ([]Target, error) {
	var targets []Target
	seen := map[netip.Addr]bool{}
	add := func(address netip.Addr, name string) error {
		if seen[address] {
			return nil
		}
		if len(targets) >= max {
			return fmt.Errorf("more than %d addresses: scan a smaller range, or several in turn", max)
		}
		seen[address] = true
		targets = append(targets, Target{Address: address, Name: name})
		return nil
	}
	for _, argument := range arguments {
		argument = strings.TrimSpace(argument)
		if prefix, err := netip.ParsePrefix(argument); err == nil {
			prefix = prefix.Masked()
			bits := prefix.Addr().BitLen() - prefix.Bits()
			if bits > 16 {
				return nil, fmt.Errorf("%s has more than 65536 addresses: scan a smaller range", argument)
			}
			for address := prefix.Addr(); prefix.Contains(address); address = address.Next() {
				// Leave out an IPv4 network's own and broadcast addresses.
				if prefix.Addr().Is4() && bits >= 2 && (address == prefix.Addr() || !prefix.Contains(address.Next())) {
					continue
				}
				if err := add(address, ""); err != nil {
					return nil, err
				}
			}
			continue
		}
		if address, err := netip.ParseAddr(argument); err == nil {
			if err := add(address, ""); err != nil {
				return nil, err
			}
			continue
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", argument)
		if err != nil || len(addresses) == 0 {
			return nil, fmt.Errorf("%s is not an address, a range or a name that resolves", argument)
		}
		for _, address := range addresses {
			if err := add(address.Unmap(), argument); err != nil {
				return nil, err
			}
		}
	}
	return targets, nil
}

// Options shape a scan.
type Options struct {
	Ports []int
	// Concurrency bounds connections open at once; Timeout one connection.
	Concurrency int
	Timeout     time.Duration
	// TLS checks the certificate and settings of each TLS service found.
	TLS   bool
	Roots *x509.CertPool
	Now   time.Time
}

// Service is an open port and what answered on it.
type Service struct {
	Port   int    `json:"port"`
	Name   string `json:"name"`
	Banner string `json:"banner,omitempty"`
	TLS    bool   `json:"tls"`
}

// Host is an address with open ports.
type Host struct {
	Address  string    `json:"address"`
	Name     string    `json:"name,omitempty"`
	Services []Service `json:"services"`
}

// Result is what a scan found.
type Result struct {
	Addresses int           `json:"addresses"`
	Ports     int           `json:"ports"`
	Hosts     []Host        `json:"hosts"`
	TLS       []TLSInfo     `json:"tls,omitempty"`
	Findings  []iac.Finding `json:"findings"`
	Notes     []string      `json:"notes,omitempty"`
}

// Scan connects to each port of each target, at most Concurrency at once,
// and reports what is open and what answered. It sends nothing but a TCP
// connect, and for web ports a HEAD request, and for TLS ports handshakes.
func Scan(ctx context.Context, targets []Target, options Options) Result {
	if options.Concurrency <= 0 {
		options.Concurrency = 64
	}
	if options.Timeout <= 0 {
		options.Timeout = 2 * time.Second
	}
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	if len(options.Ports) == 0 {
		options.Ports = DefaultPorts()
	}
	result := Result{Addresses: len(targets), Ports: len(options.Ports), Hosts: []Host{}, Findings: []iac.Finding{}}
	type job struct {
		target Target
		port   int
	}
	jobs := make(chan job)
	var mu sync.Mutex
	open := map[netip.Addr][]Service{}
	names := map[netip.Addr]string{}
	var wg sync.WaitGroup
	for worker := 0; worker < options.Concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if service, ok := probe(ctx, j.target, j.port, options.Timeout); ok {
					mu.Lock()
					open[j.target.Address] = append(open[j.target.Address], service)
					names[j.target.Address] = j.target.Name
					mu.Unlock()
				}
			}
		}()
	}
feed:
	for _, target := range targets {
		for _, port := range options.Ports {
			select {
			case <-ctx.Done():
				result.Notes = append(result.Notes, "The scan stopped early: "+ctx.Err().Error())
				break feed
			case jobs <- job{target, port}:
			}
		}
	}
	close(jobs)
	wg.Wait()

	addresses := make([]netip.Addr, 0, len(open))
	for address := range open {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })
	for _, address := range addresses {
		found := open[address]
		sort.Slice(found, func(i, j int) bool { return found[i].Port < found[j].Port })
		host := Host{Address: address.String(), Name: names[address], Services: found}
		result.Hosts = append(result.Hosts, host)
		label := host.Address
		if host.Name != "" {
			label = host.Name + " (" + host.Address + ")"
		}
		for _, service := range found {
			endpoint := net.JoinHostPort(host.Address, strconv.Itoa(service.Port))
			if known, ok := services[service.Port]; ok && known.rule != "" && !(service.TLS && known.rule == "DG-NET-002") {
				result.Findings = append(result.Findings, finding(known.rule, endpoint,
					fmt.Sprintf("%s: %s answers on port %d", label, known.name, service.Port), serviceAdvice(known.rule)))
			}
			if options.TLS && service.TLS {
				target := endpoint
				info, findings, err := CheckTLS(ctx, target, host.Name, options.Roots, options.Now, options.Timeout)
				if err != nil {
					result.Notes = append(result.Notes, err.Error())
					continue
				}
				result.TLS = append(result.TLS, info)
				result.Findings = append(result.Findings, findings...)
			}
		}
	}
	sort.SliceStable(result.Findings, func(i, j int) bool {
		return severityRank[result.Findings[i].Severity] > severityRank[result.Findings[j].Severity]
	})
	return result
}

var severityRank = map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

func serviceAdvice(rule string) string {
	switch rule {
	case "DG-NET-001":
		return "Data services should listen on localhost or a private network only, behind a firewall, with authentication and TLS. Many are found and emptied within hours of being exposed."
	case "DG-NET-002":
		return "The Docker API without TLS gives anyone who reaches it root on the machine. Close the port, or require TLS with client certificates (port 2376)."
	case "DG-NET-003":
		return "The kubelet and etcd control a cluster's nodes and its secrets. Allow them only from the control plane, and require client certificates."
	case "DG-NET-004":
		return "These send passwords and data unencrypted. Turn them off and use SSH, SFTP, or VNC over SSH."
	case "DG-NET-005":
		return "SMB and RDP are favourite targets of ransomware. Don't expose them beyond your internal network; use a VPN."
	}
	return ""
}

// probe connects to one port, and reads what the service says.
func probe(ctx context.Context, target Target, port int, timeout time.Duration) (Service, bool) {
	address := net.JoinHostPort(target.Address.String(), strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return Service{}, false
	}
	defer conn.Close()
	service := Service{Port: port, Name: "unknown"}
	if known, ok := services[port]; ok {
		service.Name = known.name
	}
	switch {
	case tlsPorts[port]:
		service.TLS = speaksTLS(ctx, address, target.Name, timeout)
	case httpPorts[port]:
		host := target.Name
		if host == "" {
			host = target.Address.String()
		}
		conn.SetDeadline(time.Now().Add(timeout))
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: DeaconGuard\r\n\r\n", host)
		reader := bufio.NewReader(conn)
		for i := 0; i < 30; i++ {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				service.Banner = printable(line[len("server:"):])
				break
			}
		}
	default:
		// Many services greet first: SSH, FTP, SMTP, Redis on error, MySQL.
		conn.SetReadDeadline(time.Now().Add(timeout))
		buffer := make([]byte, 256)
		if n, _ := conn.Read(buffer); n > 0 {
			service.Banner = printable(string(buffer[:n]))
		} else if speaksTLS(ctx, address, target.Name, timeout) {
			service.TLS = true
		}
	}
	return service, true
}

func speaksTLS(ctx context.Context, address, name string, timeout time.Duration) bool {
	_, err := handshake(ctx, address, name, &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}, timeout) //nolint:gosec // detection only
	return err == nil
}

// printable keeps the first line of a banner, without control bytes.
func printable(text string) string {
	line, _, _ := strings.Cut(text, "\n")
	var out strings.Builder
	for _, r := range strings.TrimSpace(line) {
		if r >= 32 && r < 127 {
			out.WriteRune(r)
		}
	}
	if out.Len() > 120 {
		return out.String()[:120]
	}
	return out.String()
}
