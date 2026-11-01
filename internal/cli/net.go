package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"deaconguard/internal/iac"
	"deaconguard/internal/netscan"
)

const (
	netUsage = "usage: deaconguard net scan TARGET... [--ports default|LIST] [--tls] [--web [--no-paths]] [--concurrency N] [--timeout 2s] [--max-addresses 4096]\n" +
		"                             [--fail-on SEVERITY] [--skip RULE,...] [--format table|json|sarif|junit] [--output FILE]"
	tlsUsage = "usage: deaconguard tls check HOST[:PORT]... [--fail-on SEVERITY] [--skip RULE,...] [--format table|json|sarif|junit] [--output FILE]"
	webUsage = "usage: deaconguard web check URL... [--no-paths] [--timeout 5s] [--fail-on SEVERITY] [--skip RULE,...] [--format table|json|sarif|junit] [--output FILE]"
)

// reportFlags are the output flags config, kube, net and tls commands share.
type reportFlags struct {
	failOn, format, output string
	skip                   map[string]bool
}

// parse takes one output flag, and says
// whether it was one.
func (f *reportFlags) parse(argument string, value func() (string, error)) (bool, error) {
	var err error
	switch {
	case argument == "--json":
		f.format = "json"
	case strings.HasPrefix(argument, "--fail-on"):
		f.failOn, err = value()
		f.failOn = strings.ToUpper(f.failOn)
		if err == nil && !slices.Contains(severityOrder, f.failOn) {
			err = errors.New("--fail-on is critical, high, medium or low")
		}
	case strings.HasPrefix(argument, "--skip"):
		var v string
		v, err = value()
		for _, id := range strings.Split(v, ",") {
			if id = strings.ToUpper(strings.TrimSpace(id)); id != "" {
				f.skip[id] = true
			}
		}
	case strings.HasPrefix(argument, "--format"):
		f.format, err = value()
		if err == nil && !slices.Contains(configFormats, f.format) {
			err = fmt.Errorf("--format is one of %s", strings.Join(configFormats, ", "))
		}
	case strings.HasPrefix(argument, "--output") || argument == "-o":
		f.output, err = value()
	default:
		return false, nil
	}
	return true, err
}

// argumentValue reads the value of the flag at index: --name=value or
// --name value, moving index past it.
func argumentValue(rest []string, index *int) func() (string, error) {
	argument := rest[*index]
	return func() (string, error) {
		if name, v, found := strings.Cut(argument, "="); found && strings.HasPrefix(name, "--") {
			return v, nil
		}
		if *index+1 >= len(rest) {
			return "", fmt.Errorf("%s needs a value", argument)
		}
		*index++
		return rest[*index], nil
	}
}

// runTLS handles `deaconguard tls check`: TLS handshakes only.
func runTLS(arguments []string, output, diagnostics io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "check" {
		return errors.New(tlsUsage)
	}
	flags := reportFlags{format: "table", skip: map[string]bool{}}
	var targets []string
	rest := arguments[1:]
	for index := 0; index < len(rest); index++ {
		if ok, err := flags.parse(rest[index], argumentValue(rest, &index)); err != nil {
			return err
		} else if ok {
			continue
		}
		if strings.HasPrefix(rest[index], "-") {
			return errors.New(tlsUsage)
		}
		targets = append(targets, rest[index])
	}
	if len(targets) == 0 {
		return errors.New(tlsUsage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var findings []iac.Finding
	var infos []netscan.TLSInfo
	var notes []string
	for _, target := range targets {
		address, name := target, ""
		if _, _, err := net.SplitHostPort(target); err != nil {
			address = net.JoinHostPort(target, "443")
		}
		if host, _, _ := net.SplitHostPort(address); net.ParseIP(host) == nil {
			name = host
		}
		fmt.Fprintf(diagnostics, "Checking TLS on %s\n", address)
		info, found, err := netscan.CheckTLS(ctx, address, name, nil, time.Now(), 5*time.Second)
		if err != nil {
			notes = append(notes, err.Error())
			continue
		}
		infos = append(infos, info)
		findings = append(findings, found...)
	}
	if flags.format == "table" {
		for _, info := range infos {
			fmt.Fprintf(output, "%s: %s, %s; certificate for %s, by %s, until %s; %s\n", info.Target, info.Version, info.Cipher,
				strings.Join(info.DNSNames, ", "), info.Issuer, info.NotAfter.Format("2006-01-02"), strings.Join(info.Protocols, ", "))
		}
	}
	findings = skipRules(findings, flags.skip)
	return writeFindings(findingsReport{
		findings: findings, notes: notes, document: map[string]any{"tls": infos, "findings": findings, "notes": notes},
		suite: strings.Join(targets, " "), summary: fmt.Sprintf("Checked TLS on %d of %d", len(infos), len(targets)),
	}, flags.format, flags.output, flags.failOn, output, diagnostics)
}

// runNet handles `deaconguard net scan`: which ports are open on the
// networks named, what answers on them, and with --tls their TLS.
func runNet(arguments []string, output, diagnostics io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "scan" {
		return errors.New(netUsage)
	}
	flags := reportFlags{format: "table", skip: map[string]bool{}}
	options := netscan.Options{Concurrency: 64, Timeout: 2 * time.Second}
	maxAddresses, portSpec, noPaths := 4096, "", false
	var arguments2 []string
	rest := arguments[1:]
	for index := 0; index < len(rest); index++ {
		argument := rest[index]
		value := argumentValue(rest, &index)
		if ok, err := flags.parse(argument, value); err != nil {
			return err
		} else if ok {
			continue
		}
		var err error
		switch {
		case argument == "--tls":
			options.TLS = true
		case argument == "--web":
			options.Web, options.WebPaths = true, true
		case argument == "--no-paths":
			noPaths = true
		case strings.HasPrefix(argument, "--ports"):
			portSpec, err = value()
		case strings.HasPrefix(argument, "--concurrency"):
			var v string
			if v, err = value(); err == nil {
				options.Concurrency, err = strconv.Atoi(v)
				if err == nil && (options.Concurrency < 1 || options.Concurrency > 512) {
					err = errors.New("--concurrency is 1 to 512")
				}
			}
		case strings.HasPrefix(argument, "--timeout"):
			var v string
			if v, err = value(); err == nil {
				options.Timeout, err = time.ParseDuration(v)
			}
		case strings.HasPrefix(argument, "--max-addresses"):
			var v string
			if v, err = value(); err == nil {
				maxAddresses, err = strconv.Atoi(v)
			}
		case strings.HasPrefix(argument, "-"):
			return errors.New(netUsage)
		default:
			arguments2 = append(arguments2, argument)
		}
		if err != nil {
			return err
		}
	}
	if len(arguments2) == 0 {
		return errors.New(netUsage)
	}
	if noPaths {
		if !options.Web {
			return errors.New("--no-paths goes with --web")
		}
		options.WebPaths = false
	}
	var err error
	if options.Ports, err = netscan.ParsePorts(portSpec); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	targets, err := netscan.ParseTargets(ctx, arguments2, maxAddresses)
	if err != nil {
		return err
	}
	fmt.Fprintf(diagnostics, "Scanning %d %s, %d %s each, %d connections at a time. Scan only networks you own or may test.\n",
		len(targets), pluralWord(len(targets), "address", "addresses"), len(options.Ports), pluralWord(len(options.Ports), "port", "ports"),
		options.Concurrency)
	result := netscan.Scan(ctx, targets, options)
	if flags.format == "table" {
		for _, host := range result.Hosts {
			label := host.Address
			if host.Name != "" {
				label = host.Name + " (" + host.Address + ")"
			}
			fmt.Fprintln(output, label)
			for _, service := range host.Services {
				detail := service.Name
				if service.TLS {
					detail += ", TLS"
				}
				if service.Banner != "" {
					detail += ": " + service.Banner
				}
				fmt.Fprintf(output, "  %5d/tcp  %s\n", service.Port, detail)
			}
		}
		printSites(output, result.Web)
	}
	result.Findings = skipRules(result.Findings, flags.skip)
	open := 0
	for _, host := range result.Hosts {
		open += len(host.Services)
	}
	return writeFindings(findingsReport{
		findings: result.Findings, notes: result.Notes, document: result, suite: strings.Join(arguments2, " "),
		summary: fmt.Sprintf("Scanned %d %s: %d with open ports, %d open %s", result.Addresses, pluralWord(result.Addresses, "address", "addresses"),
			len(result.Hosts), open, pluralWord(open, "port", "ports")),
	}, flags.format, flags.output, flags.failOn, output, diagnostics)
}

// printSites lists the web sites checked, for the table format.
func printSites(output io.Writer, sites []netscan.WebInfo) {
	for _, site := range sites {
		line := fmt.Sprintf("%s: %d", site.URL, site.Status)
		if site.FinalURL != "" {
			line += " → " + site.FinalURL
		}
		if site.Server != "" {
			line += ", " + site.Server
		}
		fmt.Fprintf(output, "%s (%d %s)\n", line, site.Requests, pluralWord(site.Requests, "request", "requests"))
	}
}

// runWeb handles `deaconguard web check`: GET requests only, without
// logging in, to a fixed list of paths.
func runWeb(arguments []string, output, diagnostics io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "check" {
		return errors.New(webUsage)
	}
	flags := reportFlags{format: "table", skip: map[string]bool{}}
	options := netscan.WebOptions{Paths: true, Timeout: 5 * time.Second}
	var sites []*url.URL
	rest := arguments[1:]
	for index := 0; index < len(rest); index++ {
		argument := rest[index]
		value := argumentValue(rest, &index)
		if ok, err := flags.parse(argument, value); err != nil {
			return err
		} else if ok {
			continue
		}
		switch {
		case argument == "--no-paths":
			options.Paths = false
		case strings.HasPrefix(argument, "--timeout"):
			v, err := value()
			if err == nil {
				options.Timeout, err = time.ParseDuration(v)
			}
			if err != nil || options.Timeout <= 0 {
				return errors.New("--timeout is a duration such as 5s")
			}
		case strings.HasPrefix(argument, "-"):
			return errors.New(webUsage)
		default:
			site, err := netscan.SiteURL(argument)
			if err != nil {
				return err
			}
			sites = append(sites, site)
		}
	}
	if len(sites) == 0 {
		return errors.New(webUsage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	var findings []iac.Finding
	var infos []netscan.WebInfo
	var notes []string
	for _, site := range sites {
		fmt.Fprintf(diagnostics, "Checking %s. Check only sites you own or may test.\n", site)
		siteOptions := options
		// Plain HTTP should send visitors to HTTPS when the host has it.
		siteOptions.HTTPS = site.Scheme == "http" && speaksHTTPS(ctx, site.Hostname(), options.Timeout)
		info, found, err := netscan.CheckWeb(ctx, site, siteOptions)
		if err != nil {
			notes = append(notes, err.Error())
			continue
		}
		infos = append(infos, info)
		findings = append(findings, found...)
	}
	if flags.format == "table" {
		printSites(output, infos)
	}
	findings = skipRules(findings, flags.skip)
	names := make([]string, len(sites))
	for index, site := range sites {
		names[index] = site.String()
	}
	return writeFindings(findingsReport{
		findings: findings, notes: notes, document: map[string]any{"web": infos, "findings": findings, "notes": notes},
		suite: strings.Join(names, " "), summary: fmt.Sprintf("Checked %d of %d %s", len(infos), len(sites), pluralWord(len(sites), "site", "sites")),
	}, flags.format, flags.output, flags.failOn, output, diagnostics)
}

// speaksHTTPS says whether host answers a TLS handshake on port 443.
func speaksHTTPS(ctx context.Context, host string, timeout time.Duration) bool {
	_, err := netscan.Handshake(ctx, net.JoinHostPort(host, "443"), host, timeout)
	return err == nil
}
