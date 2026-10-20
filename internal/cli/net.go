package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"deaconguard/internal/iac"
	"deaconguard/internal/netscan"
)

const (
	netUsage = "usage: deaconguard net scan TARGET... [--ports default|LIST] [--tls] [--concurrency N] [--timeout 2s] [--max-addresses 4096]\n" +
		"                             [--fail-on SEVERITY] [--skip RULE,...] [--format table|json|sarif|junit] [--output FILE]"
	tlsUsage = "usage: deaconguard tls check HOST[:PORT]... [--fail-on SEVERITY] [--skip RULE,...] [--format table|json|sarif|junit] [--output FILE]"
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
	maxAddresses, portSpec := 4096, ""
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
	fmt.Fprintf(diagnostics, "Scanning %d addresses, %d ports each, %d connections at a time. Scan only networks you own or may test.\n",
		len(targets), len(options.Ports), options.Concurrency)
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
	}
	result.Findings = skipRules(result.Findings, flags.skip)
	open := 0
	for _, host := range result.Hosts {
		open += len(host.Services)
	}
	return writeFindings(findingsReport{
		findings: result.Findings, notes: result.Notes, document: result, suite: strings.Join(arguments2, " "),
		summary: fmt.Sprintf("Scanned %d addresses: %d with open ports, %d open ports", result.Addresses, len(result.Hosts), open),
	}, flags.format, flags.output, flags.failOn, output, diagnostics)
}
