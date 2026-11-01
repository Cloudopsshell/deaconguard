package netscan

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"deaconguard/internal/buildinfo"
	"deaconguard/internal/iac"
)

var webRules = []Rule{
	{"DG-WEB-001", "CRITICAL", "A Git repository is published"},
	{"DG-WEB-002", "CRITICAL", "An environment (.env) file is published"},
	{"DG-WEB-003", "HIGH", "A Subversion working copy is published"},
	{"DG-WEB-004", "HIGH", "A server status or PHP information page is public"},
	{"DG-WEB-005", "HIGH", "Spring Boot's environment endpoint is public"},
	{"DG-WEB-006", "MEDIUM", "Prometheus metrics are public"},
	{"DG-WEB-007", "HIGH", "CORS lets any website read responses with the visitor's cookies"},
	{"DG-WEB-008", "MEDIUM", "The site answers over plain HTTP without redirecting to HTTPS"},
	{"DG-WEB-009", "MEDIUM", "Directory listing is on"},
	{"DG-WEB-010", "MEDIUM", "Cookies are set without Secure on HTTPS"},
	{"DG-WEB-011", "LOW", "Cookies are set without HttpOnly or SameSite"},
	{"DG-WEB-012", "MEDIUM", "HTTPS without HSTS, or with HSTS shorter than 180 days"},
	{"DG-WEB-013", "LOW", "Pages have no Content-Security-Policy"},
	{"DG-WEB-014", "LOW", "Pages can be framed by other sites"},
	{"DG-WEB-015", "LOW", "Pages don't set X-Content-Type-Options: nosniff"},
	{"DG-WEB-016", "LOW", "The server names its software version"},
}

// Limits of a web check: each site gets at most a few dozen kilobytes read
// from each of about 15 requests, one at a time.
const (
	webBodyLimit    = 64 << 10
	webMaxRedirects = 3
	// webConcurrency is how many sites a network scan checks at once.
	webConcurrency = 4
	// corsOrigin is a name that can't exist, sent to see whether a site
	// trusts any origin.
	corsOrigin = "https://deaconguard-cors-check.invalid"
)

// webPath is a path a site should never publish, and how to recognise it:
// a status 200 alone isn't enough, since many sites answer every path.
type webPath struct {
	path, rule string
	matches    func(body string, contentType string) bool
}

var (
	envLine      = regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]{1,63}=`)
	gitHead      = regexp.MustCompile(`^(ref: refs/|[0-9a-f]{40}\s*$)`)
	svnEntries   = regexp.MustCompile(`^\d{1,2}\s*\n`)
	metricsLines = regexp.MustCompile(`(?m)^# (HELP|TYPE) [a-zA-Z_:][a-zA-Z0-9_:]* `)
)

func notHTML(body, contentType string) bool {
	lower := strings.ToLower(body)
	return !strings.Contains(contentType, "html") && !strings.Contains(lower, "<html") && !strings.Contains(lower, "<!doctype")
}

var webPaths = []webPath{
	{"/.git/HEAD", "DG-WEB-001", func(body, contentType string) bool { return gitHead.MatchString(body) }},
	{"/.env", "DG-WEB-002", func(body, contentType string) bool {
		return notHTML(body, contentType) && len(envLine.FindAllString(body, 3)) >= 2
	}},
	{"/.svn/entries", "DG-WEB-003", func(body, contentType string) bool { return notHTML(body, contentType) && svnEntries.MatchString(body) }},
	{"/server-status", "DG-WEB-004", func(body, contentType string) bool {
		return strings.Contains(body, "Apache Server Status") || strings.HasPrefix(body, "Active connections:")
	}},
	{"/phpinfo.php", "DG-WEB-004", isPHPInfo},
	{"/info.php", "DG-WEB-004", isPHPInfo},
	{"/actuator/env", "DG-WEB-005", func(body, contentType string) bool {
		var document struct {
			PropertySources []json.RawMessage `json:"propertySources"`
		}
		return json.Unmarshal([]byte(body), &document) == nil && len(document.PropertySources) > 0
	}},
	{"/metrics", "DG-WEB-006", func(body, contentType string) bool { return len(metricsLines.FindAllString(body, 2)) >= 2 }},
}

func isPHPInfo(body, contentType string) bool {
	return strings.Contains(body, "phpinfo()") && strings.Contains(body, "PHP Version")
}

// WebOptions shape a web check.
type WebOptions struct {
	// Paths asks for the paths a site should never publish, such as
	// /.git/HEAD; without it, only the home page is read.
	Paths bool
	// HTTPS says the same host serves HTTPS on port 443, so plain HTTP
	// should redirect there.
	HTTPS   bool
	Timeout time.Duration
	// Address, if set, is where to connect instead of the URL's host, so a
	// name can be checked on each of its addresses.
	Address string
}

// WebInfo is what a web check read of a site.
type WebInfo struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	FinalURL string `json:"final_url,omitempty"`
	Server   string `json:"server,omitempty"`
	Requests int    `json:"requests"`
}

func webRule(id string) Rule {
	for _, rule := range webRules {
		if rule.ID == id {
			return rule
		}
	}
	return Rule{ID: id, Severity: "MEDIUM"}
}

func webFinding(id, site, detail string) iac.Finding {
	rule := webRule(id)
	return iac.Finding{Rule: id, Severity: rule.Severity, Title: site + ": " + rule.Title, Detail: detail, File: site, Line: 1}
}

// webClient reads one site, only GET requests, following redirects on the
// same host only, and counts what it sent.
type webClient struct {
	client   *http.Client
	site     *url.URL
	requests int
}

func newWebClient(site *url.URL, options WebOptions) *webClient {
	dialer := &net.Dialer{Timeout: options.Timeout}
	transport := &http.Transport{
		// The certificate is the TLS check's job; here only what the site
		// serves matters.
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // read-only check of a site the user owns
		MaxConnsPerHost:     1,
		TLSHandshakeTimeout: options.Timeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if options.Address != "" {
				_, port, _ := net.SplitHostPort(address)
				address = net.JoinHostPort(options.Address, port)
			}
			return dialer.DialContext(ctx, network, address)
		},
		Proxy: nil,
	}
	client := &webClient{site: site}
	client.client = &http.Client{
		Transport: transport,
		Timeout:   options.Timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= webMaxRedirects || request.URL.Hostname() != site.Hostname() {
				return http.ErrUseLastResponse
			}
			client.requests++
			return nil
		},
	}
	return client
}

type webResponse struct {
	status      int
	header      http.Header
	body        string
	finalURL    *url.URL
	contentType string
	cookies     []*http.Cookie
}

func (c *webClient) get(ctx context.Context, path string, header map[string]string) (webResponse, error) {
	target := *c.site
	target.Path, target.RawQuery = path, ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return webResponse{}, err
	}
	request.Header.Set("User-Agent", "DeaconGuard/"+buildinfo.Version+" (web check; +https://docs.deaconguard.io/usage/network)")
	for name, value := range header {
		request.Header.Set(name, value)
	}
	c.requests++
	response, err := c.client.Do(request)
	if err != nil {
		return webResponse{}, err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, webBodyLimit))
	return webResponse{status: response.StatusCode, header: response.Header, body: string(body), finalURL: response.Request.URL,
		contentType: strings.ToLower(response.Header.Get("Content-Type")), cookies: response.Cookies()}, nil
}

// SiteURL reads a site given as a URL, or as a host name or host:port,
// which is taken as HTTPS.
func SiteURL(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	site, err := url.Parse(raw)
	if err != nil || (site.Scheme != "http" && site.Scheme != "https") || site.Hostname() == "" {
		return nil, fmt.Errorf("%q is not a web address such as https://shop.example.com", raw)
	}
	site.Path, site.RawQuery, site.Fragment, site.User = "", "", "", nil
	return site, nil
}

// CheckWeb checks one site from the outside, without logging in: its home
// page's headers and cookies, whether any website may read it with the
// visitor's cookies, and, with Paths, a fixed list of files and pages that
// should never be public. It sends only GET requests, about 15 in all, one
// at a time, and reads at most 64 KB of each answer.
func CheckWeb(ctx context.Context, site *url.URL, options WebOptions) (WebInfo, []iac.Finding, error) {
	if options.Timeout <= 0 {
		options.Timeout = 5 * time.Second
	}
	label := site.String()
	client := newWebClient(site, options)
	info := WebInfo{URL: label}
	home, err := client.get(ctx, "/", nil)
	if err != nil {
		return info, nil, fmt.Errorf("%s: %w", label, unwrapURLError(err))
	}
	info.Status, info.Server = home.status, printable(home.header.Get("Server"))
	if home.finalURL.String() != site.String()+"/" {
		info.FinalURL = home.finalURL.String()
	}
	var findings []iac.Finding
	secure := home.finalURL.Scheme == "https"
	html := strings.Contains(home.contentType, "html")

	page := home.status >= 200 && home.status < 300
	// A redirect elsewhere, such as to https://www.example.com, isn't followed
	// but counts as one.
	redirected := home.status >= 300 && home.status < 400 && strings.HasPrefix(strings.ToLower(home.header.Get("Location")), "https://")
	if site.Scheme == "http" && !secure && !redirected && home.status < 400 && options.HTTPS {
		findings = append(findings, webFinding("DG-WEB-008", label,
			"Visitors who type the address get the site unencrypted, though the same host serves HTTPS. Redirect every plain HTTP request to HTTPS (301), and set HSTS on the HTTPS site."))
	}
	if strings.Contains(home.body, "<title>Index of /") || strings.Contains(home.body, "<title>Directory listing for /") {
		findings = append(findings, webFinding("DG-WEB-009", label,
			"The web server lists the files in its root folder, so anyone can browse and download them. Turn listing off (autoindex off in nginx, Options -Indexes in Apache)."))
	}
	if secure && home.status < 400 {
		hsts := home.header.Get("Strict-Transport-Security")
		if age, ok := maxAge(hsts); !ok || age < 180*24*3600 {
			detail := "There is no Strict-Transport-Security header, so a visitor's first request can be downgraded to plain HTTP."
			if ok {
				detail = fmt.Sprintf("HSTS max-age is %d days; browsers forget it sooner than they should.", age/86400)
			}
			findings = append(findings, webFinding("DG-WEB-012", label, detail+" Send Strict-Transport-Security: max-age=31536000; includeSubDomains."))
		}
	}
	if html && page {
		csp := home.header.Get("Content-Security-Policy")
		if csp == "" {
			findings = append(findings, webFinding("DG-WEB-013", label,
				"Without a Content-Security-Policy, injected scripts run with the page's rights. Start with one that names where scripts may come from."))
		}
		if home.header.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
			findings = append(findings, webFinding("DG-WEB-014", label,
				"Other sites can show these pages in a frame and trick visitors into clicking them (clickjacking). Send X-Frame-Options: DENY, or Content-Security-Policy: frame-ancestors 'self'."))
		}
		if !strings.EqualFold(strings.TrimSpace(home.header.Get("X-Content-Type-Options")), "nosniff") {
			findings = append(findings, webFinding("DG-WEB-015", label,
				"Browsers may guess a file's type and run an upload as a script. Send X-Content-Type-Options: nosniff."))
		}
	}
	if versions := versionHeaders(home.header); len(versions) > 0 {
		findings = append(findings, webFinding("DG-WEB-016", label,
			"The server says what it runs: "+strings.Join(versions, "; ")+". That tells attackers which known vulnerabilities to try. Hide versions (server_tokens off in nginx, ServerTokens Prod in Apache, expose_php = Off)."))
	}
	findings = append(findings, cookieFindings(label, home.cookies, secure)...)

	if cors, err := client.get(ctx, "/", map[string]string{"Origin": corsOrigin}); err == nil {
		allowed := cors.header.Get("Access-Control-Allow-Origin")
		if allowed == corsOrigin && strings.EqualFold(cors.header.Get("Access-Control-Allow-Credentials"), "true") {
			findings = append(findings, webFinding("DG-WEB-007", label,
				"The site trusts any origin it's sent, with credentials: a page on any website can read what this site shows a logged-in visitor. Allow only your own origins."))
		}
	}

	if options.Paths {
		reported := map[string]bool{}
		for _, check := range webPaths {
			if ctx.Err() != nil || reported[check.rule] {
				continue
			}
			response, err := client.get(ctx, check.path, nil)
			if err != nil || response.status != http.StatusOK || response.finalURL.Path != check.path {
				continue
			}
			if check.matches(response.body, response.contentType) {
				reported[check.rule] = true
				findings = append(findings, webFinding(check.rule, label, pathAdvice(check)))
			}
		}
	}
	info.Requests = client.requests
	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank[findings[i].Severity] > severityRank[findings[j].Severity]
	})
	return info, findings, nil
}

func pathAdvice(check webPath) string {
	switch check.rule {
	case "DG-WEB-001":
		return check.path + " is readable: anyone can download the site's source code and its history, often with passwords in it. Block /.git in the web server, and deploy without the .git folder."
	case "DG-WEB-002":
		return check.path + " is readable: it usually holds database passwords and API keys. Remove it from the web root, block dot files, and change every secret it held."
	case "DG-WEB-003":
		return check.path + " is readable: anyone can list and download the site's source. Block /.svn in the web server, and deploy without it."
	case "DG-WEB-004":
		return check.path + " is public: it shows the server's configuration, versions and current requests. Remove it, or allow it only from localhost."
	case "DG-WEB-005":
		return check.path + " is public: Spring Boot's environment endpoint shows configuration, sometimes with secrets. Expose only health and info, and require a login for the rest."
	case "DG-WEB-006":
		return check.path + " is public: metrics show what runs inside and how busy it is. Allow them only from your monitoring."
	}
	return ""
}

// maxAge reads max-age from an HSTS header.
func maxAge(header string) (int, bool) {
	for _, part := range strings.Split(header, ";") {
		name, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if found && strings.EqualFold(name, "max-age") {
			age, err := strconv.Atoi(strings.Trim(value, `"`))
			return age, err == nil
		}
	}
	return 0, false
}

var versionNumber = regexp.MustCompile(`\d+\.\d+`)

// versionHeaders lists headers that give a software version away.
func versionHeaders(header http.Header) []string {
	var found []string
	for _, name := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"} {
		if value := printable(header.Get(name)); value != "" && versionNumber.MatchString(value) {
			found = append(found, name+": "+value)
		}
	}
	return found
}

func cookieFindings(label string, cookies []*http.Cookie, secure bool) []iac.Finding {
	var insecure, loose []string
	for _, cookie := range cookies {
		if secure && !cookie.Secure {
			insecure = append(insecure, cookie.Name)
		}
		if !cookie.HttpOnly || cookie.SameSite == http.SameSiteDefaultMode {
			loose = append(loose, cookie.Name)
		}
	}
	var findings []iac.Finding
	if len(insecure) > 0 {
		findings = append(findings, webFinding("DG-WEB-010", label,
			"Cookies without Secure ("+strings.Join(insecure, ", ")+") are also sent over plain HTTP, where anyone on the network can read them. Set Secure on every cookie of an HTTPS site."))
	}
	if len(loose) > 0 {
		findings = append(findings, webFinding("DG-WEB-011", label,
			"Cookies without HttpOnly can be read by scripts, and without SameSite are sent with requests from other sites ("+strings.Join(loose, ", ")+"). Set HttpOnly on session cookies, and SameSite=Lax or Strict."))
	}
	return findings
}

func unwrapURLError(err error) error {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return urlError.Err
	}
	return err
}

// webPorts are the ports a network scan checks as web sites: the plain HTTP
// ports, and these when they speak TLS.
var httpsPorts = map[int]bool{443: true, 8443: true, 9443: true}

// webSites lists the web sites among a host's services.
func webSites(host Host) []*url.URL {
	name := host.Name
	if name == "" {
		name = host.Address
	}
	var sites []*url.URL
	for _, service := range host.Services {
		scheme := ""
		switch {
		case service.TLS && (httpsPorts[service.Port] || strings.HasPrefix(service.Name, "HTTPS")):
			scheme = "https"
		case !service.TLS && httpPorts[service.Port]:
			scheme = "http"
		default:
			continue
		}
		hostPort := net.JoinHostPort(name, strconv.Itoa(service.Port))
		if (scheme == "https" && service.Port == 443) || (scheme == "http" && service.Port == 80) {
			hostPort = name
			if strings.Contains(name, ":") {
				hostPort = "[" + name + "]"
			}
		}
		sites = append(sites, &url.URL{Scheme: scheme, Host: hostPort})
	}
	return sites
}

// servesHTTPS says whether a host's scan found HTTPS on port 443.
func servesHTTPS(host Host) bool {
	for _, service := range host.Services {
		if service.Port == 443 && service.TLS {
			return true
		}
	}
	return false
}
