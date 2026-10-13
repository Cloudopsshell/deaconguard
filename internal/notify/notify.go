// Package notify sends DeaconGuard's notifications: by email, to Slack, to
// Microsoft Teams, and to any webhook.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"deaconguard/internal/buildinfo"
)

// Channel types.
const (
	Email   = "email"
	Slack   = "slack"
	Teams   = "teams"
	Webhook = "webhook"
	// SIEM and ticketing.
	Syslog     = "syslog"
	Splunk     = "splunk"
	Jira       = "jira"
	ServiceNow = "servicenow"
)

// Kinds lists the channel types.
var Kinds = []string{Email, Slack, Teams, Webhook, Syslog, Splunk, Jira, ServiceNow}

// Events a channel can subscribe to.
const (
	EventExploited    = "exploited"     // a host has vulnerabilities known to be exploited it didn't have before
	EventCritical     = "critical"      // a host has new critical vulnerabilities with a fix
	EventMalware      = "malware"       // malware or signs of compromise were found
	EventIntegrity    = "integrity"     // system files differ from their packages
	EventScanFailed   = "scan_failed"   // a scan failed
	EventAudit        = "audit"         // an audit finished
	EventAgentOffline = "agent_offline" // an agent stopped checking in
	EventDigest       = "digest"        // the daily or weekly summary
	EventTest         = "test"          // Send test
)

// Events lists the events channels subscribe to, in the dashboard's order.
var Events = []string{EventExploited, EventCritical, EventMalware, EventIntegrity, EventScanFailed, EventAudit, EventAgentOffline, EventDigest}

// Levels say how urgent a message is.
const (
	LevelCritical = "critical"
	LevelWarning  = "warning"
	LevelInfo     = "info"
)

// Message is one notification, the same for every channel type.
type Message struct {
	Event string `json:"event"`
	Level string `json:"level"`
	// Title is one line, such as "web-01: 2 vulnerabilities known to be
	// exploited".
	Title string `json:"title"`
	// Lines say more, one fact each.
	Lines []string `json:"lines,omitempty"`
	// Link opens the matter in the dashboard, when the dashboard's address
	// is set.
	Link   string `json:"link,omitempty"`
	HostID string `json:"host_id,omitempty"`
	Host   string `json:"host,omitempty"`
	ScanID string `json:"scan_id,omitempty"`
	// Data is the event's details, for webhooks.
	Data map[string]any `json:"data,omitempty"`
	At   time.Time      `json:"at"`
	// Attachment is a file sent with emails only, such as the digest's CSV.
	Attachment *Attachment `json:"-"`
}

// Attachment is a file attached to an email.
type Attachment struct {
	Name        string
	ContentType string
	Data        []byte
}

// Config is a channel's settings. Which fields apply depends on its type.
// Secrets (Password, URL, Secret) never leave the server once saved; see
// Redacted.
type Config struct {
	// Email.
	Host     string   `json:"host,omitempty"`
	Port     int      `json:"port,omitempty"`
	TLS      string   `json:"tls,omitempty"` // starttls, tls (implicit, usually port 465) or none
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	From     string   `json:"from,omitempty"`
	To       []string `json:"to,omitempty"`
	// Slack, Teams and webhooks.
	URL string `json:"url,omitempty"`
	// Secret signs webhook bodies, or is Splunk's HEC token.
	Secret string `json:"secret,omitempty"`
	// Syslog: Host and Port, over Protocol: tcp, tls or udp.
	Protocol string `json:"protocol,omitempty"`
	// Splunk: the index; empty uses the token's default.
	Index string `json:"index,omitempty"`
	// Jira: the project key and issue type. Username and Password are an
	// Atlassian account's email and API token (Cloud), or Password alone a
	// personal access token (Data Center).
	Project   string `json:"project,omitempty"`
	IssueType string `json:"issue_type,omitempty"`
	// ServiceNow: the table records go in, incident by default.
	Table string `json:"table,omitempty"`
}

// TLS modes for email.
const (
	TLSStartTLS = "starttls"
	TLSImplicit = "tls"
	TLSNone     = "none"
)

// Validate checks a channel's settings for its type.
func (c Config) Validate(kind string) error {
	switch kind {
	case Email:
		if c.Host == "" || strings.ContainsAny(c.Host, " /:@") {
			return errors.New("give the mail server's host name, such as smtp.example.com")
		}
		if c.Port < 1 || c.Port > 65535 {
			return errors.New("the mail server's port is 1 to 65535, usually 587 or 465")
		}
		switch c.TLS {
		case TLSStartTLS, TLSImplicit:
		case TLSNone:
			if c.Username != "" {
				return errors.New("a username and password need encryption: choose STARTTLS or TLS")
			}
		default:
			return errors.New("choose STARTTLS, TLS or no encryption")
		}
		if _, err := mail.ParseAddress(c.From); err != nil {
			return errors.New("the From address is not an email address")
		}
		if len(c.To) == 0 || len(c.To) > 20 {
			return errors.New("give 1 to 20 recipients")
		}
		for _, to := range c.To {
			if _, err := mail.ParseAddress(to); err != nil {
				return fmt.Errorf("%q is not an email address", to)
			}
		}
		if strings.ContainsAny(c.From+c.Username, "\r\n") {
			return errors.New("addresses can't contain line breaks")
		}
	case Syslog:
		if c.Host == "" || strings.ContainsAny(c.Host, " /@") {
			return errors.New("give the syslog server's host name or address")
		}
		if c.Port < 1 || c.Port > 65535 {
			return errors.New("the syslog server's port is 1 to 65535, usually 514, or 6514 for TLS")
		}
		if c.Protocol != "tcp" && c.Protocol != "tls" && c.Protocol != "udp" {
			return errors.New("choose TCP, TLS or UDP")
		}
	case Splunk, Jira, ServiceNow:
		parsed, err := url.Parse(c.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return errors.New("give the address, starting with https://")
		}
		switch kind {
		case Splunk:
			if c.Secret == "" {
				return errors.New("give the HEC token")
			}
		case Jira:
			if c.Password == "" {
				return errors.New("give an API token (Jira Cloud, with your email as the username) or a personal access token (Data Center)")
			}
			if !projectKey.MatchString(c.Project) {
				return errors.New("give the project's key, such as SEC")
			}
		case ServiceNow:
			if c.Username == "" || c.Password == "" {
				return errors.New("give the ServiceNow account's username and password")
			}
			if c.Table != "" && !tableName.MatchString(c.Table) {
				return errors.New("the table is a name such as incident or sn_si_incident")
			}
		}
	case Slack, Teams, Webhook:
		parsed, err := url.Parse(c.URL)
		if err != nil || parsed.Host == "" || parsed.User != nil {
			return errors.New("give the webhook's full address, starting with https://")
		}
		if parsed.Scheme != "https" && !(kind == Webhook && parsed.Scheme == "http") {
			return errors.New("the webhook address must start with https://")
		}
		if len(c.URL) > 2048 || len(c.Secret) > 256 {
			return errors.New("the address or secret is too long")
		}
	default:
		return fmt.Errorf("unknown channel type %q", kind)
	}
	return nil
}

// Redacted is c without its secrets, for the dashboard: whether a password
// or secret is set, and the webhook's host.
func (c Config) Redacted() Config {
	redacted := c
	if redacted.Password != "" {
		redacted.Password = "set"
	}
	if redacted.Secret != "" {
		redacted.Secret = "set"
	}
	if redacted.URL != "" {
		if parsed, err := url.Parse(redacted.URL); err == nil {
			redacted.URL = parsed.Scheme + "://" + parsed.Host + "/…"
		} else {
			redacted.URL = "set"
		}
	}
	return redacted
}

// Merge keeps c's saved secrets where update leaves them empty, so editing
// a channel doesn't need them typed again.
func (c Config) Merge(update Config) Config {
	if update.Password == "" {
		update.Password = c.Password
	}
	if update.URL == "" {
		update.URL = c.URL
	}
	if update.Secret == "" {
		update.Secret = c.Secret
	}
	return update
}

// timeout bounds every delivery.
const timeout = 20 * time.Second

// Send delivers message on a channel of kind with config.
func Send(ctx context.Context, kind string, config Config, message Message) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch kind {
	case Email:
		return sendEmail(ctx, config, message)
	case Slack:
		return post(ctx, config.URL, slackBody(message), nil)
	case Teams:
		return post(ctx, config.URL, teamsBody(message), nil)
	case Webhook:
		body, err := json.Marshal(webhookPayload(message))
		if err != nil {
			return err
		}
		return post(ctx, config.URL, body, signer(config.Secret, message.Event))
	case Syslog:
		return sendSyslog(ctx, config, message)
	case Splunk:
		return sendSplunk(ctx, config, message)
	case Jira:
		return sendJira(ctx, config, message)
	case ServiceNow:
		return sendServiceNow(ctx, config, message)
	default:
		return fmt.Errorf("unknown channel type %q", kind)
	}
}

// client posts to webhooks: no proxy surprises beyond the environment's, no
// redirects (a redirect could send the message somewhere else).
var client = &http.Client{
	Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func post(ctx context.Context, address string, body []byte, sign func(*http.Request, []byte)) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", buildinfo.UserAgent())
	if sign != nil {
		sign(request, body)
	}
	response, err := client.Do(request)
	if err != nil {
		// The error names the address, which can hold a webhook's secret.
		var urlError *url.Error
		if errors.As(err, &urlError) {
			err = urlError.Err
		}
		return fmt.Errorf("could not reach the webhook: %w", err)
	}
	defer response.Body.Close()
	detail, _ := io.ReadAll(io.LimitReader(response.Body, 300))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		text := strings.TrimSpace(strings.ToValidUTF8(string(detail), ""))
		if text != "" {
			return fmt.Errorf("the webhook answered HTTP %d: %s", response.StatusCode, text)
		}
		return fmt.Errorf("the webhook answered HTTP %d", response.StatusCode)
	}
	return nil
}

// signer signs webhook bodies so receivers can check they come from this
// server: X-DeaconGuard-Signature is sha256= and the hex HMAC-SHA256, with
// the secret, of the timestamp, a dot, and the body.
func signer(secret, event string) func(*http.Request, []byte) {
	return func(request *http.Request, body []byte) {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		request.Header.Set("X-DeaconGuard-Event", event)
		request.Header.Set("X-DeaconGuard-Timestamp", timestamp)
		if secret != "" {
			request.Header.Set("X-DeaconGuard-Signature", "sha256="+Signature(secret, timestamp, body))
		}
	}
}

// Signature is the hex HMAC-SHA256 of "timestamp.body" with secret.
func Signature(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func webhookPayload(message Message) map[string]any {
	payload := map[string]any{
		"event": message.Event, "level": message.Level, "title": message.Title, "lines": message.Lines,
		"at": message.At.UTC().Format(time.RFC3339), "source": "deaconguard", "version": buildinfo.Version,
	}
	for key, value := range map[string]string{"link": message.Link, "host_id": message.HostID, "host": message.Host, "scan_id": message.ScanID} {
		if value != "" {
			payload[key] = value
		}
	}
	if len(message.Data) > 0 {
		payload["data"] = message.Data
	}
	return payload
}

var levelEmoji = map[string]string{LevelCritical: ":rotating_light:", LevelWarning: ":warning:", LevelInfo: ":information_source:"}

func slackBody(message Message) []byte {
	var text strings.Builder
	fmt.Fprintf(&text, "%s *%s*", levelEmoji[message.Level], slackEscape(message.Title))
	for _, line := range message.Lines {
		text.WriteString("\n• " + slackEscape(line))
	}
	if message.Link != "" {
		fmt.Fprintf(&text, "\n<%s|Open in DeaconGuard>", message.Link)
	}
	body, _ := json.Marshal(map[string]any{"text": text.String(), "unfurl_links": false})
	return body
}

// slackEscape keeps text from being read as Slack's link or mention syntax.
func slackEscape(text string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(text)
}

var teamsColor = map[string]string{LevelCritical: "Attention", LevelWarning: "Warning", LevelInfo: "Accent"}

// teamsBody is an Adaptive Card message, which Teams' Workflows webhooks
// ("When a Teams webhook request is received") and older incoming webhooks
// both accept.
func teamsBody(message Message) []byte {
	items := []map[string]any{
		{"type": "TextBlock", "text": message.Title, "weight": "Bolder", "size": "Medium", "wrap": true, "color": teamsColor[message.Level]},
	}
	for _, line := range message.Lines {
		items = append(items, map[string]any{"type": "TextBlock", "text": line, "wrap": true, "spacing": "Small"})
	}
	card := map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": items}
	if message.Link != "" {
		card["actions"] = []map[string]any{{"type": "Action.OpenUrl", "title": "Open in DeaconGuard", "url": message.Link}}
	}
	body, _ := json.Marshal(map[string]any{"type": "message", "attachments": []map[string]any{{
		"contentType": "application/vnd.microsoft.card.adaptive", "content": card,
	}}})
	return body
}

// sendEmail sends message as a plain-text email, with its attachment.
func sendEmail(ctx context.Context, config Config, message Message) error {
	address := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var connection net.Conn
	var err error
	tlsConfig := &tls.Config{ServerName: config.Host, MinVersion: tls.VersionTLS12}
	if config.TLS == TLSImplicit {
		connection, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", address)
	} else {
		connection, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return fmt.Errorf("could not reach the mail server %s: %w", address, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	smtpClient, err := smtp.NewClient(connection, config.Host)
	if err != nil {
		connection.Close()
		return fmt.Errorf("the mail server %s: %w", address, err)
	}
	defer smtpClient.Close()
	if config.TLS == TLSStartTLS {
		if ok, _ := smtpClient.Extension("STARTTLS"); !ok {
			return errors.New("the mail server does not offer STARTTLS; choose TLS or another port")
		}
		if err := smtpClient.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS with the mail server: %w", err)
		}
	}
	if config.Username != "" {
		if err := smtpClient.Auth(smtp.PlainAuth("", config.Username, config.Password, config.Host)); err != nil {
			return fmt.Errorf("the mail server refused the username or password: %w", err)
		}
	}
	from, _ := mail.ParseAddress(config.From)
	if err := smtpClient.Mail(from.Address); err != nil {
		return fmt.Errorf("the mail server refused the From address: %w", err)
	}
	for _, to := range config.To {
		recipient, _ := mail.ParseAddress(to)
		if err := smtpClient.Rcpt(recipient.Address); err != nil {
			return fmt.Errorf("the mail server refused %s: %w", recipient.Address, err)
		}
	}
	writer, err := smtpClient.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(emailBody(config, message)); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("the mail server did not accept the message: %w", err)
	}
	return smtpClient.Quit()
}

// emailBody is the message in MIME form: plain text, and the attachment if
// there is one.
func emailBody(config Config, message Message) []byte {
	var body bytes.Buffer
	header := func(name, value string) { fmt.Fprintf(&body, "%s: %s\r\n", name, value) }
	header("From", config.From)
	header("To", strings.Join(config.To, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", "[DeaconGuard] "+message.Title))
	header("Date", message.At.Format(time.RFC1123Z))
	header("Message-ID", fmt.Sprintf("<%d.%s@deaconguard>", message.At.UnixNano(), message.Event))
	header("MIME-Version", "1.0")
	header("Auto-Submitted", "auto-generated")
	var text strings.Builder
	text.WriteString(message.Title + "\r\n\r\n")
	for _, line := range message.Lines {
		text.WriteString("- " + line + "\r\n")
	}
	if message.Link != "" {
		text.WriteString("\r\nOpen in DeaconGuard: " + message.Link + "\r\n")
	}
	text.WriteString("\r\n-- \r\nSent by DeaconGuard " + buildinfo.Version + ". Change notifications under Settings, Notifications.\r\n")
	if message.Attachment == nil {
		header("Content-Type", "text/plain; charset=utf-8")
		header("Content-Transfer-Encoding", "base64")
		body.WriteString("\r\n")
		writeBase64(&body, []byte(text.String()))
		return body.Bytes()
	}
	boundary := fmt.Sprintf("deaconguard-%d", message.At.UnixNano())
	header("Content-Type", `multipart/mixed; boundary="`+boundary+`"`)
	body.WriteString("\r\n--" + boundary + "\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	writeBase64(&body, []byte(text.String()))
	attachment := message.Attachment
	fmt.Fprintf(&body, "--%s\r\nContent-Type: %s\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=%q\r\n\r\n",
		boundary, attachment.ContentType, attachment.Name)
	writeBase64(&body, attachment.Data)
	body.WriteString("--" + boundary + "--\r\n")
	return body.Bytes()
}

// writeBase64 writes data in base64 lines of 76 characters.
func writeBase64(body *bytes.Buffer, data []byte) {
	encoded := base64.StdEncoding.EncodeToString(data)
	for len(encoded) > 76 {
		body.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	body.WriteString(encoded + "\r\n")
}
