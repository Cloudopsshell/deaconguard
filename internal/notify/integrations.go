package notify

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	projectKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,19}$`)
	tableName  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,79}$`)
)

// syslogSeverity maps levels to syslog severities: critical, warning,
// informational.
var syslogSeverity = map[string]int{LevelCritical: 2, LevelWarning: 4, LevelInfo: 6}

// syslogFacility is local0.
const syslogFacility = 16

// syslogLine is message as an RFC 5424 line, with the webhook's JSON as the
// text, which SIEMs can parse.
func syslogLine(message Message) ([]byte, error) {
	payload, err := json.Marshal(webhookPayload(message))
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "-"
	}
	severity, ok := syslogSeverity[message.Level]
	if !ok {
		severity = 6
	}
	at := message.At
	if at.IsZero() {
		at = time.Now()
	}
	// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
	header := fmt.Sprintf("<%d>1 %s %s deaconguard - %s - ", syslogFacility*8+severity, at.UTC().Format("2006-01-02T15:04:05.000Z"),
		syslogField(hostname), syslogField(message.Event))
	return append([]byte(header), payload...), nil
}

// syslogField keeps a header field printable and without spaces, as
// RFC 5424 requires.
func syslogField(value string) string {
	value = strings.Map(func(r rune) rune {
		if r <= ' ' || r > '~' {
			return -1
		}
		return r
	}, value)
	if value == "" {
		return "-"
	}
	if len(value) > 48 {
		value = value[:48]
	}
	return value
}

func sendSyslog(ctx context.Context, config Config, message Message) error {
	line, err := syslogLine(message)
	if err != nil {
		return err
	}
	address := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var connection net.Conn
	switch config.Protocol {
	case "tls":
		connection, err = (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: config.Host, MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp", address)
	case "udp":
		connection, err = dialer.DialContext(ctx, "udp", address)
	default:
		connection, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return fmt.Errorf("could not reach the syslog server %s: %w", address, err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	frame := line
	if config.Protocol != "udp" {
		// TCP and TLS frame each message with its length (RFC 6587, RFC 5425).
		frame = append([]byte(strconv.Itoa(len(line))+" "), line...)
	}
	if _, err := connection.Write(frame); err != nil {
		return fmt.Errorf("sending to the syslog server: %w", err)
	}
	return nil
}

func sendSplunk(ctx context.Context, config Config, message Message) error {
	event := map[string]any{
		"time": float64(message.At.UnixMilli()) / 1000, "source": "deaconguard", "sourcetype": "deaconguard:" + message.Event,
		"event": webhookPayload(message),
	}
	if message.Host != "" {
		event["host"] = message.Host
	}
	if config.Index != "" {
		event["index"] = config.Index
	}
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return post(ctx, config.URL, body, func(request *http.Request, _ []byte) {
		request.Header.Set("Authorization", "Splunk "+config.Secret)
	})
}

// ticketText is the message as a ticket's description.
func ticketText(message Message) string {
	var text strings.Builder
	for _, line := range message.Lines {
		text.WriteString("- " + line + "\n")
	}
	if message.Link != "" {
		text.WriteString("\nOpen in DeaconGuard: " + message.Link + "\n")
	}
	text.WriteString("\nCreated by DeaconGuard (" + message.Event + ") at " + message.At.UTC().Format(time.RFC3339) + ".")
	return text.String()
}

func basicAuth(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

// sendJira opens an issue, through REST API version 2, which Jira Cloud and
// Data Center both have.
func sendJira(ctx context.Context, config Config, message Message) error {
	issueType := config.IssueType
	if issueType == "" {
		issueType = "Task"
	}
	labels := []string{"deaconguard", "deaconguard-" + strings.ReplaceAll(message.Event, "_", "-")}
	body, err := json.Marshal(map[string]any{"fields": map[string]any{
		"project": map[string]string{"key": config.Project}, "issuetype": map[string]string{"name": issueType},
		"summary": truncate(message.Title, 250), "description": ticketText(message), "labels": labels,
	}})
	if err != nil {
		return err
	}
	return post(ctx, strings.TrimSuffix(config.URL, "/")+"/rest/api/2/issue", body, func(request *http.Request, _ []byte) {
		if config.Username != "" {
			request.Header.Set("Authorization", basicAuth(config.Username, config.Password))
		} else {
			request.Header.Set("Authorization", "Bearer "+config.Password)
		}
		request.Header.Set("Accept", "application/json")
	})
}

// serviceNowUrgency maps levels to ServiceNow's urgency and impact: 1 high,
// 2 medium, 3 low.
var serviceNowUrgency = map[string]string{LevelCritical: "1", LevelWarning: "2", LevelInfo: "3"}

// sendServiceNow creates a record through the Table API.
func sendServiceNow(ctx context.Context, config Config, message Message) error {
	table := config.Table
	if table == "" {
		table = "incident"
	}
	urgency := serviceNowUrgency[message.Level]
	if urgency == "" {
		urgency = "3"
	}
	body, err := json.Marshal(map[string]string{
		"short_description": truncate(message.Title, 160), "description": ticketText(message),
		"urgency": urgency, "impact": urgency, "category": "security",
	})
	if err != nil {
		return err
	}
	return post(ctx, strings.TrimSuffix(config.URL, "/")+"/api/now/table/"+table, body, func(request *http.Request, _ []byte) {
		request.Header.Set("Authorization", basicAuth(config.Username, config.Password))
		request.Header.Set("Accept", "application/json")
	})
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return strings.ToValidUTF8(text[:limit-1], "") + "…"
}
