package notify

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var sample = Message{
	Event: EventExploited, Level: LevelCritical, Title: "web-01: 1 vulnerability known to be exploited",
	Lines: []string{"CVE-2024-38475 in apache2 <script>, fix: update to 2.4.58-1ubuntu8.2"}, Link: "https://dg.example.com/hosts/h1",
	HostID: "h1", Host: "web-01", Data: map[string]any{"cves": []string{"CVE-2024-38475"}}, At: time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC),
}

func capture(t *testing.T, status int) (*httptest.Server, chan *http.Request, chan []byte) {
	t.Helper()
	requests, bodies := make(chan *http.Request, 1), make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- r
		bodies <- body
		w.WriteHeader(status)
		_, _ = w.Write([]byte("no_text"))
	}))
	t.Cleanup(server.Close)
	return server, requests, bodies
}

func TestSlackTeamsAndWebhookBodies(t *testing.T) {
	server, requests, bodies := capture(t, http.StatusOK)
	if err := Send(context.Background(), Slack, Config{URL: server.URL}, sample); err != nil {
		t.Fatal(err)
	}
	<-requests
	var slack map[string]any
	if err := json.Unmarshal(<-bodies, &slack); err != nil || !strings.Contains(slack["text"].(string), "&lt;script&gt;") ||
		!strings.Contains(slack["text"].(string), "<https://dg.example.com/hosts/h1|Open in DeaconGuard>") {
		t.Fatalf("slack: %v %v", slack, err)
	}

	if err := Send(context.Background(), Teams, Config{URL: server.URL}, sample); err != nil {
		t.Fatal(err)
	}
	<-requests
	var teams struct {
		Attachments []struct {
			ContentType string `json:"contentType"`
			Content     struct {
				Body    []map[string]any `json:"body"`
				Actions []map[string]any `json:"actions"`
			} `json:"content"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(<-bodies, &teams); err != nil || teams.Attachments[0].ContentType != "application/vnd.microsoft.card.adaptive" ||
		teams.Attachments[0].Content.Body[0]["text"] != sample.Title || teams.Attachments[0].Content.Actions[0]["url"] != sample.Link {
		t.Fatalf("teams: %+v %v", teams, err)
	}

	if err := Send(context.Background(), Webhook, Config{URL: server.URL, Secret: "s3cret"}, sample); err != nil {
		t.Fatal(err)
	}
	request, body := <-requests, <-bodies
	timestamp := request.Header.Get("X-DeaconGuard-Timestamp")
	if request.Header.Get("X-DeaconGuard-Event") != EventExploited ||
		request.Header.Get("X-DeaconGuard-Signature") != "sha256="+Signature("s3cret", timestamp, body) {
		t.Fatalf("signature headers: %v", request.Header)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil || payload["host"] != "web-01" || payload["data"] == nil || payload["source"] != "deaconguard" {
		t.Fatalf("webhook: %v %v", payload, err)
	}
}

func TestWebhookErrorsAndRedirects(t *testing.T) {
	server, requests, _ := capture(t, http.StatusNotFound)
	err := Send(context.Background(), Slack, Config{URL: server.URL + "/T000/B000/secret"}, sample)
	<-requests
	if err == nil || !strings.Contains(err.Error(), "HTTP 404: no_text") {
		t.Fatalf("err = %v", err)
	}
	redirect := httptest.NewServer(http.RedirectHandler("http://elsewhere.example/", http.StatusFound))
	defer redirect.Close()
	if err := Send(context.Background(), Webhook, Config{URL: redirect.URL}, sample); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("a redirect was followed or accepted: %v", err)
	}
	// An unreachable webhook's error doesn't repeat its address, which can be secret.
	if err := Send(context.Background(), Slack, Config{URL: "http://127.0.0.1:1/services/T/B/very-secret"}, sample); err == nil || strings.Contains(err.Error(), "very-secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateAndRedact(t *testing.T) {
	good := Config{Host: "smtp.example.com", Port: 587, TLS: TLSStartTLS, Username: "u", Password: "p", From: "DeaconGuard <dg@example.com>", To: []string{"ops@example.com"}}
	if err := good.Validate(Email); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]Config{
		"no host":       {Port: 587, TLS: TLSStartTLS, From: "a@b.c", To: []string{"a@b.c"}},
		"port":          {Host: "smtp", Port: 0, TLS: TLSStartTLS, From: "a@b.c", To: []string{"a@b.c"}},
		"plain auth":    {Host: "smtp", Port: 25, TLS: TLSNone, Username: "u", From: "a@b.c", To: []string{"a@b.c"}},
		"no recipient":  {Host: "smtp", Port: 25, TLS: TLSNone, From: "a@b.c"},
		"bad recipient": {Host: "smtp", Port: 25, TLS: TLSNone, From: "a@b.c", To: []string{"not an address"}},
	} {
		if bad.Validate(Email) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if (Config{URL: "http://hooks.slack.com/x"}).Validate(Slack) == nil || (Config{URL: "https://hooks.slack.com/x"}).Validate(Slack) != nil ||
		(Config{URL: "http://internal/hook"}).Validate(Webhook) != nil || (Config{URL: "ftp://x"}).Validate(Webhook) == nil ||
		(Config{URL: "https://user:pw@x/"}).Validate(Teams) == nil {
		t.Fatal("webhook address checks")
	}
	redacted := Config{URL: "https://hooks.slack.com/services/T/B/secret", Password: "p", Secret: "s"}.Redacted()
	if redacted.URL != "https://hooks.slack.com/…" || redacted.Password != "set" || redacted.Secret != "set" {
		t.Fatalf("redacted: %+v", redacted)
	}
	merged := Config{URL: "https://old", Password: "old", Secret: "old"}.Merge(Config{Host: "new"})
	if merged.URL != "https://old" || merged.Password != "old" || merged.Secret != "old" || merged.Host != "new" {
		t.Fatalf("merged: %+v", merged)
	}
}

// fakeSMTP accepts one message without TLS and returns what it received.
func fakeSMTP(t *testing.T) (int, chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 1)
	go func() {
		defer listener.Close()
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		reply := func(line string) { _, _ = connection.Write([]byte(line + "\r\n")) }
		reply("220 fake ESMTP")
		var data strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			command := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(command, "EHLO"), strings.HasPrefix(command, "HELO"):
				reply("250 fake")
			case strings.HasPrefix(command, "DATA"):
				reply("354 go on")
				for {
					line, err := reader.ReadString('\n')
					if err != nil || line == ".\r\n" {
						break
					}
					data.WriteString(line)
				}
				received <- data.String()
				reply("250 queued")
			case strings.HasPrefix(command, "QUIT"):
				reply("221 bye")
				return
			default:
				reply("250 ok")
			}
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, received
}

func TestEmailWithAttachment(t *testing.T) {
	port, received := fakeSMTP(t)
	message := sample
	message.Attachment = &Attachment{Name: "vulnerabilities.csv", ContentType: "text/csv", Data: []byte("cve,host\nCVE-2024-38475,web-01\n")}
	config := Config{Host: "127.0.0.1", Port: port, TLS: TLSNone, From: "DeaconGuard <dg@example.com>", To: []string{"ops@example.com", "sec@example.com"}}
	if err := Send(context.Background(), Email, config, message); err != nil {
		t.Fatal(err)
	}
	email := <-received
	for _, want := range []string{"To: ops@example.com, sec@example.com", "Subject: [DeaconGuard] web-01: 1 vulnerability", "multipart/mixed", `filename="vulnerabilities.csv"`,
		base64.StdEncoding.EncodeToString(message.Attachment.Data)[:40]} {
		if !strings.Contains(email, want) {
			t.Errorf("email lacks %q:\n%s", want, email)
		}
	}
	if !strings.Contains(email, base64.StdEncoding.EncodeToString([]byte(message.Title + "\r\n"))[:20]) {
		t.Errorf("the body lacks the title")
	}
}

func TestEmailSubjectCannotAddHeaders(t *testing.T) {
	message := sample
	message.Title = "web-01\r\nBcc: attacker@example.com"
	body := string(emailBody(Config{From: "dg@example.com", To: []string{"ops@example.com"}}, message))
	if strings.Contains(body, "\r\nBcc:") {
		t.Fatalf("a title added a header:\n%s", body)
	}
}

func TestEmailNeedsStartTLSWhenAsked(t *testing.T) {
	port, _ := fakeSMTP(t)
	config := Config{Host: "127.0.0.1", Port: port, TLS: TLSStartTLS, From: "dg@example.com", To: []string{"ops@example.com"}}
	if err := Send(context.Background(), Email, config, sample); err == nil || !strings.Contains(err.Error(), "does not offer STARTTLS") {
		t.Fatalf("err = %v", err)
	}
}
