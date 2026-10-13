package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestSyslogOverTCPAndUDP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		length, _ := reader.ReadString(' ')
		size, _ := strconv.Atoi(strings.TrimSpace(length))
		frame := make([]byte, size)
		_, _ = io.ReadFull(reader, frame)
		received <- string(frame)
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	if err := Send(context.Background(), Syslog, Config{Host: "127.0.0.1", Port: port, Protocol: "tcp"}, sample); err != nil {
		t.Fatal(err)
	}
	line := <-received
	// local0 (16) and critical (2): 16*8+2 = 130.
	if !strings.HasPrefix(line, "<130>1 2026-10-13T09:00:00.000Z ") || !strings.Contains(line, " deaconguard - exploited - {") {
		t.Fatalf("line: %q", line)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(line[strings.Index(line, "{"):]), &payload); err != nil || payload["host"] != "web-01" {
		t.Fatalf("payload: %v %v", payload, err)
	}

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if err := Send(context.Background(), Syslog, Config{Host: "127.0.0.1", Port: udp.LocalAddr().(*net.UDPAddr).Port, Protocol: "udp"}, sample); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65536)
	size, _, err := udp.ReadFrom(buffer)
	if err != nil || !strings.HasPrefix(string(buffer[:size]), "<130>1 ") {
		t.Fatalf("udp: %q %v", buffer[:size], err)
	}
}

type captured struct {
	request *http.Request
	body    map[string]any
}

func recorder(t *testing.T) (*httptest.Server, chan captured) {
	t.Helper()
	requests := make(chan captured, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		requests <- captured{r, body}
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)
	// The test server's certificate is trusted for these tests only.
	saved := client
	client = server.Client()
	t.Cleanup(func() { client = saved })
	return server, requests
}

func TestSplunkJiraAndServiceNow(t *testing.T) {
	server, requests := recorder(t)
	if err := Send(context.Background(), Splunk, Config{URL: server.URL + "/services/collector/event", Secret: "hec-token", Index: "security"}, sample); err != nil {
		t.Fatal(err)
	}
	got := <-requests
	event, _ := got.body["event"].(map[string]any)
	if got.request.Header.Get("Authorization") != "Splunk hec-token" || got.body["index"] != "security" || got.body["sourcetype"] != "deaconguard:exploited" ||
		got.body["host"] != "web-01" || event["title"] != sample.Title {
		t.Fatalf("splunk: %v %v", got.request.Header, got.body)
	}

	if err := Send(context.Background(), Jira, Config{URL: server.URL + "/", Username: "me@example.com", Password: "api-token", Project: "SEC"}, sample); err != nil {
		t.Fatal(err)
	}
	got = <-requests
	fields := got.body["fields"].(map[string]any)
	if got.request.URL.Path != "/rest/api/2/issue" || got.request.Header.Get("Authorization") != basicAuth("me@example.com", "api-token") ||
		fields["summary"] != sample.Title || fields["issuetype"].(map[string]any)["name"] != "Task" || fields["project"].(map[string]any)["key"] != "SEC" ||
		!strings.Contains(fields["description"].(string), sample.Link) {
		t.Fatalf("jira: %s %v %v", got.request.URL.Path, got.request.Header, fields)
	}
	if err := Send(context.Background(), Jira, Config{URL: server.URL, Password: "pat", Project: "SEC", IssueType: "Bug"}, sample); err != nil {
		t.Fatal(err)
	}
	if got = <-requests; got.request.Header.Get("Authorization") != "Bearer pat" {
		t.Fatalf("jira data center: %v", got.request.Header)
	}

	if err := Send(context.Background(), ServiceNow, Config{URL: server.URL, Username: "svc", Password: "pw"}, sample); err != nil {
		t.Fatal(err)
	}
	got = <-requests
	if got.request.URL.Path != "/api/now/table/incident" || got.body["urgency"] != "1" || got.body["short_description"] != sample.Title {
		t.Fatalf("servicenow: %s %v", got.request.URL.Path, got.body)
	}
}

func TestIntegrationSettingsAreChecked(t *testing.T) {
	for name, test := range map[string]struct {
		kind   string
		config Config
		ok     bool
	}{
		"syslog":              {Syslog, Config{Host: "siem.example.com", Port: 6514, Protocol: "tls"}, true},
		"syslog protocol":     {Syslog, Config{Host: "siem.example.com", Port: 514, Protocol: "smoke"}, false},
		"splunk":              {Splunk, Config{URL: "https://splunk.example.com:8088/services/collector/event", Secret: "t"}, true},
		"splunk http":         {Splunk, Config{URL: "http://splunk:8088/x", Secret: "t"}, false},
		"splunk no token":     {Splunk, Config{URL: "https://splunk:8088/x"}, false},
		"jira":                {Jira, Config{URL: "https://acme.atlassian.net", Username: "a@b.c", Password: "t", Project: "SEC"}, true},
		"jira project":        {Jira, Config{URL: "https://acme.atlassian.net", Password: "t", Project: "sec ops"}, false},
		"servicenow":          {ServiceNow, Config{URL: "https://acme.service-now.com", Username: "u", Password: "p", Table: "sn_si_incident"}, true},
		"servicenow table":    {ServiceNow, Config{URL: "https://acme.service-now.com", Username: "u", Password: "p", Table: "../sys_user"}, false},
		"servicenow no login": {ServiceNow, Config{URL: "https://acme.service-now.com"}, false},
	} {
		if err := test.config.Validate(test.kind); (err == nil) != test.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}
