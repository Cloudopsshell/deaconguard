package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Host struct {
	ID       string  `json:"id"`
	Address  string  `json:"address"`
	Username string  `json:"username"`
	Port     int     `json:"port"`
	KeyPath  *string `json:"key_path"`
}

func DataDir() string {
	if configured := os.Getenv("OPSARMOR_HOME"); configured != "" {
		return configured
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".local", "share", "opsarmor")
	}
	return filepath.Join(home, ".local", "share", "opsarmor")
}

func KnownHostsPath() string { return filepath.Join(DataDir(), "known_hosts") }

func ListHosts() ([]Host, error) {
	path := filepath.Join(DataDir(), "hosts.json")
	contents, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return []Host{}, nil
	}
	if err != nil {
		return nil, err
	}
	var hosts []Host
	if err := json.Unmarshal(contents, &hosts); err != nil {
		return nil, fmt.Errorf("read host profiles: %w", err)
	}
	return hosts, nil
}

func AddHost(address, username string, port int, keyPath *string) (Host, error) {
	if strings.TrimSpace(address) == "" || strings.ContainsAny(address, " \t\r\n") ||
		strings.TrimSpace(username) == "" || strings.ContainsAny(username, " \t\r\n") {
		return Host{}, fmt.Errorf("a host address and SSH username without whitespace are required")
	}
	if port < 1 || port > 65535 {
		return Host{}, fmt.Errorf("SSH port must be between 1 and 65535")
	}
	if keyPath != nil {
		if _, err := os.Stat(expandHome(*keyPath)); err != nil {
			return Host{}, fmt.Errorf("SSH private key file does not exist")
		}
	}
	hosts, err := ListHosts()
	if err != nil {
		return Host{}, err
	}
	id, err := newID()
	if err != nil {
		return Host{}, err
	}
	host := Host{ID: id, Address: address, Username: username, Port: port, KeyPath: keyPath}
	hosts = append(hosts, host)
	if err := writeJSONAtomic(filepath.Join(DataDir(), "hosts.json"), hosts); err != nil {
		return Host{}, err
	}
	return host, nil
}

func GetHost(id string) (Host, error) {
	hosts, err := ListHosts()
	if err != nil {
		return Host{}, err
	}
	for _, host := range hosts {
		if host.ID == id {
			return host, nil
		}
	}
	return Host{}, fmt.Errorf("unknown host ID: %s", id)
}

func RemoveHost(id string) (Host, error) {
	hosts, err := ListHosts()
	if err != nil {
		return Host{}, err
	}
	remaining := make([]Host, 0, len(hosts))
	var removed Host
	for _, host := range hosts {
		if host.ID == id {
			removed = host
		} else {
			remaining = append(remaining, host)
		}
	}
	if removed.ID == "" {
		return Host{}, fmt.Errorf("unknown host ID: %s", id)
	}
	if err := writeJSONAtomic(filepath.Join(DataDir(), "hosts.json"), remaining); err != nil {
		return Host{}, err
	}
	return removed, nil
}

func TrustHostKey(host Host, knownHostsLine string) error {
	fields := strings.Fields(knownHostsLine)
	if len(fields) < 3 {
		return fmt.Errorf("invalid SSH known-host entry")
	}
	address := host.Address
	if host.Port != 22 {
		address = fmt.Sprintf("[%s]:%d", address, host.Port)
	}
	if fields[0] != address {
		return fmt.Errorf("SSH known-host entry does not match %s", address)
	}
	path := KnownHostsPath()
	contents, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	algorithmPinned := false
	for _, existing := range strings.Split(string(contents), "\n") {
		existingFields := strings.Fields(existing)
		if len(existingFields) < 3 || existingFields[0] != address || existingFields[1] != fields[1] {
			continue
		}
		algorithmPinned = true
		if strings.Join(existingFields[:3], " ") == strings.Join(fields[:3], " ") {
			return nil
		}
	}
	if algorithmPinned {
		return fmt.Errorf("a different SSH host key using %s is already trusted for %s", fields[1], address)
	}
	if err := os.MkdirAll(DataDir(), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := fmt.Fprintln(file, strings.Join(fields[:3], " ")); err != nil {
		return err
	}
	return file.Sync()
}

func SaveReport(report map[string]any) (map[string]any, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	directory := filepath.Join(DataDir(), "reports")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	if err := writeJSONAtomic(filepath.Join(directory, id+".json"), report); err != nil {
		return nil, err
	}
	result := make(map[string]any, len(report)+1)
	result["report_id"] = id
	for key, value := range report {
		result[key] = value
	}
	return result, nil
}

func GetReport(id string) (map[string]any, error) {
	if len(id) != 32 {
		return nil, fmt.Errorf("invalid report ID")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return nil, fmt.Errorf("invalid report ID")
	}
	path := filepath.Join(DataDir(), "reports", id+".json")
	contents, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("report not found")
	}
	if err != nil {
		return nil, err
	}
	var report map[string]any
	if err := json.Unmarshal(contents, &report); err != nil {
		return nil, fmt.Errorf("read scan report: %w", err)
	}
	report["report_id"] = id
	return report, nil
}

func newID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return hex.EncodeToString(value), nil
}

func expandHome(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(path, "~"), "/"))
}

func writeJSONAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".opsarmor-*.tmp")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if err := json.NewEncoder(file).Encode(value); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
