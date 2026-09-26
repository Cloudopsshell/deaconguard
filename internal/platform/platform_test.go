package platform

import "testing"

func TestDetectSupportedPlatforms(t *testing.T) {
	tests := []struct {
		name    string
		content string
		family  Family
		major   int
	}{
		{"Ubuntu 24.04", "ID=ubuntu\nVERSION_ID=\"24.04\"\n", Ubuntu, 24},
		{"Debian 13", "ID=debian\nVERSION_ID=13\n", Debian, 13},
		{"Amazon Linux 2023", "ID=amzn\nVERSION_ID=2023\n", AmazonLinux, 2023},
		{"RHEL 9.4", "ID=rhel\nVERSION_ID=\"9.4\"\n", RHEL, 9},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Detect(test.content)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if got.Family != test.family || got.Major != test.major {
				t.Fatalf("Detect() = %+v, want family %q and major %d", got, test.family, test.major)
			}
		})
	}
}

func TestDetectRejectsUnsupportedDistributionsAndVersions(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"CentOS Linux", "NAME=\"CentOS Linux\"\nID=centos\nVERSION_ID=7\n"},
		{"CentOS Stream awaits an authoritative feed", "NAME=\"CentOS Stream\"\nID=centos\nVERSION_ID=10\n"},
		{"RHEL 7", "ID=rhel\nVERSION_ID=7.9\n"},
		{"RHEL 10 feed not published", "ID=rhel\nVERSION_ID=10.0\n"},
		{"Amazon Linux 2", "ID=amzn\nVERSION_ID=2\n"},
		{"Rocky Linux not yet supported", "ID=rocky\nVERSION_ID=9.4\n"},
		{"Ubuntu interim release", "ID=ubuntu\nVERSION_ID=23.10\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Detect(test.content); err == nil {
				t.Fatal("Detect() unexpectedly accepted an unsupported release")
			}
		})
	}
}
