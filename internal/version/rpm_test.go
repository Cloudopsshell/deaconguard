package version

import "testing"

func TestRPMOrdering(t *testing.T) {
	tests := []struct {
		left, right string
		want        int
	}{
		{"1:3.0-1", "2.0-99", 1},
		{"3.0-1.el9", "3.0-2.el9", -1},
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0^git1-1", "1.0-1", 1},
		{"1.0-1", "1.0-1", 0},
		{"1.09-1", "1.9-1", 0},
	}
	for _, test := range tests {
		got, err := RPM(test.left, test.right)
		if err != nil || got != test.want {
			t.Errorf("RPM(%q, %q) = %d, %v; want %d", test.left, test.right, got, err, test.want)
		}
	}
}
