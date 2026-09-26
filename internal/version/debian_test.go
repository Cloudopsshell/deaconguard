package version

import "testing"

func TestDebianOrdering(t *testing.T) {
	tests := []struct {
		left, right string
		want        int
	}{
		{"1.0~rc1", "1.0", -1},
		{"1.0-1", "1.0-2", -1},
		{"1.0-1ubuntu1", "1.0-1ubuntu1.1", -1},
		{"1.01", "1.1", 0},
		{"1:1.0", "2.0", 1},
	}
	for _, test := range tests {
		got, err := Debian(test.left, test.right)
		if err != nil || got != test.want {
			t.Errorf("Debian(%q, %q) = %d, %v; want %d", test.left, test.right, got, err, test.want)
		}
	}
}
