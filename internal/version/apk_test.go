package version

import "testing"

func TestAPK(t *testing.T) {
	for _, c := range []struct {
		left, right string
		want        int
	}{
		{"1.2.3-r0", "1.2.3-r0", 0},
		{"1.2.3-r0", "1.2.3-r1", -1},
		{"1.2.10-r0", "1.2.9-r5", 1},
		{"1.2-r0", "1.2.0-r0", -1},
		{"3.1.4-r1", "3.1.4-r0", 1},
		{"1.0_rc1-r0", "1.0-r0", -1},
		{"1.0_alpha1", "1.0_beta1", -1},
		{"1.0_beta2", "1.0_beta10", -1},
		{"1.0_pre1", "1.0_rc1", -1},
		{"1.0_p1-r0", "1.0-r5", 1},
		{"1.0_git20240101", "1.0", 1},
		{"1.0a", "1.0", 1},
		{"1.0a", "1.0b", -1},
		{"1.0a", "1.1", -1},
		{"1.01", "1.1", -1},
		{"1.001", "1.01", -1},
		{"2.39.3-r0", "2.39.10-r0", -1},
	} {
		got, err := APK(c.left, c.right)
		if err != nil || got != c.want {
			t.Errorf("APK(%q, %q) = %d, %v; want %d", c.left, c.right, got, err, c.want)
		}
		if reverse, _ := APK(c.right, c.left); reverse != -c.want {
			t.Errorf("APK(%q, %q) = %d; want %d", c.right, c.left, reverse, -c.want)
		}
	}
	if _, err := APK("not a version", "1.0"); err == nil {
		t.Error("invalid version accepted")
	}
}
