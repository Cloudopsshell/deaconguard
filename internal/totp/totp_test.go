package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B: the SHA-1 secret "12345678901234567890" and its
// 8-digit codes; authenticator apps show the last 6 digits.
func TestRFC6238Vectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for unix, want := range map[int64]string{
		59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
		1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130",
	} {
		got, err := Code(secret, Step(time.Unix(unix, 0)))
		if err != nil || got != want[2:] {
			t.Errorf("at %d: %s, %v; want %s", unix, got, err, want[2:])
		}
	}
}

func TestVerify(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	current, _ := Code(secret, Step(now))
	previous, _ := Code(secret, Step(now)-1)
	tooOld, _ := Code(secret, Step(now)-2)

	step, ok := Verify(secret, current, now, 0)
	if !ok || step != Step(now) {
		t.Fatal("the current code was refused")
	}
	if _, ok := Verify(secret, current, now, step); ok {
		t.Fatal("a used code was accepted again")
	}
	if _, ok := Verify(secret, previous, now, 0); !ok {
		t.Fatal("the previous code (clock skew) was refused")
	}
	if _, ok := Verify(secret, tooOld, now, 0); ok {
		t.Fatal("a code from a minute ago was accepted")
	}
	spaced := current[:3] + " " + current[3:]
	if _, ok := Verify(secret, spaced, now, 0); !ok {
		t.Fatal("a code typed with a space was refused")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := Verify(secret, bad, now, 0); ok {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestURI(t *testing.T) {
	uri := URI("DeaconGuard", "admin@example", "JBSWY3DPEHPK3PXP")
	if !strings.HasPrefix(uri, "otpauth://totp/DeaconGuard:admin@example?") || !strings.Contains(uri, "secret=JBSWY3DPEHPK3PXP") || !strings.Contains(uri, "issuer=DeaconGuard") {
		t.Fatalf("URI = %s", uri)
	}
}
