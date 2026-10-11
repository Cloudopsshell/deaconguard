// Package totp implements time-based one-time passwords (RFC 6238) as
// authenticator apps use them: HMAC-SHA1, 6 digits, a new code every 30
// seconds.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Period is how long each code lasts.
	Period = 30 * time.Second
	digits = 6
	// skew accepts the code before and after the current one, for clocks
	// that are slightly off.
	skew = 1
)

var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a random 160-bit secret, base32-encoded as authenticator
// apps expect.
func NewSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return encoding.EncodeToString(secret), nil
}

// URI is the otpauth:// link a QR code carries for authenticator apps.
func URI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	values := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + values.Encode()
}

// Step is the 30-second interval t falls in.
func Step(t time.Time) int64 { return t.Unix() / int64(Period/time.Second) }

// Code returns the code for a step.
func Code(secret string, step int64) (string, error) {
	key, err := encoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("decode the TOTP secret: %w", err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, value%1_000_000), nil
}

// Verify checks code at t and returns the step it matched. A step at or
// before lastStep is refused, so each code works once.
func Verify(secret, code string, t time.Time, lastStep int64) (int64, bool) {
	code = strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return r
	}, code)
	if len(code) != digits {
		return 0, false
	}
	now := Step(t)
	matched, found := int64(0), false
	for step := now - skew; step <= now+skew; step++ {
		expected, err := Code(secret, step)
		if err != nil {
			return 0, false
		}
		// Compare every candidate, so timing does not reveal which matched.
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 && step > lastStep {
			matched, found = step, true
		}
	}
	return matched, found
}
