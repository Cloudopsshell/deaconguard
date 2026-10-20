package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func encode(value any) string {
	data, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(data)
}

func es256Token(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	signed := encode(map[string]string{"alg": "ES256", "kid": "ec"}) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestVerify(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	provider := &Provider{Issuer: "https://id.example", keys: map[string]crypto.PublicKey{"ec": &key.PublicKey}, fetched: now}
	claims := func() map[string]any {
		return map[string]any{"iss": "https://id.example", "aud": []string{"dg", "other"}, "azp": "dg", "sub": "u1", "nonce": "n",
			"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "groups": []any{"a", "b"}, "email_verified": "true"}
	}
	got, err := provider.Verify(context.Background(), es256Token(t, key, claims()), "dg", "n", now)
	if err != nil || got.Subject != "u1" || len(got.Strings("groups")) != 2 || !got.EmailIsVerified() {
		t.Fatalf("a good ES256 token: %+v %v", got, err)
	}

	good := es256Token(t, key, claims())
	parts := strings.Split(good, ".")
	unsigned := encode(map[string]string{"alg": "none"}) + "." + parts[1] + "."
	forged := parts[0] + "." + encode(map[string]any{"iss": "https://id.example", "aud": "dg", "sub": "admin", "nonce": "n", "exp": now.Add(time.Minute).Unix()}) + "." + parts[2]
	other := claims()
	other["azp"] = "someone-else"
	for name, token := range map[string]string{
		"unsigned (alg none)":        unsigned,
		"a changed payload":          forged,
		"issued to another party":    es256Token(t, key, other),
		"not a JWT":                  "abc",
		"signed with an unknown key": strings.Replace(good, parts[0], encode(map[string]string{"alg": "ES256", "kid": "missing"}), 1),
	} {
		if _, err := provider.Verify(context.Background(), token, "dg", "n", now); err == nil {
			t.Errorf("accepted a token %s", name)
		}
	}
	if _, err := provider.Verify(context.Background(), good, "dg", "another nonce", now); err == nil {
		t.Error("accepted a token for another sign-in")
	}
	if _, err := provider.Verify(context.Background(), good, "dg", "n", now.Add(10*time.Minute)); err == nil {
		t.Error("accepted an expired token")
	}
}

func TestDiscoverNeedsHTTPS(t *testing.T) {
	if _, err := Discover(context.Background(), NewClient(nil), "http://id.example"); err == nil {
		t.Fatal("accepted an http:// issuer")
	}
}
