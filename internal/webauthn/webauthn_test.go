package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// authenticator is a software passkey, as a test double for a real one.
type authenticator struct {
	key       crypto.Signer
	algorithm int
	id        []byte
	count     uint32
}

func newAuthenticator(t *testing.T, algorithm int) *authenticator {
	t.Helper()
	var key crypto.Signer
	var err error
	switch algorithm {
	case ES256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case RS256:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case EdDSA:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{key: key, algorithm: algorithm, id: []byte("credential-" + t.Name())}
}

func (a *authenticator) publicKey(t *testing.T) []byte {
	der, err := x509.MarshalPKIXPublicKey(a.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func clientDataFor(kind string, challenge []byte, origin string) []byte {
	data, _ := json.Marshal(clientData{Type: kind, Challenge: base64.RawURLEncoding.EncodeToString(challenge), Origin: origin})
	return data
}

func (a *authenticator) authData(rpID string, flags byte, attested bool) []byte {
	hash := sha256.Sum256([]byte(rpID))
	data := append([]byte{}, hash[:]...)
	data = append(data, flags)
	data = binary.BigEndian.AppendUint32(data, a.count)
	if attested {
		data = append(data, make([]byte, 16)...)
		data = binary.BigEndian.AppendUint16(data, uint16(len(a.id)))
		data = append(data, a.id...)
	}
	return data
}

func (a *authenticator) sign(t *testing.T, authData, clientDataJSON []byte) []byte {
	clientHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	var signature []byte
	var err error
	if a.algorithm == EdDSA {
		signature, err = a.key.Sign(rand.Reader, signed, crypto.Hash(0))
	} else {
		digest := sha256.Sum256(signed)
		signature, err = a.key.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

const verified = flagUserPresent | flagUserVerified

func ceremony(t *testing.T) Ceremony {
	challenge, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	return Ceremony{Challenge: challenge, RPID: "dg.example.com", Origin: "https://dg.example.com:8443"}
}

func TestRegisterAndSignIn(t *testing.T) {
	for _, algorithm := range Algorithms {
		a := newAuthenticator(t, algorithm)
		c := ceremony(t)
		created := clientDataFor("webauthn.create", c.Challenge, c.Origin)
		registration, err := VerifyRegistration(c, created, a.authData(c.RPID, verified|flagAttested, true), a.id, a.publicKey(t), algorithm)
		if err != nil {
			t.Fatalf("algorithm %d: registration: %v", algorithm, err)
		}
		a.count = 5
		c = ceremony(t)
		got := clientDataFor("webauthn.get", c.Challenge, c.Origin)
		authData := a.authData(c.RPID, verified, false)
		count, err := VerifyAssertion(c, got, authData, a.sign(t, authData, got), registration.PublicKey, algorithm, registration.SignCount)
		if err != nil || count != 5 {
			t.Fatalf("algorithm %d: sign-in: %d %v", algorithm, count, err)
		}
	}
}

func TestRefusals(t *testing.T) {
	a := newAuthenticator(t, ES256)
	key := a.publicKey(t)
	c := ceremony(t)
	created := clientDataFor("webauthn.create", c.Challenge, c.Origin)
	good := a.authData(c.RPID, verified|flagAttested, true)
	registrations := map[string]func() error{
		"another origin": func() error {
			_, err := VerifyRegistration(c, clientDataFor("webauthn.create", c.Challenge, "https://evil.example"), good, a.id, key, ES256)
			return err
		},
		"another challenge": func() error {
			_, err := VerifyRegistration(c, clientDataFor("webauthn.create", []byte("old"), c.Origin), good, a.id, key, ES256)
			return err
		},
		"a sign-in, not a registration": func() error {
			_, err := VerifyRegistration(c, clientDataFor("webauthn.get", c.Challenge, c.Origin), good, a.id, key, ES256)
			return err
		},
		"another site": func() error {
			_, err := VerifyRegistration(c, created, a.authData("evil.example", verified|flagAttested, true), a.id, key, ES256)
			return err
		},
		"no user verification": func() error {
			_, err := VerifyRegistration(c, created, a.authData(c.RPID, flagUserPresent|flagAttested, true), a.id, key, ES256)
			return err
		},
		"another credential": func() error {
			_, err := VerifyRegistration(c, created, good, []byte("other"), key, ES256)
			return err
		},
		"the wrong algorithm": func() error {
			_, err := VerifyRegistration(c, created, good, a.id, key, RS256)
			return err
		},
	}
	for name, register := range registrations {
		if register() == nil {
			t.Errorf("registration accepted with %s", name)
		}
	}

	a.count = 7
	got := clientDataFor("webauthn.get", c.Challenge, c.Origin)
	authData := a.authData(c.RPID, verified, false)
	signature := a.sign(t, authData, got)
	if _, err := VerifyAssertion(c, got, authData, signature, key, ES256, 7); err == nil || !strings.Contains(err.Error(), "copied") {
		t.Errorf("a counter that didn't grow: %v", err)
	}
	other := newAuthenticator(t, ES256)
	if _, err := VerifyAssertion(c, got, authData, signature, other.publicKey(t), ES256, 0); err == nil {
		t.Error("a signature by another key was accepted")
	}
	tampered := append([]byte{}, got...)
	tampered[len(tampered)-2] = ' '
	if _, err := VerifyAssertion(c, tampered, authData, signature, key, ES256, 0); err == nil {
		t.Error("changed client data was accepted")
	}
	if count, err := VerifyAssertion(c, got, authData, signature, key, ES256, 6); err != nil || count != 7 {
		t.Errorf("a growing counter: %d %v", count, err)
	}
}
