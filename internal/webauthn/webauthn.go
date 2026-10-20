// Package webauthn checks passkey registrations and sign-ins (WebAuthn Level
// 2), with the standard library only. Registrations ask for no attestation,
// so the browser's getPublicKey() gives the credential's public key (SPKI)
// and no CBOR has to be read. Every ceremony requires user verification: a
// PIN, fingerprint or face, so a passkey alone is two steps.
package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// COSE algorithms DeaconGuard accepts, in the order it prefers them.
const (
	ES256 = -7
	EdDSA = -8
	RS256 = -257
)

// Algorithms are offered to the browser as pubKeyCredParams.
var Algorithms = []int{ES256, EdDSA, RS256}

// Authenticator data flags.
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagAttested     = 0x40
)

// Ceremony is what the server expects of one registration or sign-in.
type Ceremony struct {
	Challenge []byte
	// RPID is the dashboard's host name, which passkeys are bound to.
	RPID string
	// Origin is the dashboard's origin, such as https://dg.example.com:8443.
	Origin string
}

// NewChallenge returns 32 random bytes.
func NewChallenge() ([]byte, error) {
	challenge := make([]byte, 32)
	_, err := rand.Read(challenge)
	return challenge, err
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

func (c Ceremony) checkClientData(raw []byte, kind string) error {
	var data clientData
	if err := json.Unmarshal(raw, &data); err != nil {
		return errors.New("the browser's response can't be read")
	}
	if data.Type != kind {
		return fmt.Errorf("the browser's response is for %q, not %q", data.Type, kind)
	}
	got, err := base64.RawURLEncoding.DecodeString(data.Challenge)
	if err != nil || subtle.ConstantTimeCompare(got, c.Challenge) != 1 {
		return errors.New("the response doesn't answer this request; try again")
	}
	if data.Origin != c.Origin || data.CrossOrigin {
		return fmt.Errorf("the response came from %s, not %s", data.Origin, c.Origin)
	}
	return nil
}

type authenticatorData struct {
	flags        byte
	signCount    uint32
	credentialID []byte
}

func (c Ceremony) parseAuthenticatorData(raw []byte) (authenticatorData, error) {
	if len(raw) < 37 {
		return authenticatorData{}, errors.New("the authenticator's data is too short")
	}
	rpHash := sha256.Sum256([]byte(c.RPID))
	if !bytes.Equal(raw[:32], rpHash[:]) {
		return authenticatorData{}, fmt.Errorf("the passkey is for another site, not %s", c.RPID)
	}
	data := authenticatorData{flags: raw[32], signCount: binary.BigEndian.Uint32(raw[33:37])}
	if data.flags&flagUserPresent == 0 {
		return authenticatorData{}, errors.New("the authenticator didn't confirm someone was present")
	}
	if data.flags&flagUserVerified == 0 {
		return authenticatorData{}, errors.New("the authenticator didn't verify you (with a PIN, fingerprint or face); passkeys need that here")
	}
	if data.flags&flagAttested != 0 {
		// AAGUID (16 bytes), then the credential ID's length and the ID.
		if len(raw) < 55 {
			return authenticatorData{}, errors.New("the authenticator's data is too short")
		}
		length := int(binary.BigEndian.Uint16(raw[53:55]))
		if length == 0 || length > 1023 || len(raw) < 55+length {
			return authenticatorData{}, errors.New("the authenticator's credential ID can't be read")
		}
		data.credentialID = raw[55 : 55+length]
	}
	return data, nil
}

// Registration is a passkey to save.
type Registration struct {
	CredentialID []byte
	// PublicKey is the key in PKIX (SPKI) form.
	PublicKey []byte
	Algorithm int
	SignCount uint32
}

// VerifyRegistration checks a new passkey from navigator.credentials.create:
// its client data, authenticator data, credential ID, and public key.
func VerifyRegistration(c Ceremony, clientDataJSON, authData, credentialID, publicKey []byte, algorithm int) (Registration, error) {
	if err := c.checkClientData(clientDataJSON, "webauthn.create"); err != nil {
		return Registration{}, err
	}
	data, err := c.parseAuthenticatorData(authData)
	if err != nil {
		return Registration{}, err
	}
	if data.credentialID == nil || !bytes.Equal(data.credentialID, credentialID) {
		return Registration{}, errors.New("the authenticator's data doesn't name this passkey")
	}
	if _, err := parseKey(publicKey, algorithm); err != nil {
		return Registration{}, err
	}
	return Registration{CredentialID: credentialID, PublicKey: publicKey, Algorithm: algorithm, SignCount: data.signCount}, nil
}

func parseKey(der []byte, algorithm int) (crypto.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("the passkey's public key can't be read; use a browser that supports passkeys fully")
	}
	switch algorithm {
	case ES256:
		if key, ok := key.(*ecdsa.PublicKey); ok && key.Curve == elliptic.P256() {
			return key, nil
		}
	case RS256:
		if key, ok := key.(*rsa.PublicKey); ok && key.N.BitLen() >= 2048 {
			return key, nil
		}
	case EdDSA:
		if key, ok := key.(ed25519.PublicKey); ok {
			return key, nil
		}
	}
	return nil, fmt.Errorf("passkeys with algorithm %d aren't supported; use one with ES256, EdDSA or RS256 of 2048 bits or more", algorithm)
}

// VerifyAssertion checks a sign-in from navigator.credentials.get with a
// saved passkey, and returns its new signature count. A count that doesn't
// grow, where the authenticator keeps one, means the passkey may have been
// copied, and is refused.
func VerifyAssertion(c Ceremony, clientDataJSON, authData, signature, publicKey []byte, algorithm int, storedCount uint32) (uint32, error) {
	if err := c.checkClientData(clientDataJSON, "webauthn.get"); err != nil {
		return 0, err
	}
	data, err := c.parseAuthenticatorData(authData)
	if err != nil {
		return 0, err
	}
	key, err := parseKey(publicKey, algorithm)
	if err != nil {
		return 0, err
	}
	clientHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	valid := false
	switch key := key.(type) {
	case *ecdsa.PublicKey:
		valid = ecdsa.VerifyASN1(key, digest[:], signature)
	case *rsa.PublicKey:
		valid = rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil
	case ed25519.PublicKey:
		valid = ed25519.Verify(key, signed, signature)
	}
	if !valid {
		return 0, errors.New("the passkey's signature isn't valid")
	}
	if (data.signCount != 0 || storedCount != 0) && data.signCount <= storedCount {
		return 0, errors.New("this passkey's counter went backwards, so it may have been copied; remove it on My account and add it again")
	}
	return data.signCount, nil
}
