package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"deaconguard/internal/store"
)

// softPasskey is a software authenticator for the dashboard's tests.
type softPasskey struct {
	key   *ecdsa.PrivateKey
	id    []byte
	count uint32
}

func newSoftPasskey(t *testing.T, id string) *softPasskey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &softPasskey{key: key, id: []byte(id)}
}

func (p *softPasskey) authData(rpID string, attested bool) []byte {
	hash := sha256.Sum256([]byte(rpID))
	data := append(append([]byte{}, hash[:]...), 0x01|0x04)
	if attested {
		data[32] |= 0x40
	}
	data = binary.BigEndian.AppendUint32(data, p.count)
	if attested {
		data = append(data, make([]byte, 16)...)
		data = binary.BigEndian.AppendUint16(data, uint16(len(p.id)))
		data = append(data, p.id...)
	}
	return data
}

func clientDataJSON(kind, challenge, origin string) []byte {
	data, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return data
}

// register adds the passkey to the account of cookie, as the browser would.
func (p *softPasskey) register(t *testing.T, s *Server, cookie *http.Cookie, password string) *http.Response {
	t.Helper()
	options := decode[passkeyOptions](t, do(t, s, call{method: http.MethodPost, path: "/api/account/passkeys/options", cookie: cookie, body: map[string]string{}}))
	if options.RPID != "deaconguard.example" || options.Challenge == "" {
		t.Fatalf("registration options: %+v", options)
	}
	public, _ := x509.MarshalPKIXPublicKey(&p.key.PublicKey)
	response := do(t, s, call{method: http.MethodPost, path: "/api/account/passkeys", cookie: cookie, body: passkeyRegistrationRequest{
		Name: "Laptop", Password: password, ID: b64.EncodeToString(p.id),
		ClientDataJSON:    b64.EncodeToString(clientDataJSON("webauthn.create", options.Challenge, testOrigin)),
		AuthenticatorData: b64.EncodeToString(p.authData("deaconguard.example", true)),
		PublicKey:         b64.EncodeToString(public), Algorithm: -7, Transports: []string{"internal", "hybrid"},
	}})
	return response.Result()
}

// signIn answers a sign-in challenge with the passkey.
func (p *softPasskey) signIn(t *testing.T, s *Server, cookie *http.Cookie) (*http.Cookie, int, passkeyOptions) {
	t.Helper()
	options := decode[passkeyOptions](t, do(t, s, call{method: http.MethodPost, path: "/api/login/passkey/options", cookie: cookie, body: map[string]string{}}))
	p.count++
	authData := p.authData("deaconguard.example", false)
	client := clientDataJSON("webauthn.get", options.Challenge, testOrigin)
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, p.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, s, call{method: http.MethodPost, path: "/api/login/passkey", cookie: cookie, body: passkeyLoginRequest{
		ID: b64.EncodeToString(p.id), ClientDataJSON: b64.EncodeToString(client),
		AuthenticatorData: b64.EncodeToString(authData), Signature: b64.EncodeToString(signature),
	}})
	for _, candidate := range response.Result().Cookies() {
		if candidate.Name == sessionCookie {
			return candidate, response.Code, options
		}
	}
	return nil, response.Code, options
}

func TestPasskeys(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	laptop := newSoftPasskey(t, "laptop")
	if response := laptop.register(t, s, cookie, "wrong password!"); response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusForbidden {
		t.Fatalf("a registration with the wrong password: %d", response.StatusCode)
	}
	if response := laptop.register(t, s, cookie, testPassword); response.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", response.StatusCode)
	}
	if response := laptop.register(t, s, cookie, testPassword); response.StatusCode != http.StatusConflict {
		t.Fatalf("the same passkey twice: %d", response.StatusCode)
	}
	keys := decode[[]store.Passkey](t, do(t, s, call{method: http.MethodGet, path: "/api/account/passkeys", cookie: cookie}))
	if len(keys) != 1 || keys[0].Name != "Laptop" || len(keys[0].Transports) != 2 {
		t.Fatalf("passkeys: %+v", keys)
	}
	session := decode[sessionResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/session", cookie: cookie}))
	if !session.TwoStep || session.MFAEnabled || session.Passkeys != 1 {
		t.Fatalf("session with a passkey: %+v", session)
	}

	// A passkey alone signs in, fully.
	full, code, options := laptop.signIn(t, s, nil)
	if code != http.StatusOK || full == nil || len(options.Credentials) != 0 {
		t.Fatalf("passkey sign-in: %d %+v", code, options)
	}
	if hosts := do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: full}); hosts.Code != http.StatusOK {
		t.Fatalf("hosts after a passkey sign-in: %d", hosts.Code)
	}

	// The password now needs a second step, which the passkey can be.
	pending, body, code := login(t, s, "admin", testPassword)
	if code != http.StatusOK || !body.MFAPending || len(body.MFAMethods) != 1 || body.MFAMethods[0] != "passkey" {
		t.Fatalf("password with a passkey: %d %+v", code, body)
	}
	second, code, options := laptop.signIn(t, s, pending)
	if code != http.StatusOK || second == nil || len(options.Credentials) != 1 {
		t.Fatalf("passkey as the second step: %d %+v", code, options)
	}
	if old := do(t, s, call{method: http.MethodGet, path: "/api/session", cookie: pending}); decode[sessionResponse](t, old).Authenticated {
		t.Fatal("the waiting session still works after the second step")
	}

	// Another account's passkey can't finish this account's second step.
	if _, err := store.AddUser("bob", []byte(testPassword), store.RoleViewer, false); err != nil {
		t.Fatal(err)
	}
	bobCookie, _, _ := login(t, s, "bob", testPassword)
	bobKey := newSoftPasskey(t, "bob")
	if response := bobKey.register(t, s, bobCookie, testPassword); response.StatusCode != http.StatusCreated {
		t.Fatalf("bob's passkey: %d", response.StatusCode)
	}
	pending, _, _ = login(t, s, "admin", testPassword)
	if _, code, _ := bobKey.signIn(t, s, pending); code != http.StatusUnauthorized {
		t.Fatalf("bob's passkey for admin's second step: %d", code)
	}

	// A copied passkey, whose counter goes back, is refused.
	laptop.count -= 2
	if _, code, _ := laptop.signIn(t, s, nil); code != http.StatusUnauthorized {
		t.Fatalf("a counter that went back: %d", code)
	}
	laptop.count += 5

	// When two-step sign-in is required, the last passkey stays.
	if response := do(t, s, call{method: http.MethodPatch, path: "/api/settings/security", cookie: full, body: map[string]bool{"require_mfa": true}}); response.Code != http.StatusOK {
		t.Fatalf("require two-step with a passkey: %d %s", response.Code, response.Body.String())
	}
	if response := do(t, s, call{method: http.MethodDelete, path: "/api/account/passkeys/" + keys[0].ID, cookie: full}); response.Code != http.StatusConflict {
		t.Fatalf("remove the only passkey when required: %d", response.Code)
	}
	if response := do(t, s, call{method: http.MethodPatch, path: "/api/settings/security", cookie: full, body: map[string]bool{"require_mfa": false}}); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	if response := do(t, s, call{method: http.MethodPatch, path: "/api/account/passkeys/" + keys[0].ID, cookie: full, body: map[string]string{"name": "Work laptop"}}); response.Code != http.StatusOK {
		t.Fatalf("rename: %d", response.Code)
	}
	if response := do(t, s, call{method: http.MethodDelete, path: "/api/account/passkeys/" + keys[0].ID, cookie: full}); response.Code != http.StatusOK {
		t.Fatalf("remove: %d", response.Code)
	}
	if _, code, _ := laptop.signIn(t, s, nil); code != http.StatusUnauthorized {
		t.Fatalf("a removed passkey: %d", code)
	}

	// An admin's reset removes another account's passkeys.
	bob, _ := store.UserByName("bob")
	if response := do(t, s, call{method: http.MethodPost, path: "/api/users/" + bob.ID + "/reset-mfa", cookie: full, body: map[string]string{}}); response.Code != http.StatusOK {
		t.Fatalf("reset bob: %d %s", response.Code, response.Body.String())
	}
	if bob, _ = store.UserByName("bob"); bob.Passkeys != 0 {
		t.Fatalf("bob's passkeys after a reset: %d", bob.Passkeys)
	}

	// Passkeys need a name: an IP address can't be a relying party.
	for host, want := range map[string]string{"10.0.0.5:8443": "", "[::1]:8443": "", "DG.Example.com:8443": "dg.example.com", "dg.example.com": "dg.example.com"} {
		request := httptest.NewRequest(http.MethodPost, "https://"+host+"/api/login/passkey/options", nil)
		id, origin, err := relyingParty(request)
		if id != want || (want == "" && err == nil) || (want != "" && origin != "https://"+strings.ToLower(host)) {
			t.Errorf("relying party of %s: %q %q %v", host, id, origin, err)
		}
	}
}
