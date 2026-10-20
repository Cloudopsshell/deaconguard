// Package oidctest is a small OpenID provider for tests: discovery, a key
// set, an authorization endpoint that signs in whoever the test names, and
// a token endpoint that checks the code, the client and PKCE.
package oidctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// Provider is a running test provider.
type Provider struct {
	Server       *httptest.Server
	ClientID     string
	ClientSecret string
	key          *rsa.PrivateKey

	mu sync.Mutex
	// Claims are the next sign-in's claims, beyond iss, aud, exp, iat and nonce.
	Claims map[string]any
	codes  map[string]grant
	// Tamper changes the ID token's claims before signing, for refusals.
	Tamper func(map[string]any)
}

type grant struct {
	claims    map[string]any
	challenge string
	redirect  string
}

// New starts a provider; it stops when the test ends.
func New(t *testing.T) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{ClientID: "deaconguard", ClientSecret: "s3cret", key: key, codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := p.Server.URL
		json.NewEncoder(w).Encode(map[string]string{"issuer": base, "authorization_endpoint": base + "/authorize",
			"token_endpoint": base + "/token", "jwks_uri": base + "/keys"})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		encode := base64.RawURLEncoding.EncodeToString
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256",
			"n": encode(key.N.Bytes()), "e": encode(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("client_id") != p.ClientID || query.Get("code_challenge_method") != "S256" || query.Get("response_type") != "code" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		claims := map[string]any{}
		for name, value := range p.Claims {
			claims[name] = value
		}
		claims["nonce"] = query.Get("nonce")
		code := randomText()
		p.codes[code] = grant{claims: claims, challenge: query.Get("code_challenge"), redirect: query.Get("redirect_uri")}
		p.mu.Unlock()
		back, _ := url.Parse(query.Get("redirect_uri"))
		values := back.Query()
		values.Set("code", code)
		values.Set("state", query.Get("state"))
		back.RawQuery = values.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		id, secret, _ := r.BasicAuth()
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
		p.mu.Lock()
		g, ok := p.codes[r.FormValue("code")]
		delete(p.codes, r.FormValue("code"))
		tamper := p.Tamper
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		switch {
		case id != p.ClientID || secret != p.ClientSecret:
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		case !ok || g.redirect != r.FormValue("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge:
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		now := time.Now().Unix()
		claims := g.claims
		claims["iss"], claims["aud"], claims["iat"], claims["exp"] = p.Server.URL, p.ClientID, now, now+300
		if tamper != nil {
			tamper(claims)
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": p.Sign(claims), "token_type": "Bearer", "access_token": "unused"})
	})
	p.Server = httptest.NewTLSServer(mux)
	t.Cleanup(p.Server.Close)
	return p
}

// Sign makes an RS256 JWT of claims with the provider's key.
func (p *Provider) Sign(claims map[string]any) string {
	encode := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	signed := encode(header) + "." + encode(payload)
	digest := sha256.Sum256([]byte(signed))
	signature, _ := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	return signed + "." + encode(signature)
}

func randomText() string {
	value := make([]byte, 16)
	rand.Read(value)
	return base64.RawURLEncoding.EncodeToString(value)
}
