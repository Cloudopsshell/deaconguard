// Package oidc signs people in with an OpenID Connect provider, such as
// Microsoft Entra ID, Google, Okta, Keycloak, Authentik or Dex, with the
// standard library only: discovery, the authorization code flow with PKCE,
// and ID tokens checked against the provider's published keys (RS256, RS384,
// RS512, PS256, ES256, ES384), issuer, audience, expiry and nonce.
package oidc

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// maxBody bounds what is read from the provider.
const maxBody = 1 << 20

// keysLifetime is how long the provider's keys are kept before they are
// fetched again; an unknown key ID fetches them sooner.
const keysLifetime = time.Hour

// clockSkew is how far the provider's clock may be off.
const clockSkew = 2 * time.Minute

// Provider is an OpenID provider, from its discovery document.
type Provider struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	client                *http.Client

	mu      sync.Mutex
	keys    map[string]crypto.PublicKey
	fetched time.Time
}

// NewClient is the HTTP client for a provider: no redirects to follow
// blindly, and a time limit.
func NewClient(transport http.RoundTripper) *http.Client {
	return &http.Client{Timeout: 15 * time.Second, Transport: transport}
}

func get(ctx context.Context, client *http.Client, address string, into any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered HTTP %d", address, response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, maxBody)).Decode(into)
}

// checkURL refuses provider addresses that aren't HTTPS: tokens and keys
// must not travel in clear text.
func checkURL(address, what string) error {
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" || parsed.Scheme != "https" {
		return fmt.Errorf("the provider's %s, %q, isn't an https:// address", what, address)
	}
	return nil
}

// Discover reads the provider's discovery document, from
// ISSUER/.well-known/openid-configuration, and checks it names the issuer.
func Discover(ctx context.Context, client *http.Client, issuer string) (*Provider, error) {
	issuer = strings.TrimSpace(issuer)
	if err := checkURL(issuer, "issuer"); err != nil {
		return nil, err
	}
	provider := &Provider{client: client}
	if err := get(ctx, client, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", provider); err != nil {
		return nil, fmt.Errorf("can't read the provider's discovery document: %w", err)
	}
	if provider.Issuer != issuer {
		return nil, fmt.Errorf("the provider calls itself %q, not %q; use exactly that as the issuer", provider.Issuer, issuer)
	}
	for what, address := range map[string]string{"authorization endpoint": provider.AuthorizationEndpoint,
		"token endpoint": provider.TokenEndpoint, "key set": provider.JWKSURI} {
		if err := checkURL(address, what); err != nil {
			return nil, err
		}
	}
	return provider, nil
}

// Random returns n random bytes, base64url-encoded: states, nonces and PKCE
// verifiers.
func Random(n int) (string, error) {
	value := make([]byte, n)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// Challenge is the PKCE S256 challenge of verifier.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthCodeURL is where the browser goes to sign in.
func (p *Provider) AuthCodeURL(clientID, redirectURI, state, nonce, verifier string, scopes []string) string {
	query := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"scope": {strings.Join(scopes, " ")}, "state": {state}, "nonce": {nonce},
		"code_challenge": {Challenge(verifier)}, "code_challenge_method": {"S256"},
	}
	separator := "?"
	if strings.Contains(p.AuthorizationEndpoint, "?") {
		separator = "&"
	}
	return p.AuthorizationEndpoint + separator + query.Encode()
}

// Exchange trades the code from the callback for the ID token.
func (p *Provider) Exchange(ctx context.Context, clientID, clientSecret, redirectURI, code, verifier string) (string, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	// client_secret_basic: the ID and secret are form-encoded first (RFC 6749 2.3.1).
	request.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	response, err := p.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("can't reach the provider's token endpoint: %w", err)
	}
	defer response.Body.Close()
	var body struct {
		IDToken          string `json:"id_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxBody)).Decode(&body); err != nil {
		return "", fmt.Errorf("the provider's token answer (HTTP %d) can't be read", response.StatusCode)
	}
	if body.Error != "" {
		return "", fmt.Errorf("the provider refused the sign-in: %s %s", body.Error, body.ErrorDescription)
	}
	if response.StatusCode != http.StatusOK || body.IDToken == "" {
		return "", fmt.Errorf("the provider gave no ID token (HTTP %d); check the client ID, secret and redirect URI", response.StatusCode)
	}
	return body.IDToken, nil
}

// Claims are what DeaconGuard reads from an ID token.
type Claims struct {
	Issuer            string    `json:"iss"`
	Subject           string    `json:"sub"`
	Audience          audience  `json:"aud"`
	AuthorizedParty   string    `json:"azp"`
	Expiry            float64   `json:"exp"`
	IssuedAt          float64   `json:"iat"`
	Nonce             string    `json:"nonce"`
	Email             string    `json:"email"`
	EmailVerified     *FlexBool `json:"email_verified"`
	PreferredUsername string    `json:"preferred_username"`
	Name              string    `json:"name"`
	// Raw has every claim, for the configured groups claim.
	Raw map[string]any `json:"-"`
}

// audience is a string or a list of strings.
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var one string
	if json.Unmarshal(data, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("aud is neither a string nor a list")
	}
	*a = many
	return nil
}

// FlexBool is a boolean some providers send as a string.
type FlexBool bool

func (b *FlexBool) UnmarshalJSON(data []byte) error {
	switch strings.Trim(string(data), `"`) {
	case "true":
		*b = true
	default:
		*b = false
	}
	return nil
}

// EmailIsVerified reports whether the provider says the email is the
// person's; providers that don't send the claim verify emails themselves.
func (c Claims) EmailIsVerified() bool {
	return c.EmailVerified == nil || bool(*c.EmailVerified)
}

// Strings returns a claim as a list: a list of strings, or one string, or
// nothing.
func (c Claims) Strings(name string) []string {
	switch value := c.Raw[name].(type) {
	case string:
		return []string{value}
	case []any:
		var list []string
		for _, item := range value {
			if text, ok := item.(string); ok {
				list = append(list, text)
			}
		}
		return list
	}
	return nil
}

// String returns a claim that is a string.
func (c Claims) String(name string) string {
	value, _ := c.Raw[name].(string)
	return value
}

// Verify checks an ID token's signature with the provider's keys, and its
// issuer, audience, expiry and nonce.
func (p *Provider) Verify(ctx context.Context, token, clientID, nonce string, now time.Time) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("the ID token isn't a signed JWT")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, errors.New("the ID token's header can't be read")
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return Claims{}, errors.New("the ID token's header can't be read")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, errors.New("the ID token's signature can't be read")
	}
	key, err := p.key(ctx, header.KeyID, now)
	if err != nil {
		return Claims{}, err
	}
	if err := verifySignature(header.Algorithm, key, []byte(parts[0]+"."+parts[1]), signature); err != nil {
		return Claims{}, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, errors.New("the ID token's claims can't be read")
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, errors.New("the ID token's claims can't be read")
	}
	if err := json.Unmarshal(payload, &claims.Raw); err != nil {
		return Claims{}, errors.New("the ID token's claims can't be read")
	}
	switch {
	case claims.Issuer != p.Issuer:
		return Claims{}, fmt.Errorf("the ID token is from %q, not %q", claims.Issuer, p.Issuer)
	case !contains(claims.Audience, clientID):
		return Claims{}, errors.New("the ID token is for another application")
	case len(claims.Audience) > 1 && claims.AuthorizedParty != "" && claims.AuthorizedParty != clientID:
		return Claims{}, errors.New("the ID token was issued to another application")
	case claims.Expiry == 0 || now.After(time.Unix(int64(claims.Expiry), 0).Add(clockSkew)):
		return Claims{}, errors.New("the ID token has expired; check the server's clock")
	case claims.IssuedAt != 0 && time.Unix(int64(claims.IssuedAt), 0).After(now.Add(clockSkew)):
		return Claims{}, errors.New("the ID token was issued in the future; check the server's clock")
	case claims.Nonce == "" || claims.Nonce != nonce:
		return Claims{}, errors.New("the ID token doesn't answer this sign-in; try again")
	case claims.Subject == "":
		return Claims{}, errors.New("the ID token names no subject")
	}
	return claims, nil
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func verifySignature(algorithm string, key crypto.PublicKey, signed, signature []byte) error {
	var hash crypto.Hash
	switch algorithm {
	case "RS256", "PS256", "ES256":
		hash = crypto.SHA256
	case "RS384", "ES384":
		hash = crypto.SHA384
	case "RS512":
		hash = crypto.SHA512
	default:
		return fmt.Errorf("ID tokens signed with %q aren't accepted; use RS256 or ES256", algorithm)
	}
	digest := digestOf(hash, signed)
	switch key := key.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return errors.New("the provider's RSA key is shorter than 2048 bits")
		}
		var err error
		switch algorithm {
		case "RS256", "RS384", "RS512":
			err = rsa.VerifyPKCS1v15(key, hash, digest, signature)
		case "PS256":
			err = rsa.VerifyPSS(key, hash, digest, signature, nil)
		default:
			return fmt.Errorf("an RSA key can't check a %s signature", algorithm)
		}
		if err != nil {
			return errors.New("the ID token's signature isn't valid")
		}
	case *ecdsa.PublicKey:
		size := (key.Curve.Params().BitSize + 7) / 8
		if (algorithm == "ES256" && key.Curve != elliptic.P256()) || (algorithm == "ES384" && key.Curve != elliptic.P384()) ||
			!strings.HasPrefix(algorithm, "ES") || len(signature) != 2*size {
			return errors.New("the ID token's signature doesn't fit its key")
		}
		r, s := new(big.Int).SetBytes(signature[:size]), new(big.Int).SetBytes(signature[size:])
		if !ecdsa.Verify(key, digest, r, s) {
			return errors.New("the ID token's signature isn't valid")
		}
	default:
		return errors.New("the provider's key type isn't supported")
	}
	return nil
}

func digestOf(hash crypto.Hash, data []byte) []byte {
	switch hash {
	case crypto.SHA384:
		sum := sha512.Sum384(data)
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(data)
		return sum[:]
	}
	sum := sha256.Sum256(data)
	return sum[:]
}

// key returns the provider's signing key with id, fetching the key set when
// it is old or doesn't have it, at most once a minute for unknown IDs.
func (p *Provider) key(ctx context.Context, id string, now time.Time) (crypto.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key, ok := p.lookup(id)
	if ok && now.Sub(p.fetched) < keysLifetime {
		return key, nil
	}
	if !ok && now.Sub(p.fetched) < time.Minute && p.keys != nil {
		return nil, errors.New("the ID token is signed with a key the provider doesn't publish")
	}
	keys, err := fetchKeys(ctx, p.client, p.JWKSURI)
	if err != nil {
		if ok {
			return key, nil
		}
		return nil, err
	}
	p.keys, p.fetched = keys, now
	if key, ok := p.lookup(id); ok {
		return key, nil
	}
	return nil, errors.New("the ID token is signed with a key the provider doesn't publish")
}

// lookup finds a key by ID; a token without an ID uses the only key.
func (p *Provider) lookup(id string) (crypto.PublicKey, bool) {
	if id == "" && len(p.keys) == 1 {
		for _, key := range p.keys {
			return key, true
		}
	}
	key, ok := p.keys[id]
	return key, ok
}

type jwk struct {
	Type  string `json:"kty"`
	ID    string `json:"kid"`
	Use   string `json:"use"`
	N     string `json:"n"`
	E     string `json:"e"`
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

func ecdhCurve(name string) ecdh.Curve {
	if name == "P-384" {
		return ecdh.P384()
	}
	return ecdh.P256()
}

func fetchKeys(ctx context.Context, client *http.Client, address string) (map[string]crypto.PublicKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := get(ctx, client, address, &set); err != nil {
		return nil, fmt.Errorf("can't read the provider's keys: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, item := range set.Keys {
		if item.Use != "" && item.Use != "sig" {
			continue
		}
		decode := base64.RawURLEncoding.DecodeString
		switch item.Type {
		case "RSA":
			n, err1 := decode(item.N)
			e, err2 := decode(item.E)
			if err1 != nil || err2 != nil || len(e) > 4 {
				continue
			}
			exponent := 0
			for _, b := range e {
				exponent = exponent<<8 | int(b)
			}
			keys[item.ID] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}
		case "EC":
			var curve elliptic.Curve
			switch item.Curve {
			case "P-256":
				curve = elliptic.P256()
			case "P-384":
				curve = elliptic.P384()
			default:
				continue
			}
			x, err1 := decode(item.X)
			y, err2 := decode(item.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			size := (curve.Params().BitSize + 7) / 8
			if len(x) != size || len(y) != size {
				continue
			}
			// crypto/ecdh refuses points that aren't on the curve.
			point := append(append([]byte{4}, x...), y...)
			if _, err := ecdhCurve(item.Curve).NewPublicKey(point); err != nil {
				continue
			}
			keys[item.ID] = &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("the provider publishes no signing key DeaconGuard can use")
	}
	return keys, nil
}
