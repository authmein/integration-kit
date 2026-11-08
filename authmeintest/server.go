// Package authmeintest is a fake authmein (auth.me.in, Authorizer 2.4.x) for tests and local development: OIDC
// discovery, JWKS, an authorize endpoint and a token endpoint that signs real RS256 ID tokens for a PUBLIC client (no
// secret, like the "dynamic" clients) and enforces PKCE (S256), one-time codes, the client id and the redirect URI.
//
// HOW FAR TO TRUST IT. A fake only proves what was observed in the real service; it proves your assumptions otherwise.
// Behaviours below are marked [OBS] (seen on a real auth.me.in), [DOK] (read in the Authorizer 2.4.4 source or docs) or
// [BELUM] (assumed, never seen). When a real log disagrees with this file, change this file to match reality, and add
// a test that fails against the old behaviour.
//
//   - Codes are one-time and bound to client_id, redirect_uri and the PKCE challenge. [DOK]
//   - A code voided by a newer authorize answers 401 at the token endpoint (RejectCodes). [OBS]
//   - The id_token carries sub, email, email_verified, nonce, and given_name/family_name only when the profile has a
//     name. [OBS]
//   - The MFA gate for a social login that still owes a second factor answers with a redirect to redirect_uri carrying
//     mfa_required=1&mfa_methods=...&mfa_gate=... and NO code and NO state (MFAGate). [OBS 2026-11-08]
//   - The hosted login page /app?<authorize query>&code=<id> is what /authorize answers for an unauthenticated browser;
//     the MFA hand-off lands there. [OBS]
//   - NOT imitated: the consent screen (shown on every login of a "dynamic" client), passwords, real MFA, refresh tokens,
//     social login buttons, rate limits. [BELUM]
package authmeintest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Identity is the account the fake approves.
type Identity struct {
	Sub           string
	Email         string
	Name          string // empty = the token carries no name claims at all, like an account with no profile
	EmailVerified bool
}

type codeEntry struct {
	id          Identity
	nonce       string
	challenge   string
	clientID    string
	redirectURI string
}

// Server is the fake. Set the exported configuration fields before the first request.
type Server struct {
	URL      string // issuer; set once the listener address is known
	ClientID string

	// Identity, when set, is approved automatically at /authorize (tests). When nil, /authorize shows a small form
	// asking for an email (manual development).
	Identity *Identity
	// Mutate can alter the ID token claims before signing (wrong aud, expired, wrong nonce...).
	Mutate func(claims map[string]any)
	// WrongKey signs with a key that is not in the JWKS.
	WrongKey bool
	// MFAGate makes the next /authorize answer like authmein does for a social login that still owes a second factor.
	// The hand-off to /app clears it, as finishing the second factor would.
	MFAGate bool
	// RejectCodes makes the next N token requests answer 401, as authmein does for a code voided by a newer authorize.
	RejectCodes int

	mu         sync.Mutex
	gateShown  bool
	codes      map[string]codeEntry
	lastAuth   url.Values
	lastApp    url.Values
	tokenCalls int
	sawBasic   bool
}

var (
	keyOnce  sync.Once
	goodKey  *rsa.PrivateKey
	otherKey *rsa.PrivateKey
)

func keys() (*rsa.PrivateKey, *rsa.PrivateKey) {
	keyOnce.Do(func() {
		var err error
		if goodKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if otherKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return goodKey, otherKey
}

// New returns a fake for one public client.
func New(clientID string) *Server {
	keys()
	return &Server{ClientID: clientID, codes: map[string]codeEntry{}}
}

// LastAuthorize returns the query of the last /authorize call (copy).
func (s *Server) LastAuthorize() url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneValues(s.lastAuth)
}

// LastApp returns the query of the last /app call, i.e. the MFA hand-off (copy).
func (s *Server) LastApp() url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneValues(s.lastApp)
}

// TokenCalls returns how many token requests arrived and whether any of them used an Authorization (Basic) header.
// A public client must send exactly ONE request per code and never a Basic header.
func (s *Server) TokenCalls() (n int, sawBasic bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenCalls, s.sawBasic
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b64(b)
}

// Handler serves discovery, /jwks, /authorize, /app/ and /token.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("/jwks", s.jwks)
	mux.HandleFunc("/authorize", s.authorize)
	mux.HandleFunc("/app/", s.app)
	mux.HandleFunc("/token", s.token)
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                s.URL,
		"authorization_endpoint":                s.URL + "/authorize",
		"token_endpoint":                        s.URL + "/token",
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"jwks_uri":                              s.URL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	k, _ := keys()
	writeJSON(w, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-key",
		"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes()),
	}}})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	s.lastAuth = cloneValues(q)
	s.mu.Unlock()
	if q.Get("response_type") != "code" || q.Get("client_id") != s.ClientID || q.Get("redirect_uri") == "" ||
		q.Get("state") == "" || q.Get("nonce") == "" {
		http.Error(w, "bad authorize request", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "PKCE (S256) is required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	gated, shown := s.MFAGate, s.gateShown
	if gated {
		s.gateShown = true
	}
	s.mu.Unlock()
	if gated && shown {
		// the hand-off asks for the hosted login page: like authmein, answer with /app?<query>&code=<id>
		aq := cloneValues(q)
		aq.Set("code", "hosted-"+randHex())
		http.Redirect(w, r, "/app?"+aq.Encode(), http.StatusFound)
		return
	}
	if gated {
		u, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		// Like Authorizer 2.4.4 (observed on auth.me.in, 2026-11-08): the gate redirect carries NO state and NO code.
		rq := u.Query()
		rq.Set("mfa_required", "1")
		rq.Set("mfa_methods", "totp")
		rq.Set("mfa_gate", "offer")
		u.RawQuery = rq.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}
	id := s.Identity
	if id == nil {
		if email := q.Get("dev_email"); email != "" {
			id = &Identity{Sub: "dev-" + email, Email: email, Name: q.Get("dev_name"), EmailVerified: true}
		}
	}
	if id == nil { // manual mode: ask who is logging in
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><meta charset=utf-8><title>Fake authmein</title><body style="font:16px system-ui;max-width:26rem;margin:4rem auto">
<h1>Fake authmein login</h1><p>Development provider. Enter the account to log in as.</p><form method=get action=/authorize>`)
		for k, vs := range q {
			fmt.Fprintf(w, `<input type=hidden name="%s" value="%s">`, html.EscapeString(k), html.EscapeString(vs[0]))
		}
		fmt.Fprint(w, `<p><input name=dev_email type=email placeholder="email" required style="width:100%;padding:8px"></p>
<p><input name=dev_name placeholder="name" style="width:100%;padding:8px"></p><button style="padding:8px 16px">Continue</button></form>`)
		return
	}
	code := randHex()
	s.mu.Lock()
	s.codes[code] = codeEntry{id: *id, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"),
		clientID: q.Get("client_id"), redirectURI: q.Get("redirect_uri")}
	s.mu.Unlock()
	u, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := u.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// app stands for authmein's hosted login page (/app/): the MFA hand-off lands here. It records the query it got
// (LastApp) and finishes the second factor by sending the browser on to /authorize without the gate.
func (s *Server) app(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	s.lastApp = cloneValues(q)
	s.MFAGate, s.gateShown = false, false
	s.mu.Unlock()
	q.Del("code")
	q.Del("mfa_required")
	q.Del("mfa_methods")
	q.Del("mfa_gate")
	http.Redirect(w, r, "/authorize?"+q.Encode(), http.StatusFound)
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func oauthError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.ParseForm() != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	_, _, basic := r.BasicAuth()
	s.mu.Lock()
	s.tokenCalls++
	s.sawBasic = s.sawBasic || basic
	reject := s.RejectCodes > 0
	if reject {
		s.RejectCodes--
	}
	s.mu.Unlock()
	if reject {
		oauthError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// A public client sends client_id in the body. A Basic header is what a library sends when it thinks the client has
	// a secret. [BELUM: how the real server answers it; strict on purpose] Reject it, so a client that probes with Basic
	// first burns the one-time code here too and the tests notice.
	if basic || r.PostForm.Get("client_id") != s.ClientID {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	s.mu.Lock()
	entry, ok := s.codes[r.PostForm.Get("code")]
	delete(s.codes, r.PostForm.Get("code")) // one-time use
	s.mu.Unlock()
	if !ok || entry.clientID != s.ClientID || entry.redirectURI != r.PostForm.Get("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if b64(sum[:]) != entry.challenge {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	now := time.Now()
	claims := map[string]any{
		"iss": s.URL, "sub": entry.id.Sub, "aud": s.ClientID,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": entry.nonce,
		"email": entry.id.Email, "email_verified": entry.id.EmailVerified,
	}
	// authmein sends given_name/family_name, and nothing when the profile was never filled in.
	if entry.id.Name != "" {
		first, last, _ := strings.Cut(entry.id.Name, " ")
		claims["given_name"], claims["family_name"] = first, last
	}
	if s.Mutate != nil {
		s.Mutate(claims)
	}
	writeJSON(w, map[string]any{
		"access_token": "fake-access-token", "token_type": "Bearer", "expires_in": 3600,
		"id_token": s.sign(claims),
	})
}

func (s *Server) sign(claims map[string]any) string {
	good, other := keys()
	key := good
	if s.WrongKey {
		key = other
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test-key"})
	body, _ := json.Marshal(claims)
	input := b64(header) + "." + b64(body)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return input + "." + b64(sig)
}
