package authmeinclient_test

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authmein/integration-kit/authmeinclient"
	"github.com/authmein/integration-kit/authmeintest"
)

const (
	clientID = "client-under-test"
	secret   = "0123456789abcdef0123456789abcdef-test-secret"
)

// env is one app wired to one fake authmein, the way a real app is wired to auth.me.in.
type env struct {
	t        *testing.T
	idp      *authmeintest.Server
	idpSrv   *httptest.Server
	app      *httptest.Server
	handler  *authmeinclient.Handler
	offset   atomic.Int64 // seconds added to the handler's clock
	mu       sync.Mutex
	logins   []authmeinclient.Identity
	nextSeen []string
}

func ident(email string) authmeintest.Identity {
	local, _, _ := strings.Cut(email, "@")
	return authmeintest.Identity{Sub: "sub-" + local, Email: email, Name: "Test " + local, EmailVerified: true}
}

func newEnv(t *testing.T, tweak ...func(*authmeinclient.Config)) *env {
	t.Helper()
	e := &env{t: t}
	e.idp = authmeintest.New(clientID)
	e.idpSrv = httptest.NewServer(e.idp.Handler())
	e.idp.URL = e.idpSrv.URL
	mux := http.NewServeMux()
	e.app = httptest.NewServer(mux)
	t.Cleanup(func() { e.app.Close(); e.idpSrv.Close() })

	cfg := authmeinclient.Config{Issuer: e.idp.URL, ClientID: clientID, RedirectURL: e.app.URL + "/auth/authmein/callback", SessionSecret: secret, DefaultNext: "/home"}
	for _, f := range tweak {
		f(&cfg)
	}
	h, err := authmeinclient.New(cfg, authmeinclient.Hooks{OnLogin: e.onLogin},
		authmeinclient.WithClock(func() time.Time { return time.Now().Add(time.Duration(e.offset.Load()) * time.Second) }))
	if err != nil {
		t.Fatal(err)
	}
	e.handler = h
	h.Mount(mux, "/auth/authmein")
	mux.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "home") })
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("app_session")
		if err != nil {
			http.Error(w, "no session", http.StatusUnauthorized)
			return
		}
		io.WriteString(w, c.Value)
	})
	return e
}

// onLogin is a stand-in for the app: it refuses one address and otherwise "creates a session" keyed by the account id.
func (e *env) onLogin(w http.ResponseWriter, r *http.Request, id authmeinclient.Identity, next string) error {
	e.mu.Lock()
	e.logins = append(e.logins, id)
	e.nextSeen = append(e.nextSeen, next)
	e.mu.Unlock()
	if id.Email == "denied@example.test" {
		return &authmeinclient.DeniedError{Title: "Akun belum diizinkan", Text: id.Email + " belum diundang."}
	}
	http.SetCookie(w, &http.Cookie{Name: "app_session", Value: id.Subject, Path: "/", HttpOnly: true})
	return nil
}

func (e *env) loginCount() int { e.mu.Lock(); defer e.mu.Unlock(); return len(e.logins) }
func (e *env) lastLogin() authmeinclient.Identity {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.logins[len(e.logins)-1]
}

type result struct {
	Status int
	Body   string
	URL    *url.URL
	Loc    string
}

// browser is a cookie jar plus a client that either follows redirects or stops at the first one.
func (e *env) browser(follow bool) *http.Client {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	if !follow {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}

func (e *env) get(c *http.Client, target string) result {
	e.t.Helper()
	if strings.HasPrefix(target, "/") {
		target = e.app.URL + target
	}
	resp, err := c.Get(target)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return result{Status: resp.StatusCode, Body: string(b), URL: resp.Request.URL, Loc: resp.Header.Get("Location")}
}

func (e *env) cookie(c *http.Client, name string) string {
	u, _ := url.Parse(e.app.URL + "/auth/authmein/callback") // the flow cookie is scoped to this path
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == name {
			return ck.Value
		}
	}
	return ""
}

// startFlow performs /start and returns the redirect target (the authorize URL at the fake authmein).
func (e *env) startFlow(c *http.Client, id authmeintest.Identity, next string) string {
	e.t.Helper()
	e.idp.Identity = &id
	res := e.get(c, "/auth/authmein/start?next="+url.QueryEscape(next))
	if res.Status != http.StatusFound {
		e.t.Fatalf("start: %d %s", res.Status, res.Body)
	}
	return res.Loc
}

// approve follows /authorize at the fake authmein and returns the callback URL it answers with.
func (e *env) approve(c *http.Client, authorizeURL string) string {
	e.t.Helper()
	res := e.get(c, authorizeURL)
	if res.Status != http.StatusFound {
		e.t.Fatalf("authorize: %d %s", res.Status, res.Body)
	}
	return res.Loc
}

// login runs the whole login with a following browser and returns the final page.
func (e *env) login(c *http.Client, id authmeintest.Identity, next string) result {
	e.t.Helper()
	e.idp.Identity = &id
	return e.get(c, "/auth/authmein/start?next="+url.QueryEscape(next))
}

func TestLoginHappyPath(t *testing.T) {
	e := newEnv(t)
	c := e.browser(true)
	res := e.login(c, ident("ana@example.test"), "/whoami")
	if res.Status != 200 || res.URL.Path != "/whoami" || res.Body != "sub-ana" {
		t.Fatalf("%d %s at %s", res.Status, res.Body, res.URL)
	}
	if got := e.lastLogin(); got.Subject != "sub-ana" || got.Email != "ana@example.test" || got.Name != "Test ana" {
		t.Fatalf("identity %+v", got)
	}
	if e.cookie(c, "authmein_flow") != "" {
		t.Fatal("the flow cookie must be gone after the login")
	}
}

func TestPKCEStateAndNonceAreSent(t *testing.T) {
	e := newEnv(t)
	loc := e.startFlow(e.browser(false), ident("ana@example.test"), "/home")
	u, _ := url.Parse(loc)
	q := u.Query()
	if q.Get("client_id") != clientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("nonce") == "" ||
		q.Get("redirect_uri") != e.app.URL+"/auth/authmein/callback" || !strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("authorize query %v", q)
	}
}

// The token request must carry client_id in the body, once, with no Basic header: a public client has no secret,
// and a library that probes with Basic first would burn the one-time code.
func TestPublicClientSendsOneTokenRequestWithoutBasic(t *testing.T) {
	e := newEnv(t)
	if res := e.login(e.browser(true), ident("ana@example.test"), "/home"); res.Status != 200 {
		t.Fatalf("%d %s", res.Status, res.Body)
	}
	if n, basic := e.idp.TokenCalls(); n != 1 || basic {
		t.Fatalf("token requests: %d (basic header seen: %v), want 1 and none", n, basic)
	}
}

func TestFlowCookieAttributes(t *testing.T) {
	e := newEnv(t, func(c *authmeinclient.Config) { c.CookieSecure = true })
	req, _ := http.NewRequest("GET", e.app.URL+"/auth/authmein/start", nil)
	resp, err := e.browser(false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var flow *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == "authmein_flow" {
			flow = ck
		}
	}
	if flow == nil || !flow.HttpOnly || !flow.Secure || flow.SameSite != http.SameSiteLaxMode || flow.Path != "/auth/authmein" || flow.MaxAge != 600 {
		t.Fatalf("flow cookie %+v", flow)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("the redirect to authmein must not be cached")
	}
}

func TestNextIsOnlyEverALocalPath(t *testing.T) {
	for next, want := range map[string]string{
		"/whoami?x=1":           "/whoami",
		"":                      "/home",
		"https://evil.example/": "/home",
		"//evil.example/x":      "/home",
		"/\\evil.example":       "/home",
		"javascript:alert(1)":   "/home",
		"http:/evil.example":    "/home",
	} {
		e := newEnv(t)
		res := e.login(e.browser(true), ident("ana@example.test"), next)
		if res.Status != 200 && res.Status != 401 { // /whoami answers 401 only if the cookie were missing: it is not
			t.Errorf("next=%q: %d", next, res.Status)
		}
		if res.URL.Host != strings.TrimPrefix(e.app.URL, "http://") || res.URL.Path != want {
			t.Errorf("next=%q ended at %s, want %s on this site", next, res.URL, want)
		}
	}
}

func TestSafeNext(t *testing.T) {
	if authmeinclient.SafeNext("/a/b?c=d", "/x") != "/a/b?c=d" || authmeinclient.SafeNext("//h", "/x") != "/x" {
		t.Fatal("SafeNext")
	}
}

func TestStateMismatchIsRejected(t *testing.T) {
	e := newEnv(t)
	c := e.browser(false)
	cb, _ := url.Parse(e.approve(c, e.startFlow(c, ident("ana@example.test"), "/home")))
	q := cb.Query()
	q.Set("state", "someone-elses-state")
	cb.RawQuery = q.Encode()
	if res := e.get(c, cb.String()); res.Status != http.StatusBadRequest || e.cookie(c, "app_session") != "" || e.loginCount() != 0 {
		t.Fatalf("%d %s", res.Status, res.Body)
	}
}

func TestFlowCookieMissingTamperedOrExpired(t *testing.T) {
	e := newEnv(t)
	// missing: a callback URL used from a browser that never started a login
	c := e.browser(false)
	cb := e.approve(c, e.startFlow(c, ident("ana@example.test"), "/home"))
	if res := e.get(e.browser(false), cb); res.Status != http.StatusBadRequest {
		t.Fatalf("missing flow cookie: %d", res.Status)
	}
	// tampered
	c2 := e.browser(false)
	cb2 := e.approve(c2, e.startFlow(c2, ident("ana@example.test"), "/home"))
	good := e.cookie(c2, "authmein_flow")
	req, _ := http.NewRequest("GET", cb2, nil)
	req.Header.Set("Cookie", "authmein_flow="+good[:len(good)-2]+"AA")
	resp, err := e.browser(false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("tampered flow cookie: %d", resp.StatusCode)
	}
	// expired
	c3 := e.browser(false)
	cb3 := e.approve(c3, e.startFlow(c3, ident("ana@example.test"), "/home"))
	e.offset.Store(int64((11 * time.Minute).Seconds()))
	if res := e.get(c3, cb3); res.Status != http.StatusBadRequest || !strings.Contains(res.Body, "kedaluwarsa") {
		t.Fatalf("expired flow: %d %s", res.Status, res.Body)
	}
	if e.loginCount() != 0 {
		t.Fatal("no login may complete from a bad flow cookie")
	}
}

func TestAuthorizationCodeCannotBeReplayed(t *testing.T) {
	e := newEnv(t)
	c := e.browser(false)
	cb := e.approve(c, e.startFlow(c, ident("ana@example.test"), "/home"))
	flow := e.cookie(c, "authmein_flow")
	if res := e.get(c, cb); res.Status != http.StatusFound {
		t.Fatalf("first use: %d %s", res.Status, res.Body)
	}
	req, _ := http.NewRequest("GET", cb, nil)
	req.Header.Set("Cookie", "authmein_flow="+flow)
	resp, err := e.browser(false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusFound || e.loginCount() != 1 {
		t.Fatalf("replayed code: %d (logins: %d)", resp.StatusCode, e.loginCount())
	}
}

func TestBrokenIDTokensAreRejected(t *testing.T) {
	cases := map[string]func(e *env, id *authmeintest.Identity){
		"wrong audience": func(e *env, _ *authmeintest.Identity) {
			e.idp.Mutate = func(m map[string]any) { m["aud"] = "someone-else" }
		},
		"wrong issuer": func(e *env, _ *authmeintest.Identity) {
			e.idp.Mutate = func(m map[string]any) { m["iss"] = "https://evil.example" }
		},
		"expired": func(e *env, _ *authmeintest.Identity) {
			e.idp.Mutate = func(m map[string]any) { m["exp"] = time.Now().Add(-time.Hour).Unix() }
		},
		"wrong nonce": func(e *env, _ *authmeintest.Identity) {
			e.idp.Mutate = func(m map[string]any) { m["nonce"] = "not-mine" }
		},
		"unverified email": func(_ *env, id *authmeintest.Identity) { id.EmailVerified = false },
		"no email":         func(_ *env, id *authmeintest.Identity) { id.Email = "" },
		"no subject":       func(_ *env, id *authmeintest.Identity) { id.Sub = "" },
		"bad signature":    func(e *env, _ *authmeintest.Identity) { e.idp.WrongKey = true },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			id := ident("ana@example.test")
			breakIt(e, &id)
			c := e.browser(true)
			res := e.login(c, id, "/home")
			if res.Status < 400 || e.cookie(c, "app_session") != "" || e.loginCount() != 0 {
				t.Fatalf("accepted a broken token: %d %s (OnLogin calls: %d)", res.Status, res.Body, e.loginCount())
			}
		})
	}
}

func TestAppDeniesAnIdentityItDoesNotAllow(t *testing.T) {
	e := newEnv(t)
	c := e.browser(true)
	res := e.login(c, ident("denied@example.test"), "/home")
	if res.Status != http.StatusForbidden || !strings.Contains(res.Body, "belum diundang") || e.cookie(c, "app_session") != "" {
		t.Fatalf("%d %s", res.Status, res.Body)
	}
}

// authmein sends no name at all for an account whose profile was never filled in; the handler passes an empty name.
func TestAccountWithoutAProfileNameHasAnEmptyName(t *testing.T) {
	e := newEnv(t)
	id := ident("ana@example.test")
	id.Name = ""
	if res := e.login(e.browser(true), id, "/home"); res.Status != 200 {
		t.Fatalf("%d %s", res.Status, res.Body)
	}
	if got := e.lastLogin(); got.Name != "" || got.Subject != "sub-ana" {
		t.Fatalf("%+v", got)
	}
}

// The key is the account id (sub): the same sub arriving with a new email is the same account.
func TestEmailChangeKeepsTheSameSubject(t *testing.T) {
	e := newEnv(t)
	id := ident("old@example.test")
	e.login(e.browser(true), id, "/home")
	first := e.lastLogin()
	id.Email = "new@example.test"
	e.login(e.browser(true), id, "/home")
	second := e.lastLogin()
	if first.Subject != second.Subject || second.Email != "new@example.test" {
		t.Fatalf("%+v then %+v", first, second)
	}
}

func TestUnreachableIssuerGivesAFriendlyErrorAndNoCookie(t *testing.T) {
	e := newEnv(t, func(c *authmeinclient.Config) { c.Issuer = "http://127.0.0.1:1" })
	c := e.browser(false)
	res := e.get(c, "/auth/authmein/start")
	if res.Status != http.StatusBadGateway || e.cookie(c, "authmein_flow") != "" {
		t.Fatalf("%d %s", res.Status, res.Body)
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	ok := authmeinclient.Config{ClientID: "c", RedirectURL: "https://app.example/auth/authmein/callback", SessionSecret: secret}
	hooks := authmeinclient.Hooks{OnLogin: func(http.ResponseWriter, *http.Request, authmeinclient.Identity, string) error { return nil }}
	if _, err := authmeinclient.New(ok, hooks); err != nil {
		t.Fatalf("a valid config was refused: %v", err)
	}
	for name, mutate := range map[string]func(*authmeinclient.Config){
		"short secret":        func(c *authmeinclient.Config) { c.SessionSecret = "short" },
		"no client id":        func(c *authmeinclient.Config) { c.ClientID = "" },
		"redirect not a cb":   func(c *authmeinclient.Config) { c.RedirectURL = "https://app.example/login" },
		"relative redirect":   func(c *authmeinclient.Config) { c.RedirectURL = "/auth/authmein/callback" },
		"issuer without host": func(c *authmeinclient.Config) { c.Issuer = "https://" },
		"unsafe default next": func(c *authmeinclient.Config) { c.DefaultNext = "https://evil.example" },
	} {
		c := ok
		mutate(&c)
		if _, err := authmeinclient.New(c, hooks); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := authmeinclient.New(ok, authmeinclient.Hooks{}); err == nil {
		t.Error("a missing OnLogin was accepted")
	}
}

// An account that still owes a second factor comes back without a code. That is a detour, not a failure: the browser
// goes to authmein's hosted page with the same authorize query plus the gate parameters, and the login completes.
func TestMFAGateHandOffCompletesTheLogin(t *testing.T) {
	e := newEnv(t)
	e.idp.MFAGate = true
	res := e.login(e.browser(true), ident("ana@example.test"), "/whoami")
	if res.Status != 200 || res.Body != "sub-ana" {
		t.Fatalf("%d %s", res.Status, res.Body)
	}
	q := e.idp.LastApp()
	if q.Get("mfa_required") != "1" || q.Get("mfa_gate") != "offer" || q.Get("mfa_methods") != "totp" ||
		q.Get("client_id") != clientID || q.Get("code_challenge") == "" || q.Get("state") == "" || !strings.HasPrefix(q.Get("code"), "hosted-") {
		t.Fatalf("hand-off query %v", q)
	}
}

// The detour happens once per login: a second gate answer ends in an error page instead of a redirect loop.
func TestMFAGateHandOffNeverLoops(t *testing.T) {
	e := newEnv(t)
	e.idp.MFAGate = true
	c := e.browser(false)
	cb := e.approve(c, e.startFlow(c, ident("ana@example.test"), "/home"))
	first := e.get(c, cb)
	if first.Status != http.StatusFound || !strings.Contains(first.Loc, "/app?") {
		t.Fatalf("first answer: %d %s", first.Status, first.Loc)
	}
	second := e.get(c, cb)
	if second.Status != http.StatusForbidden || e.loginCount() != 0 {
		t.Fatalf("second answer: %d %s", second.Status, second.Body)
	}
}

// A gate answer from a browser that never started a login (no flow cookie) or with a wrong state is not followed.
func TestMFAGateAnswerNeedsOurFlow(t *testing.T) {
	e := newEnv(t)
	e.idp.MFAGate = true
	c := e.browser(false)
	cb := e.approve(c, e.startFlow(c, ident("ana@example.test"), "/home"))
	if res := e.get(e.browser(false), cb); res.Status != http.StatusBadRequest {
		t.Fatalf("no flow cookie: %d", res.Status)
	}
	u, _ := url.Parse(cb)
	q := u.Query()
	q.Set("state", "not-mine") // a state that IS present must match
	u.RawQuery = q.Encode()
	if res := e.get(c, u.String()); res.Status != http.StatusBadRequest {
		t.Fatalf("wrong state: %d", res.Status)
	}
}

// Authorizer 2.4.4's gate redirect carries no state (seen on auth.me.in with a real GitHub login): it must still be
// followed, because the flow cookie proves the browser started the login. The state stays mandatory on every path that
// can end in a session: a code or an error without the right state is refused, gate parameters or not.
func TestMFAGateAnswerWithoutStateIsFollowedButNothingElseIs(t *testing.T) {
	e := newEnv(t)
	e.idp.MFAGate = true
	c := e.browser(false)
	cb := e.approve(c, e.startFlow(c, ident("ana@example.test"), "/home"))
	u, _ := url.Parse(cb)
	if u.Query().Has("state") || u.Query().Get("mfa_required") != "1" || u.Query().Has("code") {
		t.Fatalf("the fake gate answer must look like Authorizer's (no state, no code): %s", cb)
	}
	if res := e.get(c, cb); res.Status != http.StatusFound || !strings.Contains(res.Loc, "/app?") {
		t.Fatalf("stateless gate answer: %d %s", res.Status, res.Loc)
	}

	for name, extra := range map[string]string{
		"code without state":  "code=abc",
		"error without state": "error=access_denied",
		"code with bad state": "code=abc&state=not-mine",
	} {
		e := newEnv(t) // the fake gate answers once per environment
		e.idp.MFAGate = true
		c := e.browser(false)
		cb := e.approve(c, e.startFlow(c, ident("ana@example.test"), "/home"))
		res := e.get(c, cb+"&"+extra)
		if res.Status != http.StatusBadRequest || e.loginCount() != 0 {
			t.Fatalf("%s: %d %s", name, res.Status, res.Body)
		}
	}
}

// authmein answers 401 for a code voided by a newer authorize. The login restarts ONCE with fresh values.
func TestRejectedCodeRestartsTheLoginOnce(t *testing.T) {
	e := newEnv(t)
	e.idp.RejectCodes = 1
	res := e.login(e.browser(true), ident("ana@example.test"), "/whoami")
	if res.Status != 200 || res.Body != "sub-ana" {
		t.Fatalf("one restart should have been enough: %d %s", res.Status, res.Body)
	}
	if n, _ := e.idp.TokenCalls(); n != 2 {
		t.Fatalf("token requests: %d, want 2 (the rejected code, then the fresh one)", n)
	}
}

func TestRejectedCodeDoesNotRestartTwice(t *testing.T) {
	e := newEnv(t)
	e.idp.RejectCodes = 2
	c := e.browser(true)
	res := e.login(c, ident("ana@example.test"), "/whoami")
	if res.Status != http.StatusBadRequest || e.cookie(c, "app_session") != "" || e.loginCount() != 0 {
		t.Fatalf("a second rejection must end in an error page: %d %s", res.Status, res.Body)
	}
	if n, _ := e.idp.TokenCalls(); n != 2 {
		t.Fatalf("token requests: %d, want exactly 2 (never retry the same code, restart once)", n)
	}
}

func TestSecondLoginAfterFirstWorksAgain(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 2; i++ {
		if res := e.login(e.browser(true), ident("ana@example.test"), "/whoami"); res.Status != 200 {
			t.Fatalf("login %d: %d %s", i, res.Status, res.Body)
		}
	}
	if e.loginCount() != 2 {
		t.Fatalf("logins: %d", e.loginCount())
	}
}
