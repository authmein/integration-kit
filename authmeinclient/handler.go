package authmeinclient

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const flowTTL = 10 * time.Minute

// DeniedError is returned by Hooks.OnLogin when the person proved who they are but may not use this app (not on the
// allowlist, account suspended). The handler shows a 403 page with this title and text.
type DeniedError struct{ Title, Text string }

func (e *DeniedError) Error() string { return e.Title }

// Hooks is where the app plugs in. authmein only proves an identity; everything about WHO MAY ENTER and what the
// session looks like stays in the app.
type Hooks struct {
	// OnLogin receives a verified identity (signature, iss, aud, exp and nonce checked; email present, verified;
	// Subject non-empty). It should: apply the app's own allowlist/roles, upsert the app's user keyed by id.Subject,
	// create the app's session and set its cookie on w (headers only: do not write a body). `next` is the already
	// sanitised local path to return to. Return nil to finish the login, *DeniedError to refuse it with a 403 page,
	// any other error for a 500 page. Re-check the allowlist on every later request too, so removing someone takes
	// effect immediately.
	OnLogin func(w http.ResponseWriter, r *http.Request, id Identity, next string) error
}

// Handler serves the two login routes. Build it with New, mount it with Mount (or call Start and Callback yourself).
type Handler struct {
	cfg      Config
	hooks    Hooks
	provider Provider
	signer   signer
	now      func() time.Time
	log      *slog.Logger
	page     func(w http.ResponseWriter, r *http.Request, status int, title, text string)
}

// Option customises a Handler.
type Option func(*Handler)

// WithClock replaces time.Now (tests).
func WithClock(now func() time.Time) Option { return func(h *Handler) { h.now = now } }

// WithProvider replaces the real authmein provider (tests, or another OIDC provider).
func WithProvider(p Provider) Option { return func(h *Handler) { h.provider = p } }

// WithLogger replaces slog.Default(). The handler logs parameter NAMES of the MFA hand-off, never values.
func WithLogger(l *slog.Logger) Option { return func(h *Handler) { h.log = l } }

// WithPages replaces the plain error pages. Whatever you render, answer with the given status and send no-store.
func WithPages(f func(w http.ResponseWriter, r *http.Request, status int, title, text string)) Option {
	return func(h *Handler) { h.page = f }
}

// New validates the config and builds the handler.
func New(cfg Config, hooks Hooks, opts ...Option) (*Handler, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if hooks.OnLogin == nil {
		return nil, errors.New("authmeinclient: Hooks.OnLogin is required")
	}
	h := &Handler{cfg: cfg, hooks: hooks, provider: NewOIDC(cfg), signer: signer{key: []byte(cfg.SessionSecret)},
		now: time.Now, log: slog.Default(), page: defaultPage}
	for _, o := range opts {
		o(h)
	}
	return h, nil
}

// Mount registers GET <prefix>/start and GET <prefix>/callback. RedirectURL's path must be <prefix>/callback.
func (h *Handler) Mount(mux *http.ServeMux, prefix string) {
	prefix = strings.TrimRight(prefix, "/")
	mux.HandleFunc("GET "+prefix+"/start", h.Start)
	mux.HandleFunc("GET "+prefix+"/callback", h.Callback)
}

// Start begins a login: /start?next=/local/path.
func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	h.begin(w, r, flowState{Next: SafeNext(r.URL.Query().Get("next"), h.cfg.DefaultNext)})
}

func (h *Handler) setFlowCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: h.cfg.FlowCookieName, Value: value, Path: h.cfg.flowCookiePath(), MaxAge: maxAge,
		HttpOnly: true, Secure: h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode, // Lax: the callback is a top-level GET coming back from another site
	})
}

// begin (re)starts a login with a fresh state, nonce and PKCE verifier; only Next and Retried survive from `from`.
func (h *Handler) begin(w http.ResponseWriter, r *http.Request, from flowState) {
	flow := flowState{
		State: randomToken(16), Nonce: randomToken(16), Verifier: randomToken(32),
		Next: from.Next, Retried: from.Retried, Exp: h.now().Add(flowTTL).Unix(),
	}
	authURL, err := h.provider.AuthURL(r.Context(), flow.State, flow.Nonce, flow.Verifier)
	if err != nil {
		h.log.Error("authmein: provider unavailable", "err", err)
		h.page(w, r, http.StatusBadGateway, "Login tidak dapat dihubungi", "Layanan login authmein tidak dapat dihubungi. Coba lagi sebentar lagi.")
		return
	}
	if u, err := url.Parse(authURL); err == nil {
		flow.Query = u.RawQuery
	}
	h.setFlowCookie(w, h.signer.Seal(h.cfg.FlowCookieName, flow), int(flowTTL.Seconds()))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback finishes a login. Order matters: flow cookie first, then the MFA gate answer, then state, then code.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bad := func(status int, title, text string) {
		h.setFlowCookie(w, "", -1)
		h.page(w, r, status, title, text)
	}

	// The flow cookie proves this browser started the login; it is single-use.
	var flow flowState
	c, err := r.Cookie(h.cfg.FlowCookieName)
	if err != nil || h.signer.Open(h.cfg.FlowCookieName, c.Value, &flow) != nil || h.now().Unix() > flow.Exp {
		bad(http.StatusBadRequest, "Login kedaluwarsa", "Sesi login tidak valid atau sudah kedaluwarsa. Mulai lagi dari halaman login.")
		return
	}
	stateOK := subtle.ConstantTimeCompare([]byte(flow.State), []byte(q.Get("state"))) == 1

	// The MFA gate answer (Authorizer 2.4.4) is a bare redirect: it does NOT carry the state we sent, so it is judged
	// BEFORE the state check. It is safe to follow without one: it asks for nothing but a detour to authmein's own hosted
	// page, the flow cookie still proves this browser started the login, and the hand-off happens once per login
	// (flow.MFA). A state that IS present must still match. Every path that can end in a session (code, error) needs it.
	if q.Get("mfa_required") == "1" && q.Get("code") == "" && q.Get("error") == "" && (stateOK || q.Get("state") == "") {
		h.mfaHandOff(w, r, flow)
		return
	}
	if !stateOK {
		bad(http.StatusBadRequest, "Login tidak valid", "Permintaan login tidak cocok dengan yang dimulai dari browser ini. Mulai lagi.")
		return
	}
	h.setFlowCookie(w, "", -1) // single use from here on
	if q.Get("error") != "" {
		bad(http.StatusForbidden, "Login dibatalkan", "Login dibatalkan atau ditolak oleh authmein.")
		return
	}
	code := q.Get("code")
	if code == "" {
		bad(http.StatusBadRequest, "Login tidak valid", "Kode login tidak ditemukan. Mulai lagi.")
		return
	}

	id, err := h.provider.Exchange(r.Context(), code, flow.Verifier, flow.Nonce)
	if errors.Is(err, ErrCodeRejected) && !flow.Retried {
		// authmein voids a code as soon as a newer authorize happened in the same browser session: the code is dead, so
		// start over ONCE with fresh values instead of retrying it.
		h.log.Warn("authmein: authorization code rejected (401); restarting the login once")
		flow.Retried = true
		h.begin(w, r, flow)
		return
	}
	if err != nil {
		h.log.Error("authmein: login exchange failed", "err", err)
		bad(http.StatusBadRequest, "Login gagal", "Login tidak dapat diverifikasi. Coba lagi.")
		return
	}
	if !id.EmailVerified || id.Email == "" || id.Subject == "" {
		bad(http.StatusForbidden, "Email belum terverifikasi", "Akun authmein ini belum punya email yang terverifikasi. Verifikasi emailnya di auth.me.in/account, lalu coba lagi.")
		return
	}

	var denied *DeniedError
	switch err = h.hooks.OnLogin(w, r, id, flow.Next); {
	case err == nil:
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, flow.Next, http.StatusFound)
	case errors.As(err, &denied):
		bad(http.StatusForbidden, denied.Title, denied.Text)
	default:
		h.log.Error("authmein: OnLogin failed", "err", err)
		bad(http.StatusInternalServerError, "Terjadi kesalahan", "Login tidak dapat diselesaikan. Coba lagi.")
	}
}

// mfaHandOff: authmein withholds the code when the account must still set up, skip or verify a second factor, and returns
// to us with ?mfa_required=1&mfa_methods=...&mfa_gate=... instead (not a failure). Its hosted login page at /app/ knows how
// to finish that step, so the browser goes back there with the page URL authmein itself gave for this login (the 302 of
// /authorize: /app?...&code=<id>, which binds the PKCE challenge) plus those three parameters, and comes back to the
// callback with a code. We fetch that URL by repeating the same authorize request from the server: it is stateless on
// authmein's side (no cookie), the same call the browser made. Done at most once per login.
func (h *Handler) mfaHandOff(w http.ResponseWriter, r *http.Request, flow flowState) {
	fail := func() {
		h.setFlowCookie(w, "", -1)
		h.page(w, r, http.StatusForbidden, "Login belum selesai", "Langkah verifikasi dua langkah belum selesai di authmein. Mulai lagi dari halaman login.")
	}
	if flow.Query == "" || flow.MFA {
		fail()
		return
	}
	app, err := h.hostedLoginURL(r.Context(), flow.Query)
	if err != nil {
		h.log.Error("authmein: MFA hand-off", "err", err)
		fail()
		return
	}
	q := app.Query()
	for _, k := range []string{"mfa_required", "mfa_methods", "mfa_gate"} {
		if v := r.URL.Query().Get(k); v != "" && len(v) <= 200 {
			q.Set(k, v)
		}
	}
	app.RawQuery = q.Encode()
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names) // parameter NAMES only: the values carry the PKCE challenge, state and the authmein code id
	h.log.Info("authmein: MFA hand-off", "to", app.Path, "parameters", names)
	flow.MFA = true
	h.setFlowCookie(w, h.signer.Seal(h.cfg.FlowCookieName, flow), int(flowTTL.Seconds()))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, app.String(), http.StatusFound)
}

// hostedLoginURL repeats the authorize request (never following the redirect) and returns authmein's hosted login page
// URL from its Location header. Only a path under /app on the issuer itself is accepted.
func (h *Handler) hostedLoginURL(ctx context.Context, rawQuery string) (*url.URL, error) {
	issuer, err := url.Parse(h.cfg.Issuer)
	if err != nil || issuer.Host == "" {
		return nil, errors.New("bad issuer")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer.String()+"/authorize?"+rawQuery, nil)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authorize request: %w", err)
	}
	defer resp.Body.Close()
	loc, err := resp.Location()
	if err != nil || resp.StatusCode/100 != 3 {
		return nil, fmt.Errorf("authorize answered %d without a redirect", resp.StatusCode)
	}
	if loc.Host != issuer.Host || loc.Scheme != issuer.Scheme || !(loc.Path == "/app" || strings.HasPrefix(loc.Path, "/app/")) {
		return nil, fmt.Errorf("authorize redirected to an unexpected place (%s)", loc.Path)
	}
	return loc, nil
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // not recoverable
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}}</title></head>
<body style="font:16px system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem"><h1>{{.Title}}</h1><p>{{.Text}}</p><p><a href="/">Kembali</a></p></body></html>`))

func defaultPage(w http.ResponseWriter, _ *http.Request, status int, title, text string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = pageTmpl.Execute(w, map[string]string{"Title": title, "Text": text})
}
