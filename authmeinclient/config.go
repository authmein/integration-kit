// Package authmeinclient is a small, framework-free (net/http) server-side login client for authmein (auth.me.in,
// an Authorizer 2.4.x instance): Authorization Code + PKCE (S256) for a public "dynamic" client, with the behaviours
// of Authorizer that were found the hard way written into code and tests:
//
//   - the client has no secret, so client_id goes in the token request body (one request, no Basic probe: codes are one-time);
//   - a code rejected with 401 means a newer authorize voided it: the login restarts ONCE with fresh values;
//   - the MFA gate for social logins answers with ?mfa_required=1 and NO code and NO state: it is a detour, not a failure;
//   - the account key is `sub`, never the email, and the email must be verified;
//   - who may log in stays the app's decision (Hooks.OnLogin), never authmein's.
//
// The package does not keep sessions. When authmein vouches for an identity it calls Hooks.OnLogin, where the app
// applies its allowlist, creates its own session and sets its own cookie.
package authmeinclient

import (
	"errors"
	"net/url"
	"path"
	"strings"
)

// DefaultIssuer is the shared authmein instance.
const DefaultIssuer = "https://auth.me.in"

// Config configures one authmein client (one client_id = one app in one environment).
type Config struct {
	// Issuer defaults to DefaultIssuer. Tests and local development point it at authmeintest.
	Issuer string
	// ClientID is the id of the client registered for this app and environment (public: no secret).
	ClientID string
	// RedirectURL is the callback EXACTLY as registered at authmein (it cannot be changed there after registration),
	// e.g. https://app.example/auth/authmein/callback. Mount the handlers so that the callback is <prefix>/callback
	// and the login entry is <prefix>/start (see Handler.Mount): the flow cookie is scoped to that prefix.
	RedirectURL string
	// SessionSecret signs the short-lived flow cookie. At least 32 characters, from a secret store, never from the repo.
	SessionSecret string
	// CookieSecure must be true for https (the default for production). False only for http://localhost development.
	CookieSecure bool
	// FlowCookieName is the name of the login-flow cookie; unique per app. Default "authmein_flow".
	FlowCookieName string
	// DefaultNext is where a login with no (or an unsafe) `next` ends. Default "/".
	DefaultNext string
	// Scopes default to openid email profile.
	Scopes []string
}

func (c Config) withDefaults() Config {
	c.Issuer = strings.TrimRight(c.Issuer, "/")
	if c.Issuer == "" {
		c.Issuer = DefaultIssuer
	}
	if c.FlowCookieName == "" {
		c.FlowCookieName = "authmein_flow"
	}
	if c.DefaultNext == "" {
		c.DefaultNext = "/"
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "email", "profile"}
	}
	return c
}

func (c Config) validate() error {
	iss, err := url.Parse(c.Issuer)
	if err != nil || iss.Host == "" || (iss.Scheme != "https" && iss.Scheme != "http") {
		return errors.New("authmeinclient: Issuer must be an absolute http(s) URL")
	}
	if c.ClientID == "" {
		return errors.New("authmeinclient: ClientID is required")
	}
	cb, err := url.Parse(c.RedirectURL)
	if err != nil || cb.Host == "" || (cb.Scheme != "https" && cb.Scheme != "http") || !strings.HasSuffix(cb.Path, "/callback") {
		return errors.New("authmeinclient: RedirectURL must be an absolute http(s) URL whose path ends in /callback")
	}
	if len(c.SessionSecret) < 32 {
		return errors.New("authmeinclient: SessionSecret must be at least 32 characters")
	}
	if !strings.HasPrefix(c.DefaultNext, "/") {
		return errors.New("authmeinclient: DefaultNext must be a local path")
	}
	return nil
}

// flowCookiePath is the directory of the callback path, so the cookie is sent to <prefix>/start and <prefix>/callback only.
func (c Config) flowCookiePath() string {
	u, err := url.Parse(c.RedirectURL)
	if err != nil {
		return "/"
	}
	p := path.Dir(u.Path)
	if p == "." || p == "" {
		return "/"
	}
	return p
}

// SafeNext only lets a login return to a path on this site. Absolute URLs, protocol-relative "//host", backslash and
// control-character tricks fall back to `fallback`.
func SafeNext(next, fallback string) string {
	if next == "" || next[0] != '/' || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n\t") {
		return fallback
	}
	return next
}
