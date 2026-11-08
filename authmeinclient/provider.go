package authmeinclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Identity is what authmein vouches for after a successful login.
type Identity struct {
	Subject       string // stable account id at authmein: THE key for the app's own account record
	Email         string // can change at authmein; never a key
	EmailVerified bool
	Name          string // only a label; may be empty (authmein sends nothing for a profile that was never filled in)
}

// ErrCodeRejected is returned by Provider.Exchange when the token endpoint answers 401. Authorizer voids a code as soon
// as a newer authorize happened in the same browser session at authmein (a second tab, a double click).
var ErrCodeRejected = errors.New("authorization code rejected")

// Provider is the part of the login that talks to authmein. NewOIDC is the real one; tests may supply another.
type Provider interface {
	// AuthURL is where the browser is sent. state, nonce and the PKCE verifier come from the caller and return to Exchange.
	AuthURL(ctx context.Context, state, nonce, verifier string) (string, error)
	// Exchange trades the code for a verified identity: signature (JWKS), issuer, audience, expiry and nonce.
	// A 401 from the token endpoint must satisfy errors.Is(err, ErrCodeRejected).
	Exchange(ctx context.Context, code, verifier, nonce string) (Identity, error)
}

// OIDC is the real Provider: authorization-code flow with PKCE for a public client. Discovery is lazy: the app starts
// even when authmein cannot be reached, and the first login attempt retries instead of failing forever.
type OIDC struct {
	cfg   Config
	httpc *http.Client

	mu    sync.Mutex
	ready *oidcState
}

type oidcState struct {
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewOIDC builds the provider for a validated Config (use New for the whole handler).
func NewOIDC(cfg Config) *OIDC {
	return &OIDC{cfg: cfg.withDefaults(), httpc: &http.Client{Timeout: 10 * time.Second}}
}

func (o *OIDC) init() (*oidcState, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ready != nil {
		return o.ready, nil
	}
	// go-oidc keeps this context for later key fetches, so it must outlive the request.
	ctx := oidc.ClientContext(context.Background(), o.httpc)
	prov, err := oidc.NewProvider(ctx, o.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", o.cfg.Issuer, err)
	}
	ep := prov.Endpoint()
	// A public client has no secret for a Basic header. Without this the library probes: it tries the header first and, on
	// a 401, sends the same code again with client_id in the body. authmein codes are one-time, so send it exactly once.
	ep.AuthStyle = oauth2.AuthStyleInParams
	o.ready = &oidcState{
		oauth: &oauth2.Config{
			ClientID:    o.cfg.ClientID,
			Endpoint:    ep,
			RedirectURL: o.cfg.RedirectURL,
			Scopes:      o.cfg.Scopes,
		},
		// The verifier checks signature, issuer, audience (== ClientID) and expiry.
		verifier: prov.Verifier(&oidc.Config{ClientID: o.cfg.ClientID}),
	}
	return o.ready, nil
}

func (o *OIDC) AuthURL(_ context.Context, state, nonce, verifier string) (string, error) {
	st, err := o.init()
	if err != nil {
		return "", err
	}
	return st.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

func (o *OIDC) Exchange(ctx context.Context, code, verifier, nonce string) (Identity, error) {
	st, err := o.init()
	if err != nil {
		return Identity{}, err
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, o.httpc)
	tok, err := st.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.Response != nil && re.Response.StatusCode == http.StatusUnauthorized {
			return Identity{}, fmt.Errorf("%w: %v", ErrCodeRejected, err)
		}
		return Identity{}, fmt.Errorf("code exchange: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return Identity{}, errors.New("no id_token in the token response")
	}
	idt, err := st.verifier.Verify(oidc.ClientContext(ctx, o.httpc), raw)
	if err != nil {
		return Identity{}, fmt.Errorf("id_token: %w", err)
	}
	if idt.Nonce != nonce {
		return Identity{}, errors.New("id_token nonce does not match this login attempt")
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
	}
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("id_token claims: %w", err)
	}
	// authmein sends given_name/family_name (and nothing at all for accounts that never filled a profile); other providers
	// send name. The name is only a label: callers must cope with it being empty.
	name := strings.TrimSpace(claims.Name)
	if name == "" {
		name = strings.TrimSpace(claims.GivenName + " " + claims.FamilyName)
	}
	return Identity{Subject: idt.Subject, Email: claims.Email, EmailVerified: claims.EmailVerified, Name: name}, nil
}
