// Command minimal is the smallest complete app on top of authmeinclient: a public page, a protected page, login with
// authmein, an allowlist, an in-memory session and logout. Copy the shape, not the storage: a real app keeps users and
// sessions in its database (users keyed by the authmein `sub`) and re-checks the allowlist on every request.
//
//	AUTHMEIN_CLIENT_ID=<id> PUBLIC_BASE_URL=http://localhost:8080 SESSION_SECRET=<32+ chars> \
//	ALLOWED_EMAILS=you@example.com COOKIE_SECURE=false go run ./examples/minimal
//
// With the fake provider: AUTHMEIN_ISSUER=http://127.0.0.1:9099 AUTHMEIN_CLIENT_ID=dev-client (see cmd/fakeauthmein).
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/authmein/integration-kit/authmeinclient"
)

const sessionCookie = "app_session"

type session struct{ Subject, Email string }

type app struct {
	allowed  map[string]bool
	mu       sync.Mutex
	sessions map[string]session // token -> session; a real app uses its database
	secure   bool
}

func main() {
	base := strings.TrimRight(os.Getenv("PUBLIC_BASE_URL"), "/")
	a := &app{allowed: map[string]bool{}, sessions: map[string]session{}, secure: os.Getenv("COOKIE_SECURE") != "false"}
	for _, e := range strings.Split(os.Getenv("ALLOWED_EMAILS"), ",") {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			a.allowed[e] = true
		}
	}
	auth, err := authmeinclient.New(authmeinclient.Config{
		Issuer:        os.Getenv("AUTHMEIN_ISSUER"), // empty = https://auth.me.in
		ClientID:      os.Getenv("AUTHMEIN_CLIENT_ID"),
		RedirectURL:   base + "/auth/authmein/callback", // exactly as registered at authmein
		SessionSecret: os.Getenv("SESSION_SECRET"),
		CookieSecure:  a.secure,
		DefaultNext:   "/dashboard",
	}, authmeinclient.Hooks{OnLogin: a.onLogin})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	auth.Mount(mux, "/auth/authmein")
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"status":"ok"}`) })
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `<a href="/auth/authmein/start?next=/dashboard">Login dengan authmein</a>`)
	})
	mux.HandleFunc("GET /dashboard", a.require(func(w http.ResponseWriter, _ *http.Request, s session) {
		fmt.Fprintf(w, `<p>Halo %s (sub %s)</p><form method="post" action="/logout"><button>Keluar</button></form>`, s.Email, s.Subject)
	}))
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookie); err == nil {
			a.mu.Lock()
			delete(a.sessions, c.Value)
			a.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, "/", http.StatusSeeOther) // ends THIS app's session only; the authmein session stays
	})

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("minimal: listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// onLogin is the app's side of the contract: authmein proved who this is; the app decides if they may enter.
func (a *app) onLogin(w http.ResponseWriter, _ *http.Request, id authmeinclient.Identity, _ string) error {
	if !a.allowed[strings.ToLower(id.Email)] {
		return &authmeinclient.DeniedError{Title: "Akun belum diizinkan", Text: id.Email + " belum diundang. Minta admin menambahkan email ini."}
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := base64.RawURLEncoding.EncodeToString(b)
	a.mu.Lock()
	a.sessions[token] = session{Subject: id.Subject, Email: id.Email} // key by Subject, never by email
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", MaxAge: 7 * 24 * 3600,
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode})
	return nil
}

func (a *app) require(next func(http.ResponseWriter, *http.Request, session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if c, err := r.Cookie(sessionCookie); err == nil {
			token = c.Value
		}
		a.mu.Lock()
		s, ok := a.sessions[token]
		a.mu.Unlock()
		if !ok || !a.allowed[strings.ToLower(s.Email)] { // allowlist re-checked on every request
			http.Redirect(w, r, "/auth/authmein/start?next=/dashboard", http.StatusFound)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next(w, r, s)
	}
}
