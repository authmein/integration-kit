// Command fakeauthmein runs the fake authmein (package authmeintest) for trying an app's login by hand, with no real
// client registered. Point the app at it:
//
//	go run ./cmd/fakeauthmein -addr 127.0.0.1:9099 -client-id dev-client
//
//	AUTHMEIN_ISSUER=http://127.0.0.1:9099 AUTHMEIN_CLIENT_ID=dev-client \
//	PUBLIC_BASE_URL=http://localhost:8080 SESSION_SECRET=<32+ chars> COOKIE_SECURE=false
//
// It approves whatever email you type (consent, passwords and MFA are not imitated). It is a development tool: it
// refuses to listen anywhere but loopback.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"

	"github.com/authmein/integration-kit/authmeintest"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9099", "listen address (loopback only)")
	issuer := flag.String("issuer", "", "public issuer URL (default http://<addr>)")
	clientID := flag.String("client-id", "dev-client", "OAuth client id")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("bad -addr %q: %v", *addr, err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		log.Fatalf("fakeauthmein must listen on loopback only, got %q", *addr)
	}
	srv := authmeintest.New(*clientID)
	srv.URL = *issuer
	if srv.URL == "" {
		srv.URL = "http://" + *addr
	}
	log.Printf("fakeauthmein: issuer %s, client %s", srv.URL, *clientID)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}
