package authmeinclient

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// flowState rides in a signed cookie between "send the browser to authmein" and the callback. Nothing here is secret
// from the browser's owner, but all of it is tamper-proof and bound to the cookie name.
type flowState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"` // PKCE code verifier
	Next     string `json:"x"` // local path to return to after login
	Exp      int64  `json:"e"`
	Query    string `json:"q"`           // the authorize query we sent, repeated for authmein's hosted MFA step
	MFA      bool   `json:"m,omitempty"` // the MFA hand-off was already done once (never loop)
	Retried  bool   `json:"r,omitempty"` // the login was already restarted once after a rejected code (never loop)
}

// signer seals small values into tamper-proof cookie text: base64url(json) + "." + base64url(HMAC). The HMAC covers the
// cookie name too, so a value sealed for one cookie is useless in another.
type signer struct{ key []byte }

var errBadCookie = errors.New("authmeinclient: invalid signed cookie")

func (s signer) mac(name, payload string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(name))
	m.Write([]byte{0})
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s signer) Seal(name string, v any) string {
	raw, _ := json.Marshal(v)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return payload + "." + s.mac(name, payload)
}

func (s signer) Open(name, value string, v any) error {
	payload, sig, ok := strings.Cut(value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(s.mac(name, payload))) {
		return errBadCookie
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || json.Unmarshal(raw, v) != nil {
		return errBadCookie
	}
	return nil
}
