#!/usr/bin/env bash
# Smoke test for an app that logs in with authmein. Safe against production: no password, no login, no write. It reads
# the first redirect to authmein and goes no further.
#
#   scripts/smoke.sh https://app.example
#   scripts/smoke.sh http://localhost:8080
#
# Settings (environment): START_PATH (default /auth/authmein/start), CALLBACK_PATH (default /auth/authmein/callback),
# PROTECTED_PATH (a page that needs a session, default /dashboard; set to "" to skip), FLOW_COOKIE (default authmein_flow).
# Exit status is the number of failed checks.
set -u
BASE="${1:?usage: smoke.sh <base url>}"
BASE="${BASE%/}"
START_PATH="${START_PATH:-/auth/authmein/start}"
CALLBACK_PATH="${CALLBACK_PATH:-/auth/authmein/callback}"
PROTECTED_PATH="${PROTECTED_PATH-/dashboard}"
FLOW_COOKIE="${FLOW_COOKIE:-authmein_flow}"
FAIL=0
ok()    { echo "  ok    $1"; }
bad()   { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got: $2, want: $3)"; fi; }
has()   { if printf '%s' "$2" | grep -qi -e "$3"; then ok "$1"; else bad "$1 (missing: $3)"; fi; }
hasnt() { if printf '%s' "$2" | grep -qi -e "$3"; then bad "$1 (found: $3)"; else ok "$1"; fi; }
code()  { curl -s -o /dev/null -m 15 -w '%{http_code}' "$@"; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

echo "smoke test against $BASE"

echo "- login goes to authmein (the redirect is read, never followed)"
START=$(curl -s -m 15 -D - -o /dev/null "$BASE$START_PATH?next=/")
has "start answers a redirect to the authorize endpoint" "$START" '^location: https\?://[^ ]*/authorize?'
has "response_type=code (no implicit flow)" "$START" 'response_type=code'
has "PKCE with S256" "$START" 'code_challenge_method=S256'
has "a code_challenge is sent" "$START" 'code_challenge=[A-Za-z0-9_-]\{43\}'
has "state is sent" "$START" '[?&]state=[A-Za-z0-9_-]\{8,\}'
has "nonce is sent" "$START" '[?&]nonce=[A-Za-z0-9_-]\{8,\}'
has "redirect_uri is on this host" "$START" "redirect_uri=$(printf '%s' "$BASE$CALLBACK_PATH" | sed 's|:|%3A|g; s|/|%2F|g')"
has "the flow cookie is HttpOnly" "$START" "set-cookie: [^ ]*$FLOW_COOKIE=.*HttpOnly"
has "the flow cookie is SameSite=Lax" "$START" "set-cookie: [^ ]*$FLOW_COOKIE=.*SameSite=Lax"
has "the redirect is not cached" "$START" 'cache-control: .*no-store'
hasnt "no client secret or token in the redirect" "$START" 'client_secret\|access_token\|id_token'
case "$BASE" in
  https://*) has "the flow cookie is Secure on https" "$START" "set-cookie: [^ ]*$FLOW_COOKIE=.*Secure" ;;
esac

echo "- the callback cannot be used by someone who did not start a login"
check "a callback without our flow cookie is refused" "$(code "$BASE$CALLBACK_PATH?code=x&state=y")" 400
check "a stateless MFA-gate answer without our flow cookie is refused" "$(code "$BASE$CALLBACK_PATH?mfa_required=1&mfa_methods=totp&mfa_gate=offer")" 400

echo "- an off-site next does not break the start (where the login ends is proved by the unit tests)"
EVIL=$(curl -s -m 15 -D - -o /dev/null "$BASE$START_PATH?next=https://evil.example/")
has "start still redirects to the authorize endpoint" "$EVIL" '^location: https\?://[^ ]*/authorize?'

if [ -n "$PROTECTED_PATH" ]; then
  echo "- protected pages are closed"
  S=$(code -H 'Accept: text/html' "$BASE$PROTECTED_PATH")
  case "$S" in 302|303|401|403) ok "GET $PROTECTED_PATH without a session is not served ($S)" ;; *) bad "GET $PROTECTED_PATH without a session answered $S" ;; esac
fi

case "$BASE" in
  https://*)
    HOST=${BASE#https://}
    echo "- transport"
    check "http redirects to https" "$(code "http://$HOST/")" 301
    ;;
esac

echo
if [ "$FAIL" -eq 0 ]; then echo "all checks passed"; else echo "$FAIL check(s) failed"; fi
exit "$FAIL"
