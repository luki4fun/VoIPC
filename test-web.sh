#!/usr/bin/env bash
# End-to-end smoke test of the web client: starts a server with the embedded web
# client on test ports, runs two headless Chromium instances (fake microphone)
# through the in-page self-test (?selftest=1), and checks that they see each
# other, exchange the media key, hear voice, and read each other's E2E chat.
#
# Prerequisites: ./build-web.sh (or npm run build:web + cargo build -p voipc-server --release),
# chromium (or CHROME=/path/to/chrome), openssl, curl with HTTP/2.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

CHROME="${CHROME:-$(command -v chromium || command -v chromium-browser || command -v google-chrome || true)}"
[ -n "$CHROME" ] || { echo "no chromium found (set CHROME=...)" >&2; exit 1; }
SERVER="${SERVER:-target/release/voipc-server}"
[ -x "$SERVER" ] || { echo "$SERVER missing — run ./build-web.sh first" >&2; exit 1; }

TCP_PORT="${TCP_PORT:-19987}"
WEB_PORT="${WEB_PORT:-19988}"
DURATION="${DURATION:-15000}"
WORK="$(mktemp -d)"
# `wait` before rm: Chromium is still writing its profile when SIGTERM lands,
# and under `set -e` a failing rm inside the trap would turn a green run red.
trap 'kill $(jobs -p) 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$WORK" 2>/dev/null || true' EXIT

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$WORK/server.key" -out "$WORK/server.crt" -days 2 -nodes \
  -subj "/CN=voipc-test" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

# exec: the job pid must be the server itself, or the EXIT trap kills only the
# subshell and the server survives on the test ports
(cd "$WORK" && exec "$SCRIPT_DIR/$SERVER" --host 127.0.0.1 --tcp-port "$TCP_PORT" --udp-port "$TCP_PORT" \
  --web-port "$WEB_PORT" --cert server.crt --key server.key --admin-token e2e-admin > "$WORK/server.log" 2>&1) &

for _ in $(seq 1 50); do
  curl -sk --http2-prior-knowledge "https://127.0.0.1:$TCP_PORT/wt.json" > "$WORK/wt.json" 2>/dev/null && break
  sleep 0.2
done
grep -q '"hash"' "$WORK/wt.json" || { echo "server did not come up:"; cat "$WORK/server.log"; exit 1; }
echo "server up: $(cat "$WORK/wt.json")"

run_browser() { # name role extra-params logfile
  "$CHROME" --headless=new --no-sandbox --disable-gpu --ignore-certificate-errors \
    --use-fake-ui-for-media-stream --use-fake-device-for-media-stream \
    --autoplay-policy=no-user-gesture-required --enable-logging=stderr --v=0 \
    --user-data-dir="$WORK/profile-$1" \
    "https://127.0.0.1:$TCP_PORT/?selftest=1&name=$1&role=$2&duration=$DURATION$3" \
    > /dev/null 2> "$4" &
}

# alice creates the channel, becomes admin at the end and kicks bob; bob joins
# through an invite-link fragment (#channel=…) and expects the kick
run_browser alice talker "&channel=e2e&dm=bob&admin=e2e-admin&kick=bob" "$WORK/alice.log"
sleep 1
run_browser bob listener "&dm=alice&expect_kick=1#channel=e2e" "$WORK/bob.log"

deadline=$(( $(date +%s) + DURATION / 1000 + 30 ))
until grep -q "SELFTEST done" "$WORK/alice.log" && grep -q "SELFTEST done" "$WORK/bob.log"; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "timeout waiting for the self-tests"; break; }
  sleep 1
done

extract() { grep -o 'SELFTEST .*' "$1" | sed 's/", source:.*$//; s/\\"/"/g'; }
echo "--- alice"; extract "$WORK/alice.log"
echo "--- bob";   extract "$WORK/bob.log"

fail=0
check() { # description file pattern
  if grep -q "$3" "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi
}
check "alice connected"                 "$WORK/alice.log" 'SELFTEST connected'
check "bob connected"                   "$WORK/bob.log"   'SELFTEST connected'
check "alice got a media key"           "$WORK/alice.log" 'media-key-installed'
check "bob got a media key"             "$WORK/bob.log"   'media-key-installed'
check "bob saw alice speaking"          "$WORK/bob.log"   'user-speaking.*speaking.*true'
check "bob saw alice stop speaking"     "$WORK/bob.log"   'user-speaking.*speaking.*false'
check "bob played voice frames"         "$WORK/bob.log"   'voice-stats.*played.*:[1-9]'
check "bob read alice's channel message" "$WORK/bob.log"  'channel-chat-message.*hello from alice'
check "alice read bob's channel message" "$WORK/alice.log" 'channel-chat-message.*hello from bob'
check "bob read alice's DM"             "$WORK/bob.log"   'direct-chat-message.*dm from alice'
check "alice read bob's DM"             "$WORK/alice.log" 'direct-chat-message.*dm from bob'
check "bob joined via the invite link"  "$WORK/bob.log"   'channel-requested.*"source":"invite"'
check "bob received channel history"    "$WORK/bob.log"   'channel-history-received.*early from alice'
check "alice became admin"              "$WORK/alice.log" 'admin-status.*"is_admin":true'
check "bob was kicked by the admin"     "$WORK/bob.log"   'server-disconnected.*kicked from this server'
# bob's connection loss is the kick; alice must stay connected until she leaves
if grep -q 'SELFTEST error' "$WORK/alice.log" "$WORK/bob.log" || grep -q 'connection-lost' "$WORK/alice.log"; then
  echo "FAIL errors/connection loss reported:"; grep -h 'connection-lost\|SELFTEST error' "$WORK/alice.log" "$WORK/bob.log" | sed 's/", source:.*$//'; fail=1
fi

echo "--- server log tail"; tail -20 "$WORK/server.log"
exit $fail
