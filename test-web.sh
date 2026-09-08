#!/usr/bin/env bash
# End-to-end smoke test of the web client: starts a server with the embedded web
# client on test ports, runs two headless browsers (fake microphone) through the
# in-page self-test (?selftest=1), and checks that they see each other, exchange
# the media key, hear voice, and read each other's E2E chat.
#
# BROWSER=chromium (default) or BROWSER=firefox picks the engine. BROWSER_ALICE
# and BROWSER_BOB override it per side, which is how the mixed lane runs a
# Chromium sharer (H.264) against a Firefox viewer and the other way round.
#
# Prerequisites: npm run web (or npm run build:web + cargo build -p voipc-server --release),
# openssl, curl with HTTP/2, and either chromium (CHROME=/path/to/chrome) or,
# for the Firefox lane, firefox (FIREFOX=...) plus certutil to trust the test
# certificate (Arch: nss, Debian/Ubuntu: libnss3-tools).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

BROWSER="${BROWSER:-chromium}"
BROWSER_ALICE="${BROWSER_ALICE:-$BROWSER}"
BROWSER_BOB="${BROWSER_BOB:-$BROWSER}"
for b in "$BROWSER_ALICE" "$BROWSER_BOB"; do
  case "$b" in
    chromium)
      CHROME="${CHROME:-$(command -v chromium || command -v chromium-browser || command -v google-chrome || true)}"
      [ -n "$CHROME" ] || { echo "no chromium found (set CHROME=...)" >&2; exit 1; }
      ;;
    firefox)
      FIREFOX="${FIREFOX:-$(command -v firefox || true)}"
      [ -n "$FIREFOX" ] || { echo "no firefox found (set FIREFOX=...)" >&2; exit 1; }
      command -v certutil >/dev/null || { echo "certutil missing (Arch: nss, Debian: libnss3-tools)" >&2; exit 1; }
      ;;
    *) echo "unknown browser '$b' (chromium or firefox)" >&2; exit 1 ;;
  esac
done
echo "browsers: alice=$BROWSER_ALICE bob=$BROWSER_BOB"
SERVER="${SERVER:-target/release/voipc-server}"
[ -x "$SERVER" ] || { echo "$SERVER missing — run npm run web first" >&2; exit 1; }

TCP_PORT="${TCP_PORT:-19987}"
DURATION="${DURATION:-15000}"
WORK="$(mktemp -d)"
# `wait` before rm: Chromium is still writing its profile when SIGTERM lands,
# and under `set -e` a failing rm inside the trap would turn a green run red.
trap 'kill $(jobs -p) 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$WORK" 2>/dev/null || true' EXIT

# A throwaway CA signs the page certificate. Chromium would take a self-signed
# one (it is started with --ignore-certificate-errors), but Firefox only trusts
# an imported *CA*: NSS ignores the "trusted peer" flag for server certificates,
# so a self-signed page cert ends at the interstitial and the test never runs.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$WORK/ca.key" -out "$WORK/ca.crt" -days 2 -nodes \
  -subj "/CN=voipc-test-ca" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$WORK/server.key" -out "$WORK/server.csr" -nodes \
  -subj "/CN=voipc-test" 2>/dev/null
openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
  -CAcreateserial -out "$WORK/leaf.crt" -days 2 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n") 2>/dev/null
cat "$WORK/leaf.crt" "$WORK/ca.crt" > "$WORK/server.crt"

# exec: the job pid must be the server itself, or the EXIT trap kills only the
# subshell and the server survives on the test ports
(cd "$WORK" && exec "$SCRIPT_DIR/$SERVER" --host 127.0.0.1 --tcp-port "$TCP_PORT" --udp-port "$TCP_PORT" \
  --cert server.crt --key server.key --admin-token e2e-admin > "$WORK/server.log" 2>&1) &

for _ in $(seq 1 50); do
  curl -sk --http2-prior-knowledge "https://127.0.0.1:$TCP_PORT/wt.json" > "$WORK/wt.json" 2>/dev/null && break
  sleep 0.2
done
grep -q '"hash"' "$WORK/wt.json" || { echo "server did not come up:"; cat "$WORK/server.log"; exit 1; }
echo "server up: $(cat "$WORK/wt.json")"

run_browser() { # name role extra-params logfile browser
  local url="https://127.0.0.1:$TCP_PORT/?selftest=1&name=$1&role=$2&duration=$DURATION$3"
  local engine="${5:-$BROWSER}"
  if [ "$engine" = firefox ]; then
    # Firefox has no --ignore-certificate-errors: the test CA goes into the
    # profile's own NSS database. console.log goes to stdout here (Chromium
    # logs it to stderr), so both streams land in the log file.
    local profile="$WORK/profile-$1"
    mkdir -p "$profile"
    cat > "$profile/user.js" <<EOF
user_pref("media.navigator.streams.fake", true);
user_pref("media.navigator.permission.disabled", true);
user_pref("media.autoplay.default", 0);
user_pref("media.autoplay.blocking_policy", 0);
user_pref("devtools.console.stdout.content", true);
EOF
    certutil -A -n voipc-test-ca -t "C,," -i "$WORK/ca.crt" -d "sql:$profile"
    "$FIREFOX" -headless -no-remote -profile "$profile" "$url" > "$4" 2>&1 &
  else
    "$CHROME" --headless=new --no-sandbox --disable-gpu --ignore-certificate-errors \
      --use-fake-ui-for-media-stream --use-fake-device-for-media-stream \
      --autoplay-policy=no-user-gesture-required --enable-logging=stderr --v=0 \
      --user-data-dir="$WORK/profile-$1" \
      "$url" > /dev/null 2> "$4" &
  fi
}

# alice creates the channel, becomes admin at the end and kicks bob; bob joins
# through an invite-link fragment (#channel=…) and expects the kick
# alice also shares her (synthetic) screen; bob watches it
run_browser alice talker "&channel=e2e&dm=bob&admin=e2e-admin&kick=bob&share=1" \
  "$WORK/alice.log" "$BROWSER_ALICE"
sleep 1
run_browser bob listener "&dm=alice&expect_kick=1&watch=1#channel=e2e" \
  "$WORK/bob.log" "$BROWSER_BOB"

deadline=$(( $(date +%s) + DURATION / 1000 + 30 ))
until grep -q "SELFTEST done" "$WORK/alice.log" && grep -q "SELFTEST done" "$WORK/bob.log"; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "timeout waiting for the self-tests"; break; }
  sleep 1
done

# Both engines log the same lines but quote them differently (Firefox escapes
# the JSON), so normalise once and run every check against that.
extract() { grep -ao 'SELFTEST .*' "$1" | sed 's/", source:.*$//; s/\\"/"/g' > "$2" || true; }
extract "$WORK/alice.log" "$WORK/alice.txt"
extract "$WORK/bob.log" "$WORK/bob.txt"
echo "--- alice"; cat "$WORK/alice.txt"
echo "--- bob";   cat "$WORK/bob.txt"

fail=0
check() { # description file pattern
  if grep -q "$3" "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi
}
check "alice connected"                 "$WORK/alice.txt" 'SELFTEST connected'
check "bob connected"                   "$WORK/bob.txt"   'SELFTEST connected'
check "alice got a media key"           "$WORK/alice.txt" 'media-key-installed'
check "bob got a media key"             "$WORK/bob.txt"   'media-key-installed'
check "bob saw alice speaking"          "$WORK/bob.txt"   'user-speaking.*speaking.*true'
check "bob saw alice stop speaking"     "$WORK/bob.txt"   'user-speaking.*speaking.*false'
check "bob played voice frames"         "$WORK/bob.txt"   'voice-stats.*played.*:[1-9]'
check "bob read alice's channel message" "$WORK/bob.txt"  'channel-chat-message.*hello from alice'
check "alice read bob's channel message" "$WORK/alice.txt" 'channel-chat-message.*hello from bob'
check "bob read alice's DM"             "$WORK/bob.txt"   'direct-chat-message.*dm from alice'
check "alice read bob's DM"             "$WORK/alice.txt" 'direct-chat-message.*dm from bob'
check "bob joined via the invite link"  "$WORK/bob.txt"   'channel-requested.*"source":"invite"'
check "bob received channel history"    "$WORK/bob.txt"   'channel-history-received.*early from alice'
check "alice became admin"              "$WORK/alice.txt" 'admin-status.*"is_admin":true'
check "bob was kicked by the admin"     "$WORK/bob.txt"   'server-disconnected.*kicked from this server'
check "alice shared her screen"         "$WORK/alice.txt" 'share-started'
check "alice sent video frames"         "$WORK/alice.txt" 'screenshare-stats.*"frames_sent":[1-9]'
check "bob watched the share"           "$WORK/bob.txt"   'watching-screenshare'
check "bob decoded video frames"        "$WORK/bob.txt"   'screenshare-stats.*"frames_recv":[1-9]'
check "bob drew a frame on the canvas"  "$WORK/bob.txt"   'screenshare-stats.*"frames_drawn":[1-9]'
if grep -q 'screenshare-error' "$WORK/alice.txt" "$WORK/bob.txt"; then
  echo "FAIL screen share error reported:"; grep -h 'screenshare-error' "$WORK/alice.txt" "$WORK/bob.txt"; fail=1
fi
# bob's connection loss is the kick; alice must stay connected until she leaves
if grep -q 'SELFTEST error' "$WORK/alice.txt" "$WORK/bob.txt" || grep -q 'connection-lost' "$WORK/alice.txt"; then
  echo "FAIL errors/connection loss reported:"; grep -h 'connection-lost\|SELFTEST error' "$WORK/alice.txt" "$WORK/bob.txt"; fail=1
fi

echo "--- server log tail"; tail -20 "$WORK/server.log"
exit $fail
