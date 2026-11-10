#!/usr/bin/env bash
# Start each browser before any test does, twice, and print how long each start took.
#
# On a fresh runner the first start of a browser reads it from a cold disk. In green runs
# the first round with Chromium or Firefox took 10 to 40 s longer than every later round
# (runs 42707385995, 42722292137, 42831799186). Once the first Chromium stalled long
# enough that its own watchdog ended a child process ("Terminating current process after
# 15 seconds with no connection", then "Network service crashed"), and the page it was
# given never loaded (run 42840141395, lanes; soak 42831799186, postgres copy 3, was
# also that job's first Chromium). A test should never be the one that pays for that.
#
# The second start of each is the control: the gap between the two lines is the cost
# moved out of the tests. A warning, never a failure: a browser that cannot start fails
# the tests anyway, with their own diagnostics.
#
# Usage: tools/ci-warm-browsers.sh   (CHROME and FIREFOX as for test-web.sh)
set -u

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

warm() { # label, command...
  local label=$1
  shift
  local t0=$SECONDS
  if timeout 180 "$@" > "$work/$label.log" 2>&1; then
    echo "$label: $((SECONDS - t0)) s"
  else
    local rc=$?
    echo "::warning title=browser warm-up::$label did not finish in $((SECONDS - t0)) s (exit $rc)"
    tail -20 "$work/$label.log"
  fi
}

chrome="${CHROME:-$(command -v google-chrome || command -v chromium || true)}"
if [ -n "$chrome" ]; then
  for start in first second; do
    warm "chromium, $start start" "$chrome" --headless=new --no-sandbox --disable-gpu \
      --user-data-dir="$work/chrome-$start" --dump-dom about:blank
  done
fi

firefox="${FIREFOX:-$(command -v firefox || true)}"
if [ -n "$firefox" ]; then
  for start in first second; do
    mkdir -p "$work/firefox-$start"
    warm "firefox, $start start" "$firefox" -headless -no-remote -profile "$work/firefox-$start" \
      --screenshot "$work/firefox-$start.png" about:blank
  done
fi
