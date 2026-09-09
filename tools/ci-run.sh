#!/usr/bin/env bash
# Run a build or test command and, if it fails, repeat the tail of its output
# as a GitHub Actions error annotation.
#
# Reading a run's *logs* through the API needs admin rights on the repository,
# even for a public one, and artifact downloads need a token too — so a red job
# is a black box to anyone without push access, including whoever is trying to
# fix it. A run's *annotations* need nothing:
#   /repos/:owner/:repo/check-runs/:id/annotations
# test-web.sh already does this for its browser lanes; this is the same trick
# for every step that builds something.
#
# Usage:  tools/ci-run.sh "<annotation title>" <command> [args...]
set -u
set -o pipefail

title="$1"
shift

log=$(mktemp)
trap 'rm -f "$log"' EXIT

"$@" 2>&1 | tee "$log"
status=$?

if [ "$status" -ne 0 ] && [ -n "${GITHUB_ACTIONS:-}" ]; then
  # Same escaping as test-web.sh: a workflow command is one line, so every
  # newline becomes %0A and a literal % has to be escaped first.
  printf '::error title=%s::%s\n' "$title" \
    "$(tail -40 "$log" | head -c 3000 |
       awk '{ gsub(/%/, "%25"); gsub(/\r/, "%0D"); printf "%s%%0A", $0 }')"
fi

exit "$status"
