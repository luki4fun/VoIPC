#!/usr/bin/env bash
# apt on a runner, with a limit. The runner's first mirror can crawl (11 MB in 108 s on one
# runner while the others were fine), and a step that takes 3 minutes then outlasts the job's
# own 40, with no test run. Trying it again does not help, so a retry goes to the next mirror.
#
# Usage:  tools/ci-apt.sh <package>...
set -u

net=(-o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30)
for try in 1 2 3; do
  # A cut attempt can leave dpkg half way
  sudo dpkg --configure -a
  # Not -qq: when the limit cuts an update, its Get/Hit/Err lines are all that says which
  # source hung. On 2026-11-11 every runner's update hung for 20 minutes and the log could
  # not tell whose fault it was
  if sudo timeout -k 20 120 apt-get update -q "${net[@]}" &&
    sudo timeout -k 20 360 apt-get install -y --no-install-recommends "${net[@]}" "$@"; then
    exit 0
  fi
  echo "::warning::apt: attempt $try of 3 did not finish"
  echo "the sources this runner had:"
  grep -rhoE '(https?|mirror\+file):[^ ]+' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null | sort -u
  cat /etc/apt/apt-mirrors.txt 2>/dev/null
  # What was fetched stays in apt's cache, and the rest comes from the next on the list
  sudo sed -i '/azure\.archive\.ubuntu\.com/d' /etc/apt/apt-mirrors.txt
  sleep 20
done
echo "::error::apt did not finish in 3 attempts"
exit 1
