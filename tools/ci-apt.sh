#!/usr/bin/env bash
# apt on a runner, with a limit. A mirror that hung once sat on this step until the job's
# own 40 minutes ran out, with no test run and nothing in the log. Well, it takes 3 minutes.
#
# Usage:  tools/ci-apt.sh <package>...
set -u

net=(-o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30)
for try in 1 2 3; do
  # A cut attempt can leave dpkg half way
  sudo dpkg --configure -a
  if sudo timeout -k 20 120 apt-get update -qq "${net[@]}" &&
    sudo timeout -k 20 360 apt-get install -y --no-install-recommends "${net[@]}" "$@"; then
    exit 0
  fi
  echo "::warning::apt: attempt $try of 3 did not finish"
  sleep 20
done
echo "::error::apt did not finish in 3 attempts"
exit 1
