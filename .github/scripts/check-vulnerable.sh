#!/usr/bin/env bash
# Fails when any package, direct or transitive, on any target framework, has a published advisory.
# The Udap.* packages pass their dependencies on to every consumer.
#
# usage: check-vulnerable.sh   (run from the repository root after dotnet restore)
set -euo pipefail

report=$(mktemp)
dotnet list Udap.sln package --vulnerable --include-transitive | tee "$report"
if grep -q "has the following vulnerable packages" "$report"; then
  echo "::error::Vulnerable packages found; update or pin them first."
  exit 1
fi
