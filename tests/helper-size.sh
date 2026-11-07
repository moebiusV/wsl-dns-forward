#!/bin/sh
# SPDX-License-Identifier: ISC
# The daemon sends mdns-helper.ps1 to powershell.exe on the command line: stripped of comments, blank lines and
# indentation, as UTF-16, in base64.  Windows limits a command line to 32767 characters, so the stripped script
# must stay under 11000 characters (about 29000 encoded) and must be plain ASCII.
here=$(cd "$(dirname "$0")" && pwd)
S=${HELPER_SCRIPT:-$here/../mdns-helper.ps1}
LIMIT=11000
[ -f "$S" ] || { echo "FAIL: $S not found"; exit 1; }
chars=$(awk '{ sub(/\r$/, ""); gsub(/^[ \t]+|[ \t]+$/, ""); if ($0 != "" && substr($0, 1, 1) != "#") n += length($0) + 1 } END { print n + 0 }' "$S")
enc=$(( (chars * 2 + 2) / 3 * 4 ))
if LC_ALL=C grep -q '[^[:print:][:space:]]' "$S"; then echo "FAIL: $S is not plain ASCII"; exit 1; fi
if [ "$chars" -gt "$LIMIT" ]; then
    echo "FAIL: helper script is $chars characters after stripping; the limit is $LIMIT ($enc encoded, Windows allows 32767)"
    exit 1
fi
echo "helper script: $chars characters after stripping, $enc encoded; limit $LIMIT characters"
