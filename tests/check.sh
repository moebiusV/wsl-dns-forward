#!/bin/sh
# SPDX-License-Identifier: ISC
# Integration test: the daemon on a high loopback port, a fake upstream and a fake helper, queried with dig.
# WMF_WRAP=valgrind runs the daemon under valgrind and fails on errors, leaks or leaked descriptors.
: "${WMF_BIN:=./wsl-dns-forward}" "${FAKEUP:=./fakeup}"
here=$(cd "$(dirname "$0")" && pwd)
command -v dig >/dev/null 2>&1 || { echo "SKIP: dig not installed"; exit 77; }
T=$(mktemp -d); fail=0
# Package builds often run as root.  Keep the daemons as the invoking user so they can use the temporary
# directory, instead of dropping to "nobody".
UOPT=; [ "$(id -u)" = 0 ] && UOPT="-U root"
# Pretend IPv6 is not routable (as in WSL2 NAT mode) unless a test turns it on.
export WMF_IPV6=0
PORT=$((20000 + $$ % 20000)); UP=$((PORT + 1))
cleanup() { kill $DPID $UPID 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT

"$FAKEUP" $UP & UPID=$!
if [ "$WMF_WRAP" = valgrind ]; then
    WRAP="valgrind --error-exitcode=99 --leak-check=full --track-fds=yes --log-file=$T/vg.log"
fi
WMF_HELPER="$here/fake-helper.sh" $WRAP "$WMF_BIN" $UOPT -l 127.0.0.1 -p $PORT -u 127.0.0.1:$UP \
    -c "$T/lg/last-good" -P "$T/pid" 2>"$T/log" & DPID=$!
for i in 1 2 3 4 5 6 7 8 9 10; do sleep 0.5; grep -q listening "$T/log" 2>/dev/null && break; done
grep -q listening "$T/log" || { echo "FAIL: daemon did not start"; cat "$T/log"; exit 1; }

q() { dig +time=4 +tries=1 -p $PORT @127.0.0.1 "$@"; }
status() { sed -n 's/.*status: \([A-Z]*\).*/\1/p'; }
t() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1 (got '$3', want '$2')"; fail=1; fi; }

t "A host.local"            10.1.2.3 "$(q +short host.local A)"
t "A, mixed case"           10.1.2.3 "$(q +short HoSt.LoCaL A)"
t "AAAA is NOERROR/no data" NOERROR  "$(q host.local AAAA | status)"
t "AAAA has no answer"      ""       "$(q +short host.local AAAA)"
t "unknown -> SERVFAIL"     SERVFAIL "$(q nope.local A | status)"
t "loopback answer refused" SERVFAIL "$(q loop.local A | status)"
t "bad characters refused"  REFUSED  "$(q 'bad name.local' A | status)"
t "TCP"                     10.1.2.3 "$(q +tcp +short host.local A)"
t "AAAA empty without IPv6"  ""      "$(q +short dual.local AAAA)"
t "A still answered"         10.1.2.4 "$(q +short dual.local A)"
t "relay of a normal name"  9.9.9.9  "$(q +short example.test A)"
t "relay over TCP"          9.9.9.9  "$(q +tcp +short example.test A)"
t "forged replies ignored"  9.9.9.9  "$(q +short spoof.test A)"
t "no upstream answer"      SERVFAIL "$(q +time=6 drop.test A | status)"
sleep 1
t "last-known-good saved"   "host.local 10.1.2.3" "$(grep '^host.local ' "$T/lg/last-good")"

# A slow lookup must not stall other clients: slow.local takes 2 s in the helper.
q +short slow.local A >"$T/slow.out" & SLOW=$!
sleep 0.3
s=$(date +%s%N)
a=$(q +short host.local A); b=$(q +short example.test A)
ms=$(( ($(date +%s%N) - s) / 1000000 ))
t "cached answer during slow lookup" 10.1.2.3 "$a"
t "relay during slow lookup"         9.9.9.9  "$b"
if [ "$ms" -lt 800 ]; then echo "ok   not blocked (${ms} ms)"; else echo "FAIL blocked for ${ms} ms"; fail=1; fi
wait $SLOW
t "slow lookup completes"            10.7.7.7 "$(cat "$T/slow.out")"

# Many parallel queries.
PP=; for i in 1 2 3 4 5 6 7 8 9 10 11 12; do q +short host.local A >"$T/p$i" & PP="$PP $!"; done; wait $PP
t "parallel queries" "$(yes 10.1.2.3 | head -12)" "$(cat "$T"/p? "$T"/p1? 2>/dev/null | sort | head -12)"

# IPv6 routable: AAAA records are answered, and the helper is asked for both families.
PORT6=$((PORT + 5))
WMF_IPV6=1 WMF_HELPER="$here/fake-helper.sh" "$WMF_BIN" $UOPT -l 127.0.0.1 -p $PORT6 -u 127.0.0.1:$UP \
    -c "$T/lg6/last-good" 2>"$T/log6" & D6=$!
for i in 1 2 3 4 5 6 7 8 9 10; do sleep 0.3; grep -q listening "$T/log6" 2>/dev/null && break; done
q6() { dig +time=4 +tries=1 -p $PORT6 @127.0.0.1 "$@"; }
t "AAAA both addresses"        "2001:db8::1 2001:db8::2" "$(q6 +short dual.local AAAA | tr '\n' ' ' | sed 's/ $//')"
t "A on a dual-stack host"     10.1.2.4 "$(q6 +short dual.local A)"
t "AAAA over TCP"              "2001:db8::1 2001:db8::2" "$(q6 +tcp +short dual.local AAAA | tr '\n' ' ' | sed 's/ $//')"
t "IPv6-only host, AAAA"       2001:db8::5 "$(q6 +short v6only.local AAAA)"
t "IPv6-only host, A is empty" NOERROR "$(q6 v6only.local A | status)"
t "IPv6-only host, A no data"  "" "$(q6 +short v6only.local A)"
t "IPv4-only host, AAAA empty" NOERROR "$(q6 host.local AAAA | status)"
t "IPv4-only host, AAAA no data" "" "$(q6 +short host.local AAAA)"
t "unknown, AAAA SERVFAIL"     SERVFAIL "$(q6 nope.local AAAA | status)"
sleep 1
grep -q "IPv6 is routable here" "$T/log6" && echo "ok   IPv6 mode announced" || { echo "FAIL IPv6 mode not announced"; fail=1; }
grep -q "2001:db8::1,2001:db8::2" "$T/lg6/last-good" && echo "ok   IPv6 addresses kept in the cache file" || { echo "FAIL cache file lacks IPv6"; fail=1; }
kill -TERM $D6; wait $D6
grep -q "IPv6 is not routable here" "$T/log" && echo "ok   non-IPv6 mode announced" || { echo "FAIL non-IPv6 mode not announced"; fail=1; }

# The real loader: the script is stripped, encoded and passed to "powershell.exe -EncodedCommand".  A fake
# powershell.exe decodes it for comparison and then behaves like the helper.
cat > "$T/powershell.exe" <<'PS'
#!/bin/sh
while [ $# -gt 0 ]; do
    [ "$1" = -EncodedCommand ] && printf %s "$2" | base64 -d | tr -d '\000' > "$FAKE_PS_OUT"
    shift
done
exec "$FAKE_HELPER"
PS
chmod +x "$T/powershell.exe"
awk '{ sub(/\r$/, ""); gsub(/^[ \t]+|[ \t]+$/, ""); if ($0 != "" && substr($0, 1, 1) != "#") print }' "$here/../mdns-helper.ps1" > "$T/expected.ps1"
FAKE_PS_OUT="$T/decoded.ps1" FAKE_HELPER="$here/fake-helper.sh" WMF_HELPER_SCRIPT="$here/../mdns-helper.ps1" \
    "$WMF_BIN" $UOPT -w "$T/powershell.exe" -l 127.0.0.1 -p $((PORT + 6)) -u 127.0.0.1:$UP -c "$T/lg7/last-good" 2>"$T/log7" & D7=$!
for i in 1 2 3 4 5 6 7 8 9 10; do sleep 0.3; grep -q listening "$T/log7" 2>/dev/null && break; done
t "lookup through the PowerShell loader" 10.1.2.3 "$(dig +time=6 +tries=1 +short -p $((PORT + 6)) @127.0.0.1 host.local A)"
if cmp -s "$T/expected.ps1" "$T/decoded.ps1"; then echo "ok   the script reaches PowerShell stripped and intact"; else echo "FAIL decoded script differs from the stripped original"; fail=1; fi
kill -TERM $D7; wait $D7

# Address changes: an expired name is refreshed before it is answered, and the old address is used only when
# the refresh fails.
echo 10.5.5.1 > "$T/ip"
WMF_FRESH_MS=1000 FAKE_IP_FILE="$T/ip" WMF_HELPER="$here/fake-helper.sh" "$WMF_BIN" $UOPT -l 127.0.0.1 -p $((PORT + 3)) \
    -u 127.0.0.1:$UP -c "$T/lg3/last-good" 2>"$T/log3" & D3=$!
for i in 1 2 3 4 5 6 7 8 9 10; do sleep 0.3; grep -q listening "$T/log3" 2>/dev/null && break; done
q3() { dig +time=5 +tries=1 +short -p $((PORT + 3)) @127.0.0.1 chg.local A; }
t "address, first lookup"            10.5.5.1 "$(q3)"
echo 10.5.5.2 > "$T/ip"; sleep 1.3
t "changed address after expiry"     10.5.5.2 "$(q3)"
echo - > "$T/ip"; sleep 1.3
t "old address when the refresh fails" 10.5.5.2 "$(q3)"
kill -TERM $D3; wait $D3

# Background mode: the supervisor restarts a worker that dies.
WMF_HELPER="$here/fake-helper.sh" "$WMF_BIN" $UOPT -D -l 127.0.0.1 -p $((PORT + 4)) -u 127.0.0.1:$UP \
    -c "$T/lg4/last-good" -P "$T/pid4" -L "$T/log4" ; sleep 1
SUP=$(cat "$T/pid4"); W1=$(awk -v s="$SUP" '$4 == s { print $1 }' /proc/[0-9]*/stat 2>/dev/null | head -1)
t "supervised worker is running" 10.1.2.3 "$(dig +time=4 +tries=1 +short -p $((PORT + 4)) @127.0.0.1 host.local A)"
kill -9 "$W1"; sleep 2.5
t "service restored after a worker crash" 10.1.2.3 "$(dig +time=4 +tries=1 +short -p $((PORT + 4)) @127.0.0.1 host.local A)"
grep -q "\[W16\]" "$T/log4" && echo "ok   crash was reported" || { echo "FAIL no W16 diagnostic"; fail=1; }
kill -TERM "$SUP"; sleep 1
kill -0 "$SUP" 2>/dev/null && { echo "FAIL supervisor still running"; fail=1; kill -9 "$SUP"; } || echo "ok   supervisor stopped on SIGTERM"

# A dead first upstream costs one timeout, then the one that answered is tried first.
PORT2=$((PORT + 2))
WMF_HELPER="$here/fake-helper.sh" "$WMF_BIN" $UOPT -l 127.0.0.1 -p $PORT2 -u 127.0.0.1:9 -u 127.0.0.1:$UP \
    -c "$T/lg2/last-good" 2>"$T/log2" & D2=$!
for i in 1 2 3 4 5 6 7 8 9 10; do sleep 0.3; grep -q listening "$T/log2" 2>/dev/null && break; done
s=$(date +%s%N); a=$(dig +time=5 +tries=1 +short -p $PORT2 @127.0.0.1 example.test A); first=$(( ($(date +%s%N) - s) / 1000000 ))
s=$(date +%s%N); b=$(dig +time=5 +tries=1 +short -p $PORT2 @127.0.0.1 example.test A); second=$(( ($(date +%s%N) - s) / 1000000 ))
t "falls back past a dead upstream" 9.9.9.9 "$a"
if [ "$second" -lt 500 ]; then echo "ok   working upstream remembered (${first} ms, then ${second} ms)"; else echo "FAIL not remembered (${second} ms)"; fail=1; fi
grep -q "\[W07\]" "$T/log2" && echo "ok   dead upstream was reported" || { echo "FAIL no W07 diagnostic"; fail=1; }
kill -TERM $D2; wait $D2

kill -TERM $DPID; wait $DPID; rc=$?
t "clean exit on SIGTERM" 0 $rc
if [ -n "$WRAP" ]; then
    grep -q "ERROR SUMMARY: 0 errors" "$T/vg.log" || { echo "FAIL valgrind errors"; cat "$T/vg.log"; fail=1; }
    grep -E "definitely lost: [1-9]|indirectly lost: [1-9]" "$T/vg.log" && { echo "FAIL valgrind leak"; fail=1; }
    grep -B1 -A3 "Open file descriptor" "$T/vg.log" | grep -v "inherited from parent" | grep -q "Open file descriptor [3-9]" && { echo "FAIL leaked fd"; cat "$T/vg.log"; fail=1; }
fi
kill $UPID 2>/dev/null
exit $fail
