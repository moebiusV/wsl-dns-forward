#!/bin/sh
# SPDX-License-Identifier: ISC
# Stand-in for the Windows helper.  Reads "<name> [4|46]", writes "<name> <ipv4>|- [<ipv6>,...]".
while read -r n f; do
    case "$n" in
        host.local) echo "$n 10.1.2.3" ;;
        other.local) echo "$n 10.9.9.9" ;;
        dual.local) if [ "$f" = 46 ]; then echo "$n 10.1.2.4 2001:db8::1,2001:db8::2"; else echo "$n 10.1.2.4"; fi ;;
        v6only.local) if [ "$f" = 46 ]; then echo "$n - 2001:db8::5"; else echo "$n -"; fi ;;
        slow.local) sleep 2; echo "$n 10.7.7.7" ;;
        loop.local) echo "$n 127.0.0.1" ;;
        chg.local) echo "$n $(cat "$FAKE_IP_FILE" 2>/dev/null || echo -)" ;;
        *) echo "$n -" ;;
    esac
done
