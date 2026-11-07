#!/bin/sh
# SPDX-License-Identifier: ISC
# Stand-in for the Windows helper.  Reads names, writes "<name> <ip>" or "<name> -".
while read -r n; do
    case "$n" in
        host.local) echo "$n 10.1.2.3" ;;
        other.local) echo "$n 10.9.9.9" ;;
        slow.local) sleep 2; echo "$n 10.7.7.7" ;;
        loop.local) echo "$n 127.0.0.1" ;;
        chg.local) echo "$n $(cat "$FAKE_IP_FILE" 2>/dev/null || echo -)" ;;
        *) echo "$n -" ;;
    esac
done
