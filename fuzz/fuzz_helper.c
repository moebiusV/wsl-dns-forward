/* SPDX-License-Identifier: ISC */
/* Copyright (c) 2026 David Walther <david@clearbrookdistillery.com> */
/* Fuzz target: one line from the Windows helper. */
#include "../dns.h"

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    char name[DNS_NAME_MAX];
    struct dns_addrs a;
    int found;
    char *line = malloc(n + 1);

    if (!line)
        return 0;
    memcpy(line, d, n);
    line[n] = '\0';
    if (dns_parse_helper_line(line, name, &a, &found)) {
        char text[512];
        uint8_t q[300], resp[DNS_MIN_RESP];

        if (!dns_valid_local_name(name) || a.n6 < 0 || a.n6 > DNS_MAXV6 || found != (a.has4 || a.n6 > 0))
            abort();                                    /* an accepted line must be consistent */
        if (found && dns_format_addrs(name, &a, text, sizeof text)) {
            struct dns_addrs b;
            int f2;
            char n2[DNS_NAME_MAX];

            if (!dns_parse_helper_line(text, n2, &b, &f2) || !f2)
                abort();                                /* the cache file format must round-trip */
        }
        memset(q, 0, 12);
        q[5] = 1; q[12] = 1; q[13] = 'a'; q[14] = 0; q[16] = 28; q[18] = 1;       /* "a" AAAA IN */
        dns_build_local(q, 19, 28, &a, resp, sizeof resp);
    }
    dns_ipv6_usable(line, line);                        /* the /proc parsers take arbitrary text */
    {
        uint32_t ips[4];
        int k = dns_parse_resolv_conf(line, ips, 4);

        if (k < 0 || k > 4)
            abort();
    }
    free(line);
    return 0;
}
