/* SPDX-License-Identifier: ISC */
/* Copyright (c) 2026 David Walther <david@clearbrookdistillery.com> */
/* Fuzz target: one line from the Windows helper. */
#include "../dns.h"

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    char name[DNS_NAME_MAX];
    uint32_t ip = 0;
    int found;
    char *line = malloc(n + 1);

    if (!line)
        return 0;
    memcpy(line, d, n);
    line[n] = '\0';
    if (dns_parse_helper_line(line, name, &ip, &found) && !dns_valid_local_name(name))
        abort();                                        /* an accepted name must be a valid one */
    {
        uint32_t ips[4];
        int k = dns_parse_resolv_conf(line, ips, 4);

        if (k < 0 || k > 4)
            abort();
    }
    free(line);
    return 0;
}
