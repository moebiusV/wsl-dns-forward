/* SPDX-License-Identifier: ISC */
/* Copyright (c) 2026 David Walther <david@clearbrookdistillery.com> */
/* Fuzz target: a client query through classification and reply building. */
#include "../dns.h"

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    uint8_t resp[4096], tiny[DNS_MIN_RESP];
    struct dns_query q;
    size_t rl;
    enum dns_action a = dns_classify(d, n, &q, resp, sizeof resp, &rl);

    if (a == DNS_REPLY && (rl < 12 || rl > sizeof resp))
        abort();
    if (a == DNS_REPLY && rl > 12 && !dns_valid_relay_reply(d, n, resp, rl))
        abort();                                        /* our own replies must validate */
    if (a == DNS_LOCAL_A) {
        if (!dns_valid_local_name(q.name) || q.qend > n || q.qend <= 12)
            abort();
        size_t m = dns_build_a(d, q.qend, 0x04030201u, resp, sizeof resp);
        if (m != q.qend + 16 || !dns_valid_relay_reply(d, n, resp, m))
            abort();
        dns_build_a(d, q.qend, 0x04030201u, tiny, sizeof tiny);
        dns_build_reply(d, q.qend, DNS_RCODE_SERVFAIL, tiny, sizeof tiny);
    }
    dns_classify(d, n, &q, tiny, sizeof tiny, &rl);     /* smallest accepted buffer */
    return 0;
}
