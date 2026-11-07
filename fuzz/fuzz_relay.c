/* SPDX-License-Identifier: ISC */
/* Copyright (c) 2026 David Walther <david@clearbrookdistillery.com> */
/* Fuzz target: validating an upstream reply against a request.  First byte splits the input. */
#include "../dns.h"

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    size_t k;

    if (n < 2)
        return 0;
    k = 1 + (size_t)d[0] % (n - 1);
    dns_valid_relay_reply(d + 1, k, d + 1 + k, n - 1 - k);
    return 0;
}
