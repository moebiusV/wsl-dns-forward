/* SPDX-License-Identifier: ISC */
/* Copyright (c) 2026 David Walther <david@clearbrookdistillery.com> */
/* Unit tests for the pure packet logic in dns.c. */
#include "dns.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static int failures;

static int addr_eq(const struct dns_addrs *x, const struct dns_addrs *y)
{
    return x->has4 == y->has4 && x->v4 == y->v4 && x->n6 == y->n6 && memcmp(x->v6, y->v6, 16 * (size_t)x->n6) == 0;
}
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

/* Build a query for dotted name; returns length. */
static size_t mkq(uint8_t *p, uint16_t id, const char *name, unsigned qtype, unsigned qclass)
{
    size_t o = 12;
    const char *s = name;

    memset(p, 0, 12);
    p[0] = (uint8_t)(id >> 8); p[1] = (uint8_t)id; p[2] = 0x01; p[5] = 1;
    while (*s) {
        const char *dot = strchr(s, '.');
        size_t l = dot ? (size_t)(dot - s) : strlen(s);
        p[o++] = (uint8_t)l;
        memcpy(p + o, s, l);
        o += l;
        s += l + (dot ? 1 : 0);
    }
    p[o++] = 0;
    p[o++] = (uint8_t)(qtype >> 8); p[o++] = (uint8_t)qtype;
    p[o++] = (uint8_t)(qclass >> 8); p[o++] = (uint8_t)qclass;
    return o;
}

static enum dns_action cls(const uint8_t *q, size_t n, struct dns_query *dq, uint8_t *resp, size_t *rl)
{
    return dns_classify(q, n, dq, resp, 4096, rl);
}

static void test_classify(void)
{
    uint8_t q[600], r[4096];
    struct dns_query dq;
    size_t n, rl;

    n = mkq(q, 7, "Host.LOCAL", 1, 1);
    CHECK(cls(q, n, &dq, r, &rl) == DNS_LOCAL_A);
    CHECK(strcmp(dq.name, "host.local") == 0);                       /* lowercased */

    n = mkq(q, 7, "host.local", 28, 1);                              /* AAAA: looked up when IPv6 is usable */
    CHECK(cls(q, n, &dq, r, &rl) == DNS_LOCAL_AAAA && dq.qtype == 28);

    n = mkq(q, 7, "host.local", 16, 1);                              /* TXT: NOERROR, no data */
    CHECK(cls(q, n, &dq, r, &rl) == DNS_REPLY);
    CHECK((r[3] & 15) == 0 && r[7] == 0 && rl == n && r[0] == 0 && r[1] == 7 && (r[2] & 0x80));

    n = mkq(q, 7, "host.local", 1, 255);                             /* ANY class: no data */
    CHECK(cls(q, n, &dq, r, &rl) == DNS_REPLY && r[7] == 0);

    n = mkq(q, 7, "example.com", 1, 1);
    CHECK(cls(q, n, &dq, r, &rl) == DNS_RELAY);
    n = mkq(q, 7, "local", 1, 1);                                    /* the bare TLD is not a host */
    CHECK(cls(q, n, &dq, r, &rl) == DNS_RELAY);
    n = mkq(q, 7, "notlocal", 1, 1);
    CHECK(cls(q, n, &dq, r, &rl) == DNS_RELAY);

    n = mkq(q, 7, "bad name.local", 1, 1);                           /* characters the helper protocol forbids */
    CHECK(cls(q, n, &dq, r, &rl) == DNS_REPLY && (r[3] & 15) == DNS_RCODE_REFUSED);
    n = mkq(q, 7, "a\"b.local", 1, 1);
    CHECK(cls(q, n, &dq, r, &rl) == DNS_REPLY && (r[3] & 15) == DNS_RCODE_REFUSED);
    n = mkq(q, 7, "x.local", 1, 1);
    q[13] = '\n';                                                    /* newline inside a label */
    CHECK(cls(q, n, &dq, r, &rl) == DNS_REPLY && (r[3] & 15) == DNS_RCODE_REFUSED);

    n = mkq(q, 7, "host.local", 1, 1);
    q[2] |= 0x80;                                                    /* a response, not a query */
    CHECK(cls(q, n, &dq, r, &rl) == DNS_DROP);
    q[2] = (uint8_t)(q[2] & 0x7f);
    q[2] |= 0x10;                                                    /* opcode 2 */
    CHECK(cls(q, n, &dq, r, &rl) == DNS_REPLY && (r[3] & 15) == DNS_RCODE_NOTIMP);
    q[2] = 0x01; q[5] = 0;                                           /* qdcount 0 */
    CHECK(cls(q, n, &dq, r, &rl) == DNS_REPLY && (r[3] & 15) == DNS_RCODE_FORMERR);
    q[5] = 2;                                                        /* qdcount 2 */
    CHECK(cls(q, n, &dq, r, &rl) == DNS_REPLY && (r[3] & 15) == DNS_RCODE_FORMERR);

    CHECK(cls(q, 5, &dq, r, &rl) == DNS_DROP);                       /* shorter than a header */
    n = mkq(q, 7, "host.local", 1, 1);
    CHECK(cls(q, n - 3, &dq, r, &rl) == DNS_REPLY);                  /* truncated question: FORMERR */
    q[12] = 0xC0; q[13] = 0x0C;                                      /* compression pointer in a question */
    CHECK(cls(q, n, &dq, r, &rl) == DNS_REPLY && (r[3] & 15) == DNS_RCODE_FORMERR);
    memset(q + 12, 0, 20); q[12] = 64;                               /* label of 64 */
    CHECK(cls(q, 40, &dq, r, &rl) == DNS_REPLY && (r[3] & 15) == DNS_RCODE_FORMERR);

    {                                                                 /* name over 253 characters */
        uint8_t big[600];
        size_t o = 12, k;

        memset(big, 0, 12); big[2] = 1; big[5] = 1;
        for (k = 0; k < 6; k++) {
            big[o++] = 50;
            memset(big + o, 'a', 50);
            o += 50;
        }
        big[o++] = 0; big[o++] = 0; big[o++] = 1; big[o++] = 0; big[o++] = 1;
        CHECK(cls(big, o, &dq, r, &rl) == DNS_REPLY && (r[3] & 15) == DNS_RCODE_FORMERR);
    }

    {                                                                 /* labels with NUL or '.' are never local */
        uint8_t w[64];
        size_t o = mkq(w, 1, "xx.local", 1, 1);
        w[13] = '.';
        CHECK(cls(w, o, &dq, r, &rl) == DNS_REPLY && (r[3] & 15) == DNS_RCODE_FORMERR);
    }

    CHECK(dns_classify(q, 20, &dq, r, 100, &rl) == DNS_DROP);        /* response buffer too small */
}

static void test_build(void)
{
    uint8_t q[100], r[512];
    size_t n = mkq(q, 0x1234, "host.local", 1, 1), rl;
    uint32_t ip = htonl(0x0a010203);

    rl = dns_build_a(q, n, ip, r, sizeof r);
    CHECK(rl == n + 16);
    CHECK(r[0] == 0x12 && r[1] == 0x34 && (r[2] & 0x80) && (r[3] & 0x80) && r[7] == 1);
    CHECK(memcmp(r + n, "\xC0\x0C\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x0a\x01\x02\x03", 16) == 0);
    CHECK(dns_valid_relay_reply(q, n, r, rl));                        /* our own answer validates */
    CHECK(dns_build_a(q, n, ip, r, n + 5) == 0);                      /* does not fit */
    CHECK(dns_build_reply(q, 3, 0, r, sizeof r) == 0);
}

static void test_relay(void)
{
    uint8_t q[100], r[100], r2[100];
    size_t n = mkq(q, 0x4242, "example.com", 1, 1);

    memcpy(r, q, n);
    r[2] = 0x81; r[3] = 0x80;
    CHECK(dns_valid_relay_reply(q, n, r, n));
    memcpy(r2, r, n); r2[1] ^= 1;
    CHECK(!dns_valid_relay_reply(q, n, r2, n));                       /* wrong ID */
    memcpy(r2, r, n); r2[2] = 0x01;
    CHECK(!dns_valid_relay_reply(q, n, r2, n));                       /* QR clear */
    memcpy(r2, r, n); r2[13] = 'X';
    CHECK(!dns_valid_relay_reply(q, n, r2, n));                       /* different question */
    memcpy(r2, r, n); r2[5] = 0;
    CHECK(!dns_valid_relay_reply(q, n, r2, n));                       /* no question echoed */
    CHECK(!dns_valid_relay_reply(q, n, r, 11));
    memcpy(r2, r, n); r2[12 + 1 + 11 + 1] = 28;                       /* different type */
    CHECK(!dns_valid_relay_reply(q, n, r2, n));
}

static void test_helper_line(void)
{
    char name[DNS_NAME_MAX];
    struct dns_addrs a;
    int found;
    static const uint8_t v6a[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    CHECK(dns_parse_helper_line("host.local 10.1.2.3", name, &a, &found) && found && a.has4 && a.v4 == htonl(0x0a010203));
    CHECK(strcmp(name, "host.local") == 0 && a.n6 == 0);
    CHECK(dns_parse_helper_line("host.local 10.1.2.3\r\n", name, &a, &found) && found);
    CHECK(dns_parse_helper_line("host.local -", name, &a, &found) && !found && !a.has4 && a.n6 == 0);
    CHECK(dns_parse_helper_line("host.local 127.0.0.1", name, &a, &found) && !found);        /* loopback refused */
    CHECK(dns_parse_helper_line("host.local 0.0.0.0", name, &a, &found) && !found);
    CHECK(dns_parse_helper_line("host.local 224.0.0.251", name, &a, &found) && !found);      /* multicast refused */
    CHECK(dns_parse_helper_line("host.local 255.255.255.255", name, &a, &found) && !found);
    CHECK(dns_parse_helper_line("host.local 169.254.1.1", name, &a, &found) && found);       /* link-local is legitimate */
    CHECK(!dns_parse_helper_line("host.local 10.1.2", name, &a, &found));
    CHECK(!dns_parse_helper_line("host.local 1", name, &a, &found));                         /* inet_aton-style shorthand */
    CHECK(!dns_parse_helper_line("host.local 0x7f.1", name, &a, &found));
    CHECK(!dns_parse_helper_line("host.local 10.1.2.3 extra", name, &a, &found));            /* not an IPv6 list */
    CHECK(!dns_parse_helper_line("host.local 10.1.2.3\nHOST.local 1.1.1.1", name, &a, &found));
    CHECK(!dns_parse_helper_line("Host.local 10.1.2.3", name, &a, &found));                  /* must be lowercase */
    CHECK(!dns_parse_helper_line("example.com 10.1.2.3", name, &a, &found));
    CHECK(!dns_parse_helper_line("nospace", name, &a, &found));
    CHECK(!dns_parse_helper_line("", name, &a, &found));
    CHECK(!dns_parse_helper_line(" 10.1.2.3", name, &a, &found));

    /* IPv6 */
    CHECK(dns_parse_helper_line("h.local 10.1.2.3 2001:db8::1", name, &a, &found) && found && a.has4 && a.n6 == 1);
    CHECK(memcmp(a.v6[0], v6a, 16) == 0);
    CHECK(dns_parse_helper_line("h.local - 2001:db8::1,2001:db8::2\r\n", name, &a, &found) && found && !a.has4 && a.n6 == 2);
    CHECK(dns_parse_helper_line("h.local - fe80::1,2001:db8::1", name, &a, &found) && found && a.n6 == 1);   /* link-local dropped */
    CHECK(dns_parse_helper_line("h.local - fe80::1", name, &a, &found) && !found && a.n6 == 0);
    CHECK(dns_parse_helper_line("h.local - ::1,::,ff02::fb,::ffff:1.2.3.4", name, &a, &found) && !found);  /* all unusable */
    CHECK(dns_parse_helper_line("h.local - fd00::1", name, &a, &found) && found && a.n6 == 1);            /* ULA is fine */
    CHECK(dns_parse_helper_line("h.local - 2001:db8::1,2001:db8::2,2001:db8::3,2001:db8::4,2001:db8::5", name, &a, &found)
          && a.n6 == DNS_MAXV6);                                                                  /* capped, not an error */
    CHECK(!dns_parse_helper_line("h.local - 2001:db8::zz", name, &a, &found));
    CHECK(!dns_parse_helper_line("h.local - 2001:db8::1 junk", name, &a, &found));
    CHECK(!dns_parse_helper_line("h.local 10.1.2.3 ", name, &a, &found));                       /* empty IPv6 field */
}

static void test_local_build(void)
{
    uint8_t q[100], r[512];
    char text[300];
    struct dns_addrs a, b;
    int found;
    size_t n = mkq(q, 0x1234, "host.local", 28, 1), rl;

    CHECK(dns_parse_helper_line("host.local 10.1.2.3 2001:db8::1,2001:db8::2", text, &a, &found) && found);
    rl = dns_build_local(q, n, 28, &a, r, sizeof r);
    CHECK(rl == n + 2 * 28 && r[7] == 2 && (r[3] & 15) == 0 && r[0] == 0x12);
    CHECK(r[n + 3] == 28 && r[n + 11] == 16 && r[n + 12] == 0x20 && r[n + 13] == 0x01);      /* type AAAA, rdlen 16 */
    CHECK(dns_valid_relay_reply(q, n, r, rl));
    n = mkq(q, 0x1234, "host.local", 1, 1);
    rl = dns_build_local(q, n, 1, &a, r, sizeof r);                                           /* A from a dual-stack set */
    CHECK(rl == n + 16 && r[7] == 1);
    memset(&b, 0, sizeof b);                                                                  /* nothing of the kind: no data */
    rl = dns_build_local(q, n, 1, &b, r, sizeof r);
    CHECK(rl == n && r[7] == 0 && (r[3] & 15) == 0);
    n = mkq(q, 1, "h.local", 28, 1);
    b = a; b.has4 = 1; b.n6 = 0;
    rl = dns_build_local(q, n, 28, &b, r, sizeof r);                                          /* IPv4 only host asked for AAAA */
    CHECK(rl == n && r[7] == 0);
    CHECK(dns_build_local(q, n, 28, &a, r, n + 10) == 0);                                     /* does not fit */

    CHECK(dns_format_addrs("h.local", &a, text, sizeof text) > 0);
    CHECK(strcmp(text, "h.local 10.1.2.3 2001:db8::1,2001:db8::2") == 0);
    CHECK(dns_parse_helper_line(text, text + 100, &b, &found) && found && addr_eq(&a, &b));    /* round trip */
    b.has4 = 0;
    CHECK(dns_format_addrs("h.local", &b, text, sizeof text) > 0 && strcmp(text, "h.local - 2001:db8::1,2001:db8::2") == 0);
    CHECK(dns_format_addrs("h.local", &a, text, 8) == 0);                                     /* too small */
}

static void test_ipv6_usable(void)
{
    static const char nat_addrs[] = "fe8000000000000002155dfffed13fcc 02 40 20 80     eth0\n"
                                    "00000000000000000000000000000001 01 80 10 80       lo\n";
    static const char nat_routes[] = "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 "
                                     "00000000000000000000000000000000 00000100 00000000 00000000 00000001     eth0\n"
                                     "00000000000000000000000000000001 80 00000000000000000000000000000000 00 "
                                     "00000000000000000000000000000000 00000000 00000002 00000000 80200001       lo\n";
    static const char mir_addrs[] = "20010db8000000000000000000000042 02 40 00 80     eth0\n"
                                    "fe8000000000000002155dfffed13fcc 02 40 20 80     eth0\n";
    static const char mir_routes[] = "20010db8000000000000000000000000 40 00000000000000000000000000000000 00 "
                                     "00000000000000000000000000000000 00000100 00000000 00000000 00000001     eth0\n"
                                     "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
                                     "fe800000000000000000000000000001 00000064 00000001 00000000 00000003     eth0\n";
    static const char reject_routes[] = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
                                        "00000000000000000000000000000000 ffffffff 00000001 00000000 00200200      lo\n";

    CHECK(!dns_ipv6_usable(nat_addrs, nat_routes));                  /* WSL2 NAT: link-local only, no default route */
    CHECK(dns_ipv6_usable(mir_addrs, mir_routes));                   /* a global address and a default route */
    CHECK(!dns_ipv6_usable(mir_addrs, nat_routes));                  /* address but no default route */
    CHECK(!dns_ipv6_usable(nat_addrs, mir_routes));                  /* default route but only a link-local address */
    CHECK(!dns_ipv6_usable(mir_addrs, reject_routes));               /* a reject route on lo is not connectivity */
    CHECK(!dns_ipv6_usable("20010db8000000000000000000000042 02 40 00 80 lo\n", mir_routes));   /* global on loopback */
    CHECK(!dns_ipv6_usable("20010db8000000000000000000000042 02 40 00 40 eth0\n", mir_routes));  /* tentative address */
    CHECK(!dns_ipv6_usable("", ""));
    CHECK(!dns_ipv6_usable("garbage\n\n   \n", "more garbage"));
}

static void test_names(void)
{
    CHECK(dns_valid_local_name("a.local"));
    CHECK(dns_valid_local_name("my-host_1.sub.local"));
    CHECK(!dns_valid_local_name(".local"));
    CHECK(!dns_valid_local_name("local"));
    CHECK(!dns_valid_local_name("a..local"));
    CHECK(!dns_valid_local_name("a.local."));
    CHECK(!dns_valid_local_name("A.local"));
    CHECK(!dns_valid_local_name("a b.local"));
    CHECK(!dns_valid_local_name("a.localx"));
}

static void test_resolv(void)
{
    uint32_t ips[4];
    int n;

    n = dns_parse_resolv_conf("nameserver 127.0.0.1\nnameserver 172.24.96.1\nnameserver 192.168.1.254\n", ips, 4);
    CHECK(n == 2 && ips[0] == htonl(0xAC186001u) && ips[1] == htonl(0xC0A801FEu));
    n = dns_parse_resolv_conf("# comment\nsearch lan\n  nameserver\t10.255.255.254  \r\nnameserver 10.255.255.254\n", ips, 4);
    CHECK(n == 1 && ips[0] == htonl(0x0AFFFFFEu));                      /* tabs, CRLF, duplicates */
    CHECK(dns_parse_resolv_conf("nameserver 127.0.0.53\nnameserver 0.0.0.0\nnameserver ::1\nnameserver abc\n", ips, 4) == 0);
    CHECK(dns_parse_resolv_conf("nameserver1 1.2.3.4\nnameservers 1.2.3.4\n", ips, 4) == 0);
    CHECK(dns_parse_resolv_conf("nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 9.9.9.9\n", ips, 2) == 2);   /* max */
    CHECK(dns_parse_resolv_conf("", ips, 4) == 0);
    CHECK(dns_parse_resolv_conf("nameserver 1.2.3.4", ips, 4) == 1);    /* no trailing newline */
}

int main(void)
{
    test_classify();
    test_build();
    test_relay();
    test_helper_line();
    test_local_build();
    test_ipv6_usable();
    test_names();
    test_resolv();
    if (failures)
        printf("%d check(s) failed\n", failures);
    else
        puts("test_dns: all checks passed");
    return failures ? 1 : 0;
}
