/* SPDX-License-Identifier: ISC */
/* Copyright (c) 2026 David Walther <david@clearbrookdistillery.com> */

/*
 * dns.h - pure DNS packet logic for wsl-dns-forward.
 *
 * Nothing in here does I/O, so every function can be driven directly by the
 * fuzzers and the unit tests.
 */
#ifndef WMF_DNS_H
#define WMF_DNS_H

#include <stddef.h>
#include <stdint.h>

#define DNS_NAME_MAX 256        /* buffer size for a dotted name, including the NUL */
#define DNS_MIN_RESP 512        /* smallest response buffer the builders accept */
#define DNS_ANSWER_TTL 60

#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_FORMERR 1
#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_NOTIMP 4
#define DNS_RCODE_REFUSED 5

enum dns_action {
    DNS_DROP,       /* ignore the packet */
    DNS_REPLY,      /* send the prepared reply */
    DNS_RELAY,      /* forward the original packet to the upstream resolver */
    DNS_LOCAL_A     /* an A query for a .local name: look it up over mDNS */
};

struct dns_query {
    char name[DNS_NAME_MAX];    /* lowercased, dotted, no trailing dot */
    unsigned qtype;
    unsigned qclass;
    size_t qend;                /* offset just past the question section */
};

/*
 * Parse the single question of a message.  Returns the offset just past the
 * question, or 0 if the message is malformed.  Names with compression
 * pointers, over-long labels or names, or label bytes that are NUL or '.' are
 * rejected, so a successful parse yields an unambiguous dotted name.
 */
size_t dns_parse_question(const uint8_t *msg, size_t len, char name[DNS_NAME_MAX],
                          unsigned *qtype, unsigned *qclass);

/* Strict check: lowercase [a-z0-9_-] labels of at most 63 bytes ending in ".local". */
int dns_valid_local_name(const char *name);

/*
 * Decide what to do with a client query.  For DNS_REPLY, *rlen bytes of
 * resp are ready to send.  resp must be at least DNS_MIN_RESP bytes.
 */
enum dns_action dns_classify(const uint8_t *req, size_t len, struct dns_query *q,
                             uint8_t *resp, size_t cap, size_t *rlen);

/* Build a reply with the given rcode and no answers (header plus the question, if qend > 12). */
size_t dns_build_reply(const uint8_t *req, size_t qend, int rcode, uint8_t *resp, size_t cap);

/* Build a NOERROR reply carrying one A record.  ip is in network byte order. */
size_t dns_build_a(const uint8_t *req, size_t qend, uint32_t ip, uint8_t *resp, size_t cap);

/* Does this upstream reply answer this request?  (QR set, same ID, same question.) */
int dns_valid_relay_reply(const uint8_t *req, size_t reqlen, const uint8_t *rep, size_t replen);

/*
 * Parse one line from the Windows helper: "<name> <ipv4>" or "<name> -".
 * Returns 1 if the line is well formed.  *found is 1 and *ip (network order)
 * is set for an address; unusable addresses (loopback, multicast, 0/8,
 * reserved) are treated as "not found".
 */
int dns_parse_helper_line(const char *line, char name[DNS_NAME_MAX], uint32_t *ip, int *found);

/*
 * Extract usable upstream resolvers from the text of a resolv.conf: IPv4 "nameserver" lines, skipping
 * loopback, 0.0.0.0 and duplicates (loopback would be this daemon itself).  Fills ips[] (network order)
 * and returns how many were found, at most max.
 */
int dns_parse_resolv_conf(const char *text, uint32_t *ips, int max);

#endif
