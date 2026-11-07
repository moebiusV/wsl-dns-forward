/* SPDX-License-Identifier: ISC */
/* Copyright (c) 2026 David Walther <david@clearbrookdistillery.com> */
/*
 * Test upstream DNS server: fakeup PORT
 * Answers every A query with 9.9.9.9.  Special names:
 *   spoof.test  first sends forged answers (wrong ID, then from another port, 6.6.6.6), then the real one
 *   slow.test   answers after 1.5 seconds (in a child process)
 *   drop.test   never answers
 */
#include "../dns.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct sockaddr_in a = { 0 };
    int s = socket(AF_INET, SOCK_DGRAM, 0), other = socket(AF_INET, SOCK_DGRAM, 0);

    if (argc != 2 || s < 0)
        return 2;
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)atoi(argv[1]));
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) {
        perror("bind");
        return 1;
    }
    signal(SIGCHLD, SIG_IGN);
    for (;;) {
        uint8_t q[4096], r[4096];
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(s, q, sizeof q, 0, (struct sockaddr *)&from, &fl);
        char name[DNS_NAME_MAX];
        unsigned t, c;
        size_t qend, rl;

        if (n < 12)
            continue;
        qend = dns_parse_question(q, (size_t)n, name, &t, &c);
        if (!qend)
            continue;
        rl = dns_build_a(q, qend, inet_addr("9.9.9.9"), r, sizeof r);
        if (!rl)
            continue;
        if (strcmp(name, "drop.test") == 0)
            continue;
        if (strcmp(name, "spoof.test") == 0) {
            uint8_t bad[4096];

            memcpy(bad, r, rl);
            memcpy(bad + rl - 4, "\x06\x06\x06\x06", 4);
            bad[1] ^= 0xff;                                  /* wrong ID, right socket */
            sendto(s, bad, rl, 0, (struct sockaddr *)&from, fl);
            bad[1] ^= 0xff;                                  /* right ID, wrong source port */
            sendto(other, bad, rl, 0, (struct sockaddr *)&from, fl);
        }
        if (strcmp(name, "slow.test") == 0) {
            if (fork() == 0) {
                usleep(1500000);
                sendto(s, r, rl, 0, (struct sockaddr *)&from, fl);
                _exit(0);
            }
            continue;
        }
        sendto(s, r, rl, 0, (struct sockaddr *)&from, fl);
    }
}
