/* SPDX-License-Identifier: ISC */
/* Copyright (c) 2026 David Walther <david@clearbrookdistillery.com> */

/*
 * wsl-dns-forward - a local DNS forwarder that makes .local (mDNS) names
 * resolve inside WSL2.  See wsl-dns-forward(8).
 *
 * One poll() loop, no threads.  Queries that need the network (relays to the
 * upstream resolver, lookups through the Windows helper) are asynchronous
 * "jobs", so a slow answer never stalls other clients.
 */
#define _GNU_SOURCE
#include "config.h"
#include "dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netinet/in.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAXPKT 4096
#define MAXUP 6
#define NCACHE 64
#define MAXJOB 64
#define MAXTCP 16
#define MAXWANT 32
#define FRESH_MS_DEFAULT 120000L
#define STALE_WAIT_MS 2000L            /* how long an expired name waits for a refresh before its cached address is used */
#define HELPER_TIMEOUT_MS 6000L
#define RELAY_TIMEOUT_MS 2000L
#define TCP_TIMEOUT_MS 5000L
#define BACKOFF_MIN_MS 500L
#define BACKOFF_MAX_MS 30000L
#define SCRIPT_MAX 24000            /* keep the powershell command line under the 32 KB limit */

#ifndef PKGDATADIR
#define PKGDATADIR "/usr/local/share/wsl-dns-forward"
#endif
#ifndef LOCALSTATEDIR
#define LOCALSTATEDIR "/var"
#endif

/* ---------- configuration and globals ---------- */

static const char *listen_addr = "127.0.0.1";
static int listen_port = 53;
static struct sockaddr_in upstream[MAXUP];
static int nup;
static long fresh_ms = FRESH_MS_DEFAULT;   /* WMF_FRESH_MS overrides it, for the tests */
static int up_pref;             /* index of the upstream that answered last; tried first */
static int up_auto;             /* upstreams were discovered, not given with -u */
static const char *cache_path = LOCALSTATEDIR "/cache/wsl-dns-forward/last-good";
static const char *run_user = "nobody";
static const char *powershell_path = POWERSHELL_PATH;
static volatile sig_atomic_t quit_flag;
static int udp_fd = -1, tcp_fd = -1;

static void logmsg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void logmsg(const char *fmt, ...)
{
    char ts[32];
    time_t t = time(NULL);
    struct tm tmv;
    va_list ap;

    if (localtime_r(&t, &tmv))
        strftime(ts, sizeof ts, "%F %T", &tmv);
    else
        snprintf(ts, sizeof ts, "%ld", (long)t);
    fprintf(stderr, "%s ", ts);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static long now_ms(void);

/*
 * Diagnostics for people who are not DNS experts.  Every problem is reported as
 *   [ID] what happened
 *       why: the most likely cause
 *       try: what to do about it
 *       see: where to read more
 * The IDs are listed in wsl-dns-forward(8), section DIAGNOSTICS, and in the README.
 * "slot" >= 0 limits repeats of that diagnostic to one per 10 seconds.
 */
static void diag(int slot, const char *id, const char *why, const char *fix, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));
static void diag(int slot, const char *id, const char *why, const char *fix, const char *fmt, ...)
{
    long now = now_ms();
    char msg[400];
    va_list ap;

    if (slot >= 0 && slot < 16) {
        static long last[16];

        if (last[slot] && now - last[slot] < 10000)
            return;
        last[slot] = now;
    }
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    logmsg("[%s] %s", id, msg);
    if (why)
        fprintf(stderr, "    why: %s\n", why);
    if (fix)
        fprintf(stderr, "    try: %s\n", fix);
    fprintf(stderr, "    see: man 8 wsl-dns-forward, section DIAGNOSTICS, entry %s\n", id);
}

static long now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + (long)(ts.tv_nsec / 1000000L);
}

/* ---------- cache with last-known-good persistence ---------- */

struct entry {
    char name[DNS_NAME_MAX];
    uint32_t ip;                /* network order */
    long when;                  /* monotonic ms of the last successful lookup; 0 = loaded from disk */
};
static struct entry cache[NCACHE];
static int ncache;

static struct entry *cache_find(const char *name)
{
    for (int i = 0; i < ncache; i++)
        if (strcmp(cache[i].name, name) == 0)
            return &cache[i];
    return NULL;
}

static void cache_save(void)
{
    char tmp[512];
    FILE *f;
    int fd;

    if (snprintf(tmp, sizeof tmp, "%s.tmp", cache_path) >= (int)sizeof tmp)
        return;
    unlink(tmp);
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) {
        diag(0, "W08", "the daemon cannot store the last-known-good addresses, so after a restart a failed lookup "
             "has no previous address to fall back on",
             "make sure that directory exists and the run user may write to it, or pick another with -c FILE",
             "cannot save %s: %s", cache_path, strerror(errno));
        return;
    }
    f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        return;
    }
    for (int i = 0; i < ncache; i++) {
        char ip[INET_ADDRSTRLEN];
        struct in_addr a = { cache[i].ip };
        if (inet_ntop(AF_INET, &a, ip, sizeof ip))
            fprintf(f, "%s %s\n", cache[i].name, ip);
    }
    fflush(f);
    fsync(fileno(f));
    if (fclose(f) == 0 && rename(tmp, cache_path) == 0)
        return;
    diag(0, "W08", "the daemon cannot store the last-known-good addresses, so after a restart a failed lookup "
         "has no previous address to fall back on",
         "make sure that directory exists and the run user may write to it, or pick another with -c FILE",
         "cannot save %s: %s", cache_path, strerror(errno));
    unlink(tmp);
}

static void cache_put(const char *name, uint32_t ip)
{
    struct entry *e = cache_find(name);
    int changed = 0;

    if (!e) {
        if (ncache == NCACHE) {
            memmove(cache, cache + 1, sizeof cache[0] * (NCACHE - 1));
            ncache--;
        }
        e = &cache[ncache++];
        snprintf(e->name, sizeof e->name, "%s", name);
        changed = 1;
    } else if (e->ip != ip) {
        changed = 1;
    }
    e->ip = ip;
    e->when = now_ms();
    if (changed)
        cache_save();
}

static void cache_load(void)
{
    FILE *f = fopen(cache_path, "re");
    char line[512];

    if (!f)
        return;
    while (ncache < NCACHE && fgets(line, sizeof line, f)) {
        char name[DNS_NAME_MAX];
        uint32_t ip;
        int found;

        if (dns_parse_helper_line(line, name, &ip, &found) && found) {
            snprintf(cache[ncache].name, sizeof cache[ncache].name, "%s", name);
            cache[ncache].ip = ip;
            cache[ncache].when = 0;             /* from disk: stale until refreshed */
            ncache++;
        }
    }
    fclose(f);
}

/* ---------- the Windows helper process ---------- */

static struct {
    pid_t pid;
    int in, out;                /* names are written to in; answers are read from out */
    char buf[1024];
    size_t len;
    long retry_at;
    long backoff;
} H = { -1, -1, -1, { 0 }, 0, 0, BACKOFF_MIN_MS };

static const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* powershell -EncodedCommand takes base64 of the UTF-16LE script text. */
static char *encode_script(const char *path)
{
    FILE *f = fopen(path, "re");
    uint8_t *u16;
    char *out, *p;
    size_t n = 0, bytes;
    int c;

    if (!f)
        return NULL;
    u16 = malloc(SCRIPT_MAX * 2);
    if (!u16) {
        fclose(f);
        return NULL;
    }
    while ((c = fgetc(f)) != EOF) {
        if (c == '\r')
            continue;
        if (n >= SCRIPT_MAX / 3 || c > 127) {   /* too large, or not plain ASCII */
            fclose(f);
            free(u16);
            return NULL;
        }
        u16[2 * n] = (uint8_t)c;
        u16[2 * n + 1] = 0;
        n++;
    }
    fclose(f);
    bytes = n * 2;
    out = malloc((bytes + 2) / 3 * 4 + 1);
    if (!out) {
        free(u16);
        return NULL;
    }
    p = out;
    for (size_t i = 0; i < bytes; i += 3) {
        uint32_t v = (uint32_t)u16[i] << 16 | (i + 1 < bytes ? (uint32_t)u16[i + 1] << 8 : 0)
                     | (i + 2 < bytes ? u16[i + 2] : 0u);
        *p++ = b64t[v >> 18 & 63];
        *p++ = b64t[v >> 12 & 63];
        *p++ = i + 1 < bytes ? b64t[v >> 6 & 63] : '=';
        *p++ = i + 2 < bytes ? b64t[v & 63] : '=';
    }
    *p = '\0';
    free(u16);
    return out;
}

static void helper_stop(void)
{
    if (H.in >= 0)
        close(H.in);
    if (H.out >= 0)
        close(H.out);
    if (H.pid > 0) {
        kill(H.pid, SIGTERM);
        waitpid(H.pid, NULL, WNOHANG);          /* anything left is reaped by the main loop */
    }
    H.in = H.out = -1;
    H.pid = -1;
    H.len = 0;
    H.retry_at = now_ms() + H.backoff;
    H.backoff = H.backoff * 2 > BACKOFF_MAX_MS ? BACKOFF_MAX_MS : H.backoff * 2;
}

static int helper_start(void)
{
    int to[2], from[2];
    const char *override = getenv("WMF_HELPER");        /* a shell command; used by the tests */
    const char *script;
    char *enc = NULL;
    pid_t pid;

    if (now_ms() < H.retry_at)
        return -1;
    if (!override) {
        script = getenv("WMF_HELPER_SCRIPT");
        enc = encode_script(script ? script : PKGDATADIR "/mdns-helper.ps1");
        if (!enc) {
            diag(1, "E02", "the Windows helper script is missing, unreadable, not plain ASCII, or too large, so "
                 ".local names cannot be looked up",
                 "reinstall the package, or check that the file exists and is readable; the WMF_HELPER_SCRIPT "
                 "environment variable can point to another copy",
                 "cannot load the helper script %s", script ? script : PKGDATADIR "/mdns-helper.ps1");
            H.retry_at = now_ms() + BACKOFF_MAX_MS;
            return -1;
        }
    }
    if (pipe2(to, O_CLOEXEC) < 0 || pipe2(from, O_CLOEXEC) < 0) {
        diag(2, "E03", "the system is out of file descriptors or processes",
             "check the limits with: ulimit -n; ulimit -u", "cannot create pipes for the helper: %s", strerror(errno));
        free(enc);
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        diag(2, "E03", "the system is out of processes or memory", "check with: free -m; ulimit -u",
             "cannot start the helper process: %s", strerror(errno));
        free(enc);
        close(to[0]); close(to[1]); close(from[0]); close(from[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(to[0], 0);
        dup2(from[1], 1);
        if (override)
            execl("/bin/sh", "sh", "-c", override, (char *)NULL);
        else if (access(powershell_path, X_OK) == 0)
            execl(powershell_path, "powershell.exe", "-NoProfile", "-NonInteractive",
                  "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc, (char *)NULL);
        else {                                  /* not where configured: try $PATH (WSL appends Windows' PATH) */
            diag(-1, "W03", "powershell.exe is not at the configured path",
                 "if this keeps appearing, start the daemon with -w /path/to/powershell.exe",
                 "%s is not executable; trying powershell.exe from PATH", powershell_path);
            execlp("powershell.exe", "powershell.exe", "-NoProfile", "-NonInteractive",
                   "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc, (char *)NULL);
        }
        diag(-1, "E04", "WSL could not start Windows PowerShell. Either interop (running Windows programs from "
             "Linux) is off, or PowerShell is somewhere unexpected",
             "test it with: powershell.exe -NoProfile -Command 1   If that fails, make sure /etc/wsl.conf has no "
             "[interop] enabled=false, then run 'wsl --shutdown' from Windows. If PowerShell lives elsewhere, "
             "start the daemon with -w /path/to/powershell.exe",
             "cannot run powershell.exe: %s", strerror(errno));
        _exit(127);
    }
    free(enc);
    close(to[0]);
    close(from[1]);
    H.pid = pid;
    H.in = to[1];
    H.out = from[0];
    fcntl(H.in, F_SETFL, O_NONBLOCK);
    fcntl(H.out, F_SETFL, O_NONBLOCK);
    H.len = 0;
    logmsg("helper started (pid %d)", (int)pid);
    return 0;
}

/* ---------- jobs, connections, lookups ---------- */

struct job {
    int active;
    int tcp;                    /* index into conns[], or -1 for UDP */
    struct sockaddr_in from;
    uint8_t req[MAXPKT];
    size_t reqlen;
    struct dns_query q;
    int waiting;                /* 1: waiting on the helper; 0: relaying to an upstream */
    int has_stale;              /* an older address is known and is used if the lookup fails */
    uint32_t stale_ip;
    int sock;
    int up;
    long deadline;
};
static struct job jobs[MAXJOB];

struct conn {
    int fd;                     /* -1 when unused */
    uint8_t buf[MAXPKT + 2];
    size_t len;
    long deadline;
    int busy;                   /* a job is outstanding for this connection */
};
static struct conn conns[MAXTCP];

struct want {
    int used;
    char name[DNS_NAME_MAX];
    long deadline;
};
static struct want wants[MAXWANT];

static void conn_close(int i)
{
    if (conns[i].fd >= 0)
        close(conns[i].fd);
    conns[i].fd = -1;
    conns[i].len = 0;
    conns[i].busy = 0;
}

static void send_reply(int tcp, const struct sockaddr_in *from, const uint8_t *resp, size_t n)
{
    if (n == 0) {
        if (tcp >= 0)
            conn_close(tcp);
        return;
    }
    if (tcp < 0) {
        sendto(udp_fd, resp, n, MSG_DONTWAIT, (const struct sockaddr *)from, sizeof *from);
    } else {
        uint8_t out[MAXPKT + 2];

        out[0] = (uint8_t)(n >> 8);
        out[1] = (uint8_t)n;
        memcpy(out + 2, resp, n);
        send(conns[tcp].fd, out, n + 2, MSG_NOSIGNAL | MSG_DONTWAIT);
        conn_close(tcp);                        /* one query per connection */
    }
}

static void job_free(struct job *j)
{
    if (j->sock >= 0)
        close(j->sock);
    j->sock = -1;
    j->active = 0;
}

static void job_done(struct job *j, const uint8_t *resp, size_t n)
{
    send_reply(j->tcp, &j->from, resp, n);
    job_free(j);
}

static void job_stale_or_fail(struct job *j);

static void job_servfail(struct job *j)
{
    uint8_t resp[DNS_MIN_RESP];
    size_t n = dns_build_reply(j->req, j->q.qend, DNS_RCODE_SERVFAIL, resp, sizeof resp);

    job_done(j, resp, n);
}

/* The lookup failed: fall back to the last-known-good address if there is one. */
static void job_stale_or_fail(struct job *j)
{
    if (j->has_stale) {
        uint8_t resp[MAXPKT];
        size_t n = dns_build_a(j->req, j->q.qend, j->stale_ip, resp, sizeof resp);

        job_done(j, resp, n);
    } else {
        job_servfail(j);
    }
}

static struct job *job_alloc(void)
{
    for (int i = 0; i < MAXJOB; i++) {
        if (!jobs[i].active) {
            memset(&jobs[i], 0, sizeof jobs[i]);
            jobs[i].active = 1;
            jobs[i].sock = -1;
            jobs[i].tcp = -1;
            return &jobs[i];
        }
    }
    return NULL;
}

/* Send the job's request to the next usable upstream.  Returns 0 when none are left. */
static int relay_try(struct job *j)
{
    for (; j->up < nup; j->up++) {
        const struct sockaddr_in *u = &upstream[(up_pref + j->up) % nup];
        int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);

        if (s < 0)
            continue;
        if (connect(s, (const struct sockaddr *)u, sizeof *u) == 0
            && send(s, j->req, j->reqlen, 0) == (ssize_t)j->reqlen) {
            j->sock = s;
            j->deadline = now_ms() + RELAY_TIMEOUT_MS;
            return 1;
        }
        diag(4, "W07", "the upstream DNS server could not be reached from here",
             "check the network, and that the address is right (see the 'upstream' lines at start-up)",
             "cannot send to upstream %s: %s", inet_ntoa(u->sin_addr), strerror(errno));
        close(s);
    }
    if (nup == 0)
        diag(5, "E06", "the daemon does not know where to send ordinary (non-.local) DNS queries",
             "give it one with -u ADDRESS, for example -u 8.8.8.8, or reuse the nameservers that were in "
             "/etc/resolv.conf before the install (saved as /etc/resolv.conf.pre-wsl-dns-forward). Keep "
             "those lines after 'nameserver 127.0.0.1' and the daemon finds them by itself",
             "no upstream resolver is configured, so only .local names can be answered");
    else
        diag(5, "W07", "no upstream DNS server replied: the network may be down, or the address is wrong",
             "test one directly with: dig @ADDRESS example.com   (ADDRESS is shown in the 'upstream' lines at "
             "start-up). Plain names such as example.com will not resolve until one answers. If the address "
             "is wrong, list the right nameservers after 'nameserver 127.0.0.1' in /etc/resolv.conf or use -u",
             "no upstream resolver answered");
    return 0;
}

/* Ask the helper about name (one outstanding request per name).  Returns 0 on failure. */
static int want_add(const char *name)
{
    struct want *w = NULL;
    char line[DNS_NAME_MAX + 2];
    int n;

    for (int i = 0; i < MAXWANT; i++) {
        if (wants[i].used && strcmp(wants[i].name, name) == 0)
            return 1;
        if (!wants[i].used && !w)
            w = &wants[i];
    }
    if (!w)
        return 0;
    if (H.pid < 0 && helper_start() < 0)
        return 0;
    n = snprintf(line, sizeof line, "%s\n", name);
    if (n < 0 || write(H.in, line, (size_t)n) != n) {
        helper_stop();
        return 0;
    }
    w->used = 1;
    snprintf(w->name, sizeof w->name, "%s", name);
    w->deadline = now_ms() + HELPER_TIMEOUT_MS;
    return 1;
}

static void want_done(struct want *w, uint32_t ip, int found)
{
    char name[DNS_NAME_MAX];

    snprintf(name, sizeof name, "%s", w->name);
    w->used = 0;
    if (found)
        cache_put(name, ip);
    else if (cache_find(name))
        logmsg("lookup of %s failed; keeping the last-known-good address", name);
    else
        logmsg("lookup of %s failed", name);
    for (int i = 0; i < MAXJOB; i++) {
        struct job *j = &jobs[i];

        if (!j->active || !j->waiting || strcmp(j->q.name, name) != 0)
            continue;
        if (found) {
            uint8_t resp[MAXPKT];
            size_t n = dns_build_a(j->req, j->q.qend, ip, resp, sizeof resp);

            job_done(j, resp, n);
        } else {
            job_stale_or_fail(j);
        }
    }
}

static void wants_fail_all(void)
{
    for (int i = 0; i < MAXWANT; i++)
        if (wants[i].used)
            want_done(&wants[i], 0, 0);
}

static void handle_helper_line(const char *line)
{
    char name[DNS_NAME_MAX];
    uint32_t ip = 0;
    int found;

    if (!dns_parse_helper_line(line, name, &ip, &found))
        return;
    for (int i = 0; i < MAXWANT; i++) {
        if (wants[i].used && strcmp(wants[i].name, name) == 0) {
            H.backoff = BACKOFF_MIN_MS;
            want_done(&wants[i], ip, found);
            return;
        }
    }
}

static void helper_readable(void)
{
    size_t off = H.len < sizeof H.buf - 1 ? H.len : 0;      /* an over-long line can only be garbage */
    ssize_t r = read(H.out, H.buf + off, sizeof H.buf - 1 - off);

    H.len = off;

    if (r == 0 || (r < 0 && errno != EAGAIN && errno != EINTR)) {
        diag(3, "W05", "Windows PowerShell stopped, so new .local lookups fail until the daemon restarts it "
             "automatically (addresses already seen are still answered)",
             "if it keeps happening, run the helper by hand to see its error: powershell.exe -NoProfile "
             "-ExecutionPolicy Bypass -File " PKGDATADIR "/mdns-helper.ps1  (antivirus or a PowerShell policy "
             "can block it)",
             "the Windows helper exited");
        helper_stop();
        wants_fail_all();
        return;
    }
    if (r < 0)
        return;
    H.len += (size_t)r;
    for (;;) {
        char *nl = memchr(H.buf, '\n', H.len);
        size_t used;

        if (!nl) {
            if (H.len >= sizeof H.buf - 1)
                H.len = 0;                      /* an over-long line can only be garbage */
            break;
        }
        *nl = '\0';
        handle_helper_line(H.buf);
        used = (size_t)(nl - H.buf) + 1;
        memmove(H.buf, H.buf + used, H.len - used);
        H.len -= used;
    }
}

/* Serve one query.  tcp is the connection index or -1. */
static void handle_query(const uint8_t *buf, size_t n, int tcp, const struct sockaddr_in *from)
{
    uint8_t resp[MAXPKT];
    struct dns_query q;
    size_t rl;
    struct job *j;
    const struct entry *e;

    switch (dns_classify(buf, n, &q, resp, sizeof resp, &rl)) {
    case DNS_DROP:
        send_reply(tcp, from, NULL, 0);
        return;
    case DNS_REPLY:
        send_reply(tcp, from, resp, rl);
        return;
    case DNS_RELAY:
        j = job_alloc();
        if (!j) {
            send_reply(tcp, from, NULL, 0);
            return;
        }
        j->tcp = tcp;
        if (from)
            j->from = *from;
        memcpy(j->req, buf, n);
        j->reqlen = n;
        j->q = q;
        if (tcp >= 0)
            conns[tcp].busy = 1;
        if (!relay_try(j))
            job_servfail(j);
        return;
    case DNS_LOCAL_A:
        break;
    }

    e = cache_find(q.name);
    if (e && e->when) {
        long age = now_ms() - e->when;

        if (age < fresh_ms) {                   /* fresh: answer now, and refresh before it expires */
            rl = dns_build_a(buf, q.qend, e->ip, resp, sizeof resp);
            send_reply(tcp, from, resp, rl);
            if (age >= fresh_ms / 4 * 3)
                want_add(q.name);
            return;
        }
    }
    /* Missing or expired.  Look it up and wait, so a host whose address changed is never answered with the
     * old one; use the old address only if the lookup fails or takes too long. */
    j = job_alloc();
    if (!j) {
        if (e)
            rl = dns_build_a(buf, q.qend, e->ip, resp, sizeof resp);
        else
            rl = dns_build_reply(buf, q.qend, DNS_RCODE_SERVFAIL, resp, sizeof resp);
        send_reply(tcp, from, resp, rl);
        return;
    }
    j->tcp = tcp;
    if (from)
        j->from = *from;
    memcpy(j->req, buf, n);
    j->reqlen = n;
    j->q = q;
    j->waiting = 1;
    j->has_stale = e != NULL;
    j->stale_ip = e ? e->ip : 0;
    j->deadline = now_ms() + (e ? STALE_WAIT_MS : HELPER_TIMEOUT_MS);
    if (tcp >= 0)
        conns[tcp].busy = 1;
    if (!want_add(q.name))
        job_stale_or_fail(j);
}

/* ---------- sockets ---------- */

static int bind_sock(int type)
{
    int s = socket(AF_INET, type | SOCK_CLOEXEC | SOCK_NONBLOCK, 0), one = 1;
    struct sockaddr_in a;

    if (s < 0) {
        diag(-1, "E01", "the system refused to create a network socket", "check ulimit -n, and that networking "
             "is up", "socket: %s", strerror(errno));
        return -1;
    }
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)listen_port);
    if (inet_pton(AF_INET, listen_addr, &a.sin_addr) != 1) {
        diag(-1, "E01", "-l wants an IPv4 address such as 127.0.0.1", "check the -l option; see: wsl-dns-forward -h",
             "bad listen address %s", listen_addr);
        close(s);
        return -1;
    }
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 || (type == SOCK_STREAM && listen(s, 8) < 0)) {
        diag(-1, "E01",
             errno == EACCES ? "only root may listen on ports below 1024"
             : errno == EADDRINUSE ? "another program already uses this port; often a second copy of this "
               "daemon, or a DNS server such as dnsmasq or systemd-resolved"
             : "the address could not be opened",
             errno == EACCES ? "start the daemon as root (it then drops to an unprivileged user), or test with -p 5353"
             : errno == EADDRINUSE ? "see who has it with: ss -lunp 'sport = :53'   A leftover copy of this "
               "daemon can be stopped with: kill $(cat /run/wsl-dns-forward.pid)"
             : "check -l and -p",
             "cannot listen on %s port %d (%s): %s", listen_addr, listen_port,
             type == SOCK_STREAM ? "tcp" : "udp", strerror(errno));
        close(s);
        return -1;
    }
    return s;
}

static void accept_tcp(void)
{
    for (;;) {
        int c = accept4(tcp_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK), i;

        if (c < 0)
            return;
        for (i = 0; i < MAXTCP && conns[i].fd >= 0; i++)
            ;
        if (i == MAXTCP) {
            close(c);
            continue;
        }
        conns[i].fd = c;
        conns[i].len = 0;
        conns[i].busy = 0;
        conns[i].deadline = now_ms() + TCP_TIMEOUT_MS;
    }
}

static void conn_readable(int i)
{
    struct conn *c = &conns[i];
    ssize_t r;
    size_t want;

    if (c->busy) {                              /* a query is already in flight; ignore the rest */
        char sink[64];

        r = recv(c->fd, sink, sizeof sink, 0);
        if (r == 0)
            conn_close(i);
        return;
    }
    r = recv(c->fd, c->buf + c->len, sizeof c->buf - c->len, 0);
    if (r == 0 || (r < 0 && errno != EAGAIN && errno != EINTR)) {
        conn_close(i);
        return;
    }
    if (r < 0)
        return;
    c->len += (size_t)r;
    if (c->len < 2)
        return;
    want = (size_t)(c->buf[0] << 8 | c->buf[1]);
    if (want < 12 || want > MAXPKT) {
        conn_close(i);
        return;
    }
    if (c->len < want + 2)
        return;
    handle_query(c->buf + 2, want, i, NULL);
}

static void udp_readable(void)
{
    for (int k = 0; k < 32; k++) {
        uint8_t req[MAXPKT];
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(udp_fd, req, sizeof req, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);

        if (n < 0)
            return;
        handle_query(req, (size_t)n, -1, &from);
    }
}

static void job_readable(struct job *j)
{
    uint8_t rep[MAXPKT];
    ssize_t n = recv(j->sock, rep, sizeof rep, 0);

    if (n > 0 && dns_valid_relay_reply(j->req, j->reqlen, rep, (size_t)n)) {
        up_pref = (up_pref + j->up) % nup;              /* remember which one works */
        job_done(j, rep, (size_t)n);
    }
    /* otherwise: not an answer to this query; keep waiting until the deadline */
}

static void sweep_timers(void)
{
    long now = now_ms();

    for (int i = 0; i < MAXTCP; i++)
        if (conns[i].fd >= 0 && now >= conns[i].deadline) {
            for (int k = 0; k < MAXJOB; k++)
                if (jobs[k].active && jobs[k].tcp == i)
                    job_free(&jobs[k]);
            conn_close(i);
        }
    for (int i = 0; i < MAXWANT; i++)
        if (wants[i].used && now >= wants[i].deadline)
            want_done(&wants[i], 0, 0);
    for (int i = 0; i < MAXJOB; i++) {
        struct job *j = &jobs[i];

        if (!j->active || now < j->deadline)
            continue;
        if (j->waiting) {
            job_stale_or_fail(j);
        } else {
            close(j->sock);
            j->sock = -1;
            diag(6, "W07", "the upstream DNS server is slow, down, or the address is wrong",
                 "test it directly with: dig @ADDRESS example.com",
                 "upstream %s did not answer within %ld ms%s",
                 inet_ntoa(upstream[(up_pref + j->up) % nup].sin_addr),
                 RELAY_TIMEOUT_MS, j->up + 1 < nup ? "; trying the next one" : "");
            j->up++;
            if (!relay_try(j))
                job_servfail(j);
        }
    }
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
}

static void run_loop(void)
{
    while (!quit_flag) {
        struct pollfd pfd[2 + MAXTCP + MAXJOB + 1];
        int kind[2 + MAXTCP + MAXJOB + 1], idx[2 + MAXTCP + MAXJOB + 1];
        int np = 0;
        long next = 1000, now = now_ms();

        pfd[np] = (struct pollfd){ udp_fd, POLLIN, 0 };       kind[np] = 0; idx[np++] = 0;
        pfd[np] = (struct pollfd){ tcp_fd, POLLIN, 0 };       kind[np] = 1; idx[np++] = 0;
        for (int i = 0; i < MAXTCP; i++)
            if (conns[i].fd >= 0) {
                pfd[np] = (struct pollfd){ conns[i].fd, POLLIN, 0 };
                kind[np] = 2; idx[np++] = i;
                if (conns[i].deadline - now < next)
                    next = conns[i].deadline - now;
            }
        for (int i = 0; i < MAXJOB; i++)
            if (jobs[i].active) {
                if (jobs[i].sock >= 0) {
                    pfd[np] = (struct pollfd){ jobs[i].sock, POLLIN, 0 };
                    kind[np] = 3; idx[np++] = i;
                }
                if (jobs[i].deadline - now < next)
                    next = jobs[i].deadline - now;
            }
        if (H.out >= 0) {
            pfd[np] = (struct pollfd){ H.out, POLLIN, 0 };
            kind[np] = 4; idx[np++] = 0;
        }
        for (int i = 0; i < MAXWANT; i++)
            if (wants[i].used && wants[i].deadline - now < next)
                next = wants[i].deadline - now;
        if (next < 1)
            next = 1;

        if (poll(pfd, (nfds_t)np, (int)next) < 0 && errno != EINTR)
            break;
        for (int p = 0; p < np; p++) {
            if (!pfd[p].revents)
                continue;
            switch (kind[p]) {
            case 0: udp_readable(); break;
            case 1: accept_tcp(); break;
            case 2:
                if (conns[idx[p]].fd == pfd[p].fd)
                    conn_readable(idx[p]);
                break;
            case 3:
                if (jobs[idx[p]].active && jobs[idx[p]].sock == pfd[p].fd)
                    job_readable(&jobs[idx[p]]);
                break;
            case 4:
                if (H.out == pfd[p].fd)
                    helper_readable();
                break;
            }
        }
        sweep_timers();
    }
}

/* ---------- start-up ---------- */

static int add_upstream(const char *spec)
{
    char host[64];
    const char *colon = strchr(spec, ':');
    size_t hl = colon ? (size_t)(colon - spec) : strlen(spec);
    long port = 53;
    struct sockaddr_in *u;

    if (nup >= MAXUP || hl == 0 || hl >= sizeof host)
        return -1;
    memcpy(host, spec, hl);
    host[hl] = '\0';
    if (colon) {
        char *end;

        port = strtol(colon + 1, &end, 10);
        if (*end || port < 1 || port > 65535)
            return -1;
    }
    u = &upstream[nup];
    memset(u, 0, sizeof *u);
    u->sin_family = AF_INET;
    u->sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &u->sin_addr) != 1)
        return -1;
    nup++;
    return 0;
}

/*
 * Default upstreams: the non-loopback nameservers in /etc/resolv.conf.  The setup lists the system's existing
 * nameservers after 127.0.0.1, and they match whichever Windows and WSL version is running (the WSL gateway
 * on Windows 10, the 10.255.255.254 DNS tunnel on Windows 11, or Windows' own servers in mirrored mode).
 */
static void add_discovered(uint32_t ip)
{
    struct sockaddr_in *u;

    for (int i = 0; i < nup; i++)
        if (upstream[i].sin_addr.s_addr == ip)
            return;
    if (nup >= MAXUP)
        return;
    u = &upstream[nup++];
    memset(u, 0, sizeof *u);
    u->sin_family = AF_INET;
    u->sin_port = htons(53);
    u->sin_addr.s_addr = ip;
}

static void resolv_upstream(void)
{
    const char *path = getenv("WMF_RESOLV_CONF");
    FILE *f = fopen(path ? path : "/etc/resolv.conf", "re");
    char text[8192];
    uint32_t ips[MAXUP];
    size_t n;

    if (!f)
        return;
    n = fread(text, 1, sizeof text - 1, f);
    fclose(f);
    text[n] = '\0';
    n = (size_t)dns_parse_resolv_conf(text, ips, 4);
    for (size_t i = 0; i < n; i++)
        add_discovered(ips[i]);
}

static void default_upstream(void)              /* the WSL gateway, which proxies DNS on Windows 10 */
{
    FILE *f = fopen("/proc/net/route", "re");
    char line[256], ifn[32];
    unsigned long dst, gw;

    if (!f)
        return;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "%31s %lx %lx", ifn, &dst, &gw) == 3 && dst == 0 && gw)
            add_discovered((uint32_t)gw);
    fclose(f);
}

static void on_signal(int sig)
{
    (void)sig;
    quit_flag = 1;
}

static pid_t worker_pid = -1;
static volatile sig_atomic_t sup_quit;

static void on_sup_signal(int sig)
{
    sup_quit = 1;
    if (worker_pid > 0)
        kill(worker_pid, sig);
}

/*
 * Background mode: a root supervisor keeps the listening sockets open and restarts the worker if it ever
 * dies (a crash, an out-of-memory kill), so DNS is not lost.  Restarts back off from 1 to 30 seconds when
 * the worker keeps dying young.
 */
static int supervise(int (*run)(void))
{
    struct sigaction sa;
    long delay = 1000;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sup_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    while (!sup_quit) {
        long started = now_ms();
        int st = 0;
        pid_t w = fork();

        if (w < 0) {
            diag(-1, "E03", "the system is out of processes or memory", "check with: free -m; ulimit -u",
                 "cannot start the worker process: %s", strerror(errno));
        } else if (w == 0) {
            worker_pid = -1;
            _exit(run());
        } else {
            worker_pid = w;
            while (waitpid(w, &st, 0) < 0 && errno == EINTR)
                ;
            worker_pid = -1;
            if (sup_quit)
                break;
            if (WIFEXITED(st) && WEXITSTATUS(st) == 0)
                break;
            if (WIFEXITED(st) && WEXITSTATUS(st) == 1)      /* start-up failure: restarting cannot help */
                return 1;
            if (now_ms() - started > 10000)
                delay = 1000;
            diag(-1, "W16", "the DNS worker process died unexpectedly; the supervisor restarts it, and "
                 "queries in flight were lost",
                 "if this repeats, run the daemon in the foreground (without -D) to watch it, and report "
                 "the messages above this one",
                 "worker died (%s %d); restarting in %ld ms", WIFSIGNALED(st) ? "signal" : "exit status",
                 WIFSIGNALED(st) ? WTERMSIG(st) : WEXITSTATUS(st), delay);
        }
        for (long waited = 0; waited < delay && !sup_quit; waited += 100)
            poll(NULL, 0, 100);
        if (delay < 30000)
            delay *= 2;
    }
    return 0;
}

static void usage(FILE *out)
{
    fputs("usage: wsl-dns-forward [-D] [-l ADDR] [-p PORT] [-u HOST[:PORT]]... [-U USER]\n"
          "                       [-w POWERSHELL] [-c CACHEFILE] [-P PIDFILE] [-L LOGFILE]\n"
          "       wsl-dns-forward -h | -V\n", out);
}

static struct passwd *run_pw;

/* Everything after the sockets are open: drop root, load the cache, serve until told to stop. */
static int run_worker(void)
{
    struct sigaction sa;

    if (run_pw) {                                       /* drop root now that the port is bound */
        if (setgroups(0, NULL) < 0 || setgid(run_pw->pw_gid) < 0 || setuid(run_pw->pw_uid) < 0
            || setuid(0) == 0) {
            diag(-1, "E09", "the daemon was started as root but could not switch to the unprivileged user",
                 "check the user exists (id %s). To run as root anyway, start with -U root",
                 "cannot drop privileges to %s: %s", run_user, strerror(errno));
            return 1;
        }
    }
    if (chdir("/") < 0)
        return 1;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    cache_load();
    logmsg("listening on %s:%d, %d upstream(s), %d cached name(s), user %s, helper %s", listen_addr,
           listen_port, nup, ncache, run_pw ? run_user : "(unchanged)",
           getenv("WMF_HELPER") ? "(test override)" : powershell_path);
    for (int i = 0; i < nup; i++)
        logmsg("upstream %d: %s:%d%s", i + 1, inet_ntoa(upstream[i].sin_addr), ntohs(upstream[i].sin_port),
               up_auto ? " (discovered)" : "");
    run_loop();
    logmsg("stopping");
    helper_stop();
    for (int i = 0; i < MAXJOB; i++)
        if (jobs[i].active)
            job_free(&jobs[i]);
    for (int i = 0; i < MAXTCP; i++)
        conn_close(i);
    close(udp_fd);
    close(tcp_fd);
    return 0;
}

int main(int argc, char **argv)
{
    int daemonize = 0, o;
    const char *pidfile = NULL, *logfile = LOCALSTATEDIR "/log/wsl-dns-forward.log";
    struct passwd *pw = NULL;

    while ((o = getopt(argc, argv, "Dl:p:u:U:w:c:P:L:hV")) != -1) {
        switch (o) {
        case 'D': daemonize = 1; break;
        case 'l': listen_addr = optarg; break;
        case 'p': {
            char *end;
            long v = strtol(optarg, &end, 10);

            if (*end || v < 1 || v > 65535) {
                diag(-1, "E13", "-p wants a port number from 1 to 65535", "for example: -p 5353 (53 is the normal DNS port)",
                     "bad port: %s", optarg);
                return 2;
            }
            listen_port = (int)v;
            break;
        }
        case 'u':
            if (add_upstream(optarg) < 0) {
                diag(-1, "E13", "-u wants an IPv4 address with an optional port, and at most 4 may be given",
                     "for example: -u 172.20.0.1 or -u 192.168.1.1:53", "bad upstream: %s", optarg);
                return 2;
            }
            break;
        case 'U': run_user = optarg; break;
        case 'w': powershell_path = optarg; break;
        case 'c': cache_path = optarg; break;
        case 'P': pidfile = optarg; break;
        case 'L': logfile = optarg; break;
        case 'V': puts(PACKAGE_STRING); return 0;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 2;
        }
    }
    if (optind != argc) {
        usage(stderr);
        return 2;
    }
    {
        const char *fresh = getenv("WMF_FRESH_MS");         /* test hook: how long an address stays fresh */

        if (fresh && atol(fresh) > 0)
            fresh_ms = atol(fresh);
    }
    if (!nup) {
        /* Nothing given with -u.  Candidates, in order: the nameservers in /etc/resolv.conf, the WSL gateway
         * (Windows 10 runs a DNS proxy there) and 10.255.255.254 (the DNS tunnel of Windows 11 22H2 and
         * later).  Dead ones cost nothing once a live one has answered, because that one is tried first. */
        up_auto = 1;
        resolv_upstream();
        default_upstream();
        add_discovered(inet_addr("10.255.255.254"));
    }
    for (int i = 0; i < nup; i++) {                     /* never forward to ourselves */
        struct in_addr la;

        if (inet_pton(AF_INET, listen_addr, &la) == 1 && upstream[i].sin_addr.s_addr == la.s_addr
            && ntohs(upstream[i].sin_port) == listen_port) {
            diag(-1, "E13", "forwarding to itself would loop forever",
                 "choose a real DNS server with -u, or a different listen port with -p",
                 "upstream %s:%d is this server", listen_addr, listen_port);
            return 2;
        }
    }

    if (getuid() != 0 && strcmp(run_user, "nobody") != 0)
        diag(-1, "W10", "changing user needs root, and this process is not root", "nothing is wrong; to drop "
             "privileges, start the daemon as root", "not running as root, so -U %s has no effect", run_user);
    if (getuid() == 0 && strcmp(run_user, "root") == 0)
        diag(-1, "W10", "the daemon does not need root once it has opened port 53",
             "drop the '-U root' option to run as the unprivileged user nobody", "running as root");
    if (getuid() == 0 && strcmp(run_user, "root") != 0) {
        pw = getpwnam(run_user);
        if (!pw) {
            diag(-1, "E09", "the user given with -U (default: nobody) does not exist on this system",
                 "list users with: getent passwd   then pick one with -U NAME", "no such user: %s", run_user);
            return 1;
        }
    }
    udp_fd = bind_sock(SOCK_DGRAM);
    tcp_fd = bind_sock(SOCK_STREAM);
    if (udp_fd < 0 || tcp_fd < 0)
        return 1;
    for (int i = 0; i < MAXTCP; i++)
        conns[i].fd = -1;

    {                                                   /* the cache directory, owned by the run user */
        char dir[512];
        char *sl;

        snprintf(dir, sizeof dir, "%s", cache_path);
        sl = strrchr(dir, '/');
        if (sl && sl != dir) {
            *sl = '\0';
            if (mkdir(dir, 0755) < 0 && errno != EEXIST)
                diag(-1, "W08", "the directory for the last-known-good addresses cannot be created",
                     "create it by hand and give it to the run user, or choose another path with -c FILE",
                     "cannot create %s: %s", dir, strerror(errno));
            else if (pw && chown(dir, pw->pw_uid, pw->pw_gid) < 0)
                diag(-1, "W08", "the run user cannot write there, so last-known-good addresses will not be kept",
                     "fix the owner: chown USER /path (or run the daemon as root with -U root)",
                     "cannot give %s to %s: %s", dir, run_user, strerror(errno));
        }
    }

    if (daemonize) {
        pid_t p = fork();
        int lf, dn;

        if (p < 0)
            return 1;
        if (p > 0)
            return 0;
        setsid();
        lf = open(logfile, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (lf < 0)
            diag(-1, "W11", "the log file cannot be opened, so messages like this one will be lost",
                 "create the directory or choose another file with -L FILE; or omit -D to log to the terminal",
                 "cannot open log file %s: %s", logfile, strerror(errno));
        dn = open("/dev/null", O_RDWR);
        if (dn >= 0) {
            dup2(dn, 0);
            dup2(dn, 1);
            dup2(lf >= 0 ? lf : dn, 2);
        }
    }
    if (pidfile) {
        FILE *f = fopen(pidfile, "we");

        if (f) {
            fprintf(f, "%d\n", (int)getpid());
            fclose(f);
        } else {
            diag(-1, "W12", "the pid file cannot be written, so stopping the daemon by pid file will not work",
                 "check the directory exists and is writable, or choose another file with -P FILE",
                 "cannot write pid file %s: %s", pidfile, strerror(errno));
        }
    }

    run_pw = pw;
    if (daemonize)
        return supervise(run_worker);
    return run_worker();
}
