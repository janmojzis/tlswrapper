/*
20171021
Jan Mojzis
Public domain.
*/
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <netdb.h>
#include <netinet/in.h>
#include "e.h"
#include "blocking.h"
#include "log.h"
#include "jail.h"
#include "randommod.h"
#include "resolvehost.h"

static void swap(unsigned char *x, unsigned char *y) {

    unsigned char t[16];

    memcpy(t, x, 16);
    memcpy(x, y, 16);
    memcpy(y, t, 16);
}

static void sortip(unsigned char *s, long long nn) {

    long long i;
    long long n = nn;

    if (nn < 0) return;

    n >>= 4;
    while (n > 1) {
        i = randommod(n);
        --n;
        swap(s + 16 * i, s + 16 * n);
    }

    for (i = 0; i + 16 <= nn; i += 16) {
        if (memcmp(s + i, "\0\0\0\0\0\0\0\0\0\0\377\377", 12)) {
            swap(s + i, s);
            break;
        }
    }
}

long long resolvehost(unsigned char *ip, long long iplen, const char *host) {

    int err;
    struct addrinfo *res, *res0 = 0, hints;
    long long len = 0;

    log_t3("resolvehost(host = ", host, ")");

    if (!ip || iplen < 16 || !host) {
        errno = EINVAL;
        return -1;
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    err = getaddrinfo(host, 0, &hints, &res0);
    if (err) {
        len = -1;
        log_t6("getaddrinfo(host = ", host, ") = ", gai_strerror(err),
               ", errno = ", e_str(errno));
        /* XXX, getaddrinfo error handling is funny */
        if (err == EAI_NONAME && errno == EMFILE) err = EAI_SYSTEM;
        if (err != EAI_SYSTEM) errno = 0;
        if (err == EAI_NONAME) len = 0;
#ifdef EAI_NODATA
        if (err == EAI_NODATA) len = 0;
#endif
        goto done;
    }

    for (res = res0; res; res = res->ai_next) {

        if (res->ai_addrlen == sizeof(struct sockaddr_in)) {
            if (len + 16 <= iplen) {
                memcpy(ip + len, "\0\0\0\0\0\0\0\0\0\0\377\377", 12);
                memcpy(ip + len + 12,
                       &((struct sockaddr_in *) res->ai_addr)->sin_addr, 4);
                len += 16;
            }
        }
        if (res->ai_addrlen == sizeof(struct sockaddr_in6)) {
            if (len + 16 <= iplen) {
                memcpy(ip + len,
                       &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr, 16);
                len += 16;
            }
        }
    }
    if (len > 0) {
        long long i;
        sortip(ip, len);
        for (i = 0; i < iplen - len; ++i) ip[len + i] = ip[i];
    }
done:
    log_t4("resolvehost(host = ", host, ") = ", lognum(len));
    if (res0) freeaddrinfo(res0);
    return len;
}

static pid_t resolvehost_pid = -1;
static int resolvehost_fd = -1;

int resolvehost_init(void) {

    int sockets[2] = {-1, -1};

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == -1) goto cleanup;

    resolvehost_pid = fork();
    if (resolvehost_pid == -1) goto cleanup;
    if (resolvehost_pid == 0) {
        unsigned char buf[257];
        unsigned char ip[128 + 1];
        long long r, iplen = 0;
        struct pollfd p[1];
        pid_t ppid = getppid();

        close(sockets[1]);
        blocking_disable(sockets[0]);

        if (jail(0, 0, 0) == -1) _exit(111);

        while (ppid == getppid()) {
            p[0].fd = sockets[0];
            p[0].events = POLLIN;
            jail_poll(p, 1, 1000);
            if (p[0].revents) {
                r = recv(sockets[0], buf, sizeof buf, 0);
                if (r == sizeof buf) break;
                if (r == -1) {
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN) continue;
                    if (errno == EWOULDBLOCK) continue;
                }
                if (r == -1) _exit(111);
                if (r == 0) break;

                buf[255] = 0;
                iplen = resolvehost(ip + 1, sizeof ip - 1, (char *) buf);
                ip[0] = iplen;
                if (iplen == -1) iplen = 0;
                iplen += 1;

                r = send(sockets[0], ip, iplen, 0);
                if (r == -1) _exit(111);
            }
        }
        _exit(0);
    }
    close(sockets[0]);
    resolvehost_fd = sockets[1];
    return 1;

cleanup:
    if (sockets[0] != -1) close(sockets[0]);
    if (sockets[1] != -1) close(sockets[1]);
    return 0;
}

long long resolvehost_do(unsigned char *ip, long long iplen, const char *host) {

    char buf[256] = {0};
    long long i, len, r;

    if (!ip || iplen < 16 || !host) {
        errno = EINVAL;
        return -1;
    }

    for (i = 0; host[i]; ++i) {};

    if (i > 255) {
        errno = EINVAL;
        return -1;
    }

    for (i = 0; host[i]; ++i) buf[i] = host[i];

    r = send(resolvehost_fd, buf, sizeof buf, 0);
    if (r != sizeof buf) return -1;

    r = recv(resolvehost_fd, buf, sizeof buf, 0);
    if (r <= 0) return -1;
    if (r == 1) return buf[0];
    len = r - 1;
    if (iplen < len) len = iplen;

    for (i = 0; i < len; ++i) ip[i] = (unsigned char) buf[i + 1];
    return len;
}

void resolvehost_close(void) {
    if (resolvehost_fd != -1) {
        unsigned char buf[257] = {0};
        /*
        we don't have permission to kill the child process,
        so sending bulfen > 256 signals the end of the child process
        */
        (void) send(resolvehost_fd, buf, sizeof buf, 0);
        close(resolvehost_fd);
        resolvehost_fd = -1;
    }
    if (resolvehost_pid != -1) {
        int status;
        long long r;
        do {
            r = waitpid(resolvehost_pid, &status, 0);
        } while (r == -1 && errno == EINTR);
        resolvehost_pid = -1;
    }
}
