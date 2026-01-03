#define _GNU_SOURCE
#include "tp_worker.h"
#include "tp_util.h"
#include "tp_tls.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <sched.h>

/* slot state and struct are internal to worker.c */
typedef enum { SLOT_FREE = 0, SLOT_CONNECTING, SLOT_HANDSHAKING } slot_state_t;

struct slot {
    int id;
    int fd;
    SSL *ssl;
    slot_state_t state;
    int64_t start_ms;
    int64_t deadline_ms;
    const struct addrinfo *ai;
    int64_t conn_ms;
    int64_t tls_start_ms;
};

/* forward declarations */
static int slot_start_attempt(struct slot *s, int epfd, SSL_CTX *ctx, const char *servername, int timeout_sec, int skip_verify);
static void slot_cleanup(struct slot *s, int epfd);
static int slot_process_event(struct slot *s, int epfd, uint32_t events, SSL_CTX *ctx, const char *servername, int timeout_sec, int skip_verify);

/* claim one task from global tasks_left. returns 1 if claimed, 0 if none left or stop requested */
static int claim_task(atomic_int *tasks_left, atomic_int *stop_flag) {
    if (stop_flag && atomic_load(stop_flag)) return 0;
    int cur = atomic_load(tasks_left);
    while (cur > 0) {
        if (stop_flag && atomic_load(stop_flag)) return 0;
        if (atomic_compare_exchange_weak(tasks_left, &cur, cur - 1)) {
            return 1;
        }
    }
    return 0;
}

/* start a non-blocking connect on slot; returns:
 *  -1: immediate error
 *   0: pending (registered for EPOLLOUT)
 *   1: connected and started handshake (returned with ssl created and possibly handshake started)
 */
static int slot_start_attempt(struct slot *s, int epfd, SSL_CTX *ctx, const char *servername, int timeout_sec, int skip_verify) {
    int sock = socket(s->ai->ai_family, s->ai->ai_socktype, s->ai->ai_protocol);
    if (sock < 0) return -1;
    if (set_nonblock(sock) != 0) { close(sock); return -1; }
    s->fd = sock;
    s->start_ms = now_ms();
    s->deadline_ms = s->start_ms + (int64_t)timeout_sec * 1000;
    s->state = SLOT_CONNECTING;
    s->conn_ms = 0;
    s->tls_start_ms = 0;

    int c = connect(sock, s->ai->ai_addr, s->ai->ai_addrlen);
    if (c == 0) {
        /* connected immediately */
    } else if (c < 0) {
        if (errno != EINPROGRESS) {
            close(sock); s->fd = -1; s->state = SLOT_FREE;
            return -1;
        }
        /* pending */
        if (epoll_add_or_mod(epfd, sock, s, EPOLLOUT) != 0) { close(sock); s->fd = -1; s->state = SLOT_FREE; return -1; }
        return 0;
    }

    /* connected immediately -> record connect time and start SSL handshake */
    s->conn_ms = now_ms() - s->start_ms;
    s->tls_start_ms = now_ms();

    s->ssl = SSL_new(ctx);
    if (!s->ssl) { close(sock); s->fd = -1; s->state = SLOT_FREE; return -1; }
    if (servername && *servername) SSL_set_tlsext_host_name(s->ssl, servername);
    if (!skip_verify) SSL_set_verify(s->ssl, SSL_VERIFY_PEER, NULL);
    else SSL_set_verify(s->ssl, SSL_VERIFY_NONE, NULL);

    SSL_set_fd(s->ssl, s->fd);
    s->state = SLOT_HANDSHAKING;

    int r = SSL_connect(s->ssl);
    if (r == 1) {
        return 1;
    } else {
        int serr = SSL_get_error(s->ssl, r);
        uint32_t want = 0;
        if (serr == SSL_ERROR_WANT_READ) want = EPOLLIN;
        else if (serr == SSL_ERROR_WANT_WRITE) want = EPOLLOUT;
        else { SSL_free(s->ssl); s->ssl = NULL; close(sock); s->fd = -1; s->state = SLOT_FREE; return -1; }
        if (epoll_add_or_mod(epfd, s->fd, s, want) != 0) { SSL_free(s->ssl); s->ssl = NULL; close(sock); s->fd = -1; s->state = SLOT_FREE; return -1; }
        return 0;
    }
}

/* cleanup slot */
static void slot_cleanup(struct slot *s, int epfd) {
    if (s->fd >= 0) {
        epoll_remove_fd(epfd, s->fd);
        close(s->fd);
        s->fd = -1;
    }
    if (s->ssl) {
        SSL_free(s->ssl);
        s->ssl = NULL;
    }
    s->state = SLOT_FREE;
    s->conn_ms = 0;
    s->tls_start_ms = 0;
}

/* process events for a slot (called when epoll reports events)
 * return codes:
 *  0 = pending
 *  1 = handshake succeeded
 * -1 = handshake failed
 */
static int slot_process_event(struct slot *s, int epfd, uint32_t events, SSL_CTX *ctx, const char *servername, int timeout_sec, int skip_verify)
{
    (void)timeout_sec; /* parameter not used here; silence compiler warning */
    int64_t now = now_ms();
    if (now > s->deadline_ms) {
        slot_cleanup(s, epfd);
        return -1;
    }

    if (s->state == SLOT_CONNECTING) {
        int soerr = 0;
        socklen_t len = sizeof(soerr);
        if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &soerr, &len) < 0) { slot_cleanup(s, epfd); return -1; }
        if (soerr != 0) { errno = soerr; slot_cleanup(s, epfd); return -1; }

        /* connected */
        s->conn_ms = now_ms() - s->start_ms;
        s->tls_start_ms = now_ms();

        s->ssl = SSL_new(ctx);
        if (!s->ssl) { slot_cleanup(s, epfd); return -1; }
        if (servername && *servername) SSL_set_tlsext_host_name(s->ssl, servername);
        if (!skip_verify) SSL_set_verify(s->ssl, SSL_VERIFY_PEER, NULL);
        else SSL_set_verify(s->ssl, SSL_VERIFY_NONE, NULL);
        SSL_set_fd(s->ssl, s->fd);
        s->state = SLOT_HANDSHAKING;

        int r = SSL_connect(s->ssl);
        if (r == 1) return 1;
        int serr = SSL_get_error(s->ssl, r);
        uint32_t want = 0;
        if (serr == SSL_ERROR_WANT_READ) want = EPOLLIN;
        else if (serr == SSL_ERROR_WANT_WRITE) want = EPOLLOUT;
        else { slot_cleanup(s, epfd); return -1; }
        if (epoll_add_or_mod(epfd, s->fd, s, want) != 0) { slot_cleanup(s, epfd); return -1; }
        return 0;
    } else if (s->state == SLOT_HANDSHAKING) {
        if (events & (EPOLLERR | EPOLLHUP)) { slot_cleanup(s, epfd); return -1; }
        int r = SSL_connect(s->ssl);
        if (r == 1) return 1;
        int serr = SSL_get_error(s->ssl, r);
        uint32_t want = 0;
        if (serr == SSL_ERROR_WANT_READ) want = EPOLLIN;
        else if (serr == SSL_ERROR_WANT_WRITE) want = EPOLLOUT;
        else { slot_cleanup(s, epfd); return -1; }
        if (epoll_add_or_mod(epfd, s->fd, s, want) != 0) { slot_cleanup(s, epfd); return -1; }
        return 0;
    }

    slot_cleanup(s, epfd);
    return -1;
}

/* worker thread implementation */
void *worker_run(void *arg) {
    struct worker_args *w = (struct worker_args*)arg;
    int epfd = -1;
    SSL_CTX *ctx = NULL;
    struct slot *slots = NULL;

    ctx = create_thread_ctx(w->cipher_str, w->skip_verify);
    if (!ctx) {
        fprintf(stderr, "thread %d: SSL_CTX_new failed\n", w->thread_id);
        goto out;
    }

    epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        goto out;
    }

    /* optional CPU affinity */
    if (w->set_affinity_auto) {
        long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
        if (nprocs > 0) {
            int cpu = w->thread_id % (int)nprocs;
            cpu_set_t cpus;
            CPU_ZERO(&cpus);
            CPU_SET(cpu, &cpus);
            if (sched_setaffinity(0, sizeof(cpus), &cpus) != 0) {
                /* not fatal */
            }
        }
    }

    int sc = w->slots_count;
    slots = calloc((size_t)sc, sizeof(struct slot));
    if (!slots) {
        perror("calloc slots");
        goto out;
    }
    for (int i = 0; i < sc; ++i) {
        slots[i].id = i;
        slots[i].fd = -1;
        slots[i].ssl = NULL;
        slots[i].state = SLOT_FREE;
        slots[i].ai = w->ai;
        slots[i].conn_ms = 0;
        slots[i].tls_start_ms = 0;
    }

    /* local buffers */
    int cap = w->capacity;
    int idx = 0;
    struct epoll_event events[64];

    /* initial fill of slots */
    for (int i = 0; i < sc; ++i) {
        if (!claim_task(w->tasks_left, w->stop_flag)) break;
        int rc = slot_start_attempt(&slots[i], epfd, ctx, w->servername, w->timeout_sec, w->skip_verify);
        if (rc < 0) {
            /* immediate failure */
            w->failures++;
            continue;
        } else if (rc == 1) {
            /* immediate success */
            int64_t conn_ms = slots[i].conn_ms;
            int64_t tls_ms = now_ms() - slots[i].tls_start_ms;
            if (idx < cap) {
                w->conn_times[idx] = conn_ms;
                w->tls_times[idx] = tls_ms;
                /* store cipher and version if buffers present */
                if (w->cipher_names) {
                    const char *cname = SSL_get_cipher_name(slots[i].ssl);
                    if (cname) strncpy(&w->cipher_names[idx * 64], cname, 63);
                    else w->cipher_names[idx * 64] = '\0';
                }
                if (w->tls_versions) {
                    const char *v = SSL_get_version(slots[i].ssl);
                    if (v) strncpy(&w->tls_versions[idx * 16], v, 15);
                    else w->tls_versions[idx * 16] = '\0';
                }
                idx++;
            }
            w->successes++;
            slot_cleanup(&slots[i], epfd);
        } else {
            /* pending */
        }
    }

    /* main loop */
    while (1) {
        /* if stop requested and no active slots, exit */
        int active = 0;
        for (int i = 0; i < sc; ++i) if (slots[i].state != SLOT_FREE) { active = 1; break; }

        if (!active) {
            /* try to claim one more task to keep loop moving */
            if (!claim_task(w->tasks_left, w->stop_flag)) break;
            /* find a free slot to start */
            int found = 0;
            for (int i = 0; i < sc; ++i) if (slots[i].state == SLOT_FREE) {
                int rc = slot_start_attempt(&slots[i], epfd, ctx, w->servername, w->timeout_sec, w->skip_verify);
                if (rc < 0) { w->failures++; }
                else if (rc == 1) {
                    int64_t conn_ms = slots[i].conn_ms;
                    int64_t tls_ms = now_ms() - slots[i].tls_start_ms;
                    if (idx < cap) {
                        w->conn_times[idx] = conn_ms;
                        w->tls_times[idx] = tls_ms;
                        if (w->cipher_names) {
                            const char *cname = SSL_get_cipher_name(slots[i].ssl);
                            if (cname) strncpy(&w->cipher_names[idx * 64], cname, 63);
                            else w->cipher_names[idx * 64] = '\0';
                        }
                        if (w->tls_versions) {
                            const char *v = SSL_get_version(slots[i].ssl);
                            if (v) strncpy(&w->tls_versions[idx * 16], v, 15);
                            else w->tls_versions[idx * 16] = '\0';
                        }
                        idx++;
                    }
                    w->successes++;
                    slot_cleanup(&slots[i], epfd);
                }
                found = 1;
                break;
            }
            (void)found;
        }

        int n = epoll_wait(epfd, events, sizeof(events)/sizeof(events[0]), 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < n; ++i) {
            struct slot *s = (struct slot*)events[i].data.ptr;
            if (!s) continue;
            uint32_t ev = events[i].events;
            int res = slot_process_event(s, epfd, ev, ctx, w->servername, w->timeout_sec, w->skip_verify);
            if (res == 0) {
                /* pending */
                continue;
            } else if (res == 1) {
                /* success */
                int64_t conn_ms = s->conn_ms;
                int64_t tls_ms = now_ms() - s->tls_start_ms;
                if (idx < cap) {
                    w->conn_times[idx] = conn_ms;
                    w->tls_times[idx] = tls_ms;
                    if (w->cipher_names) {
                        const char *cname = SSL_get_cipher_name(s->ssl);
                        if (cname) strncpy(&w->cipher_names[idx * 64], cname, 63);
                        else w->cipher_names[idx * 64] = '\0';
                    }
                    if (w->tls_versions) {
                        const char *v = SSL_get_version(s->ssl);
                        if (v) strncpy(&w->tls_versions[idx * 16], v, 15);
                        else w->tls_versions[idx * 16] = '\0';
                    }
                    idx++;
                }
                w->successes++;
                /* graceful shutdown */
                SSL_shutdown(s->ssl);
                slot_cleanup(s, epfd);
                /* try to claim new task and restart slot */
                if (claim_task(w->tasks_left, w->stop_flag)) {
                    int rc = slot_start_attempt(s, epfd, ctx, w->servername, w->timeout_sec, w->skip_verify);
                    if (rc < 0) { w->failures++; slot_cleanup(s, epfd); }
                    else if (rc == 1) {
                        int64_t conn2 = s->conn_ms;
                        int64_t tls2 = now_ms() - s->tls_start_ms;
                        if (idx < cap) {
                            w->conn_times[idx] = conn2;
                            w->tls_times[idx] = tls2;
                            if (w->cipher_names) {
                                const char *cname = SSL_get_cipher_name(s->ssl);
                                if (cname) strncpy(&w->cipher_names[idx * 64], cname, 63);
                                else w->cipher_names[idx * 64] = '\0';
                            }
                            if (w->tls_versions) {
                                const char *v = SSL_get_version(s->ssl);
                                if (v) strncpy(&w->tls_versions[idx * 16], v, 15);
                                else w->tls_versions[idx * 16] = '\0';
                            }
                            idx++;
                        }
                        w->successes++;
                        SSL_shutdown(s->ssl);
                        slot_cleanup(s, epfd);
                    }
                }
            } else { /* res == -1 failure */
                w->failures++;
                slot_cleanup(s, epfd);
                if (claim_task(w->tasks_left, w->stop_flag)) {
                    int rc = slot_start_attempt(s, epfd, ctx, w->servername, w->timeout_sec, w->skip_verify);
                    if (rc < 0) { w->failures++; slot_cleanup(s, epfd); }
                    else if (rc == 1) {
                        int64_t conn2 = s->conn_ms;
                        int64_t tls2 = now_ms() - s->tls_start_ms;
                        if (idx < cap) {
                            w->conn_times[idx] = conn2;
                            w->tls_times[idx] = tls2;
                            if (w->cipher_names) {
                                const char *cname = SSL_get_cipher_name(s->ssl);
                                if (cname) strncpy(&w->cipher_names[idx * 64], cname, 63);
                                else w->cipher_names[idx * 64] = '\0';
                            }
                            if (w->tls_versions) {
                                const char *v = SSL_get_version(s->ssl); /* note: SSL_get_version is a typo? Keep as previous implementation */
                                if (v) strncpy(&w->tls_versions[idx * 16], v, 15);
                                else w->tls_versions[idx * 16] = '\0';
                            }
                            idx++;
                        }
                        w->successes++;
                        SSL_shutdown(s->ssl);
                        slot_cleanup(s, epfd);
                    }
                }
            }
        }

        /* deadline sweep */
        int64_t tnow = now_ms();
        for (int i = 0; i < sc; ++i) {
            if (slots[i].state != SLOT_FREE && tnow > slots[i].deadline_ms) {
                w->failures++;
                slot_cleanup(&slots[i], epfd);
                if (claim_task(w->tasks_left, w->stop_flag)) {
                    int rc = slot_start_attempt(&slots[i], epfd, ctx, w->servername, w->timeout_sec, w->skip_verify);
                    if (rc < 0) { w->failures++; slot_cleanup(&slots[i], epfd); }
                    else if (rc == 1) {
                        int64_t conn2 = slots[i].conn_ms;
                        int64_t tls2 = now_ms() - slots[i].tls_start_ms;
                        if (idx < cap) {
                            w->conn_times[idx] = conn2;
                            w->tls_times[idx] = tls2;
                            if (w->cipher_names) {
                                const char *cname = SSL_get_cipher_name(slots[i].ssl);
                                if (cname) strncpy(&w->cipher_names[idx * 64], cname, 63);
                                else w->cipher_names[idx * 64] = '\0';
                            }
                            if (w->tls_versions) {
                                const char *v = SSL_get_version(slots[i].ssl);
                                if (v) strncpy(&w->tls_versions[idx * 16], v, 15);
                                else w->tls_versions[idx * 16] = '\0';
                            }
                            idx++;
                        }
                        w->successes++;
                        SSL_shutdown(slots[i].ssl);
                        slot_cleanup(&slots[i], epfd);
                    }
                }
            }
        }
    }

    /* store successes count */
    w->successes = idx;

out:
    if (slots) {
        for (int i = 0; i < w->slots_count; ++i) slot_cleanup(&slots[i], epfd);
        free(slots);
    }
    if (epfd >= 0) close(epfd);
    if (ctx) SSL_CTX_free(ctx);
    return NULL;
}