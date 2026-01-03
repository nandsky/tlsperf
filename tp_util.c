#define _POSIX_C_SOURCE 200809L
#include "tp_util.h"
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>

int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return -1;
    return 0;
}

int epoll_add_or_mod(int epfd, int fd, void *ptr, unsigned int events) {
    struct epoll_event ev;
    ev.events = events | EPOLLERR | EPOLLHUP;
    ev.data.ptr = ptr;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev) != 0) {
        if (errno == ENOENT) {
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) != 0) return -1;
        } else return -1;
    }
    return 0;
}

void epoll_remove_fd(int epfd, int fd) {
    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
}

int cmp_int64(const void *a, const void *b) {
    int64_t va = *(const int64_t*)a;
    int64_t vb = *(const int64_t*)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

double avg_int64(const int64_t *arr, int n) {
    if (n <= 0) return 0.0;
    long double s = 0;
    for (int i = 0; i < n; ++i) s += arr[i];
    return (double)(s / n);
}

int64_t percentile_int64(const int64_t *arr, int n, double p) {
    if (n <= 0) return 0;
    if (p <= 0) return arr[0];
    if (p >= 100) return arr[n-1];
    double pos = (p / 100.0) * (n - 1);
    int idx = (int)pos;
    double frac = pos - idx;
    if (idx + 1 < n) {
        return (int64_t)((1.0 - frac) * arr[idx] + frac * arr[idx+1] + 0.5);
    } else return arr[idx];
}