#ifndef TP_UTIL_H
#define TP_UTIL_H

#include <stdint.h>

/* Monotonic milliseconds */
int64_t now_ms(void);

/* set fd non-blocking; returns 0 on success */
int set_nonblock(int fd);

/* epoll helpers */
int epoll_add_or_mod(int epfd, int fd, void *ptr, unsigned int events);
void epoll_remove_fd(int epfd, int fd);

/* sorting / statistics helpers */
int cmp_int64(const void *a, const void *b);
double avg_int64(const int64_t *arr, int n);
/* percentile: p in [0,100], arr MUST be sorted ascending, n>0 */
int64_t percentile_int64(const int64_t *arr, int n, double p);

#endif /* TP_UTIL_H */