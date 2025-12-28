/*
 * Usage:
 *   tlsperf <host-or-ip> [-p port] [-n count] [-t timeout_seconds] [-k] [-s servername]
 *
 * -p port            : TCP port to connect (default 443)
 * -n count           : number of handshakes to perform (default 1000)
 * -t timeout_seconds : connect timeout in seconds (default 5)
 * -k                 : skip certificate verification (insecure)
 * -s servername      : set SNI / server name (useful when host is IP)
 *
 */

 #define _POSIX_C_SOURCE 200809L

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <errno.h>
 #include <time.h>
 #include <sys/types.h>
 #include <sys/socket.h>
 #include <sys/time.h>
 #include <netdb.h>
 #include <arpa/inet.h>
 #include <netinet/in.h>

 #include <openssl/ssl.h>
 #include <openssl/err.h>

 static void usage(const char *prog) {
     fprintf(stderr,
         "Usage: %s <host-or-ip> [-p port] [-n count] [-t timeout_seconds] [-k] [-s servername]\n"
         "  -p port            : TCP port to connect (default 443)\n"
         "  -n count           : number of handshakes to perform (default 1000)\n"
         "  -t timeout_seconds : connect timeout in seconds (default 5)\n"
         "  -k                 : skip certificate verification (insecure)\n"
         "  -s servername      : set SNI / server name (useful when host is IP)\n",
         prog);
 }

 static int connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t alen, int timeout_sec) {
     struct timeval tv;
     tv.tv_sec = timeout_sec;
     tv.tv_usec = 0;
     setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
     setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

     if (connect(sockfd, addr, alen) == 0) return 0;
     return -1;
 }

 static int make_tls_handshake(SSL_CTX *ctx, const struct addrinfo *ai, const char *servername, int timeout_sec, int skip_verify) {
     int sock = -1;
     SSL *ssl = NULL;
     int ret = -1;

     sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
     if (sock < 0) goto cleanup;

     if (connect_with_timeout(sock, ai->ai_addr, ai->ai_addrlen, timeout_sec) != 0) goto cleanup;

     ssl = SSL_new(ctx);
     if (!ssl) goto cleanup;

     if (servername && *servername) {
         /* set SNI */
         SSL_set_tlsext_host_name(ssl, servername);
     }

     if (!skip_verify) {
         SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
     } else {
         SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
     }

     SSL_set_fd(ssl, sock);

     if (SSL_connect(ssl) <= 0) {
         goto cleanup;
     }

     /* Optionally could check peer cert here if not skipping verify */

     /* Graceful shutdown */
     SSL_shutdown(ssl);
     ret = 0;

 cleanup:
     if (ssl) {
         SSL_free(ssl);
     }
     if (sock >= 0) close(sock);
     return ret;
 }

 static long timediff_us(const struct timespec *a, const struct timespec *b) {
     long s = a->tv_sec - b->tv_sec;
     long ns = a->tv_nsec - b->tv_nsec;
     return s * 1000000L + ns / 1000L;
 }

 int main(int argc, char **argv) {
     if (argc < 2) {
         usage(argv[0]);
         return 1;
     }

     const char *host = argv[1];
     const char *servername = NULL;
     int port = 443;
     int count = 1000;
     int timeout_sec = 5;
     int skip_verify = 0;

     for (int i = 2; i < argc; ++i) {
         if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
             port = atoi(argv[++i]);
         } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
             count = atoi(argv[++i]);
         } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
             timeout_sec = atoi(argv[++i]);
         } else if (strcmp(argv[i], "-k") == 0) {
             skip_verify = 1;
         } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
             servername = argv[++i];
         } else {
             fprintf(stderr, "Unknown argument: %s\n", argv[i]);
             usage(argv[0]);
             return 1;
         }
     }

     char portstr[16];
     snprintf(portstr, sizeof(portstr), "%d", port);

     /* Resolve address once */
     struct addrinfo hints, *res = NULL;
     memset(&hints, 0, sizeof(hints));
     hints.ai_family = AF_UNSPEC;
     hints.ai_socktype = SOCK_STREAM;

     int gai = getaddrinfo(host, portstr, &hints, &res);
     if (gai != 0) {
         fprintf(stderr, "getaddrinfo(%s:%s) failed: %s\n", host, portstr, gai_strerror(gai));
         return 1;
     }

     /* Init OpenSSL */
     SSL_library_init();
     SSL_load_error_strings();
     OpenSSL_add_all_algorithms();

     SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
     if (!ctx) {
         fprintf(stderr, "SSL_CTX_new failed\n");
         freeaddrinfo(res);
         return 1;
     }

     /* Load default trusted roots (best-effort) */
     if (!skip_verify) {
         if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
             /* not fatal, but warn */
             fprintf(stderr, "Warning: could not load system default CA paths, certificate verification may fail\n");
         }
     }

     printf("Target: %s:%d  count=%d  timeout=%ds  skip_verify=%s  sni=%s\n",
            host, port, count, timeout_sec, skip_verify ? "yes" : "no", servername ? servername : "(none)");

     long min_us = LONG_MAX, max_us = 0;
     long sum_us = 0;
     int success = 0;

     struct timespec t_start_all, t_end_all;
     clock_gettime(CLOCK_MONOTONIC, &t_start_all);

     for (int i = 0; i < count; ++i) {
         struct timespec t0, t1;
         clock_gettime(CLOCK_MONOTONIC, &t0);

         int ok = make_tls_handshake(ctx, res, servername ? servername : host, timeout_sec, skip_verify);

         clock_gettime(CLOCK_MONOTONIC, &t1);
         long us = timediff_us(&t1, &t0);

         if (ok == 0) {
             success++;
             if (us < min_us) min_us = us;
             if (us > max_us) max_us = us;
             sum_us += us;
         } else {
             fprintf(stderr, "handshake %d failed (elapsed %ld us)\n", i + 1, us);
         }

         /* Optional: progress output every N iterations */
         if ((i + 1) % 100 == 0 || (i + 1) == count) {
             fprintf(stderr, "progress: %d/%d (success=%d)\n", i + 1, count, success);
         }
     }

     clock_gettime(CLOCK_MONOTONIC, &t_end_all);
     long total_us = timediff_us(&t_end_all, &t_start_all);

     printf("\nResults:\n");
     printf("  total attempts: %d\n", count);
     printf("  successful : %d\n", success);
     printf("  total elapsed (wall): %.3f s\n", total_us / 1e6);
     if (success > 0) {
         double avg = (double)sum_us / success;
         printf("  avg handshake (incl. TCP connect): %.3f ms\n", avg / 1000.0);
         printf("  min handshake: %.3f ms\n", min_us / 1000.0);
         printf("  max handshake: %.3f ms\n", max_us / 1000.0);
         double hps = (double)success / (total_us / 1e6);
         printf("  throughput: %.2f handshakes/sec\n", hps);
     } else {
         printf("  no successful handshake\n");
     }

     SSL_CTX_free(ctx);
     freeaddrinfo(res);
     ERR_free_strings();
     EVP_cleanup();

     return 0;
 }
