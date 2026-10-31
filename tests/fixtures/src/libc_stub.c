/* Link-time stand-in for glibc: only symbol names and versions matter, the code
 * never runs. Built as libc.so.6 with libc_stub.map, or linked statically. */
typedef unsigned long size_t;
int puts(const char *s) { (void)s; return 0; }
char *gets(char *s) { return s; }
int printf(const char *f, ...) { (void)f; return 0; }
int system(const char *c) { (void)c; return 0; }
long read(int fd, void *b, size_t n) { (void)fd; (void)b; (void)n; return 0; }
int setvbuf(void *s, char *b, int m, size_t n) { (void)s; (void)b; (void)m; (void)n; return 0; }
char *strcpy(char *d, const char *s) { (void)s; return d; }
void exit(int c) { (void)c; for (;;) {} }
int __libc_start_main(int (*m)(int, char **, char **), int argc, char **argv,
                      void (*i)(void), void (*f)(void), void (*r)(void), void *e) {
    (void)i; (void)f; (void)r; (void)e;
    exit(m(argc, argv, 0));
    return 0;
}
void *stdout;
void *stdin;
#ifndef STATIC_LIBC
int __printf_chk(int flag, const char *f, ...) { (void)flag; (void)f; return 0; }
char *__strcpy_chk(char *d, const char *s, size_t n) { (void)s; (void)n; return d; }
void __stack_chk_fail(void) { for (;;) {} }
#endif
