/* A classic ret2win-style CTF challenge (anyz test fixture).
 * Prototypes are declared by hand so the file builds without any libc headers. */
int puts(const char *);
char *gets(char *);
int printf(const char *, ...);
int system(const char *);
int setvbuf(void *, char *, int, unsigned long);
#ifdef __APPLE__
extern void *__stdoutp;
#define STDOUT __stdoutp
#else
extern void *stdout;
#define STDOUT stdout
#endif

void win(void) {
    system("/bin/sh");
}

void vuln(void) {
    char buf[64];
    puts("What's your name?");
    gets(buf);
    printf("Hello, %s!\n", buf);
}

int main(void) {
    setvbuf(STDOUT, 0, 2, 0);
    vuln();
    puts("FLAG{this_is_not_the_flag}");
    return 0;
}
