// Hardened C++ fixture: PIE, stack protector, full RELRO, CET and FORTIFY-style
// calls (the __*_chk entry points are called directly, since fixtures are built
// without glibc headers).
extern "C" {
int puts(const char *);
long read(int, void *, unsigned long);
int __printf_chk(int, const char *, ...);
char *__strcpy_chk(char *, const char *, unsigned long);
}

namespace ctf {
struct Vault {
    int pin;
    bool open(int guess) const { return guess == pin; }
};

int check(const char *name, int len) {
    return len > 3 && name[0] == 'a';
}
}  // namespace ctf

int main(int argc, char **argv) {
    char buf[64];
    char name[32];
    long n = read(0, buf, sizeof buf - 1);
    if (n < 0) n = 0;
    buf[n] = 0;
    __strcpy_chk(name, argc > 1 ? argv[1] : "anon", sizeof name);
    ctf::Vault v{1337};
    if (ctf::check(name, (int)n) && v.open((int)n)) puts("opened");
    __printf_chk(1, "hi %s: %s\n", name, buf);
    return 0;
}
