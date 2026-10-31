/* Windows flavour of the CTF fixture (real headers: MinGW-w64 / MSVC). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

void win(void) { system("cmd.exe"); }

void vuln(void) {
    char buf[64];
    puts("What's your name?");
    if (fgets(buf, 256, stdin)) printf("Hello, %s!\n", buf);
}

int main(void) {
    if (IsDebuggerPresent()) return 1;
    LPVOID p = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (p) VirtualFree(p, 0, MEM_RELEASE);
    vuln();
    return 0;
}
