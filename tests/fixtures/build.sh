#!/usr/bin/env bash
# Rebuild the anyz test fixtures in tests/fixtures/bin/.
#
# Needs only clang + lld (any host: Linux, macOS or Windows) and, for the PE
# fixtures, MinGW-w64 gcc. No Linux/macOS SDK is required: binaries link against
# the stubs in src/ (libc_stub.c -> libc.so.6 with glibc symbol versions,
# libSystem.tbd), which provide symbol names only. The fixtures are never run.
#
# Tested with clang/lld 18 (Android NDK r27) and MinGW-w64 GCC 15 (MSYS2).
# MSVC fixtures are built separately by build_msvc.cmd.
#
# Override tools with: CLANG, LLD, STRIP, LIPO, MINGW_CC.
set -euo pipefail
cd "$(dirname "$0")"
# Git Bash / MSYS2 would otherwise rewrite /lib64/... arguments into Windows paths.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

CLANG=${CLANG:-clang}
LLD=${LLD:-ld.lld}
STRIP=${STRIP:-llvm-strip}
LIPO=${LIPO:-llvm-lipo}
MINGW_CC=${MINGW_CC:-x86_64-w64-mingw32-gcc}

SRC=src
OUT=bin
# Relative scratch dir: absolute MSYS paths like /tmp mean nothing to native tools.
TMP=.build-tmp
rm -rf "$TMP" && mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"

ELF="$CLANG --target=x86_64-linux-gnu"
ELF_LINK="$ELF -fuse-ld=lld -nostdlib -Wl,--build-id=sha1 -Wl,--hash-style=gnu"
INTERP=-Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2
CFLAGS="-fno-builtin"

echo "== ELF x86-64 (clang + lld, stub glibc)"
$ELF_LINK -shared -fPIC -O1 $CFLAGS -Wl,-soname,libc.so.6 \
    -Wl,--version-script=$SRC/libc_stub.map $SRC/libc_stub.c -o "$TMP/libc.so.6"
$ELF -c $SRC/start_x64.S -o "$TMP/start.o"

# Classic CTF target: no PIE, no canary, partial RELRO, NX on, lazy binding.
$ELF -O0 $CFLAGS -fno-pie -fno-stack-protector -fcf-protection=none \
    -c $SRC/vuln.c -o "$TMP/vuln.o"
$ELF_LINK -no-pie -Wl,--image-base=0x400000 $INTERP -Wl,-z,relro,-z,lazy \
    "$TMP/start.o" "$TMP/vuln.o" "$TMP/libc.so.6" -o $OUT/elf-x64-vuln
$STRIP -s $OUT/elf-x64-vuln -o $OUT/elf-x64-vuln-stripped

# Hardened C++: PIE, stack protector, full RELRO, CET (IBT+SHSTK), fortified calls.
$ELF -x c++ -O2 $CFLAGS -fPIE -fstack-protector-all -fcf-protection=full \
    -fno-exceptions -fno-rtti -c $SRC/hardened.cpp -o "$TMP/hardened.o"
$ELF_LINK -pie $INTERP -Wl,-z,relro,-z,now \
    "$TMP/start.o" "$TMP/hardened.o" "$TMP/libc.so.6" -o $OUT/elf-x64-hardened

# Static, executable stack, single RWX segment (-N): every mitigation off.
$ELF -O0 $CFLAGS -fno-pie -fno-stack-protector -fcf-protection=none -DSTATIC_LIBC \
    -c $SRC/libc_stub.c -o "$TMP/libc_static.o"
$ELF_LINK -static -Wl,--image-base=0x400000 -Wl,-z,execstack -Wl,-N \
    "$TMP/start.o" "$TMP/vuln.o" "$TMP/libc_static.o" -o $OUT/elf-x64-static

echo "== Mach-O arm64 / x86-64 / fat (clang + ld64.lld, stub libSystem)"
LD64="$LLD -flavor darwin"
$CLANG --target=arm64-apple-macos11 -O1 $CFLAGS -fstack-protector-all \
    -c $SRC/vuln.c -o "$TMP/vuln-arm64.o"
$LD64 -arch arm64 -platform_version macos 11.0 14.0 \
    "$TMP/vuln-arm64.o" $SRC/libSystem.tbd -o $OUT/macho-arm64
$CLANG --target=x86_64-apple-macos10.15 -O1 $CFLAGS -fstack-protector-all \
    -c $SRC/vuln.c -o "$TMP/vuln-x64.o"
$LD64 -arch x86_64 -platform_version macos 10.15 14.0 \
    "$TMP/vuln-x64.o" $SRC/libSystem.tbd -o $OUT/macho-x64
$LIPO -create $OUT/macho-x64 $OUT/macho-arm64 -output $OUT/macho-fat

echo "== PE32+ (MinGW-w64)"
# Put MinGW's own binutils first: other toolchains on PATH (e.g. the NDK) ship an ld.
PATH="$(dirname "$(command -v "$MINGW_CC")"):$PATH"
$MINGW_CC -O1 -Wl,--no-insert-timestamp $SRC/vuln_win.c -o $OUT/pe-x64-mingw.exe
$MINGW_CC -O1 -s -shared -Wl,--no-insert-timestamp $SRC/dll.c $SRC/dll.def \
    -o $OUT/pe-x64-dll.dll

echo "== raw x86-64 shellcode (execve /bin//sh)"
printf '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05' \
    > $OUT/shellcode-x64.bin

ls -l $OUT
