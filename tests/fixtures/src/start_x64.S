/* glibc-style _start for x86-64 plus the notes real crt1.o carries. */
    .text
    .globl _start
    .type _start, @function
_start:
    endbr64
    xor %ebp, %ebp
    mov %rdx, %r9
    pop %rsi
    mov %rsp, %rdx
    and $-16, %rsp
    push %rax
    push %rsp
    xor %r8d, %r8d
    xor %ecx, %ecx
    lea main(%rip), %rdi
    call *__libc_start_main@GOTPCREL(%rip)
    hlt
    .size _start, .-_start

    .section .note.ABI-tag, "a", @note
    .p2align 2
    .long 4, 16, 1          /* namesz, descsz, NT_GNU_ABI_TAG */
    .asciz "GNU"
    .long 0, 3, 2, 0        /* Linux 3.2.0 */

    .section .note.gnu.property, "a", @note
    .p2align 3
    .long 4, 16, 5          /* namesz, descsz, NT_GNU_PROPERTY_TYPE_0 */
    .asciz "GNU"
    .long 0xc0000002, 4, 3  /* X86_FEATURE_1_AND: IBT | SHSTK */
    .p2align 3

    .section .note.GNU-stack, "", @progbits
