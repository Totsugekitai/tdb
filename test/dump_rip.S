.intel_syntax noprefix
.code64
.global vmmcall
vmmcall:
    pushq   r8
    pushq   rdi
    movq    rax, [rdi + 0x00]
    movq    rbx, [rdi + 0x08]
    movq    rcx, [rdi + 0x10]
    movq    rdx, [rdi + 0x18]
    movq    rsi, [rdi + 0x20]
    movq    rdi, [rdi + 0x28]
    vmcall
    popq    r8
    movq    [r8 + 0x30], rax
    movq    [r8 + 0x38], rbx
    movq    [r8 + 0x40], rcx
    movq    [r8 + 0x48], rdx
    movq    [r8 + 0x50], rsi
    movq    [r8 + 0x58], rdi
    popq    r8
    ret
