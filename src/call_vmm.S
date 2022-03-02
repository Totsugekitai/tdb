.intel_syntax noprefix
.code64
.global vmcall_tdb
# VmcallStruct のメモリレイアウト
# 00-07 vmcall_number
# 08-0f arg.rbx
# 10-17 arg.rcx
# 18-1f arg.rdx
# 20-27 arg.rsi
# 28-2f arg.rdi
# 30-37 ret.rax
# 38-3f ret.rbx
# 40-47 ret.rcx
# 48-4f ret.rdx
# 50-57 ret.rsi
# 58-5f ret.rdi
# fn vmmcall_tdb(vmcall_struct: *mut VmcallStruct);
vmcall_tdb:
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