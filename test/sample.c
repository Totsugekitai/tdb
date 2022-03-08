#include <stdio.h>
#include <stdint.h>

const char *str = "panda";

typedef struct {
  uint64_t vmcall_number;
  struct {
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
  } args;
  struct {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
  } ret;
} vmcall_struct_t;

void dump_vmcall_struct(vmcall_struct_t *vm) {
  printf("vmcall_number: %lld\n", vm->vmcall_number);
  printf("args.rbx: %llx\n", vm->args.rbx);
  printf("args.rcx: %llx\n", vm->args.rcx);
  printf("args.rdx: %llx\n", vm->args.rdx);
  printf("args.rsi: %llx\n", vm->args.rsi);
  printf("args.rdi: %llx\n", vm->args.rdi);
  printf("ret.rax: %llx\n", vm->ret.rax);
  printf("ret.rbx: %llx\n", vm->ret.rbx);
  printf("ret.rcx: %llx\n", vm->ret.rcx);
  printf("ret.rdx: %llx\n", vm->ret.rdx);
  printf("ret.rsi: %llx\n", vm->ret.rsi);
  printf("ret.rdi: %llx\n", vm->ret.rdi);
}

extern void vmmcall(vmcall_struct_t *vmstruct);

static int func1(int p1) {
  printf("hello world %x %s\n", p1, str);
  return 0;
}

static int func2(int p2) { return func1(p2 + 0xcafe); }

const char *dump_rip = "dump_rip";

int main(void) {
  // vmcall_struct_t vmstruct;
  // vmstruct.vmcall_number = 0;
  // vmstruct.args.rbx = (uint64_t)dump_rip;

  // printf("%p\n", dump_rip);
  // dump_vmcall_struct(&vmstruct);

  // vmmcall(&vmstruct);

  // uint64_t dump_rip_number = vmstruct.ret.rax;
  // printf("%lld\n", dump_rip_number);
  // vmstruct.vmcall_number = dump_rip_number;

  // vmmcall(&vmstruct);

  register int p = 0xbeef;
  return func2(p);
}
