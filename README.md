# loongarch_vcpu

`loongarch_vcpu` provides the LoongArch64 virtual CPU implementation for the
ArceOS hypervisor stack.

It contains:
- LoongArch guest context frame definitions
- LVZ register access helpers
- Per-CPU virtualization state management
- Guest entry/exit handling
- Exception and interrupt handling support
