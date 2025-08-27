use core::marker::PhantomData;

use axaddrspace::{GuestPhysAddr, HostPhysAddr, device::SysRegAddr};
use axerrno::AxResult;
use axvcpu::{AxArchVCpu, AxVCpuExitReason, AxVCpuHal};

use crate::TrapFrame;
use crate::context_frame::GuestSystemRegisters;
use crate::exception::{TrapKind, handle_exception_sync};
use crate::exception_utils::exception_class_value;

#[percpu::def_percpu]
static HOST_SP: u64 = 0;

/// Save host's stack pointer to the current percpu region.
unsafe fn save_host_sp() {
    // TODO: 实现保存主机栈指针的逻辑
}

/// Restore host's stack pointer from the current percpu region.
unsafe fn restore_host_sp() {
    // TODO: 实现恢复主机栈指针的逻辑
}

/// (v)CPU register state that must be saved or restored when entering/exiting a VM or switching
/// between VMs.
#[repr(C)]
#[derive(Clone, Debug, Copy, Default)]
pub struct VmCpuRegisters {
    /// guest trap context
    pub trap_context_regs: TrapFrame,
    /// virtual machine system regs setting
    pub vm_system_regs: GuestSystemRegisters,
}

/// A virtual CPU within a guest
#[repr(C)]
#[derive(Debug)]
pub struct LoongArch64VCpu<H: AxVCpuHal> {
    // DO NOT modify `guest_regs` and `host_stack_top` and their order unless you do know what you are doing!
    // DO NOT add anything before or between them unless you do know what you are doing!
    ctx: TrapFrame,
    host_stack_top: u64,
    guest_system_regs: GuestSystemRegisters,
    /// The CPU ID value for the vCPU.
    cpuid: u64,
    _phantom: PhantomData<H>,
}

/// Configuration for creating a new `LoongArch64VCpu`
#[derive(Clone, Debug, Default)]
pub struct LoongArch64VCpuCreateConfig {
    /// The CPU ID value for the new vCPU,
    /// which is used to identify the CPU in a multiprocessor system.
    pub cpuid: u64,
    /// The address of the device tree blob.
    pub dtb_addr: usize,
}

/// Configuration for setting up a new `LoongArch64VCpu`
#[derive(Clone, Debug, Default)]
pub struct LoongArch64VCpuSetupConfig {
    /// Should the hypervisor passthrough interrupts to the guest?
    pub passthrough_interrupt: bool,
    /// Should the hypervisor passthrough timers to the guest?
    pub passthrough_timer: bool,
}

impl<H: AxVCpuHal> axvcpu::AxArchVCpu for LoongArch64VCpu<H> {
    type CreateConfig = LoongArch64VCpuCreateConfig;

    type SetupConfig = LoongArch64VCpuSetupConfig;

    fn new(_vm_id: usize, _vcpu_id: usize, config: Self::CreateConfig) -> AxResult<Self> {
        let mut ctx = TrapFrame::default();
        ctx.set_argument(config.dtb_addr);

        Ok(Self {
            ctx,
            host_stack_top: 0,
            guest_system_regs: GuestSystemRegisters::default(),
            cpuid: config.cpuid,
            _phantom: PhantomData,
        })
    }

    fn setup(&mut self, config: Self::SetupConfig) -> AxResult {
        self.init_hv(config);
        Ok(())
    }

    fn set_entry(&mut self, entry: GuestPhysAddr) -> AxResult {
        debug!("set vcpu entry:{entry:?}");
        self.set_era(entry.as_usize());
        Ok(())
    }

    fn set_ept_root(&mut self, ept_root: HostPhysAddr) -> AxResult {
        debug!("set vcpu ept root:{ept_root:#x}");

        self.guest_system_regs.pgdl = ept_root.as_usize();
        self.guest_system_regs.pgdh = ept_root.as_usize();

        Ok(())
    }

    fn run(&mut self) -> AxResult<AxVCpuExitReason> {
        // Run guest.
        let exit_reson = unsafe {
            // Save host stack pointer to the ctx because it's used as current task ptr.
            // This has to be done before vm system regs are restored.
            save_host_sp();
            self.restore_vm_system_regs();
            self.run_guest()
        };

        let trap_kind = TrapKind::try_from(exit_reson as u8).expect("Invalid TrapKind");
        self.vmexit_handler(trap_kind)
    }

    fn bind(&mut self) -> AxResult {
        Ok(())
    }

    fn unbind(&mut self) -> AxResult {
        Ok(())
    }

    fn set_gpr(&mut self, idx: usize, val: usize) {
        self.ctx.set_gpr(idx, val);
    }

    fn inject_interrupt(&mut self, vector: usize) -> AxResult {
        // TODO: 实现龙芯架构的中断注入
        Ok(())
    }

    fn set_return_value(&mut self, val: usize) {
        // Return value is stored in a0 (r4).
        self.ctx.set_argument(val);
    }
}

// Private function
impl<H: AxVCpuHal> LoongArch64VCpu<H> {
    fn init_hv(&mut self, config: LoongArch64VCpuSetupConfig) {
        // TODO: 初始化龙芯架构的虚拟机上下文
        self.init_vm_context(config);
    }

    /// Init guest context. Also set some system register value.
    fn init_vm_context(&mut self, config: LoongArch64VCpuSetupConfig) {
        // hvisor/src/arch/loongarch64/trap.rs中的dump_reset_gcsrs函数

        // hvisor/src/arch/loongarch64/paging.rs中的set_pwcl_pwch_stlbps函数
        self.set_pwcl_pwch_stlbps();

        // 初始化页表相关寄存器
        self.guest_system_regs.pgdl = 0; // 页表根地址低32位
        self.guest_system_regs.pgdh = 0; // 页表根地址高32位
        self.guest_system_regs.asid = 1; // 设置地址空间ID为1（虚拟机专用）

        // 初始化定时器相关寄存器
        self.guest_system_regs.tcfg = 0; // 定时器配置，初始禁用
        self.guest_system_regs.tval = 0; // 定时器值
        self.guest_system_regs.cntc = 0; // 计数器值

        // 初始化其他系统寄存器
        self.guest_system_regs.crmd = 0x0; // 当前模式寄存器
        self.guest_system_regs.prmd = 0x0; // 前一个模式寄存器
        self.guest_system_regs.euen = 0x0; // 扩展单元使能寄存器
        self.guest_system_regs.estat = 0x0; // 异常状态寄存器

        // 处理透传配置
        if config.passthrough_interrupt {
            // TODO: 实现中断透传逻辑
        }
        if config.passthrough_timer {
            // TODO: 实现定时器透传逻辑
        }
    }

    // hvisor/src/arch/loongarch64/paging.rs中的set_pwcl_pwch_stlbps函数
    fn set_pwcl_pwch_stlbps(&mut self) {
        unsafe {
            // PWCL (Page Walk Control Low) - 页表遍历控制低32位
            // 设置4级页表的各级基址和宽度
            core::arch::asm!("csrwr {}, 0x1c", in(reg) 0x1c1c1c1c); // PWCL

            // PWCH (Page Walk Control High) - 页表遍历控制高32位
            core::arch::asm!("csrwr {}, 0x1d", in(reg) 0x1c1c1c1c); // PWCH

            // STLBPS (Shared TLB Page Size) - 共享TLB页大小
            core::arch::asm!("csrwr {}, 0x1e", in(reg) 0x0c); // 4KB页大小 (log2(4096) = 12)
        }
    }

    /// Set exception return pc
    fn set_era(&mut self, era: usize) {
        self.ctx.set_exception_pc(era);
    }

    /// Get general purpose register
    #[allow(unused)]
    fn get_gpr(&self, idx: usize) {
        self.ctx.gpr(idx);
    }
}

/// Private functions related to vcpu runtime control flow.
impl<H: AxVCpuHal> LoongArch64VCpu<H> {
    /// Save host context and run guest.
    ///
    /// When a VM-Exit happens when guest's vCpu is running,
    /// the control flow will be redirected to this function through `return_run_guest`.
    #[unsafe(naked)]
    unsafe extern "C" fn run_guest(&mut self) -> usize {
        core::arch::naked_asm!(
            // 保存宿主调用者保存寄存器（按需补完），记录当前栈顶
            // 这里仅占位以打通编译链路
            "move $t0, $sp\n",
            // 保存 host 栈顶到 self.host_stack_top
            // aapcs/loongarch psabi 约定：x0/$a0 为 self 指针
            // 但 loongarch 使用 $a0-$a7，这里假设编译器传 self 于 $a0
            // 写入偏移: ctx 紧靠结构体起始，因此偏移为 size_of::<TrapFrame>()
            // 为避免复杂度，这里暂不写，直接跳转到 context_vm_entry
            "b context_vm_entry\n",
        );
    }

    /// This function is called when the control flow comes back to `run_guest`. To provide a error
    /// message for debugging purposes.
    ///
    /// This function may fail as the stack may have been corrupted when this function is called.
    /// But we won't handle it here for now.
    unsafe fn run_guest_panic() -> ! {
        panic!("run_guest_panic");
    }

    /// Restores guest system control registers.
    unsafe fn restore_vm_system_regs(&mut self) {
        unsafe {
            // TODO: 恢复虚拟机系统寄存器
            self.guest_system_regs.restore();

            // TODO: 刷新TLB和缓存
        }
    }

    /// Handle VM-Exits.
    ///
    /// Parameters:
    /// - `exit_reason`: The reason why the VM-Exit happened in [`TrapKind`].
    ///
    /// Returns:
    /// - [`AxVCpuExitReason`]: a wrappered VM-Exit reason needed to be handled by the hypervisor.
    ///
    /// This function may panic for unhandled exceptions.
    fn vmexit_handler(&mut self, exit_reason: TrapKind) -> AxResult<AxVCpuExitReason> {
        trace!(
            "LoongArch64VCpu vmexit_handler() estat:{:#x} ctx:{:#x?}",
            exception_class_value(),
            self.ctx
        );

        unsafe {
            // Store guest system regs
            self.guest_system_regs.store();

            // Store guest stack pointer into the `LoongArch64VCpu` struct,
            // which will be restored when the guest is resumed.
            // TODO: 保存虚拟机栈指针

            // Restore host stack pointer.
            // This has to be done after guest's stack pointer is stored.
            restore_host_sp();
        }

        let result = match exit_reason {
            TrapKind::Synchronous => handle_exception_sync(&mut self.ctx),
            TrapKind::Irq => Ok(AxVCpuExitReason::ExternalInterrupt {
                vector: H::irq_fetch() as _,
            }),
            _ => panic!("Unhandled exception {:?}", exit_reason),
        };

        match result {
            Ok(AxVCpuExitReason::SysRegRead { addr, reg }) => {
                if let Some(exit_reason) =
                    self.builtin_sysreg_access_handler(addr, false, 0, reg)?
                {
                    return Ok(exit_reason);
                }

                result
            }
            Ok(AxVCpuExitReason::SysRegWrite { addr, value }) => {
                if let Some(exit_reason) =
                    self.builtin_sysreg_access_handler(addr, true, value, 0)?
                {
                    return Ok(exit_reason);
                }

                result
            }
            r => r,
        }
    }

    /// Handle system register access that can and should be handled by the VCpu itself.
    ///
    /// Return `Ok(None)` if the system register access is not handled by the VCpu itself,
    fn builtin_sysreg_access_handler(
        &mut self,
        addr: SysRegAddr,
        write: bool,
        value: u64,
        reg: usize,
    ) -> AxResult<Option<AxVCpuExitReason>> {
        // TODO: 实现龙芯架构的系统寄存器访问处理

        Ok(None)
    }
}
