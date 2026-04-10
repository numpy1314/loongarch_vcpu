// Copyright 2025 The Axvisor Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use axaddrspace::{GuestPhysAddr, HostPhysAddr};
use axerrno::AxResult;
use axvcpu::{AxArchVCpu, AxVCpuExitReason};

use crate::context_frame::{LoongArchContextFrame, LoongArchGuestSystemRegisters};
use crate::exception::{TrapKind, handle_exception_sync, handle_exception_irq};

// External assembly functions
unsafe extern "C" {
    fn _run_guest(ctx: *mut LoongArchContextFrame) -> !;
    fn _guest_exit();
}

#[percpu::def_percpu]
static HOST_SP: usize = 0;

/// Save host's stack pointer to the current percpu region.
unsafe fn save_host_sp() {
    let sp: usize;
    unsafe {
        core::arch::asm!("move {0}, $sp", out(reg) sp);
        HOST_SP.write_current_raw(sp);
    }
}

/// Restore host's stack pointer from the current percpu region.
unsafe fn restore_host_sp() {
    let sp = unsafe { HOST_SP.read_current_raw() };
    unsafe {
        core::arch::asm!("move $sp, {0}", in(reg) sp);
    }
}

/// (v)CPU register state that must be saved or restored when entering/exiting a VM or switching
/// between VMs.
#[repr(C)]
#[derive(Clone, Debug, Copy, Default)]
pub struct VmCpuRegisters {
    /// guest trap context
    pub trap_context_regs: LoongArchContextFrame,
    /// virtual machine system regs setting
    pub vm_system_regs: LoongArchGuestSystemRegisters,
}

/// A virtual CPU within a guest
#[repr(C)]
#[derive(Debug)]
pub struct LoongArchVCpu {
    // DO NOT modify `guest_regs` and `host_stack_top` and their order unless you do know what you are doing!
    // DO NOT add anything before or between them unless you do know what you are doing!
    ctx: LoongArchContextFrame,
    host_stack_top: usize,
    guest_system_regs: LoongArchGuestSystemRegisters,
    /// The CPU ID for the vCPU.
    cpu_id: usize,
}

/// Configuration for creating a new `LoongArchVCpu`
#[derive(Clone, Debug, Default)]
pub struct LoongArchVCpuCreateConfig {
    /// The CPU ID for the new vCPU,
    /// which is used to identify the CPU in a multiprocessor system.
    pub cpu_id: usize,
    /// The address of the device tree blob.
    pub dtb_addr: usize,
}

/// Configuration for setting up a new `LoongArchVCpu`
#[derive(Clone, Debug, Default)]
pub struct LoongArchVCpuSetupConfig {
    /// Should the hypervisor passthrough interrupts to the guest?
    pub passthrough_interrupt: bool,
    /// Should the hypervisor passthrough timers to the guest?
    pub passthrough_timer: bool,
}

impl axvcpu::AxArchVCpu for LoongArchVCpu {
    type CreateConfig = LoongArchVCpuCreateConfig;
    type SetupConfig = LoongArchVCpuSetupConfig;

    fn new(_vm_id: usize, _vcpu_id: usize, config: Self::CreateConfig) -> AxResult<Self> {
        let mut ctx = LoongArchContextFrame::default();
        // Set a0 (x[4]) to DTB address as argument for guest kernel
        ctx.set_argument(config.dtb_addr);

        Ok(Self {
            ctx,
            host_stack_top: 0,
            guest_system_regs: LoongArchGuestSystemRegisters::default(),
            cpu_id: config.cpu_id,
        })
    }

    fn setup(&mut self, config: Self::SetupConfig) -> AxResult {
        self.init_hv(config);
        Ok(())
    }

    fn set_entry(&mut self, entry: GuestPhysAddr) -> AxResult {
        debug!("set vcpu entry:{entry:?}");
        self.set_sepc(entry.as_usize());
        Ok(())
    }

    fn set_ept_root(&mut self, ept_root: HostPhysAddr) -> AxResult {
        debug!("set vcpu ept root:{ept_root:#x}");
        // Set guest page table root (PGD)
        // LoongArch uses GPGD (Guest Page Global Directory) CSR for guest page tables
        self.guest_system_regs.gpgd = ept_root.as_usize();
        Ok(())
    }

    fn run(&mut self) -> AxResult<AxVCpuExitReason> {
        // Run guest.
        let exit_reason = unsafe {
            // Save host SP to the ctx because it's used as current task ptr.
            // This has to be done before vm system regs are restored.
            save_host_sp();
            self.restore_vm_system_regs();
            self.run_guest()
        };

        let trap_kind = TrapKind::try_from(exit_reason as u8).expect("Invalid TrapKind");
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
        // TODO: Implement interrupt injection for LoongArch
        // hardware_inject_virtual_interrupt is not available in axvisor_api for LoongArch
        debug!("Inject interrupt: vector={}", vector);
        Ok(())
    }

    fn set_return_value(&mut self, val: usize) {
        // Return value is stored in a0 (x[4]).
        self.ctx.set_a0(val);
    }
}

// Private function
impl LoongArchVCpu {
    fn init_hv(&mut self, config: LoongArchVCpuSetupConfig) {
        // TODO: Initialize hypervisor settings for LoongArch
        // - Set up CSR values for guest mode
        // - Configure interrupt/timer passthrough
        self.init_vm_context(config);
    }

    /// Init guest context. Also set some CSR register values.
    fn init_vm_context(&mut self, config: LoongArchVCpuSetupConfig) {
        use crate::registers::*;

        // Initialize guest CRMD (Current Mode Register) in context frame
        // CRMD bits: [1:0] = PLV (Privilege Level), [2] = IE (Interrupt Enable)
        // PLV=0: kernel mode (most privileged), PLV=3: user mode
        // For guest kernel, we set PLV=1 (guest kernel mode), IE=1 (interrupts enabled)
        // 0x5 = 0b101 = PLV=1, IE=1
        self.ctx.crmd = 0x5; // PLV=1 (guest kernel mode), IE=1

        // Initialize guest PRMD (Previous Mode Register) in context frame
        // Used to save CRMD on exception entry
        self.ctx.prmd = 0;

        // Initialize guest ESTAT (Exception Status) in context frame
        // Clear all exception status bits
        self.ctx.estat = 0;

        // Note: GSTAT.GID for this VM is set by hypervisor core during VM creation
        // GID is used for TLB isolation between different VMs
        // GID=0 is reserved for hypervisor, GID>=1 for guests

        if config.passthrough_timer {
            // Enable guest timer
            // Set TCFG.EN=1 and configure timer period
            self.guest_system_regs.gtcfg = 0x1; // Enable timer
        }

        if config.passthrough_interrupt {
            // Configure interrupt passthrough in GINTC
            // Allow hardware interrupts to be delivered directly to guest
            // This would be done through GINTC CSR
        }

        // Note: Guest page table root (gpgd) is set by set_ept_root() after setup()
        // Do NOT clear gpgd here - it would overwrite the EPT root set by the VMM.
        // Only initialize the low/high page table base registers if needed.
        self.guest_system_regs.gpgdl = 0;
        self.guest_system_regs.gpgdh = 0;

        // Set guest exception entry point
        // GCSR_EENTRY should point to guest's exception vector base
        // This is typically set by the guest kernel
        self.guest_system_regs.geentry = 0;
    }

    /// Set exception return pc (SEPC)
    fn set_sepc(&mut self, sepc: usize) {
        self.ctx.sepc = sepc;
    }

    /// Get general purpose register
    #[allow(unused)]
    fn get_gpr(&self, idx: usize) -> usize {
        self.ctx.gpr(idx)
    }
}

/// Private functions related to vcpu runtime control flow.
impl LoongArchVCpu {
    /// Save host context and run guest.
    ///
    /// When a VM-Exit happens when guest's vCpu is running,
    /// the control flow will be redirected to this function through `return_run_guest`.
    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    unsafe extern "C" fn run_guest(&mut self) -> usize {
        core::arch::naked_asm!(
            // Save host registers (callee-saved)
            // LoongArch calling convention: s0-s8 ($r23-$r31) are callee-saved
            // Also save ra ($r1) which contains return address to run() method.
            // Save $r21 as well because percpu uses it as the host CPU-local base.
            "addi.d $sp, $sp, -14 * 8",
            "st.d $ra, $sp, 0",      // Save ra (return address)
            "st.d $s0, $sp, 8",      // Save s0 (will store context frame pointer)
            "st.d $s1, $sp, 16",
            "st.d $s2, $sp, 24",
            "st.d $s3, $sp, 32",
            "st.d $s4, $sp, 40",
            "st.d $s5, $sp, 48",
            "st.d $s6, $sp, 56",
            "st.d $s7, $sp, 64",
            "st.d $s8, $sp, 72",
            "st.d $fp, $sp, 80",
            "st.d $tp, $sp, 88",
            "st.d $r21, $sp, 96",
            // Save current host stack top to self.host_stack_top
            // self pointer is $a0 (first argument)
            // host_stack_top offset = size_of::<LoongArchContextFrame>()
            "move $t0, $sp",
            "addi.d $t1, $a0, {host_stack_top_offset}",
            "st.d $t0, $t1, 0",
            // Go to _run_guest assembly function
            // $a0 already points to self, need to pass pointer to ctx (same as $a0)
            "bl {run_guest_asm}",
            // Panic if control returns here (should never happen)
            "bl {run_guest_panic}",
            host_stack_top_offset = const core::mem::size_of::<crate::context_frame::LoongArchContextFrame>(),
            run_guest_asm = sym _run_guest,
            run_guest_panic = sym Self::run_guest_panic,
        );
    }

    /// This function is called when the control flow comes back to `run_guest`. To provide a error
    /// message for debugging purposes.
    ///
    /// This function may fail as the stack may have been corrupted when this function is called.
    /// But we won't handle it here for now.
    unsafe fn run_guest_panic() -> ! {
        panic!("run_guest_panic: control returned to run_guest, which should never happen");
    }

    /// Restores guest system control registers.
    unsafe fn restore_vm_system_regs(&mut self) {
        // Restore guest system registers from saved state
        // GID setting is handled by hypervisor core, not here
        self.guest_system_regs.restore();
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
            "LoongArchVCpu vmexit_handler() exit_reason:{:?}",
            exit_reason
        );

        unsafe {
            // Store guest system regs
            self.guest_system_regs.store();
            // Host SP is already restored by vmexit_trampoline
        }

        match exit_reason {
            TrapKind::Synchronous => handle_exception_sync(&mut self.ctx),
            TrapKind::Irq => handle_exception_irq(&mut self.ctx),
            // TODO: Handle other trap kinds
            _ => panic!("Unhandled exception {:?}", exit_reason),
        }
    }
}
