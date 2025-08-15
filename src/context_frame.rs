use core::{arch::asm, fmt::Formatter};

use aarch64_cpu::registers::*;

/// A struct representing the AArch64 CPU context frame.
///
/// This context frame includes
/// * the general-purpose registers (GPRs),
/// * the stack pointer associated with EL0 (SP_EL0),
/// * the exception link register (ELR),
/// * the saved program status register (SPSR).
///
/// The `#[repr(C)]` attribute ensures that the struct has a C-compatible
/// memory layout, which is important when interfacing with hardware or
/// other low-level components.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Aarch64ContextFrame {
    /// An array of 31 `u64` values representing the general-purpose registers.
    pub gpr: [u64; 31],
    /// The stack pointer associated with EL0 (SP_EL0)
    pub sp_el0: u64,
    /// The exception link register, which stores the return address after an exception.
    pub elr: u64,
    /// The saved program status register, which holds the state of the program at the time of an exception.
    pub spsr: u64,
}

/// Implementations of [`fmt::Display`] for [`Aarch64ContextFrame`].
impl core::fmt::Display for Aarch64ContextFrame {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        for i in 0..31 {
            write!(f, "x{:02}: {:016x}   ", i, self.gpr[i])?;
            if (i + 1) % 2 == 0 {
                writeln!(f)?;
            }
        }
        writeln!(f, "spsr:{:016x}", self.spsr)?;
        write!(f, "elr: {:016x}", self.elr)?;
        writeln!(f, "   sp_el0:  {:016x}", self.sp_el0)?;
        Ok(())
    }
}

impl Default for Aarch64ContextFrame {
    /// Returns the default context frame.
    ///
    /// The default state sets the SPSR to mask all exceptions and sets the mode to EL1h.
    fn default() -> Self {
        Aarch64ContextFrame {
            gpr: [0; 31],
            spsr: (SPSR_EL1::M::EL1h
                + SPSR_EL1::I::Masked
                + SPSR_EL1::F::Masked
                + SPSR_EL1::A::Masked
                + SPSR_EL1::D::Masked)
                .value,
            elr: 0,
            sp_el0: 0,
        }
    }
}

impl Aarch64ContextFrame {
    /// Returns the exception program counter (ELR).
    pub fn exception_pc(&self) -> usize {
        self.elr as usize
    }

    /// Sets the exception program counter (ELR).
    ///
    /// # Arguments
    ///
    /// * `pc` - The new program counter value.
    pub fn set_exception_pc(&mut self, pc: usize) {
        self.elr = pc as u64;
    }

    /// Sets the argument in register x0.
    ///
    /// # Arguments
    ///
    /// * `arg` - The argument to be passed in register x0.
    pub fn set_argument(&mut self, arg: usize) {
        self.gpr[0] = arg as u64;
    }

    /// Sets the value of a general-purpose register (GPR).
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the general-purpose register (0 to 31).
    /// * `val` - The value to be set in the register.
    ///
    /// # Behavior
    /// - If `index` is between 0 and 30, the register at the specified index is set to `val`.
    /// - If `index` is 31, the operation is ignored, as it corresponds to the zero register
    ///   (`wzr` or `xzr` in AArch64), which always reads as zero and cannot be modified.
    ///
    /// # Panics
    /// Panics if the provided `index` is outside the range 0 to 31.
    pub fn set_gpr(&mut self, index: usize, val: usize) {
        match index {
            0..=30 => self.gpr[index] = val as u64,
            31 => warn!("Try to set zero register at index [{index}] as {val}"),
            _ => {
                panic!("Invalid general-purpose register index {index}")
            }
        }
    }

    /// Retrieves the value of a general-purpose register (GPR).
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the general-purpose register (0 to 31).
    ///
    /// # Returns
    /// The value stored in the specified register.
    ///
    /// # Panics
    /// Panics if the provided `index` is not in the range 0 to 31.
    ///
    /// # Notes
    /// * For `index` 31, this method returns 0, as it corresponds to the zero register (`wzr` or `xzr` in AArch64).
    pub fn gpr(&self, index: usize) -> usize {
        match index {
            0..=30 => self.gpr[index] as usize,
            31 => 0,
            _ => {
                panic!("Invalid general-purpose register index {index}")
            }
        }
    }
}

/// Represents the VM context for a guest virtual machine in a hypervisor environment.
///
/// The `GuestSystemRegisters` structure contains various registers and states needed to manage
/// and restore the context of a virtual machine (VM). This includes timer registers,
/// system control registers, exception registers, and hypervisor-specific registers.
///
/// The structure is aligned to 16 bytes to ensure proper memory alignment for efficient access.
#[repr(C)]
#[repr(align(16))]
#[derive(Debug, Clone, Copy, Default)]
pub struct GuestSystemRegisters {
    // generic timer
    pub cntvoff_el2: u64,
    cntp_cval_el0: u64,
    cntv_cval_el0: u64,
    pub cntkctl_el1: u32,
    pub cntvct_el0: u64,
    cntp_ctl_el0: u32,
    cntv_ctl_el0: u32,
    cntp_tval_el0: u32,
    cntv_tval_el0: u32,
    pub cnthctl_el2: u64,

    // vpidr and vmpidr
    vpidr_el2: u32,
    pub vmpidr_el2: u64,

    // 64bit EL1/EL0 register
    pub sp_el0: u64,
    sp_el1: u64,
    elr_el1: u64,
    spsr_el1: u32,
    pub sctlr_el1: u32,
    actlr_el1: u64,
    cpacr_el1: u32,
    ttbr0_el1: u64,
    ttbr1_el1: u64,
    tcr_el1: u64,
    esr_el1: u32,
    far_el1: u64,
    par_el1: u64,
    mair_el1: u64,
    amair_el1: u64,
    vbar_el1: u64,
    contextidr_el1: u32,
    tpidr_el0: u64,
    tpidr_el1: u64,
    tpidrro_el0: u64,

    // hypervisor context
    pub hcr_el2: u64,
    pub vttbr_el2: u64,
    cptr_el2: u64,
    hstr_el2: u64,
    pub pmcr_el0: u64,
    pub vtcr_el2: u64,

    // exception
    far_el2: u64,
    hpfar_el2: u64,
}

impl GuestSystemRegisters {
    /// Resets the VM context by setting all registers to zero.
    ///
    /// This method allows the `GuestSystemRegisters` instance to be reused by resetting
    /// its state to the default values (all zeros).
    #[allow(unused)]
    pub fn reset(&mut self) {
        *self = GuestSystemRegisters::default()
    }

    /// Stores the current values of all relevant registers into the `GuestSystemRegisters` structure.
    ///
    /// This method uses inline assembly to read the values of various system registers
    /// and stores them in the corresponding fields of the `GuestSystemRegisters` structure.
    pub unsafe fn store(&mut self) {
        unsafe {
            asm!("mrs {0}, CNTVOFF_EL2", out(reg) self.cntvoff_el2);
            asm!("mrs {0}, CNTV_CVAL_EL0", out(reg) self.cntv_cval_el0);
            asm!("mrs {0:x}, CNTKCTL_EL1", out(reg) self.cntkctl_el1);
            asm!("mrs {0:x}, CNTP_CTL_EL0", out(reg) self.cntp_ctl_el0);
            asm!("mrs {0:x}, CNTV_CTL_EL0", out(reg) self.cntv_ctl_el0);
            asm!("mrs {0:x}, CNTP_TVAL_EL0", out(reg) self.cntp_tval_el0);
            asm!("mrs {0:x}, CNTV_TVAL_EL0", out(reg) self.cntv_tval_el0);
            asm!("mrs {0}, CNTVCT_EL0", out(reg) self.cntvct_el0);
            asm!("mrs {0}, CNTHCTL_EL2", out(reg) self.cnthctl_el2);
            // MRS!("self.vpidr_el2, VPIDR_EL2, "x");
            asm!("mrs {0}, VMPIDR_EL2", out(reg) self.vmpidr_el2);

            asm!("mrs {0}, SP_EL0", out(reg) self.sp_el0);
            asm!("mrs {0}, SP_EL1", out(reg) self.sp_el1);
            asm!("mrs {0}, ELR_EL1", out(reg) self.elr_el1);
            asm!("mrs {0:x}, SPSR_EL1", out(reg) self.spsr_el1);
            asm!("mrs {0:x}, SCTLR_EL1", out(reg) self.sctlr_el1);
            asm!("mrs {0:x}, CPACR_EL1", out(reg) self.cpacr_el1);
            asm!("mrs {0}, TTBR0_EL1", out(reg) self.ttbr0_el1);
            asm!("mrs {0}, TTBR1_EL1", out(reg) self.ttbr1_el1);
            asm!("mrs {0}, TCR_EL1", out(reg) self.tcr_el1);
            asm!("mrs {0:x}, ESR_EL1", out(reg) self.esr_el1);
            asm!("mrs {0}, FAR_EL1", out(reg) self.far_el1);
            asm!("mrs {0}, PAR_EL1", out(reg) self.par_el1);
            asm!("mrs {0}, MAIR_EL1", out(reg) self.mair_el1);
            asm!("mrs {0}, AMAIR_EL1", out(reg) self.amair_el1);
            asm!("mrs {0}, VBAR_EL1", out(reg) self.vbar_el1);
            asm!("mrs {0:x}, CONTEXTIDR_EL1", out(reg) self.contextidr_el1);
            asm!("mrs {0}, TPIDR_EL0", out(reg) self.tpidr_el0);
            asm!("mrs {0}, TPIDR_EL1", out(reg) self.tpidr_el1);
            asm!("mrs {0}, TPIDRRO_EL0", out(reg) self.tpidrro_el0);

            asm!("mrs {0}, PMCR_EL0", out(reg) self.pmcr_el0);
            asm!("mrs {0}, VTCR_EL2", out(reg) self.vtcr_el2);
            asm!("mrs {0}, VTTBR_EL2", out(reg) self.vttbr_el2);
            asm!("mrs {0}, HCR_EL2", out(reg) self.hcr_el2);
            asm!("mrs {0}, ACTLR_EL1", out(reg) self.actlr_el1);
            // println!("save sctlr {:x}", self.sctlr_el1);
        }
    }

    /// Restores the values of all relevant system registers from the `GuestSystemRegisters` structure.
    ///
    /// This method uses inline assembly to write the values stored in the `GuestSystemRegisters` structure
    /// back to the system registers. This is essential for restoring the state of a virtual machine
    /// or thread during context switching.
    ///
    /// Each system register is restored with its corresponding value from the `GuestSystemRegisters`, ensuring
    /// that the virtual machine or thread resumes execution with the correct context.
    pub unsafe fn restore(&self) {
        unsafe {
            asm!("msr CNTV_CVAL_EL0, {0}", in(reg) self.cntv_cval_el0);
            asm!("msr CNTKCTL_EL1, {0:x}", in (reg) self.cntkctl_el1);
            asm!("msr CNTV_CTL_EL0, {0:x}", in (reg) self.cntv_ctl_el0);
            asm!("msr CNTHCTL_EL2, {0}", in(reg) self.cnthctl_el2);
            // The restoration of SP_EL0 is done in `exception_return_el2`,
            // which move the value from `self.ctx.sp_el0` to `SP_EL0`.
            // asm!("msr SP_EL0, {0}", in(reg) self.sp_el0);
            asm!("msr SP_EL1, {0}", in(reg) self.sp_el1);
            asm!("msr ELR_EL1, {0}", in(reg) self.elr_el1);
            asm!("msr SPSR_EL1, {0:x}", in(reg) self.spsr_el1);
            asm!("msr SCTLR_EL1, {0:x}", in(reg) self.sctlr_el1);
            asm!("msr CPACR_EL1, {0:x}", in(reg) self.cpacr_el1);
            asm!("msr TTBR0_EL1, {0}", in(reg) self.ttbr0_el1);
            asm!("msr TTBR1_EL1, {0}", in(reg) self.ttbr1_el1);
            asm!("msr TCR_EL1, {0}", in(reg) self.tcr_el1);
            asm!("msr ESR_EL1, {0:x}", in(reg) self.esr_el1);
            asm!("msr FAR_EL1, {0}", in(reg) self.far_el1);
            asm!("msr PAR_EL1, {0}", in(reg) self.par_el1);
            asm!("msr MAIR_EL1, {0}", in(reg) self.mair_el1);
            asm!("msr AMAIR_EL1, {0}", in(reg) self.amair_el1);
            asm!("msr VBAR_EL1, {0}", in(reg) self.vbar_el1);
            asm!("msr CONTEXTIDR_EL1, {0:x}", in(reg) self.contextidr_el1);
            asm!("msr TPIDR_EL0, {0}", in(reg) self.tpidr_el0);
            asm!("msr TPIDR_EL1, {0}", in(reg) self.tpidr_el1);
            asm!("msr TPIDRRO_EL0, {0}", in(reg) self.tpidrro_el0);

            asm!("msr PMCR_EL0, {0}", in(reg) self.pmcr_el0);
            asm!("msr ACTLR_EL1, {0}", in(reg) self.actlr_el1);

            asm!("msr VTCR_EL2, {0}", in(reg) self.vtcr_el2);
            asm!("msr VTTBR_EL2, {0}", in(reg) self.vttbr_el2);
            asm!("msr HCR_EL2, {0}", in(reg) self.hcr_el2);
            asm!("msr VMPIDR_EL2, {0}", in(reg) self.vmpidr_el2);
            asm!("msr CNTVOFF_EL2, {0}", in(reg) self.cntvoff_el2);
        }
    }
}