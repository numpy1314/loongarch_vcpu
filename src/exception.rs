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

use crate::context_frame::LoongArchContextFrame;
use axaddrspace::GuestPhysAddr;
use axerrno::{AxError, AxResult};
use axvcpu::AxVCpuExitReason;

/// Exception code for HVC (Hypervisor Call) in LoongArch
/// From LoongArch Volume 1: HVC exception code is 0x17
const ECODE_HVC: usize = 0x17;

/// Exception code for PIL (Page Invalid Load)
const ECODE_PIL: usize = 0x1;

/// Exception code for PIS (Page Invalid Store)
const ECODE_PIS: usize = 0x2;

/// Exception code for PIF (Page Invalid Fetch)
const ECODE_PIF: usize = 0x3;

/// Exception code for PME (Page Modified Exception)
const ECODE_PME: usize = 0x4;

/// Exception code for PPI (Page Privilege Illegal)
const ECODE_PPI: usize = 0x5;

/// Exception code for TLBR (TLB Refill)
const ECODE_TLBR: usize = 0x8;

/// Exception code for RSE (Reserved Instruction Exception)
const ECODE_RSE: usize = 0x10;

/// Trap kind enumeration for LoongArch
/// Similar to ARM's TrapKind, representing different types of traps/exceptions
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapKind {
    Synchronous = 0,
    Irq = 1,
    // LoongArch may have other trap types, add as needed
}

impl From<u8> for TrapKind {
    fn from(value: u8) -> Self {
        match value {
            0 => TrapKind::Synchronous,
            1 => TrapKind::Irq,
            _ => TrapKind::Synchronous, // Default to Synchronous for unknown values
        }
    }
}

/// Equals to [`TrapKind::Synchronous`], used in assembly code.
const EXCEPTION_SYNC: usize = TrapKind::Synchronous as usize;
/// Equals to [`TrapKind::Irq`], used in assembly code.
const EXCEPTION_IRQ: usize = TrapKind::Irq as usize;

/// Get the exception code from GCSR_ESTAT (Guest Exception Status)
/// In LoongArch, when a guest exception occurs, GCSR_ESTAT[21:16] stores exception code (ECODE)
fn get_exception_code() -> usize {
    use crate::registers::gcsr_read;
    let estat = unsafe { gcsr_read::<{ crate::registers::GCSR_ESTAT }>() };
    (estat >> 16) & 0x3F // ECODE bits [21:16]
}

/// Get the exception subcode from GCSR_ESTAT
/// GCSR_ESTAT[30:22] stores exception subcode (ESUBCODE)
fn get_exception_subcode() -> usize {
    use crate::registers::gcsr_read;
    let estat = unsafe { gcsr_read::<{ crate::registers::GCSR_ESTAT }>() };
    (estat >> 22) & 0x1FF // ESUBCODE bits [30:22]
}

/// Get the bad virtual address from GCSR_BADV (Guest Bad Virtual Address)
fn get_badv() -> usize {
    use crate::registers::gcsr_read;
    unsafe { gcsr_read::<{ crate::registers::GCSR_BADV }>() }
}

/// Get the bad instruction from GCSR_BADI (Guest Bad Instruction)
fn get_badi() -> usize {
    use crate::registers::gcsr_read;
    unsafe { gcsr_read::<{ crate::registers::GCSR_BADI }>() }
}

/// Handle synchronous exceptions that occur during the execution of a guest VM.
///
/// This function examines the exception code (ECODE) to determine the cause of the exception
/// and then handles it accordingly.
///
/// Currently we handle HVC (Hypervisor Call) exceptions and possibly other synchronous exceptions.
///
/// # Arguments
///
/// * `ctx` - A mutable reference to the `LoongArchContextFrame`, which contains the saved state
///   of the guest VM's CPU registers at the time of the exception.
///
/// # Returns
///
/// An `AxResult` containing an `AxVCpuExitReason` indicating the reason for the VM exit.
/// This could be due to a hypercall (`Hypercall`) or other reasons.
///
/// # Panics
///
/// If an unhandled exception code is encountered, the function will panic, outputting
/// details about the exception.
pub fn handle_exception_sync(ctx: &mut LoongArchContextFrame) -> AxResult<AxVCpuExitReason> {
    let ecode = get_exception_code();
    let esubcode = get_exception_subcode();

    trace!(
        "LoongArch handle_exception_sync: ecode={:#x}, esubcode={:#x}, sepc={:#x}",
        ecode,
        esubcode,
        ctx.sepc
    );

    match ecode {
        ECODE_HVC => {
            // HVC exception: Hypervisor Call
            // According to LoongArch Virtualization specification:
            // - Hypercall number is passed in a0 (x[4])
            // - Arguments are passed in a1 (x[5]), a2 (x[6]), a3 (x[7]), a4 (x[8]), a5 (x[9]), a6 (x[10])
            // - Return value is placed in a0
            // - sepc should be advanced by 4 (instruction length of hvcl)

            let nr = ctx.get_a0() as u64; // hypercall number
            let args = [
                ctx.get_a1() as u64,
                ctx.get_a2() as u64,
                ctx.get_a3() as u64,
                ctx.get_a4() as u64,
                ctx.get_a5() as u64,
                ctx.get_a6() as u64,
            ];

            trace!(
                "HVC exception: nr={:#x}, args={:?}",
                nr,
                args
            );

            // Advance sepc by 4 (hvcl instruction length)
            ctx.sepc += 4;

            // Return hypercall exit reason
            Ok(AxVCpuExitReason::Hypercall { nr, args })
        }
        ECODE_PIL | ECODE_PIS | ECODE_PIF | ECODE_PME | ECODE_PPI => {
            // Page fault exceptions
            let badv = get_badv();
            let badi = get_badi();
            trace!(
                "Page fault exception: ecode={:#x}, badv={:#x}, badi={:#x}, sepc={:#x}",
                ecode, badv, badi, ctx.sepc
            );

            // Determine fault type
            let is_write = ecode == ECODE_PIS || ecode == ECODE_PME;
            let is_exec = ecode == ECODE_PIF;
            let is_priv = ecode == ECODE_PPI;

            // Return nested page fault exit reason
            use axaddrspace::MappingFlags;
            let mut access_flags = MappingFlags::empty();
            if is_write {
                access_flags |= MappingFlags::WRITE;
            } else if is_exec {
                access_flags |= MappingFlags::EXECUTE;
            } else {
                access_flags |= MappingFlags::READ;
            }
            Ok(AxVCpuExitReason::NestedPageFault {
                addr: GuestPhysAddr::from(badv),
                access_flags,
            })
        }
        ECODE_TLBR => {
            // TLB refill exception
            let badv = get_badv();
            trace!(
                "TLB refill exception: badv={:#x}, sepc={:#x}",
                badv, ctx.sepc
            );

            // For TLB refill, we need to emulate TLB miss handling
            // For now, treat as nested page fault
            use axaddrspace::MappingFlags;
            Ok(AxVCpuExitReason::NestedPageFault {
                addr: GuestPhysAddr::from(badv),
                access_flags: MappingFlags::READ,
            })
        }
        ECODE_RSE => {
            // Reserved instruction exception (illegal instruction)
            let badi = get_badi();
            trace!(
                "Illegal instruction exception: badi={:#x}, sepc={:#x}",
                badi, ctx.sepc
            );

            // No IllegalInstruction variant in AxVCpuExitReason, treat as Halt
            // TODO: Add proper handling for illegal instructions
            Ok(AxVCpuExitReason::Halt)
        }
        // TODO: Handle other synchronous exceptions
        _ => {
            // Unhandled exception
            let badv = get_badv();
            let badi = get_badi();
            panic!(
                "Unhandled synchronous exception: ecode={:#x}, esubcode={:#x}, sepc={:#x}, badv={:#x}, badi={:#x}",
                ecode, esubcode, ctx.sepc, badv, badi
            );
        }
    }
}

/// Handle IRQ exceptions
/// This function should be called when an IRQ trap occurs.
pub fn handle_exception_irq(_ctx: &mut LoongArchContextFrame) -> AxResult<AxVCpuExitReason> {
    // For now, just return ExternalInterrupt with vector 0
    // TODO: Determine actual interrupt vector from CSR.ESTAT or other sources
    Ok(AxVCpuExitReason::ExternalInterrupt { vector: 0 })
}

/// Assembly linkage for exception handling
/// This includes the global_asm! macro to include assembly exception handler
core::arch::global_asm!(
    include_str!("exception.S")
);

/// VM exit trampoline - called from assembly exception handler
///
/// This function is called by the assembly exception handler after saving
/// guest context. It restores the host context and returns to the hypervisor.
///
/// # Safety
/// This function is unsafe because it handles low-level context switching
/// and assumes proper stack and register state.
///
/// # Functionality
/// 1. Restores host stack pointer from `LoongArchVCpu.host_stack_top`
/// 2. Restores host callee-saved registers (x22-x31)
/// 3. Returns control to `LoongArchVCpu.run()` method
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn vmexit_trampoline() -> ! {
    core::arch::naked_asm!(
        // Currently `$sp` points to the base address of `LoongArchVCpu.ctx`
        // which stores guest's `LoongArchContextFrame`.
        // Calculate offset to `host_stack_top` field.
        // `host_stack_top` offset = size_of::<LoongArchContextFrame>()
        // LoongArchContextFrame size: 32 registers (256 bytes) + 4 CSRs (32 bytes) = 288 bytes
        "addi.d $t0, $sp, 288",    // $t0 now points to &LoongArchVCpu.host_stack_top
        "ld.d $t1, $t0, 0",        // $t1 = host_stack_top value
        "move $sp, $t1",           // Restore host stack pointer

        // Restore host registers saved in run_guest()
        // $ra was saved at offset 0, $s0 at 8, $s1-$s8 at offsets 16-72,
        // $fp at 80, $tp at 88, $r21 at 96.
        "ld.d $ra, $sp, 0",        // Restore ra (return address to run() method)
        "ld.d $s0, $sp, 8",        // Restore s0 (context frame pointer)
        "ld.d $s1, $sp, 16",
        "ld.d $s2, $sp, 24",
        "ld.d $s3, $sp, 32",
        "ld.d $s4, $sp, 40",
        "ld.d $s5, $sp, 48",
        "ld.d $s6, $sp, 56",
        "ld.d $s7, $sp, 64",
        "ld.d $s8, $sp, 72",
        "ld.d $fp, $sp, 80",
        "ld.d $tp, $sp, 88",
        "ld.d $r21, $sp, 96",

        // Adjust stack pointer (remove saved registers space: 14 registers * 8 bytes = 112 bytes)
        "addi.d $sp, $sp, 14 * 8",

        // Return control to LoongArchVCpu.run()
        // The exit reason is already in $a0 register (set by exception vector)
        "jr $ra"                   // Jump to return address (ra)
    )
}

/// Current EL IRQ handler (for hypervisor itself)
#[unsafe(no_mangle)]
fn current_el_irq_handler(_ctx: &mut LoongArchContextFrame) {
    // TODO: Implement hypervisor-level IRQ handling
    // Note: handle_irq is not available in axvisor_api for LoongArch
}

/// Current EL synchronous exception handler (for hypervisor itself)
#[unsafe(no_mangle)]
fn current_el_sync_handler(ctx: &mut LoongArchContextFrame) {
    error!("Unhandled synchronous exception from current EL in hypervisor");
    panic!("Current EL sync exception: {:#x?}", ctx);
}
