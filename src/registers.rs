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

//! LoongArch Virtualization Extension Registers
//!
//! This module provides correct register definitions and access functions
//! based on the LoongArch Virtualization Extension (LVZ) specification.
//!
//! ## Register Types
//!
//! 1. **Regular CSRs** - Accessed via `csrrd`/`csrwr` instructions:
//!    - GSTAT (0x50): Guest Status Register
//!    - GTLBC (0x15): Guest TLB Control Register
//!    - GINTC (0x52): Guest Interrupt Control Register
//!
//! 2. **Guest CSRs (GCSRs)** - Accessed via `gcsrrd`/`gcsrwr` instructions:
//!    - GCSR_CRMD (0x0): Guest Current Mode
//!    - GCSR_PRMD (0x1): Guest Previous Mode
//!    - GCSR_ESTAT (0x5): Guest Exception Status
//!    - GCSR_ERA (0x6): Guest Exception Return Address
//!    - GCSR_EENTRY (0xC): Guest Exception Entry
//!    - GCSR_PGD (0x1B): Guest Page Global Directory
//!    - etc.

// ============================================================================
// CSR Address Constants
// ============================================================================

/// Guest Status Register (CSR 0x50)
pub const CSR_GSTAT: u16 = 0x50;

/// Guest TLB Control Register (CSR 0x15)
pub const CSR_GTLBC: u16 = 0x15;

/// Guest Control Register (CSR 0x51)
pub const CSR_GCTL: u16 = 0x51;

/// Guest Interrupt Control Register (CSR 0x52)
pub const CSR_GINTC: u16 = 0x52;

/// Exception Entry Base Address (CSR 0xC)
pub const CSR_EENTRY: u16 = 0xC;

/// Exception Status Register (CSR 0x5)
pub const CSR_ESTAT: u16 = 0x5;

// ============================================================================
// GCSR Offsets (for gcsrrd/gcsrwr instructions)
// ============================================================================

/// GCSR: Guest Current Mode Register
pub const GCSR_CRMD: usize = 0x0;
/// GCSR: Guest Previous Mode Register
pub const GCSR_PRMD: usize = 0x1;
/// GCSR: Guest Exception Status Register
pub const GCSR_ESTAT: usize = 0x5;
/// GCSR: Guest Exception Return Address
pub const GCSR_ERA: usize = 0x6;
/// GCSR: Guest Bad Virtual Address
pub const GCSR_BADV: usize = 0x7;
/// GCSR: Guest Bad Instruction
pub const GCSR_BADI: usize = 0x8;
/// GCSR: Guest Exception Entry
pub const GCSR_EENTRY: usize = 0xC;
/// GCSR: Guest TLB Index
pub const GCSR_TLBIDX: usize = 0x10;
/// GCSR: Guest TLB Entry High
pub const GCSR_TLBEHI: usize = 0x11;
/// GCSR: Guest TLB Entry Low 0
pub const GCSR_TLBELO0: usize = 0x12;
/// GCSR: Guest TLB Entry Low 1
pub const GCSR_TLBELO1: usize = 0x13;
/// GCSR: Guest ASID
pub const GCSR_ASID: usize = 0x18;
/// GCSR: Guest Page Global Directory Low
pub const GCSR_PGDL: usize = 0x19;
/// GCSR: Guest Page Global Directory High
pub const GCSR_PGDH: usize = 0x1A;
/// GCSR: Guest Page Global Directory
pub const GCSR_PGD: usize = 0x1B;
/// GCSR: Guest Timer Config
pub const GCSR_TCFG: usize = 0x41;
/// GCSR: Guest Timer Value
pub const GCSR_TVAL: usize = 0x42;
/// GCSR: Guest Timer Clear
pub const GCSR_TICLR: usize = 0x44;

// ============================================================================
// GSTAT Bit Fields
// ============================================================================

/// GVM (Guest Virtualization Mode) bit - bit 0
pub const GSTAT_GVM: usize = 1 << 0;

/// PGM (Privileged Guest Mode) bit - bit 1
pub const GSTAT_PGM: usize = 1 << 1;

/// GIDBITS field mask (bits 4-9)
pub const GSTAT_GIDBITS_MASK: usize = 0x3F << 4;

/// GIDBITS field shift
pub const GSTAT_GIDBITS_SHIFT: usize = 4;

/// GID field mask (bits 16-23)
pub const GSTAT_GID_MASK: usize = 0xFF << 16;

/// GID field shift
pub const GSTAT_GID_SHIFT: usize = 16;

// ============================================================================
// GTLBC Bit Fields
// ============================================================================

/// TGID field mask (bits 16-23)
pub const GTLBC_TGID_MASK: usize = 0xFF << 16;

/// TGID field shift
pub const GTLBC_TGID_SHIFT: usize = 16;

/// USE_TGID bit - bit 12
pub const GTLBC_USE_TGID: usize = 1 << 12;

// ============================================================================
// GINTC Bit Fields
// ============================================================================

/// HWIS field mask (bits 0-7)
pub const GINTC_HWIS_MASK: usize = 0xFF;

/// HWIS field shift
pub const GINTC_HWIS_SHIFT: usize = 0;

/// HWIP field mask (bits 8-15)
pub const GINTC_HWIP_MASK: usize = 0xFF << 8;

/// HWIP field shift
pub const GINTC_HWIP_SHIFT: usize = 8;

// ============================================================================
// CSR Access Functions
// ============================================================================

/// Read a regular CSR using csrrd instruction
/// Uses const generic to ensure CSR number is known at compile time
#[inline(always)]
pub unsafe fn csr_read<const CSR_NUM: u16>() -> usize {
    let value: usize;
    core::arch::asm!("csrrd {}, {}", out(reg) value, const CSR_NUM);
    value
}

/// Write a regular CSR using csrwr instruction
/// Uses const generic to ensure CSR number is known at compile time
#[inline(always)]
pub unsafe fn csr_write<const CSR_NUM: u16>(value: usize) {
    core::arch::asm!("csrwr {}, {}", in(reg) value, const CSR_NUM);
}

// ============================================================================
// GCSR Access Functions
// ============================================================================

/// Read a Guest CSR using gcsrrd instruction
/// Uses const generic to ensure GCSR offset is known at compile time
#[inline(always)]
pub unsafe fn gcsr_read<const GCSR_OFFSET: usize>() -> usize {
    let value: usize;
    core::arch::asm!("gcsrrd {}, {}", out(reg) value, const GCSR_OFFSET);
    value
}

/// Write a Guest CSR using gcsrwr instruction
/// Uses const generic to ensure GCSR offset is known at compile time
#[inline(always)]
pub unsafe fn gcsr_write<const GCSR_OFFSET: usize>(value: usize) {
    core::arch::asm!("gcsrwr {}, {}", in(reg) value, const GCSR_OFFSET);
}

// ============================================================================
// GSTAT Register Operations
// ============================================================================

/// Read GSTAT register
#[inline(always)]
pub fn gstat_read() -> usize {
    unsafe { csr_read::<CSR_GSTAT>() }
}

/// Write GSTAT register
#[inline(always)]
pub unsafe fn gstat_write(value: usize) {
    csr_write::<CSR_GSTAT>(value)
}

/// Check if virtualization is supported (PGM bit)
pub fn has_virtualization_support() -> bool {
    (gstat_read() & GSTAT_PGM) != 0
}

/// Check if guest mode is enabled (GVM bit)
pub fn is_guest_mode_enabled() -> bool {
    (gstat_read() & GSTAT_GVM) != 0
}

/// Enable guest mode (set GVM bit)
pub unsafe fn enable_guest_mode() {
    let val = gstat_read() | GSTAT_GVM;
    gstat_write(val);
}

/// Disable guest mode (clear GVM bit)
pub unsafe fn disable_guest_mode() {
    let val = gstat_read() & !GSTAT_GVM;
    gstat_write(val);
}

/// Get current GID from GSTAT
pub fn current_gid() -> usize {
    (gstat_read() & GSTAT_GID_MASK) >> GSTAT_GID_SHIFT
}

/// Set GID in GSTAT
pub unsafe fn set_gid(gid: usize) {
    let val = (gstat_read() & !GSTAT_GID_MASK) | ((gid << GSTAT_GID_SHIFT) & GSTAT_GID_MASK);
    gstat_write(val);
}

// ============================================================================
// GTLBC Register Operations
// ============================================================================

/// Read GTLBC register
#[inline(always)]
pub fn gtlbc_read() -> usize {
    unsafe { csr_read::<CSR_GTLBC>() }
}

/// Write GTLBC register
#[inline(always)]
pub unsafe fn gtlbc_write(value: usize) {
    csr_write::<CSR_GTLBC>(value)
}

/// Set TGID in GTLBC
pub unsafe fn set_tgid(tgid: usize) {
    let val = (gtlbc_read() & !GTLBC_TGID_MASK) | ((tgid << GTLBC_TGID_SHIFT) & GTLBC_TGID_MASK);
    gtlbc_write(val);
}

/// Get TGID from GTLBC
pub fn get_tgid() -> usize {
    (gtlbc_read() & GTLBC_TGID_MASK) >> GTLBC_TGID_SHIFT
}

// ============================================================================
// GINTC Register Operations
// ============================================================================

/// Read GINTC register
#[inline(always)]
pub fn gintc_read() -> usize {
    unsafe { csr_read::<CSR_GINTC>() }
}

/// Write GINTC register
#[inline(always)]
pub unsafe fn gintc_write(value: usize) {
    csr_write::<CSR_GINTC>(value)
}

/// Set HWIS (Hardware Interrupt Status) in GINTC
pub unsafe fn gintc_set_hwis(hwis: usize) {
    let val = (gintc_read() & !GINTC_HWIS_MASK) | ((hwis << GINTC_HWIS_SHIFT) & GINTC_HWIS_MASK);
    gintc_write(val);
}

/// Get HWIS from GINTC
pub fn gintc_get_hwis() -> usize {
    (gintc_read() & GINTC_HWIS_MASK) >> GINTC_HWIS_SHIFT
}

// ============================================================================
// GCSR Operations
// ============================================================================

/// Read GCSR_ESTAT
#[inline(always)]
pub fn gcsr_estat_read() -> usize {
    unsafe { gcsr_read::<GCSR_ESTAT>() }
}

/// Write GCSR_ESTAT
#[inline(always)]
pub unsafe fn gcsr_estat_write(value: usize) {
    gcsr_write::<GCSR_ESTAT>(value)
}

/// Read GCSR_ERA
#[inline(always)]
pub fn gcsr_era_read() -> usize {
    unsafe { gcsr_read::<GCSR_ERA>() }
}

/// Write GCSR_ERA
#[inline(always)]
pub unsafe fn gcsr_era_write(value: usize) {
    gcsr_write::<GCSR_ERA>(value)
}

/// Read GCSR_EENTRY
#[inline(always)]
pub fn gcsr_eentry_read() -> usize {
    unsafe { gcsr_read::<GCSR_EENTRY>() }
}

/// Write GCSR_EENTRY
#[inline(always)]
pub unsafe fn gcsr_eentry_write(value: usize) {
    gcsr_write::<GCSR_EENTRY>(value)
}

/// Read GCSR_PGD
#[inline(always)]
pub fn gcsr_pgd_read() -> usize {
    unsafe { gcsr_read::<GCSR_PGD>() }
}

/// Write GCSR_PGD
#[inline(always)]
pub unsafe fn gcsr_pgd_write(value: usize) {
    gcsr_write::<GCSR_PGD>(value)
}

/// Read GCSR_BADV
#[inline(always)]
pub fn gcsr_badv_read() -> usize {
    unsafe { gcsr_read::<GCSR_BADV>() }
}

/// Read GCSR_CRMD
#[inline(always)]
pub fn gcsr_crmd_read() -> usize {
    unsafe { gcsr_read::<GCSR_CRMD>() }
}

/// Write GCSR_CRMD
#[inline(always)]
pub unsafe fn gcsr_crmd_write(value: usize) {
    gcsr_write::<GCSR_CRMD>(value)
}

// ============================================================================
// TLB Operations
// ============================================================================

/// Flush TLB for specific GID
pub unsafe fn flush_tlb_gid(gid: usize) {
    core::arch::asm!("invtlb 0x6, {}, {}", in(reg) gid, in(reg) 0);
    core::arch::asm!("dbar 0");
}

/// Flush all TLB entries
pub unsafe fn flush_tlb_all() {
    core::arch::asm!("invtlb 0, $r0, $r0");
    core::arch::asm!("dbar 0");
}
