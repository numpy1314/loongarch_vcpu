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

use core::fmt::Formatter;

/// Index of LoongArch general purpose registers in `LoongArchContextFrame`.
#[allow(missing_docs)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GprIndex {
    R0 = 0,   // Zero register
    R1,       // ra (return address)
    R2,       // tp (thread pointer)
    R3,       // sp (stack pointer)
    R4,       // a0
    R5,       // a1
    R6,       // a2
    R7,       // a3
    R8,       // a4
    R9,       // a5
    R10,      // a6
    R11,      // a7
    R12,      // t0
    R13,      // t1
    R14,      // t2
    R15,      // t3
    R16,      // t4
    R17,      // t5
    R18,      // t6
    R19,      // t7
    R20,      // t8
    R21,      // s0/fp
    R22,      // s1
    R23,      // s2
    R24,      // s3
    R25,      // s4
    R26,      // s5
    R27,      // s6
    R28,      // s7
    R29,      // s8
    R30,      // s9
    R31,      // s10
}

impl GprIndex {
    /// Get register index from raw value.
    pub fn from_raw(raw: u32) -> Option<Self> {
        use GprIndex::*;
        match raw {
            0 => Some(R0),
            1 => Some(R1),
            2 => Some(R2),
            3 => Some(R3),
            4 => Some(R4),
            5 => Some(R5),
            6 => Some(R6),
            7 => Some(R7),
            8 => Some(R8),
            9 => Some(R9),
            10 => Some(R10),
            11 => Some(R11),
            12 => Some(R12),
            13 => Some(R13),
            14 => Some(R14),
            15 => Some(R15),
            16 => Some(R16),
            17 => Some(R17),
            18 => Some(R18),
            19 => Some(R19),
            20 => Some(R20),
            21 => Some(R21),
            22 => Some(R22),
            23 => Some(R23),
            24 => Some(R24),
            25 => Some(R25),
            26 => Some(R26),
            27 => Some(R27),
            28 => Some(R28),
            29 => Some(R29),
            30 => Some(R30),
            31 => Some(R31),
            _ => None,
        }
    }
}

/// A struct representing the LoongArch CPU context frame.
///
/// This context frame includes:
/// * the general-purpose registers (GPRs),
/// * the exception program counter (sepc/era),
/// * the status register (crmd/prmd).
///
/// The `#[repr(C)]` attribute ensures that the struct has a C-compatible
/// memory layout, which is important when interfacing with hardware or
/// other low-level components.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct LoongArchContextFrame {
    /// An array of 32 `usize` values representing the general-purpose registers.
    pub x: [usize; 32],
    /// The exception program counter (sepc/era)
    pub sepc: usize,
    /// Current mode register (CRMD)
    pub crmd: usize,
    /// Previous mode register (PRMD)
    pub prmd: usize,
    /// Exception status register (ESTAT)
    pub estat: usize,
}

impl Default for LoongArchContextFrame {
    fn default() -> Self {
        LoongArchContextFrame {
            x: [0; 32],
            sepc: 0,
            crmd: 0,
            prmd: 0,
            estat: 0,
        }
    }
}

impl core::fmt::Display for LoongArchContextFrame {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        for i in 0..32 {
            write!(f, "x{:02}: {:016x}   ", i, self.x[i])?;
            if (i + 1) % 2 == 0 {
                writeln!(f)?;
            }
        }
        writeln!(f, "sepc: {:016x}", self.sepc)?;
        writeln!(f, "crmd: {:016x}", self.crmd)?;
        writeln!(f, "prmd: {:016x}", self.prmd)?;
        write!(f, "estat: {:016x}", self.estat)
    }
}

impl LoongArchContextFrame {
    /// Returns the exception program counter (sepc).
    pub fn exception_pc(&self) -> usize {
        self.sepc
    }

    /// Sets the exception program counter (sepc).
    ///
    /// # Arguments
    ///
    /// * `pc` - The new program counter value.
    pub fn set_exception_pc(&mut self, pc: usize) {
        self.sepc = pc;
    }

    /// Sets the argument in register a0 (x[4]).
    ///
    /// # Arguments
    ///
    /// * `arg` - The argument to be passed in register a0.
    pub fn set_argument(&mut self, arg: usize) {
        self.x[4] = arg;
    }

    /// Sets the value of a general-purpose register (GPR).
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the general-purpose register (0 to 31).
    /// * `val` - The value to be set in the register.
    ///
    /// # Behavior
    /// - If `index` is between 0 and 31, the register at the specified index is set to `val`.
    /// - If `index` is 0, the operation is ignored, as it corresponds to the zero register.
    ///
    /// # Panics
    /// Panics if the provided `index` is outside the range 0 to 31.
    pub fn set_gpr(&mut self, index: usize, val: usize) {
        match index {
            0 => (), // Ignore writes to zero register
            1..=31 => self.x[index] = val,
            _ => panic!("Invalid general-purpose register index {}", index),
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
    /// * For `index` 0, this method returns 0, as it corresponds to the zero register.
    pub fn gpr(&self, index: usize) -> usize {
        match index {
            0 => 0,
            1..=31 => self.x[index],
            _ => panic!("Invalid general-purpose register index {}", index),
        }
    }

    /// Gets the value of a0 register.
    pub fn get_a0(&self) -> usize {
        self.x[4]
    }

    /// Gets the value of a1 register.
    pub fn get_a1(&self) -> usize {
        self.x[5]
    }

    /// Gets the value of a2 register.
    pub fn get_a2(&self) -> usize {
        self.x[6]
    }

    /// Gets the value of a3 register.
    pub fn get_a3(&self) -> usize {
        self.x[7]
    }

    /// Gets the value of a4 register.
    pub fn get_a4(&self) -> usize {
        self.x[8]
    }

    /// Gets the value of a5 register.
    pub fn get_a5(&self) -> usize {
        self.x[9]
    }

    /// Gets the value of a6 register.
    pub fn get_a6(&self) -> usize {
        self.x[10]
    }

    /// Gets the value of a7 register.
    pub fn get_a7(&self) -> usize {
        self.x[11]
    }

    /// Sets the value of a0 register.
    pub fn set_a0(&mut self, val: usize) {
        self.x[4] = val;
    }

    /// Sets the value of a1 register.
    pub fn set_a1(&mut self, val: usize) {
        self.x[5] = val;
    }

    /// Sets the value of a2 register.
    pub fn set_a2(&mut self, val: usize) {
        self.x[6] = val;
    }

    /// Sets the value of a3 register.
    pub fn set_a3(&mut self, val: usize) {
        self.x[7] = val;
    }
}

/// Represents the VM context for a guest virtual machine in a hypervisor environment.
///
/// The `LoongArchGuestSystemRegisters` structure contains various CSR registers needed to manage
/// and restore the context of a virtual machine (VM).
///
/// The structure is aligned to 16 bytes to ensure proper memory alignment for efficient access.
#[repr(C)]
#[repr(align(16))]
#[derive(Debug, Clone, Copy, Default)]
pub struct LoongArchGuestSystemRegisters {
    // Guest-related CSRs
    /// Guest page table base address (PGD)
    pub gpgd: usize,
    /// Guest page table base address low (PGDL)
    pub gpgdl: usize,
    /// Guest page table base address high (PGDH)
    pub gpgdh: usize,
    /// Guest ASID
    pub gasid: usize,
    /// Guest timer configuration (GTCFG)
    pub gtcfg: usize,
    /// Guest timer value (GTVAL)
    pub gtval: usize,
    /// Guest timer clear (GTICLR)
    pub gticlr: usize,
    /// Guest TLB entry high (GTLBEHI)
    pub gtlbehi: usize,
    /// Guest TLB entry low 0 (GTLBELO0)
    pub gtlbello0: usize,
    /// Guest TLB entry low 1 (GTLBELO1)
    pub gtlbello1: usize,
    /// Guest TLB index (GTLBIDX)
    pub gtlbidx: usize,
    /// Guest status (GSTAT)
    pub gstat: usize,
    /// Guest control (GCTL)
    pub gctl: usize,
    /// Guest exception entry (GEENTRY)
    pub geentry: usize,
    /// Guest exception return address (GERA)
    pub gera: usize,
    /// Guest bad virtual address (GBADV)
    pub gbadv: usize,
    /// Guest bad instruction (GBADI)
    pub gbadi: usize,
}

impl LoongArchGuestSystemRegisters {
    /// Resets the VM context by setting all registers to zero.
    ///
    /// This method allows the `LoongArchGuestSystemRegisters` instance to be reused by resetting
    /// its state to the default values (all zeros).
    #[allow(unused)]
    pub fn reset(&mut self) {
        *self = LoongArchGuestSystemRegisters::default()
    }

    /// Stores the current values of all relevant guest GCSR registers.
    ///
    /// This method uses `gcsrrd` instruction to read GCSR values.
    /// GCSRs are Guest Control and Status Registers, accessed via gcsrrd/gcsrwr instructions.
    ///
    /// GCSR offsets (from LoongArch Virtualization spec):
    /// - GCSR_PGD (0x1B): Guest Page Global Directory
    /// - GCSR_PGDL (0x19): Guest PGD Low
    /// - GCSR_PGDH (0x1A): Guest PGD High
    /// - GCSR_ASID (0x18): Guest ASID
    /// - GCSR_TCFG (0x41): Guest Timer Config
    /// - GCSR_TVAL (0x42): Guest Timer Value
    /// - GCSR_TICLR (0x44): Guest Timer Clear
    /// - GCSR_TLBEHI (0x11): Guest TLB Entry High
    /// - GCSR_TLBELO0 (0x12): Guest TLB Entry Low 0
    /// - GCSR_TLBELO1 (0x13): Guest TLB Entry Low 1
    /// - GCSR_TLBIDX (0x10): Guest TLB Index
    /// - GCSR_ESTAT (0x5): Guest Exception Status
    /// - GCSR_ERA (0x6): Guest Exception Return Address
    /// - GCSR_EENTRY (0xC): Guest Exception Entry
    /// - GCSR_BADV (0x7): Guest Bad Virtual Address
    /// - GCSR_BADI (0x8): Guest Bad Instruction
    pub unsafe fn store(&mut self) {
        use crate::registers::*;
        unsafe {
            // Guest page table GCSRs
            self.gpgd = gcsr_read::<GCSR_PGD>();
            self.gpgdl = gcsr_read::<GCSR_PGDL>();
            self.gpgdh = gcsr_read::<GCSR_PGDH>();
            self.gasid = gcsr_read::<GCSR_ASID>();

            // Guest timer GCSRs
            self.gtcfg = gcsr_read::<GCSR_TCFG>();
            self.gtval = gcsr_read::<GCSR_TVAL>();
            self.gticlr = gcsr_read::<GCSR_TICLR>();

            // Guest TLB GCSRs
            self.gtlbehi = gcsr_read::<GCSR_TLBEHI>();
            self.gtlbello0 = gcsr_read::<GCSR_TLBELO0>();
            self.gtlbello1 = gcsr_read::<GCSR_TLBELO1>();
            self.gtlbidx = gcsr_read::<GCSR_TLBIDX>();

            // Guest control/status GCSRs
            // Note: GSTAT is a regular CSR (0x50), not a GCSR
            // It contains GVM (Guest Virtualization Mode) and GID (Guest ID) fields
            self.gstat = crate::registers::gstat_read();
            self.gera = gcsr_read::<GCSR_ERA>();
            self.geentry = gcsr_read::<GCSR_EENTRY>();
            self.gbadv = gcsr_read::<GCSR_BADV>();
            self.gbadi = gcsr_read::<GCSR_BADI>();

            // Note: GCTL is a regular CSR (0x51), not a GCSR
            self.gctl = crate::registers::csr_read::<{ crate::registers::CSR_GCTL }>();
        }
    }

    /// Restores the values of all relevant guest GCSR registers.
    ///
    /// This method uses `gcsrwr` instruction to write GCSR values.
    pub unsafe fn restore(&self) {
        use crate::registers::*;
        unsafe {
            // Guest page table GCSRs
            gcsr_write::<GCSR_PGD>(self.gpgd);
            gcsr_write::<GCSR_PGDL>(self.gpgdl);
            gcsr_write::<GCSR_PGDH>(self.gpgdh);
            gcsr_write::<GCSR_ASID>(self.gasid);

            // Guest timer GCSRs
            gcsr_write::<GCSR_TCFG>(self.gtcfg);
            gcsr_write::<GCSR_TVAL>(self.gtval);
            gcsr_write::<GCSR_TICLR>(self.gticlr);

            // Guest TLB GCSRs
            gcsr_write::<GCSR_TLBEHI>(self.gtlbehi);
            gcsr_write::<GCSR_TLBELO0>(self.gtlbello0);
            gcsr_write::<GCSR_TLBELO1>(self.gtlbello1);
            gcsr_write::<GCSR_TLBIDX>(self.gtlbidx);

            // Guest control/status GCSRs
            // Note: We intentionally don't restore gstat here as it's handled separately
            gcsr_write::<GCSR_ERA>(self.gera);
            gcsr_write::<GCSR_EENTRY>(self.geentry);
            // Note: GBADV and GBADI are read-only, so we don't restore them

            // Restore GCTL (Guest Control Register) - regular CSR, not GCSR
            csr_write::<CSR_GCTL>(self.gctl);
        }
    }
}