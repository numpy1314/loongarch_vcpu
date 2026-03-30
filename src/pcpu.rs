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

use core::mem;
use axerrno::AxResult;
use axvcpu::AxArchPerCpu;

// External symbol for exception vectors defined in exception.S
extern "C" {
    static _exception_vectors: u8;
}

/// Per-CPU data for LoongArch.
/// A pointer to this struct is loaded into thread pointer when a CPU starts.
#[repr(C)]
#[repr(align(4096))]
pub struct LoongArchPerCpu {
    /// CPU ID
    pub cpu_id: usize,
    /// Original value of exception vector base before enabling virtualization
    pub original_eentry: usize,
    /// Original value of GSTAT (Guest Status) CSR
    pub original_gstat: usize,
    /// Original value of GEENTRY (Guest Exception Entry) CSR
    pub original_geentry: usize,
}

/// Get GSTAT (Guest Status) CSR value
fn read_gstat() -> usize {
    let gstat: usize;
    unsafe {
        core::arch::asm!("csrrd {}, 0x180", out(reg) gstat);
    }
    gstat
}

/// Write GSTAT (Guest Status) CSR
fn write_gstat(value: usize) {
    unsafe {
        core::arch::asm!("csrwr {}, 0x180", in(reg) value);
    }
}

/// Get GCTL (Guest Control) CSR value
fn read_gctl() -> usize {
    let gctl: usize;
    unsafe {
        core::arch::asm!("csrrd {}, 0x181", out(reg) gctl);
    }
    gctl
}

/// Write GCTL (Guest Control) CSR
fn write_gctl(value: usize) {
    unsafe {
        core::arch::asm!("csrwr {}, 0x181", in(reg) value);
    }
}

/// Get GEENTRY (Guest Exception Entry) CSR value
fn read_geentry() -> usize {
    let geentry: usize;
    unsafe {
        core::arch::asm!("csrrd {}, 0x182", out(reg) geentry);
    }
    geentry
}

/// Write GEENTRY (Guest Exception Entry) CSR
fn write_geentry(value: usize) {
    unsafe {
        core::arch::asm!("csrwr {}, 0x182", in(reg) value);
    }
}

impl AxArchPerCpu for LoongArchPerCpu {
    fn new(cpu_id: usize) -> AxResult<Self> {
        Ok(Self {
            cpu_id,
            original_eentry: 0,
            original_gstat: 0,
            original_geentry: 0,
        })
    }

    fn is_enabled(&self) -> bool {
        // Check if virtualization is enabled by examining GSTAT.GVM
        // GSTAT[0] is GVM (Guest Virtualization Mode) bit
        let gstat = read_gstat();
        (gstat & 0x1) != 0
    }

    fn hardware_enable(&mut self) -> AxResult {
        // Save original exception entry (EENTRY) CSR
        // EENTRY is CSR 0xC (Exception Entry Base Address)
        let eentry: usize;
        unsafe {
            core::arch::asm!("csrrd {}, 0xC", out(reg) eentry);
        }
        self.original_eentry = eentry;

        // Save original GSTAT
        self.original_gstat = read_gstat();

        // Save original GEENTRY
        self.original_geentry = read_geentry();

        // Enable guest virtualization mode by setting GSTAT.GVM = 1
        // According to LoongArch Virtualization specification:
        // - Set GSTAT[0] = 1 to enable guest mode
        // - Set GCTL[0] = 1 to enable guest timer
        let mut gstat = read_gstat();
        gstat |= 0x1; // Set GVM bit
        write_gstat(gstat);

        let mut gctl = read_gctl();
        gctl |= 0x1; // Enable guest timer
        write_gctl(gctl);

        // Set GEENTRY to guest exception entry point (_exception_vectors)
        let geentry_addr = unsafe { &_exception_vectors as *const u8 as usize };
        write_geentry(geentry_addr);

        debug!("LoongArch virtualization enabled for CPU {}, GEENTRY={:#x}", self.cpu_id, geentry_addr);
        Ok(())
    }

    fn hardware_disable(&mut self) -> AxResult {
        // Restore original GSTAT
        write_gstat(self.original_gstat);

        // Restore original GEENTRY
        write_geentry(self.original_geentry);

        // Restore original EENTRY
        unsafe {
            core::arch::asm!("csrwr {}, 0xC", in(reg) self.original_eentry);
        }

        debug!("LoongArch virtualization disabled for CPU {}", self.cpu_id);
        Ok(())
    }

    fn max_guest_page_table_levels(&self) -> usize {
        // LoongArch uses 4-level page tables (PGD, PUD, PMD, PTE) for 48-bit virtual address
        // TODO: Determine based on actual hardware support
        4
    }
}