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

use axerrno::AxResult;
use axvcpu::AxArchPerCpu;

use crate::registers::*;

// External symbol for exception vectors defined in exception.S
unsafe extern "C" {
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
    /// Original value of GCSR_EENTRY (Guest Exception Entry)
    pub original_gcsr_eentry: usize,
}

impl AxArchPerCpu for LoongArchPerCpu {
    fn new(cpu_id: usize) -> AxResult<Self> {
        Ok(Self {
            cpu_id,
            original_eentry: 0,
            original_gstat: 0,
            original_gcsr_eentry: 0,
        })
    }

    fn is_enabled(&self) -> bool {
        // Check if virtualization is enabled by examining GSTAT.GVM
        // GSTAT[0] is GVM (Guest Virtualization Mode) bit
        is_guest_mode_enabled()
    }

    fn hardware_enable(&mut self) -> AxResult {
        // Save original exception entry (EENTRY) CSR
        // EENTRY is CSR 0xC (Exception Entry Base Address)
        self.original_eentry = unsafe { csr_read::<CSR_EENTRY>() };

        // Save original GSTAT
        self.original_gstat = gstat_read();

        // Save original GCSR_EENTRY
        self.original_gcsr_eentry = gcsr_eentry_read();

        // Enable guest virtualization mode by setting GSTAT.GVM = 1
        // According to LoongArch Virtualization specification:
        // - Set GSTAT.GVM = 1 to enable guest mode
        unsafe {
            enable_guest_mode();
        }

        // Set GCSR_EENTRY to guest exception entry point (_exception_vectors)
        let geentry_addr = unsafe { &_exception_vectors as *const u8 as usize };
        unsafe {
            gcsr_eentry_write(geentry_addr);
        }

        debug!("LoongArch virtualization enabled for CPU {}, GCSR_EENTRY={:#x}", self.cpu_id, geentry_addr);
        Ok(())
    }

    fn hardware_disable(&mut self) -> AxResult {
        // Restore original GSTAT
        unsafe {
            gstat_write(self.original_gstat);
        }

        // Restore original GCSR_EENTRY
        unsafe {
            gcsr_eentry_write(self.original_gcsr_eentry);
        }

        // Restore original EENTRY
        unsafe {
            csr_write::<CSR_EENTRY>(self.original_eentry);
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
