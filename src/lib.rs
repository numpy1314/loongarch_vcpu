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

#![no_std]
#![feature(doc_cfg)]
#![cfg(target_arch = "loongarch64")]
#![doc = include_str!("../README.md")]

#[macro_use]
extern crate log;

mod context_frame;
mod exception;
mod pcpu;
mod vcpu;

pub use self::pcpu::LoongArchPerCpu;
pub use self::vcpu::{LoongArchVCpu, LoongArchVCpuCreateConfig};

/// Return if current platform support virtualization extension.
pub fn has_hardware_support() -> bool {
    let cpucfg2: u64;
    unsafe {
        core::arch::asm!("cpucfg {0:r}, {1:r}", out(reg) cpucfg2, in(reg) 2);
    }
    (cpucfg2 & (1 << 10)) != 0
}
