#![no_std]
#![feature(doc_cfg)]
use core::arch::asm;

#[macro_use]
extern crate log;

mod context_frame;
#[macro_use]
mod exception_utils;
mod exception;
mod pcpu;
// mod smc;
mod vcpu;
mod register;
/// context frame for loongarch64
pub type TrapFrame = context_frame::LoongArch64ContextFrame;

pub use self::pcpu::LoongArch64PerCpu;
pub use self::vcpu::{LoongArch64VCpu, LoongArch64VCpuCreateConfig, LoongArch64VCpuSetupConfig};

/// Return if current platform support virtualization extension.
pub fn has_hardware_support() -> bool {
    let cpucfg2: u64;
    unsafe {
        asm!("cpucfg {0}, {1}", out(reg) cpucfg2, in(reg) 2);
    }
    (cpucfg2 & (1 << 10)) != 0
}
