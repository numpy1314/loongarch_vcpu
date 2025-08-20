#![no_std]
#![feature(doc_cfg)]
use core::arch::asm;

/// Return if current platform support virtualization extension.
pub fn has_hardware_support() -> bool {
    let cpucfg2: u64;
    unsafe {
        asm!("cpucfg {0:r}, {1:r}", out(reg) cpucfg2, in(reg) 2);
    }
    (cpucfg2 & (1 << 10)) != 0
}
