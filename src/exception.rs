use crate::TrapFrame;
use crate::exception_utils::{
    exception_class, exception_class_value, exception_data_abort_access_is_write,
    exception_data_abort_access_reg, exception_data_abort_access_reg_width,
    exception_data_abort_access_width, exception_data_abort_handleable,
    exception_data_abort_is_permission_fault, exception_data_abort_is_translate_fault,
    exception_esr, exception_fault_addr, exception_next_instruction_step, exception_sysreg_addr,
    exception_sysreg_direction_write, exception_sysreg_gpr,
};
use axaddrspace::{
    GuestPhysAddr,
    device::{AccessWidth, SysRegAddr},
};
use axerrno::{AxError, AxResult};
use axvcpu::AxVCpuExitReason;
use log::error;

numeric_enum_macro::numeric_enum! {
#[repr(u8)]
#[derive(Debug)]
pub enum TrapKind {
    Synchronous = 0,
    Irq = 1,
    Fiq = 2,
    SError = 3,
}
}

/// Equals to [`TrapKind::Synchronous`], used in exception.S.
const EXCEPTION_SYNC: usize = TrapKind::Synchronous as usize;
/// Equals to [`TrapKind::Irq`], used in exception.S.
const EXCEPTION_IRQ: usize = TrapKind::Irq as usize;

core::arch::global_asm!(
    include_str!("exception.S"),
    // exception_sync = const EXCEPTION_SYNC,
    // exception_irq = const EXCEPTION_IRQ,
);

/// 同步异常处理骨架
pub fn handle_exception_sync(ctx: &mut TrapFrame) -> AxResult<AxVCpuExitReason> {
    // 依 arm_vcpu 的处理模型，先根据“异常类别”分发
    match exception_class() {
        // 占位：将所有情况先按 data abort 路径处理，便于上层接管 MMIO
        Some(_ecode) => {
            let era = ctx.exception_pc();
            let next = era + exception_next_instruction_step();
            ctx.set_exception_pc(next);
            handle_data_abort(ctx)
        }
        None => {
            error!(
                "Unhandled sync exception: estat={:#x}, class={:#x}, ctx={:#x?}",
                exception_esr(),
                exception_class_value(),
                ctx
            );
            panic!("Unhandled synchronous exception (LoongArch)");
        }
    }
}

fn handle_data_abort(context_frame: &mut TrapFrame) -> AxResult<AxVCpuExitReason> {
    let addr = exception_fault_addr()?;
    let access_width = exception_data_abort_access_width();
    let is_write = exception_data_abort_access_is_write();
    let reg = exception_data_abort_access_reg();
    let reg_width = exception_data_abort_access_reg_width();

    trace!(
        "LA64 Data fault @{addr:?}, ERA {:#x}, estat: 0x{:x}",
        context_frame.exception_pc(),
        exception_esr(),
    );

    let width = match AccessWidth::try_from(access_width) {
        Ok(access_width) => access_width,
        Err(_) => return Err(AxError::InvalidInput),
    };

    let reg_width = match AccessWidth::try_from(reg_width) {
        Ok(reg_width) => reg_width,
        Err(_) => return Err(AxError::InvalidInput),
    };

    if !exception_data_abort_handleable() {
        panic!(
            "Core data abort not handleable {:#x}, estat {:#x}",
            addr,
            exception_esr()
        );
    }

    if !exception_data_abort_is_translate_fault() {
        if exception_data_abort_is_permission_fault() {
            return Err(AxError::Unsupported);
        } else {
            panic!("Core data abort is not translate fault {:#x}", addr,);
        }
    }

    if is_write {
        return Ok(AxVCpuExitReason::MmioWrite {
            addr,
            width,
            data: context_frame.gpr(reg) as u64,
        });
    }
    Ok(AxVCpuExitReason::MmioRead {
        addr,
        width,
        reg,
        reg_width,
        signed_ext: false,
    })
}
