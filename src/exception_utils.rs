use axaddrspace::GuestPhysAddr;
use axerrno::{AxResult, AxError};

/// 获取异常综合信息寄存器（LoongArch: ESTAT/ESUBCL 等）原始值
#[inline(always)]
pub fn exception_esr() -> usize {
    // LoongArch 使用 ESTAT 表示异常原因，使用 BADI/BADV 指示错误
    // 这里只做最小实现，直接读 ESTAT
    let estat: usize;
    unsafe { core::arch::asm!("gcsrrd {0}, 0x5", out(reg) estat) };
    estat
}

/// 获取异常类别（EC）。为保持与 arm_vcpu 一致，返回 Option<…> 占位。
#[inline(always)]
pub fn exception_class() -> Option<u64> {
    // 简化：返回 ESTAT 的 ECODE 字段（[21:16]），占位为 Some(value)
    let estat = exception_esr() as u64;
    let ecode = (estat >> 16) & 0x3f;
    Some(ecode)
}

/// 获取异常类别原始数值
#[inline(always)]
pub fn exception_class_value() -> usize {
    ((exception_esr() >> 16) & 0x3f) as usize
}

/// 获取导致异常的访存地址（BADV）并返回 GPA
#[inline(always)]
pub fn exception_fault_addr() -> AxResult<GuestPhysAddr> {
    // LoongArch: BADV 保存故障地址
    let badv: usize;
    unsafe { core::arch::asm!("gcsrrd {0}, 0x7", out(reg) badv) };
    Ok(GuestPhysAddr::from(badv))
}

/// 计算异常后应前进的指令步长（16/32 位指令）
#[inline(always)]
pub fn exception_next_instruction_step() -> usize {
    // LoongArch 基本指令长度 4 字节，这里默认 4
    4
}

/// 数据访问异常是否为写访问
#[inline(always)]
pub fn exception_data_abort_access_is_write() -> bool {
    // 占位：无法直接从 ESTAT 得到访存方向，这里默认读访问
    false
}

/// 数据访问异常关联的通用寄存器编号
#[inline(always)]
pub fn exception_data_abort_access_reg() -> usize {
    // 占位：返回 a0 (r4)
    4
}

/// 数据访问异常中寄存器宽度（4 或 8 字节）
#[inline(always)]
pub fn exception_data_abort_access_reg_width() -> usize {
    8
}

/// 数据访问异常的访存宽度（返回字节数：1/2/4/8）
#[inline(always)]
pub fn exception_data_abort_access_width() -> usize {
    // 默认 8 字节，占位
    8
}

/// 数据访问异常是否可由二阶段页表处理
#[inline(always)]
pub fn exception_data_abort_handleable() -> bool {
    true
}

/// 是否为权限错误
#[inline(always)]
pub fn exception_data_abort_is_permission_fault() -> bool {
    // 占位：默认非权限错误
    false
}

/// 是否为地址翻译错误
#[inline(always)]
pub fn exception_data_abort_is_translate_fault() -> bool {
    true
}

/// 系统寄存器访问：根据 ISS 计算系统寄存器编码
#[inline(always)]
pub const fn exception_sysreg_addr(iss: usize) -> usize {
    // 占位：直接返回 iss（上层会把它当成 SysRegAddr::new 的编码）
    iss
}

/// 系统寄存器访问方向（写为 true/读为 false）
#[inline(always)]
pub fn exception_sysreg_direction_write(_iss: u64) -> bool {
    // 占位：默认读
    false
}

/// 系统寄存器访问使用的通用寄存器编号
#[inline(always)]
pub fn exception_sysreg_gpr(_iss: u64) -> u64 {
    // 占位：使用 a0 (r4)
    4
}

/// 返回 ISS 原始值（供上层通用解析）
#[inline(always)]
pub fn exception_iss() -> usize {
    // LoongArch 没有与 ARM ESR::ISS 完全等价的统一编码。
    // 这里作为占位，返回 ESTAT 全部位作为“ISS”。
    exception_esr()
}
