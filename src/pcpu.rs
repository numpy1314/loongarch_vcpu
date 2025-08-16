use core::{cell::OnceCell, marker::PhantomData, arch::asm};
use axerrno::AxResult;
use axvcpu::{AxArchPerCpu, AxVCpuHal};
use percpu::def_percpu;

// 手动定义 LoongArch CSR 地址
const CSR_EENTRY: usize = 0x0C;   // 例外入口地址
const CSR_GSTAT: usize = 0x50;    // 客户机状态寄存器
const CSR_GCTL: usize = 0x51;     // 客户机控制寄存器
const CSR_GINTCTL: usize = 0x52;  // 客户机中断控制寄存器

// GSTAT 寄存器位域
const GSTAT_PGM: usize = 1 << 1;  // 客户机模式位
const GSTAT_GID_MASK: usize = 0xFF << 16; // GID 域掩码
const GSTAT_GID_SHIFT: usize = 16;

// GCTL 寄存器位域
const GCTL_TOTI: usize = 1 << 9;   // Trap On Timer Inst
const GCTL_TOCI: usize = 1 << 20;  // Trap On Cacheop Inst
const GCTL_TOPI: usize = 1 << 13;  // Trap On Privilege Inst
const GCTL_TOHU: usize = 1 << 15;  // Trap On Host Unimplemented CSR

// GINTCTL 寄存器位域
const GINTCTL_HWIP: usize = 0xFF << 8;   // 硬件中断直连使能
const GINTCTL_HWIC: usize = 0xFF << 16;  // 硬件中断清除使能

/// Per-CPU 数据结构
#[repr(C)]
#[repr(align(4096))]
pub struct LoongArchPerCpu<H: AxVCpuHal> {
    pub cpu_id: usize,
    _phantom: PhantomData<H>,
}

#[def_percpu]
static ORI_EXCEPTION_VECTOR_BASE: usize = 0;

#[def_percpu]
pub static IRQ_HANDLER: OnceCell<&(dyn Fn() + Send + Sync)> = OnceCell::new();

unsafe extern "C" {
    fn exception_vector_base_vcpu();
}

// CSR 读写辅助函数
fn csr_read(csr_num: usize) -> usize {
    let value;
    unsafe {
        asm!(
            "csrrd {}, {}",
            out(reg) value,
            in(reg) csr_num
        );
    }
    value
}

fn csr_write(csr_num: usize, value: usize) {
    unsafe {
        asm!(
            "csrwr {}, {}",
            in(reg) value,
            in(reg) csr_num
        );
    }
}

impl<H: AxVCpuHal> AxArchPerCpu for LoongArchPerCpu<H> {
    fn new(cpu_id: usize) -> AxResult<Self> {
        // Replace with a valid handler, e.g. H::irq_handler if it exists, or a default empty handler
        let _ = unsafe { IRQ_HANDLER.current_ref_mut_raw() }
            .set(&|| {})
            .map(|_| {});

        Ok(Self {
            cpu_id,
            _phantom: PhantomData,
        })
    }

    fn is_enabled(&self) -> bool {
        // 检查是否在客户机模式 (GSTAT.PGM=1)
        (csr_read(CSR_GSTAT) & GSTAT_PGM) != 0
    }

    fn hardware_enable(&mut self) -> AxResult {
        // 保存原始异常入口
        unsafe { ORI_EXCEPTION_VECTOR_BASE.write_current_raw(csr_read(CSR_EENTRY)) }

        // 设置新的异常向量基址
        csr_write(CSR_EENTRY, exception_vector_base_vcpu as usize);

        // 配置客户机状态寄存器
        let mut gstat = csr_read(CSR_GSTAT);
        // 设置客户机ID (CPU ID)
        gstat = (gstat & !GSTAT_GID_MASK) | ((self.cpu_id as usize) << GSTAT_GID_SHIFT);
        // 启用客户机模式
        gstat |= GSTAT_PGM;
        csr_write(CSR_GSTAT, gstat);

        // 配置客户机控制寄存器
        let gctl = GCTL_TOTI | GCTL_TOCI | GCTL_TOPI | GCTL_TOHU;
        csr_write(CSR_GCTL, gctl);

        // 配置中断控制
        csr_write(CSR_GINTCTL, GINTCTL_HWIP | GINTCTL_HWIC);

        Ok(())
    }

    fn hardware_disable(&mut self) -> AxResult {
        // 恢复原始异常入口
        csr_write(
            CSR_EENTRY, 
            unsafe { ORI_EXCEPTION_VECTOR_BASE.read_current_raw() }
        );
        
        // 清除客户机模式
        let mut gstat = csr_read(CSR_GSTAT);
        gstat &= !GSTAT_PGM;
        csr_write(CSR_GSTAT, gstat);
        
        Ok(())
    }
}