use core::{cell::OnceCell, marker::PhantomData};

use axerrno::AxResult;
use axvcpu::{AxArchPerCpu, AxVCpuHal};

/// Per-CPU data. A pointer to this struct is loaded into TP when a CPU starts. This structure
#[repr(C)]
#[repr(align(4096))]
pub struct LoongArch64PerCpu<H: AxVCpuHal> {
    /// per cpu id
    pub cpu_id: usize,
    _phantom: PhantomData<H>,
}

#[percpu::def_percpu]
static IRQ_HANDLER: OnceCell<&(dyn Fn() + Send + Sync)> = OnceCell::new();

unsafe extern "C" {
    fn exception_vector_base_vcpu();
}

impl<H: AxVCpuHal> AxArchPerCpu for LoongArch64PerCpu<H> {
    fn new(cpu_id: usize) -> AxResult<Self> {
        // 注册底层宿主提供的 IRQ 分发回调
        let _ = unsafe { IRQ_HANDLER.current_ref_mut_raw() }
            .set(&|| H::irq_hanlder())
            .map(|_| {});

        Ok(Self {
            cpu_id,
            _phantom: PhantomData,
        })
    }

    fn is_enabled(&self) -> bool {
        // TODO(la64): 查询虚拟化开关（如 CSR.VINTC/CSR.ECFG 等），此处先返回 true
        true
    }

    fn hardware_enable(&mut self) -> AxResult {
        unsafe {
            // TODO(la64): 设置异常向量到 vcpu 入口，开启必要的虚拟化/中断位
            let base = exception_vector_base_vcpu as usize;
            core::arch::asm!(
                // 设定异常入口 EENTRY = base
                "gcsrwr {0}, 0x0c", // EENTRY
                in(reg) base,
            );
        }
        Ok(())
    }

    fn hardware_disable(&mut self) -> AxResult {
        // TODO(la64): 恢复原异常向量/关闭虚拟化
        Ok(())
    }
}
