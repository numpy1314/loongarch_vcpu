use core::{arch::asm, fmt::Formatter};

/// A struct representing the LoongArch64 CPU context frame.
///
/// This context frame includes
/// * the general-purpose registers (GPRs),
/// * the stack pointer,
/// * the exception link register (ERA),
/// * the saved program status registers.
///
/// The `#[repr(C)]` attribute ensures that the struct has a C-compatible
/// memory layout, which is important when interfacing with hardware or
/// other low-level components.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct LoongArch64ContextFrame {
    /// An array of 32 `usize` values representing the general-purpose registers.
    pub gpr: [usize; 32],
    /// The stack pointer
    pub sp: usize,
    /// The exception link register, which stores the return address after an exception.
    pub era: usize,
    /// The saved program status registers, which hold the state of the program at the time of an exception.
    pub crmd: usize,
    pub prmd: usize,
    pub euen: usize,
    pub estat: usize,
}

/// Implementations of [`fmt::Display`] for [`LoongArch64ContextFrame`].
impl core::fmt::Display for LoongArch64ContextFrame {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        for i in 0..32 {
            write!(f, "r{:02}: {:016x}   ", i, self.gpr[i])?;
            if (i + 1) % 2 == 0 {
                writeln!(f)?;
            }
        }
        writeln!(f, "crmd:{:016x}", self.crmd)?;
        writeln!(f, "prmd:{:016x}", self.prmd)?;
        writeln!(f, "euen:{:016x}", self.euen)?;
        writeln!(f, "estat:{:016x}", self.estat)?;
        write!(f, "era: {:016x}", self.era)?;
        writeln!(f, "   sp:  {:016x}", self.sp)?;
        Ok(())
    }
}

impl Default for LoongArch64ContextFrame {
    /// Returns the default context frame.
    ///
    /// The default state sets the status registers to mask all exceptions and sets the mode appropriately.
    fn default() -> Self {
        LoongArch64ContextFrame {
            gpr: [0; 32],
            crmd: 0, // TODO: 设置默认的CRMD值
            prmd: 0, // TODO: 设置默认的PRMD值
            euen: 0, // TODO: 设置默认的EUEN值
            estat: 0, // TODO: 设置默认的ESTAT值
            era: 0,
            sp: 0,
        }
    }
}

impl LoongArch64ContextFrame {
    /// Returns the exception program counter (ERA).
    pub fn exception_pc(&self) -> usize {
        self.era
    }

    /// Sets the exception program counter (ERA).
    ///
    /// # Arguments
    ///
    /// * `pc` - The new program counter value.
    pub fn set_exception_pc(&mut self, pc: usize) {
        self.era = pc;
    }

    /// Sets the argument in register a0 (r4).
    ///
    /// # Arguments
    ///
    /// * `arg` - The argument to be passed in register a0.
    pub fn set_argument(&mut self, arg: usize) {
        self.gpr[4] = arg; // a0 is r4 in LoongArch
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
    /// - If `index` is 0, the operation is ignored, as it corresponds to the zero register
    ///   (`r0` in LoongArch), which always reads as zero and cannot be modified.
    ///
    /// # Panics
    /// - If `index` is greater than 31.
    pub fn set_gpr(&mut self, index: usize, val: usize) {
        if index == 0 {
            // r0 is the zero register, ignore writes
            return;
        }
        if index > 31 {
            panic!("Invalid GPR index: {}", index);
        }
        self.gpr[index] = val;
    }

    /// Gets the value of a general-purpose register (GPR).
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the general-purpose register (0 to 31).
    ///
    /// # Returns
    /// - The value of the register at the specified index.
    ///
    /// # Panics
    /// - If `index` is greater than 31.
    pub fn gpr(&self, index: usize) -> usize {
        if index > 31 {
            panic!("Invalid GPR index: {}", index);
        }
        self.gpr[index]
    }
}

/// Guest-visible system registers snapshot for LoongArch64.
/// Only a necessary subset is modeled here; expand as your entry/exit paths require.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct GuestSystemRegisters {
    // 通用控制和状态寄存器 (General Control and Status Registers)
    pub gcsr_crmd: usize,   // CRMD - 当前模式寄存器
    pub gcsr_prmd: usize,   // PRMD - 前一个模式寄存器
    pub gcsr_euen: usize,   // EUEN - 扩展单元使能寄存器
    pub gcsr_misc: usize,   // MISC - 杂项寄存器
    pub gcsr_ectl: usize,   // ECTL - 异常控制寄存器
    pub gcsr_estat: usize,  // ESTAT - 异常状态寄存器
    pub gcsr_era: usize,    // ERA - 异常返回地址
    pub gcsr_badv: usize,   // BADV - 错误地址寄存器
    pub gcsr_badi: usize,   // BADI - 错误指令寄存器
    pub gcsr_eentry: usize, // EENTRY - 异常入口地址

    // TLB寄存器 (TLB Registers)
    pub gcsr_tlbidx: usize,  // TLBIDX - TLB索引寄存器
    pub gcsr_tlbehi: usize,  // TLBEHI - TLB条目高位寄存器
    pub gcsr_tlbelo0: usize, // TLBELO0 - TLB条目低位0寄存器
    pub gcsr_tlbelo1: usize, // TLBELO1 - TLB条目低位1寄存器

    // 页表寄存器 (Page Table Registers)
    pub gcsr_asid: usize, // ASID - 地址空间ID
    pub gcsr_pgdl: usize, // PGDL - 页表根地址低32位
    pub gcsr_pgdh: usize, // PGDH - 页表根地址高32位
    pub gcsr_pgd: usize,  // PGD - 页表根地址
    pub gcsr_pwcl: usize, // PWCL - 页表遍历控制低32位
    pub gcsr_pwch: usize, // PWCH - 页表遍历控制高32位

    // 二级TLB寄存器 (Second Level TLB Registers)
    pub gcsr_stlbps: usize, // STLBPS - 共享TLB页大小
    pub gcsr_ravcfg: usize, // RAVCFG - 随机访问向量配置

    // 处理器寄存器 (Processor Registers)
    pub gcsr_cpuid: usize,  // CPUID - CPU ID寄存器
    pub gcsr_prcfg1: usize, // PRCFG1 - 处理器配置1
    pub gcsr_prcfg2: usize, // PRCFG2 - 处理器配置2
    pub gcsr_prcfg3: usize, // PRCFG3 - 处理器配置3

    // 保存寄存器 (Saved Registers)
    pub gcsr_save0: usize,  // SAVE0 - 保存寄存器0
    pub gcsr_save1: usize,  // SAVE1 - 保存寄存器1
    pub gcsr_save2: usize,  // SAVE2 - 保存寄存器2
    pub gcsr_save3: usize,  // SAVE3 - 保存寄存器3
    pub gcsr_save4: usize,  // SAVE4 - 保存寄存器4
    pub gcsr_save5: usize,  // SAVE5 - 保存寄存器5
    pub gcsr_save6: usize,  // SAVE6 - 保存寄存器6
    pub gcsr_save7: usize,  // SAVE7 - 保存寄存器7
    pub gcsr_save8: usize,  // SAVE8 - 保存寄存器8
    pub gcsr_save9: usize,  // SAVE9 - 保存寄存器9
    pub gcsr_save10: usize, // SAVE10 - 保存寄存器10
    pub gcsr_save11: usize, // SAVE11 - 保存寄存器11
    pub gcsr_save12: usize, // SAVE12 - 保存寄存器12
    pub gcsr_save13: usize, // SAVE13 - 保存寄存器13
    pub gcsr_save14: usize, // SAVE14 - 保存寄存器14
    pub gcsr_save15: usize, // SAVE15 - 保存寄存器15

    // 定时器寄存器 (Timer Registers)
    pub gcsr_tid: usize,   // TID - 定时器ID
    pub gcsr_tcfg: usize,  // TCFG - 定时器配置
    pub gcsr_tval: usize,  // TVAL - 定时器值
    pub gcsr_cntc: usize,  // CNTC - 计数器值
    pub gcsr_ticlr: usize, // TICLR - 定时器中断清除

    // 链接加载缓冲区寄存器 (Load Linked Buffers Registers)
    pub gcsr_llbctl: usize, // LLBCTL - 链接加载缓冲区控制

    // TLB读取条目寄存器 (TLB Read Entry Registers)
    pub gcsr_tlbrentry: usize, // TLBRENTRY - TLB读取条目
    pub gcsr_tlbrbadv: usize,  // TLBRBADV - TLB读取错误地址
    pub gcsr_tlbrera: usize,   // TLBRERA - TLB读取异常返回地址
    pub gcsr_tlbrsave: usize,  // TLBRSAVE - TLB读取保存寄存器
    pub gcsr_tlbrelo0: usize,  // TLBRELO0 - TLB读取条目低位0
    pub gcsr_tlbrelo1: usize,  // TLBRELO1 - TLB读取条目低位1
    pub gcsr_tlbrehi: usize,   // TLBREHI - TLB读取条目高位
    pub gcsr_tlbrprmd: usize,  // TLBRPRMD - TLB读取前一个模式

    // 数据内存窗口寄存器 (Data Memory Write Registers)
    pub gcsr_dmw0: usize, // DMW0 - 数据内存窗口0
    pub gcsr_dmw1: usize, // DMW1 - 数据内存窗口1
    pub gcsr_dmw2: usize, // DMW2 - 数据内存窗口2
    pub gcsr_dmw3: usize, // DMW3 - 数据内存窗口3

    // 为了兼容性保留的简化字段名
    pub pgdl: usize, // 页表根地址低32位 (兼容性字段)
    pub pgdh: usize, // 页表根地址高32位 (兼容性字段)
    pub asid: usize, // 地址空间ID (兼容性字段)
    pub tcfg: usize, // 定时器配置 (兼容性字段)
    pub tval: usize, // 定时器值 (兼容性字段)
    pub cntc: usize, // 计数器值 (兼容性字段)
    pub crmd: usize, // 当前模式寄存器 (兼容性字段)
    pub prmd: usize, // 前一个模式寄存器 (兼容性字段)
    pub euen: usize, // 扩展单元使能寄存器 (兼容性字段)
    pub estat: usize, // 异常状态寄存器 (兼容性字段)
}

impl GuestSystemRegisters {
    /// Store current system registers to this struct.
    pub fn store(&mut self) {
        unsafe {
            // hvisor/src/arch/loongarch64/trap.rs
            
            // 页表相关寄存器
            core::arch::asm!("gcsrrd {}, 0x19", out(reg) self.pgdl); // PGDL
            core::arch::asm!("gcsrrd {}, 0x1a", out(reg) self.pgdh); // PGDH
            core::arch::asm!("gcsrrd {}, 0x18", out(reg) self.asid); // ASID
            
            // 定时器相关寄存器
            core::arch::asm!("gcsrrd {}, 0x41", out(reg) self.tcfg); // TCFG
            core::arch::asm!("gcsrrd {}, 0x42", out(reg) self.tval); // TVAL
            core::arch::asm!("gcsrrd {}, 0x43", out(reg) self.cntc); // CNTC
            
            // 其他系统寄存器
            core::arch::asm!("gcsrrd {}, 0x0", out(reg) self.crmd);  // CRMD
            core::arch::asm!("gcsrrd {}, 0x1", out(reg) self.prmd);  // PRMD
            core::arch::asm!("gcsrrd {}, 0x2", out(reg) self.euen);  // EUEN
            core::arch::asm!("gcsrrd {}, 0x5", out(reg) self.estat); // ESTAT
        }
    }

    /// Restore system registers from this struct.
    pub fn restore(&self) {
        unsafe {
            // hvisor/src/arch/loongarch64/trap.rs
            
            // 恢复页表相关寄存器
            core::arch::asm!("gcsrwr {}, 0x19", in(reg) self.pgdl); // PGDL
            core::arch::asm!("gcsrwr {}, 0x1a", in(reg) self.pgdh); // PGDH
            core::arch::asm!("gcsrwr {}, 0x18", in(reg) self.asid); // ASID
            
            // 恢复定时器相关寄存器
            core::arch::asm!("gcsrwr {}, 0x41", in(reg) self.tcfg); // TCFG
            core::arch::asm!("gcsrwr {}, 0x42", in(reg) self.tval); // TVAL
            core::arch::asm!("gcsrwr {}, 0x43", in(reg) self.cntc); // CNTC
            
            // 恢复其他系统寄存器
            core::arch::asm!("gcsrwr {}, 0x0", in(reg) self.crmd);  // CRMD
            core::arch::asm!("gcsrwr {}, 0x1", in(reg) self.prmd);  // PRMD
            core::arch::asm!("gcsrwr {}, 0x2", in(reg) self.euen);  // EUEN
            core::arch::asm!("gcsrwr {}, 0x5", in(reg) self.estat); // ESTAT
        }
    }
}

pub type TrapFrame = LoongArch64ContextFrame;
