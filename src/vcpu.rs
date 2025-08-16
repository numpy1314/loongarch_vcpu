use core::marker::PhantomData;
use register::{cpu::LocalRegisterCopy, register_bitfields, register_structs};

// 定义LoongArch CSR寄存器地址
const CSR_GSTAT: u32 = 0x50;
const CSR_GCTL: u32 = 0x51;
const CSR_GTLBC: u32 = 0x15;
const CSR_TLBRPRMD: u32 = 0x15;
const CSR_MERRCTL: u32 = 0x1C;
const CSR_GINTC: u32 = 0x52;
const CSR_GCNTC: u32 = 0x53;
const CSR_ERA: u32 = 0x6;
const CSR_BADV: u32 = 0x7;
const CSR_ESTAT: u32 = 0x5;

// 寄存器位域定义
register_bitfields! {
    u64,
    // 客户机状态寄存器 (GSTAT)
    GSTAT [
        GID      OFFSET(16) NUMBITS(8) [],  // 客户机ID
        PGM      OFFSET(1)  NUMBITS(1) [],  // 客户机模式标志
    ],
    
    // 客户机控制寄存器 (GCTL)
    GCTL [
        TOPI     OFFSET(7)  NUMBITS(1) [],  // 特权指令陷入
        TOTI     OFFSET(9)  NUMBITS(1) [],  // 计时器指令陷入
        TOE      OFFSET(11) NUMBITS(1) [],  // 例外陷入
        TOP      OFFSET(13) NUMBITS(1) [],  // PLV修改陷入
        TOHU     OFFSET(15) NUMBITS(1) [],  // 未实现CSR访问陷入
        TOCI     OFFSET(20) NUMBITS(2) [   // Cache操作陷入级别
            ALL = 0,
            EXCLUDE_HIT = 1,
            EXCLUDE_HIT_AND_WB = 2
        ],
        GPMNum   OFFSET(24) NUMBITS(3) []  // 性能监测器分配数量
    ],
    
    // TLB重填例外前模式信息 (TLBRPRMD)
    TLBRPRMD [
        PGM      OFFSET(3) NUMBITS(1) []  // 例外前客户机模式
    ],
    
    // 机器错误控制 (MERRCTL)
    MERRCTL [
        PGM      OFFSET(5) NUMBITS(1) []  // 客户机模式标志
    ],
    
    // 客户机中断控制 (GINTCTL)
    GINTC [
        HWIS     OFFSET(0)  NUMBITS(8) [],  // 软件注入中断
        HWIP     OFFSET(8)  NUMBITS(8) [],  // 直连中断使能
        HWIC     OFFSET(16) NUMBITS(8) []   // 中断清除控制
    ],
    
    // 例外状态 (ESTAT)
    ESTAT [
        ECODE    OFFSET(16) NUMBITS(6) [],  // 例外代码
        ESUBCODE OFFSET(22) NUMBITS(9) []   // 例外子代码
    ]
}

// 客户机TLB控制寄存器 (GTLBC)
register_structs! {
    pub GTLBC (0x18) {
        (0x00 => GMTLBNum: ReadWrite<u8, 6>),  // Guest MTLB项数
        (0x01 => useTGID: ReadWrite<u8, 1>),    // TGID使用标志
        (0x02 => TOTLBI: ReadWrite<u8, 1>),     // TLB指令陷入
        (0x03 => _reserved),
        (0x08 => TGID: ReadWrite<u8, 8>)        // 目标GID
    }
}

/// Per-CPU数据结构
#[repr(C)]
#[repr(align(4096))]
pub struct LoongArchPerCpu<H: VcpuHal> {
    pub cpu_id: usize,
    host_gstat: LocalRegisterCopy<u64, GSTAT::Register>,  // 保存的Host GSTAT
    host_era: u64,                                        // 保存的Host ERA
    _phantom: PhantomData<H>,
}

impl<H: VcpuHal> LoongArchPerCpu<H> {
    pub fn new(cpu_id: usize) -> Self {
        Self {
            cpu_id,
            host_gstat: LocalRegisterCopy::new(0),
            host_era: 0,
            _phantom: PhantomData,
        }
    }

    /// 启用虚拟化硬件支持
    pub fn hardware_enable(&mut self) {
        // 保存Host状态
        self.host_gstat.set(unsafe { csr_read(CSR_GSTAT) });
        self.host_era = unsafe { csr_read(CSR_ERA) };
        
        // 配置虚拟化扩展
        let mut gctl = unsafe { csr_read(CSR_GCTL) };
        GCTL::TOPI.set(&mut gctl, 1);    // 特权指令陷入
        GCTL::TOTI.set(&mut gctl, 1);    // 计时器指令陷入
        GCTL::TOE.set(&mut gctl, 1);     // 例外陷入
        GCTL::TOP.set(&mut gctl, 1);     // PLV修改陷入
        GCTL::TOHU.set(&mut gctl, 1);    // 未实现CSR访问陷入
        GCTL::TOCI.set(&mut gctl, 0);    // 所有Cache操作陷入
        unsafe { csr_write(CSR_GCTL, gctl) };
        
        // 配置中断处理
        let mut gintc = unsafe { csr_read(CSR_GINTC) };
        GINTC::HWIP.set(&mut gintc, 0xFF);  // 使能所有直连中断
        unsafe { csr_write(CSR_GINTC, gintc) };
    }

    /// 禁用虚拟化硬件支持
    pub fn hardware_disable(&mut self) {
        // 恢复Host状态
        unsafe {
            csr_write(CSR_GSTAT, self.host_gstat.get());
            csr_write(CSR_ERA, self.host_era);
        }
    }
}

/// vCPU结构体
pub struct LoongArchVcpu<H: VcpuHal> {
    gid: u8,                          // 客户机ID
    guest_pgd: u64,                   // 客户机页表基址
    entry_point: u64,                 // 客户机入口地址
    _phantom: PhantomData<H>,
}

impl<H: VcpuHal> LoongArchVcpu<H> {
    pub fn new(gid: u8, pgd: u64) -> Self {
        Self {
            gid,
            guest_pgd: pgd,
            entry_point: 0,
            _phantom: PhantomData,
        }
    }

    /// 设置客户机入口点
    pub fn set_entry_point(&mut self, entry: u64) {
        self.entry_point = entry;
    }

    /// 运行vCPU
    pub fn run(&self) -> VmExitReason {
        // 设置客户机状态
        let mut gstat = unsafe { csr_read(CSR_GSTAT) };
        GSTAT::GID.set(&mut gstat, self.gid as u64);
        GSTAT::PGM.set(&mut gstat, 1);  // 进入客户机模式
        unsafe { csr_write(CSR_GSTAT, gstat) };
        
        // 设置客户机页表
        unsafe { gcsr_write(CSR_PGD, self.guest_pgd) };
        
        // 设置入口点
        unsafe { gcsr_write(CSR_ERA, self.entry_point) };
        
        // 执行客户机代码
        unsafe { asm!("ertn") };
        
        // 处理退出
        self.handle_exit()
    }

    /// 处理客户机退出
    fn handle_exit(&self) -> VmExitReason {
        let estat = unsafe { csr_read(CSR_ESTAT) };
        let ecode = ESTAT::ECODE.get(estat) as u32;
        let esubcode = ESTAT::ESUBCODE.get(estat) as u32;
        let badv = unsafe { csr_read(CSR_BADV) };
        
        match ecode {
            0x1F => VmExitReason::HvcCall(esubcode),  // HVCL指令
            0x22 => VmExitReason::GcsrAccess(badv),   // CSR访问
            0x23 => VmExitReason::GprAccess(badv),    // 特权资源访问
            _ => VmExitReason::Unknown(ecode, esubcode),
        }
    }
}

/// CSR读取（内联汇编实现）
unsafe fn csr_read(csr_num: u32) -> u64 {
    let value: u64;
    asm!("csrrd {}, {}", out(reg) value, const csr_num);
    value
}

/// CSR写入（内联汇编实现）
unsafe fn csr_write(csr_num: u32, value: u64) {
    asm!("csrwr {}, {}", in(reg) value, const csr_num);
}

/// Guest CSR读取（GCSRRD指令）
unsafe fn gcsr_read(csr_num: u32) -> u64 {
    let value: u64;
    asm!("gcsrrd {}, {}", out(reg) value, const csr_num);
    value
}

/// Guest CSR写入（GCSRWR指令）
unsafe fn gcsr_write(csr_num: u32, value: u64) {
    asm!("gcsrwr {}, {}", in(reg) value, const csr_num);
}

/// 虚拟机退出原因
pub enum VmExitReason {
    HvcCall(u32),        // HVCL调用
    GcsrAccess(u64),     // CSR访问
    GprAccess(u64),      // 特权资源访问
    Unknown(u32, u32),   // 未知原因
}

/// VCPU硬件抽象层
pub trait VcpuHal {
    fn handle_interrupt(&self);
    fn handle_exception(&self, ecode: u32, esubcode: u32);
}