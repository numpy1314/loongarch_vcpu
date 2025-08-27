#include <asm/asm.h>

.section .text

/*
 * Exception entry points for LoongArch64
 * These are the entry points for various exceptions that can occur during VM execution
 */

/*
 * Synchronous exception entry point
 * This is called when a synchronous exception occurs in the guest VM
 */
.align 4
.global exception_sync_entry
exception_sync_entry:
    // TODO: 实现同步异常入口点
    
    // TODO: 保存所有通用寄存器到栈上
    
    // TODO: 保存必要的系统寄存器
    
    // TODO: 跳转到handle_exception_sync函数
    
    // TODO: 恢复寄存器并返回到虚拟机

/*
 * IRQ exception entry point
 * This is called when an IRQ occurs in the guest VM
 */
.align 4
.global exception_irq_entry
exception_irq_entry:
    // TODO: 实现IRQ异常入口点
    
    // TODO: 保存所有通用寄存器到栈上
    
    // TODO: 保存必要的系统寄存器
    
    // TODO: 跳转到IRQ处理函数
    
    // TODO: 恢复寄存器并返回到虚拟机

/*
 * FIQ exception entry point
 * This is called when an FIQ occurs in the guest VM
 */
.align 4
.global exception_fiq_entry
exception_fiq_entry:
    // TODO: 实现FIQ异常入口点
    
    // TODO: 保存通用寄存器

    // TODO: 保存所有通用寄存器到栈上
    
    // TODO: 保存必要的系统寄存器
    
    // TODO: 跳转到FIQ处理函数
    
    // TODO: 恢复寄存器并返回到虚拟机

/*
 * SError exception entry point
 * This is called when an SError occurs in the guest VM
 */
.align 4
.global exception_serror_entry
exception_serror_entry:
    // TODO: 实现SError异常入口点
    
    // TODO: 保存所有通用寄存器到栈上
    
    // TODO: 保存必要的系统寄存器
    
    // TODO: 跳转到SError处理函数
    
    // TODO: 恢复寄存器并返回到虚拟机

/*
 * VM entry point
 * This is the entry point for entering a guest VM
 */
.align 4
.global context_vm_entry
context_vm_entry:
    // TODO: 实现虚拟机入口点
    
    // TODO: 恢复虚拟机的通用寄存器
    
    // TODO: 恢复虚拟机的系统寄存器
    
    // TODO: 设置虚拟机的运行状态
    
    // TODO: 跳转到虚拟机的入口地址

/*
 * VM exit point
 * This is the exit point when leaving a guest VM
 */
.align 4
.global context_vm_exit
context_vm_exit:
    // TODO: 实现虚拟机退出点
    
    // TODO: 保存虚拟机的通用寄存器
    
    // TODO: 保存虚拟机的系统寄存器
    
    // TODO: 恢复主机的寄存器
    
    // TODO: 返回到主机代码

/*
 * Exception return
 * This is used to return from an exception handler
 */
.align 4
.global exception_return
exception_return:

// 占位：提供与 arm_vcpu 一致的符号，指向异常向量基址
.align 4
.global exception_vector_base_vcpu
exception_vector_base_vcpu:
    // 简单跳转到同步异常入口（可根据需要细分）
    b exception_sync_entry
    // TODO: 实现异常返回
    
    // TODO: 恢复保存的寄存器
    
    // TODO: 返回到异常发生的地方
