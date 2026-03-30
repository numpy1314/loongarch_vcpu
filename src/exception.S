/*
 * Copyright 2025 The Axvisor Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * LoongArch exception handling assembly code
 *
 * This file contains the low-level exception handling routines for LoongArch.
 * It includes:
 * - _run_guest: Entry point to run a guest VM
 * - _guest_exit: Handler for VM exits
 * - exception vectors for different trap types
 * - register save/restore macros
 */

.section .text

/*
 * Macro to save guest registers to LoongArchContextFrame
 *
 * On entry:
 *   - sp points to LoongArchContextFrame base address
 *   - All guest registers are in their original state
 *
 * On exit:
 *   - x0-x31, sepc, crmd, prmd, estat saved to context frame
 *   - sp unchanged
 */
.macro SAVE_GUEST_REGS
    // Save general purpose registers x0-x31
    // Note: x0 is zero register but we save it for completeness
    st.d    $r0, $sp, 0
    st.d    $r1, $sp, 8
    st.d    $r2, $sp, 16
    st.d    $r3, $sp, 24
    st.d    $r4, $sp, 32
    st.d    $r5, $sp, 40
    st.d    $r6, $sp, 48
    st.d    $r7, $sp, 56
    st.d    $r8, $sp, 64
    st.d    $r9, $sp, 72
    st.d    $r10, $sp, 80
    st.d    $r11, $sp, 88
    st.d    $r12, $sp, 96
    st.d    $r13, $sp, 104
    st.d    $r14, $sp, 112
    st.d    $r15, $sp, 120
    st.d    $r16, $sp, 128
    st.d    $r17, $sp, 136
    st.d    $r18, $sp, 144
    st.d    $r19, $sp, 152
    st.d    $r20, $sp, 160
    st.d    $r21, $sp, 168
    st.d    $r22, $sp, 176
    st.d    $r23, $sp, 184
    st.d    $r24, $sp, 192
    st.d    $r25, $sp, 200
    st.d    $r26, $sp, 208
    st.d    $r27, $sp, 216
    st.d    $r28, $sp, 224
    st.d    $r29, $sp, 232
    st.d    $r30, $sp, 240
    st.d    $r31, $sp, 248

    // Save CSR registers
    csrrd   $t0, 0x6      // ERA (Exception Return Address, same as sepc)
    st.d    $t0, $sp, 256  // sepc field
    csrrd   $t0, 0x0      // CRMD
    st.d    $t0, $sp, 264  // crmd field
    csrrd   $t0, 0x1      // PRMD
    st.d    $t0, $sp, 272  // prmd field
    csrrd   $t0, 0x5      // ESTAT
    st.d    $t0, $sp, 280  // estat field
.endm

/*
 * Macro to restore guest registers from LoongArchContextFrame
 *
 * On entry:
 *   - sp points to LoongArchContextFrame base address
 *   - Context frame contains saved register values
 *
 * On exit:
 *   - x0-x31, sepc, crmd, prmd, estat restored
 *   - sp unchanged
 */
.macro RESTORE_GUEST_REGS
    // Restore CSR registers (except ERA which will be restored later)
    ld.d    $t0, $sp, 256  // ERA (sepc)
    csrwr   $t0, 0x6
    ld.d    $t0, $sp, 264  // CRMD
    csrwr   $t0, 0x0
    ld.d    $t0, $sp, 272  // PRMD
    csrwr   $t0, 0x1
    ld.d    $t0, $sp, 280  // ESTAT
    csrwr   $t0, 0x5

    // Restore general purpose registers x1-x31
    // Note: x0 is zero register, skip it
    ld.d    $r1, $sp, 8
    ld.d    $r2, $sp, 16
    ld.d    $r3, $sp, 24
    ld.d    $r4, $sp, 32
    ld.d    $r5, $sp, 40
    ld.d    $r6, $sp, 48
    ld.d    $r7, $sp, 56
    ld.d    $r8, $sp, 64
    ld.d    $r9, $sp, 72
    ld.d    $r10, $sp, 80
    ld.d    $r11, $sp, 88
    ld.d    $r12, $sp, 96
    ld.d    $r13, $sp, 104
    ld.d    $r14, $sp, 112
    ld.d    $r15, $sp, 120
    ld.d    $r16, $sp, 128
    ld.d    $r17, $sp, 136
    ld.d    $r18, $sp, 144
    ld.d    $r19, $sp, 152
    ld.d    $r20, $sp, 160
    ld.d    $r21, $sp, 168
    ld.d    $r22, $sp, 176
    ld.d    $r23, $sp, 184
    ld.d    $r24, $sp, 192
    ld.d    $r25, $sp, 200
    ld.d    $r26, $sp, 208
    ld.d    $r27, $sp, 216
    ld.d    $r28, $sp, 224
    ld.d    $r29, $sp, 232
    ld.d    $r30, $sp, 240
    ld.d    $r31, $sp, 248

    // x0 is zero register, no need to restore
    ld.d    $r0, $sp, 0    // Load but won't affect zero register
.endm

/*
 * Enter the guest given in `LoongArchContextFrame` from `a0`
 *
 * Parameters:
 *   a0 - Pointer to LoongArchContextFrame (guest state)
 *
 * This function:
 * 1. Saves host context (minimal)
 * 2. Restores guest context from LoongArchContextFrame
 * 3. Enters guest mode with ertn (Exception Return) instruction
 */
.global _run_guest
_run_guest:
    // a0 contains pointer to LoongArchContextFrame
    // Save return address (ra) temporarily
    move    $t1, $ra

    // Set sp to point to context frame
    move    $sp, $a0
    // Save context frame pointer in x21 (s0/fp) for exception vectors
    move    $r21, $a0

    // Restore guest registers from context frame
    RESTORE_GUEST_REGS

    // Return to guest using ertn
    // This will jump to ERA (sepc) and restore previous mode
    ertn

    // Should not reach here
    jr      $t1  // Return to caller if ertn fails

/*
 * Guest exit handler - called from exception vector
 *
 * This function:
 * 1. Saves guest context to LoongArchContextFrame
 * 2. Jumps to Rust vmexit_trampoline with exit reason in a0
 * 3. vmexit_trampoline restores host context and returns to hypervisor
 */
.global _guest_exit
_guest_exit:
    // sp points to LoongArchContextFrame (set by exception vector)
    // Save guest registers to context frame
    SAVE_GUEST_REGS

    // a0 already contains exit reason (set by exception vector)
    // Jump to vmexit_trampoline (not call, as it will restore ra and return directly)
    b       vmexit_trampoline

/*
 * Exception vector table
 * LoongArch requires exception vectors at EENTRY + (ECODE * vector_offset)
 * Each vector is 80 bytes (0x50) aligned
 */
.section .vectors, "ax"
.align 12  // 4KB alignment for exception vector base
.global _exception_vectors
_exception_vectors:
    // Vector for ECODE 0x0 - Int (Interrupt)
    .org 0x0
    b       _irq_handler_vector

    // Vector for ECODE 0x1 - PIL (Page Invalid Load)
    .org 0x80
    b       _sync_handler_vector

    // Vector for ECODE 0x2 - PIS (Page Invalid Store)
    .org 0x100
    b       _sync_handler_vector

    // Vector for ECODE 0x3 - PIF (Page Invalid Fetch)
    .org 0x180
    b       _sync_handler_vector

    // Vector for ECODE 0x4 - PME (Page Modified Exception)
    .org 0x200
    b       _sync_handler_vector

    // Vector for ECODE 0x5 - PPI (Page Privilege Illegal)
    .org 0x280
    b       _sync_handler_vector

    // Vector for ECODE 0x8 - TLBR (TLB Refill)
    .org 0x400
    b       _sync_handler_vector

    // Vector for ECODE 0x9 - TLBL (TLB Load)
    .org 0x480
    b       _sync_handler_vector

    // Vector for ECODE 0xA - TLBS (TLB Store)
    .org 0x500
    b       _sync_handler_vector

    // Vector for ECODE 0xB - TLBM (TLB Modify)
    .org 0x580
    b       _sync_handler_vector

    // Vector for ECODE 0xC - FPE (Floating Point Exception)
    .org 0x600
    b       _sync_handler_vector

    // Vector for ECODE 0xD - SXE (System Call Exception)
    .org 0x680
    b       _sync_handler_vector

    // Vector for ECODE 0xE - BRK (Breakpoint Exception)
    .org 0x700
    b       _sync_handler_vector

    // Vector for ECODE 0xF - DBE (Debug Exception)
    .org 0x780
    b       _sync_handler_vector

    // Vector for ECODE 0x10 - RSE (Reserved Instruction Exception)
    .org 0x800
    b       _sync_handler_vector

    // Vector for ECODE 0x11 - FPD (Floating Point Disabled)
    .org 0x880
    b       _sync_handler_vector

    // Vector for ECODE 0x12 - LSXE (LSX Exception)
    .org 0x900
    b       _sync_handler_vector

    // Vector for ECODE 0x13 - LASXE (LASX Exception)
    .org 0x980
    b       _sync_handler_vector

    // Vector for ECODE 0x14 - BTE (Binary Translation Exception)
    .org 0xA00
    b       _sync_handler_vector

    // Vector for ECODE 0x15 - GSPR (Guest SPR Access)
    .org 0xA80
    b       _sync_handler_vector

    // Vector for ECODE 0x16 - HVC (Hypervisor Call) - Most important for us!
    .org 0xB00
    b       _hvc_handler_vector

    // Vector for ECODE 0x17 - GCSC (Guest CSR Access)
    .org 0xB80
    b       _sync_handler_vector

    // Vector for ECODE 0x18 - GDVPE (Guest DVPE)
    .org 0xC00
    b       _sync_handler_vector

    // Vector for ECODE 0x19 - GPERF (Guest Performance)
    .org 0xC80
    b       _sync_handler_vector

    // Vector for ECODE 0x1A - GTIMER (Guest Timer)
    .org 0xD00
    b       _sync_handler_vector

    // Vector for ECODE 0x1B - GIPI (Guest IPI)
    .org 0xD80
    b       _sync_handler_vector

/*
 * IRQ handler vector
 */
_irq_handler_vector:
    // Set sp to point to context frame (stored in x21/s0/fp)
    move    $sp, $r21

    // Save guest context
    SAVE_GUEST_REGS

    // Set exit reason to Irq (1)
    li.d    $a0, 1  // TrapKind::Irq

    // Jump to common exit handler
    b       _guest_exit

/*
 * Synchronous exception handler vector (for most exceptions)
 */
_sync_handler_vector:
    // Set sp to point to context frame (stored in x21/s0/fp)
    move    $sp, $r21

    // Save guest context
    SAVE_GUEST_REGS

    // Set exit reason to Synchronous (0)
    li.d    $a0, 0  // TrapKind::Synchronous

    // Jump to common exit handler
    b       _guest_exit

/*
 * HVC handler vector (special handling for hypercalls)
 */
_hvc_handler_vector:
    // Set sp to point to context frame (stored in x21/s0/fp)
    move    $sp, $r21

    // Save guest context
    SAVE_GUEST_REGS

    // Set exit reason to Synchronous (0)
    // HVC is handled as synchronous exception in Rust
    li.d    $a0, 0  // TrapKind::Synchronous

    // Jump to common exit handler
    b       _guest_exit