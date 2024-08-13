// See LICENSE for license details.

#ifndef __MISALIGN_MACROS_SCALAR_H
#define __MISALIGN_MACROS_SCALAR_H

#include "riscv_test.h"

// page_table: leaf page table (level 0)
// page_table + (1 << 12): level 1 page table
// page_table + (2 << 12): level 2 page table

// map va to pa
#define MAKE_PAGE_TABLE( vaddr, paddr, page_table ) \
  \
  /* Construct the page table */ \
  \
  /* Level 0 PTE contents */ \
  /* PPN for tdat */ \
  la a0, paddr; \
  srl a0, a0, 12; \
  \
  /* attributes */ \
  sll a0, a0, PTE_PPN_SHIFT; \
  li a1, PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D; \
  or a0, a0, a1; \
  \
  \
  /* Level 0 PTE address */ \
  la a1, page_table; \
  /* equals to addi a1, a1, ((vaddr >> 12) & 0x1FF) * 8 */ \
  la t0, vaddr; \
  srli t0, t0, 12; \
  andi t0, t0, 0x1FF; \
  slli t0, t0, 3; \
  \
  /* Level 0 PTE store */ \
  add a1, a1, t0; \
  sd a0, (a1); \
  \
  /* Level 1 PTE contents */ \
  la a0, page_table; \
  srl a0, a0, 12; \
  sll a0, a0, PTE_PPN_SHIFT; \
  li a1, PTE_V; \
  or a0, a0, a1; \
  \
  /* Level 1 PTE address */\
  la a1, page_table; \
  \
  /* equals to addi a1, a1, ((vaddr >> 21) & 0x1FF) * 8 */ \
  la t0, vaddr; \
  srli t0, t0, 21; \
  andi t0, t0, 0x1FF; \
  slli t0, t0, 3; \
  add a1, a1, t0; \
  \
  li a2, 1 << 12; \
  add a1, a1, a2; \
  \
  /* Level 1 PTE store */ \
  sd a0, (a1); \
  \
  /* Level 2 PTE contents */ \
  la a0, page_table; \
  li a1, 1 << 12; \
  add a0, a0, a1; \
  srl a0, a0, 12; \
  sll a0, a0, PTE_PPN_SHIFT; \
  li a1, PTE_V; \
  or a0, a0, a1; \
  \
  /* Level 2 PTE address */ \
  la a1, page_table; \
  /* equals to addi a1, a1, ((vaddr >> 30) & 0x1FF) * 8 */ \
  la t0, vaddr; \
  srli t0, t0, 30; \
  andi t0, t0, 0x1FF; \
  slli t0, t0, 3; \
  add a1, a1, t0; \
  \
  li a2, 2 << 12; \
  add a1, a1, a2; \
  \
  /* Level 2 PTE store */ \
  sd a0, (a1);

// construct satp
#define TURN_ON_VM( page_table ) \
  la a1, page_table; \
  li a2, 2 << 12; \
  add a1, a1, a2; \
  srl a1, a1, 12; \
  li a0, (SATP_MODE & ~(SATP_MODE<<1)) * SATP_MODE_SV39; \
  or a0, a0, a1; \
  csrw satp, a0; \
  sfence.vma;

// Set up MPRV with MPP=S and SUM=1, so loads and stores can use virtual address in M mode
// the following equals to: li a1, ((MSTATUS_MPP & ~(MSTATUS_MPP<<1)) * PRV_S) | MSTATUS_MPRV 
#define USE_VA_IN_M_MODE \
  li a1, MSTATUS_MPRV; \
  csrs mstatus, a1; \
  li a1, MSTATUS_MPP; \
  csrc mstatus, a1; \
  li a1, 0x00000800; \
  csrs mstatus, a1;

#endif
