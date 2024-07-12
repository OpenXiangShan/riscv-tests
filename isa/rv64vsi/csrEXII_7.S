# See LICENSE for license details.

#*****************************************************************************
# csrEXii_7.S
#-----------------------------------------------------------------------------
#
# Test csr virtual instruction and check nemu tval
# sstatus .vs =0 ,  # 访问  vstart, vxsat, vxrm, vcsr, vl, vtype, vlenb
#


#include "riscv_test.h"
#include "test_macros.h"


#define INSERT_INSTRUCTIONS(start, end, step)                           \
        .set current, start;                                            \
        .rept ((end) - (start)) / (0x100000 * step) + 1;                      \
        .word current;                                                  \
        .set current, current + 0x100000 * step;                               \
        .endr;         
RVTEST_RV64VS

RVTEST_CODE_BEGIN

  li TESTNUM, 4
  csrw 0x7B0, 0  // only for trap to M
test_csr:
  la t2, instr_array
 # 访问 vstart
    csrr x0, vstart
    csrw vstart, 0

    # 访问 vxsat
    csrr x0, vxsat
    csrw vxsat, 0

    # 访问 vxrm
    csrr x0, vxrm
    csrw vxrm, 0

    # 访问 vcsr
    csrr x0, vcsr
    csrw vcsr, 0

    # 访问 vl
    csrr x0, vl
    csrw vl, 0

    # 访问 vtype
    csrr x0, vtype
    csrw vtype, 0

    # 访问 vlenb
    csrr x0, vlenb
    csrw vlenb, 0
  j pass


  TEST_PASSFAIL

  .align 4
  .global vstvec_handler
  .global mtvec_handler
vstvec_handler:
  lwu t1, 0(t2)
  csrr t0, stval
  li a2, 0x80001 
  bne t0, t1, fail
  csrr t0, sepc
  addi t0, t0, 4
  csrw sepc, t0
  addi t2, t2, 4
  sret

mtvec_handler:
  // reset deleg to S/VS
  RVTEST_MTVEC_HANDLER_INIT
  li a0, SSTATUS_FS
  csrc sstatus, a0
  mret
           

RVTEST_CODE_END

  # .pushsection .text_exec_writable,"awx",@progbits
  #   .align 4
  #   instr_array: .word 64
  # .popsection
  
  .data
  .global nodeleg

nodeleg:
  .word 0

RVTEST_DATA_BEGIN

  TEST_DATA

  .align 4
  instr_array: 
    .word 0x00802073
    .word 0x00805073
    .word 0x00902073
    .word 0x00905073
    .word 0x00a02073
    .word 0x00a05073
    .word 0x00f02073
    .word 0x00f05073
    .word 0xc2002073
    .word 0xc2005073
    .word 0xc2102073
    .word 0xc2105073
    .word 0xc2202073
    .word 0xc2205073

RVTEST_DATA_END

