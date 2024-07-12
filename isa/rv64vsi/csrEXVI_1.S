# See LICENSE for license details.

#*****************************************************************************
# csrEXVI_1.S
#-----------------------------------------------------------------------------
#
# Test csr virtual instruction and check nemu tval
# hstatus.VTVM = 1 , satp
#


#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64VS

RVTEST_CODE_BEGIN


  li TESTNUM, 4
  csrw 0x7B0, 0  // only for trap to M
test_csr:
  la t2, instr_array
  li a2, 0x80001
  csrw satp, 0
  csrr x0, satp
  j pass


  TEST_PASSFAIL

  .align 4
  .global stvec_handler
  .global mtvec_handler
## !!!!notice EX_VI cannot deleg to VS
stvec_handler:
  lwu t1, 0(t2)
  csrr t0, stval

  bne t0, t1, fail
  csrr t0, sepc
  addi t0, t0, 4
  csrw sepc, t0
  addi t2, t2, 4
  sret

mtvec_handler:
  // reset deleg to S/VS
  RVTEST_MTVEC_HANDLER_INIT
  // set TVM
  li a0, HSTATUS_TVM
  csrs hstatus, a0  
  li a2, 0x80001 
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
    .word 0x18005073
    .word 0x18002073

RVTEST_DATA_END
