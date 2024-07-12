# See LICENSE for license details.

#*****************************************************************************
# csrEXII_6.S
#-----------------------------------------------------------------------------
#
# Test csr virtual instruction and check nemu tval
# mcounteren.TM=1 menvcfg.STCE=1 get s/vstimcmp with no exception
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64S

RVTEST_CODE_BEGIN


#ifdef __HYPERVISOR_MODE
  #define stvec_handler vstvec_handler
#endif

  li TESTNUM, 4
  csrw 0x7B0, 0  // only for trap to M
test_csr:
  la t2, instr_array
  li a2, 0x80001
  csrw stimecmp, 0
  csrr x0, stimecmp
  csrw vstimecmp, 0
  csrr x0, vstimecmp
  j pass


  TEST_PASSFAIL

  .align 4
  .global stvec_handler
  .global mtvec_handler
stvec_handler:
  j fail
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
  li a0, COUNTER_TM
  csrs mcounteren, a0
  li a0, ENVCFG_STCE
  csrs menvcfg, a0
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
    .word 0x00105073
    .word 0x00102073
    .word 0x24D05073
    .word 0x24D02073

RVTEST_DATA_END
