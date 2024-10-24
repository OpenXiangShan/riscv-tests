# See LICENSE for license details.

#*****************************************************************************
# ssdbltrp.S
#-----------------------------------------------------------------------------
#
# Test S level double trap, when menvcfg.DTE close only test with ssdbltrp open
#

#include "riscv_test.h"
#include "test_macros.h"


RVTEST_RV64S

RVTEST_CODE_BEGIN

csrw 0x7B0, 0  // first trap to M

li a3, 1
csrw 0x7B0, 0  // only for trap to S
li t3, MSTATUS_SDT
csrr a1, sstatus
and t0, a1, t3
bnez t0, fail



TEST_PASSFAIL

    .align 4
    .global stvec_handler
    .global mtvec_handler

stvec_handler:
  li t0, 0x8
  csrr t0, sstatus;
  // when menvcfg DTE close SDT not set 1
  li t1, MSTATUS_SDT
  and t1, t1, t0
  bnez t1, fail
  li t0, 2
  beq a3, t0, pass
  add a3, a3, 1
  csrw 0x7B0, 0 
  csrr t0, sepc;                                                     
  addi t0, t0, 4;                                                      
  csrw sepc, t0;
  sret

mtvec_handler:
  li a3, 1
  // reset deleg to S/VS
  RVTEST_MTVEC_HANDLER_INIT
  // check menvcfg.DTE open
  li t0, ENVCFG_DTE
  csrr a1, menvcfg
  and t1, a1, t0
  beqz t1, fail 
  // check menvcfg.DTE close
  csrc menvcfg, t0
  csrr t0, mepc;                                                     
  addi t0, t0, 4;                                                      
  csrw mepc, t0;
  mret

RVTEST_CODE_END

  .data
  .global nodeleg

nodeleg:
  .word 0
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END
