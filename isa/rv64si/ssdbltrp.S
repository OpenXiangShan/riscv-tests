# See LICENSE for license details.

#*****************************************************************************
# ssdbltrp.S
#-----------------------------------------------------------------------------
#
# Test S level double trap, when menvcfg.DTE open default  only test with ssdbltrp_open
#

#include "riscv_test.h"
#include "test_macros.h"


RVTEST_RV64S

RVTEST_CODE_BEGIN

csrw 0x7B0, 0  // only for trap to S
li t3, MSTATUS_SDT
csrr a1, sstatus
and t0, a1, t3
bnez t0, fail
csrw 0x7B0, 0  // only for trap to S
li t3, MSTATUS_SDT
csrr a1, sstatus
and t0, a1, t3
bnez t0, fail
csrw 0x7B0, 0  // only for trap to S
li t3, MSTATUS_SDT
csrr a1, sstatus
and t0, a1, t3
bnez t0, fail
j pass



TEST_PASSFAIL

    .align 4
    .global stvec_handler
    .global mtvec_handler

stvec_handler:
  li t0, 0x8
  csrr t0, sstatus;
  // check sdt set 1
  li t1, MSTATUS_SDT
  and t1, t1, t0
  beqz t1, fail
  csrw 0x7B0, 0 
  csrr t0, sepc;                                                     
  addi t0, t0, 4;                                                      
  csrw sepc, t0;
  sret

mtvec_handler:
  li t1, 0x2;
  csrr t0, mtval2;
  bne t1, t0, fail;
  li t1, 16
  csrr t0, mcause;
  bne t1, t0, fail;
  csrr t0, mstatus;
  li t1, MSTATUS_SDT | MNSTATUS_MNPP_S
  and t1, t1, t0
  beqz t1, fail
  li t1, MNSTATUS_MNPP_M & (!MNSTATUS_MNPP_S)
  and t1, t1, t0
  bnez t1, fail
  csrr t0, mepc;                                                     
  addi t0, t0, 4;                                                      
  csrw mepc, t0;
  mret

RVTEST_CODE_END

  .data

RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END
