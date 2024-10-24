# See LICENSE for license details.

#*****************************************************************************
# nmi.S
#-----------------------------------------------------------------------------
#
# Test nmi
# when mnstatus.nmie open，test when  NEMU/xiangshan trigger nmi interrupt by set nmi signal always 1 (cannot test with norm xiangshan or test by nemu itself)
#

#include "riscv_test.h"
#include "test_macros.h"


RVTEST_RV64M

RVTEST_CODE_BEGIN


li a0, MNSTATUS_NMIE 
csrs 0x744, a0
li t0 , (1<<63)
csrr t1, 0x742
bne t0, t1, fail
j pass



TEST_PASSFAIL

    .align 4
    .global mtvec_handler

mtvec_handler:
  // reset deleg to S/VS
  li t0, MNSTATUS_MNPP_M
  csrr t1, 0x744
  bne t0, t1, fail
  li t0, (1<<63) | 1
  csrr t1, 0x742
  bne t0, t1, fail
  li	a0,0
  .insn	4, 0x006b
  .word 0x70200073

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END
