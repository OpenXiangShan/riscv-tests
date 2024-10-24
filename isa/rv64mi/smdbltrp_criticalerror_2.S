# See LICENSE for license details.

#*****************************************************************************
# smdbltrp_criticalerror_2.S
#-----------------------------------------------------------------------------
#
# Test when mnstatus.nmie=0 and trap cause critical error (if trap in mnhandler) (only can test with smdbltrp open)
#


#include "riscv_test.h"
#include "test_macros.h"


RVTEST_RV64M

RVTEST_CODE_BEGIN

li a0, MNSTATUS_NMIE 
csrs 0x744, a0
csrr a1, mstatus
# clear MDT
li t0, MSTATUS_MDT
csrc mstatus, t0
li t0, 0x8
csrw 0x7B0, 0  # only for trap to M
li t3, MSTATUS_MDT
csrr a1, mstatus
and t0, a1, t3
bnez t0, fail
csrw 0x7B0, 0  # only for trap to M
li t3, MSTATUS_MDT
csrr a1, mstatus
and t0, a1, t3
bnez t0, fail
csrw 0x7B0, 0  # only for trap to M
li t3, MSTATUS_MDT
csrr a1, mstatus
and t0, a1, t3
bnez t0, fail
j pass



TEST_PASSFAIL

    .align 4
    .global mtvec_handler
    .global mntvec_handler

mtvec_handler:
  la t0, mntvec_handler
  csrw mtvec, t0
  csrw 0x7B0, 0  # dbltrap 
  csrr t0, mepc
  addi t0, t0, 4
  csrw mepc, t0
  la t0, mtvec_handler
  csrw mtvec, t0
  mret

mntvec_handler:
  csrw 0x7B0, 0  # dbltrap 
  j fail
  .word 0x70200073

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END
