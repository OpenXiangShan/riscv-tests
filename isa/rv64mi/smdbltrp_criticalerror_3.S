# See LICENSE for license details.

#*****************************************************************************
# smdbltrp_criticalerror_2.S
#-----------------------------------------------------------------------------
#
# Test cause critical error (if mtvec not set) (only can test with smdbltrp open)
#
#include "riscv_test.h"
#include "test_macros.h"


RVTEST_RV64M

RVTEST_CODE_BEGIN

li a0, MNSTATUS_NMIE 
csrs 0x744, a0
csrr a1, mstatus
# clear mtvec
li a0, 0
csrw mtvec, a0
# clear MDT
li t0, MSTATUS_MDT
csrc mstatus, t0
li t0, 0x8
csrw 0x7B0, 0  # only for trap to M



TEST_PASSFAIL

    .align 4
    .global mtvec_handler

mtvec_handler:
  j fail
  mret

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END
