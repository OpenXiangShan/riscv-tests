# See LICENSE for license details.

#*****************************************************************************
# smdbltrp_criticalerror.S
#-----------------------------------------------------------------------------
#
# Test when mnstatus.nmie=0 and trap cause critical error (if trap when nmie = 0)
#


#include "riscv_test.h"
#include "test_macros.h"


RVTEST_RV64M

RVTEST_CODE_BEGIN

# clear NMIE
li a0, MNSTATUS_NMIE 
csrc 0x744, a0
csrr a1, 0x744

csrw 0x7B0, 0  # only for trap to M
j fail

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
