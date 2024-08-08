# See LICENSE for license details.

#*****************************************************************************
# cbo_clean.S
#-----------------------------------------------------------------------------
#
# Test if cbo.clean can work
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64M
RVTEST_CODE_BEGIN

  la   x1, tdat
  li   x2, 0xdead
  sd   x2, 0(x1)
  .word 0x0010A00F  # cbo.clean(x1)

  ld   x4, 0(x1)
  beq  x4, x0, die

  RVTEST_PASS

  .align 2
  .global mtvec_handler
mtvec_handler:
die:
  RVTEST_FAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

.align 4
tdat:
    .dword 0

RVTEST_DATA_END
