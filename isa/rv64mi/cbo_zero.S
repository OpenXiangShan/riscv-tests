# See LICENSE for license details.

#*****************************************************************************
# cbo_zero.S
#-----------------------------------------------------------------------------
#
# Test if cbo.zero can work
# data should be all zero after cbo.zero
#

#include "riscv_test.h"
#include "test_macros.h"

#define CACHEBLOCKS 128
#define DOUBLEWORDNUM (CACHEBLOCKS * 8)

RVTEST_RV64M
RVTEST_CODE_BEGIN

# use cbo.zero to clean all `CACHEBLOCKS` blocks
  li   x2, CACHEBLOCKS
  la   x1, tdat
1:
  .word 0x0040A00F  # cbo.zero(x1)
  addi x1, x1, 64
  addi x2, x2, -1
  bne  x2, x0, 1b

# test if all `CACHEBLOCKS` blocks are zero
  li   x2, DOUBLEWORDNUM
  la   x1, tdat
2:
  ld   x3, 0(x1)
  bne  x3, x0, die
  addi x1, x1, 8
  addi x2, x2, -1
  bne  x2, x0, 2b

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
    .fill DOUBLEWORDNUM, 8, 0xdeadbeefdeadbeef # 128 cache blocks

RVTEST_DATA_END
