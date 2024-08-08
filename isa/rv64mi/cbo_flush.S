# See LICENSE for license details.

#*****************************************************************************
# cbo_flush.S
#-----------------------------------------------------------------------------
#
# Test if cbo.flush can work
# data should be correct
# make sure cbo.flush has flushed the cache block out of cache
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64M
RVTEST_CODE_BEGIN

  la   x1, tdat
  li   x2, 0xdead
  sd   x2, 0(x1)
  .word 0x0020A00F  # cbo.flush(x1)

  csrr x3, mcycle
  ld   x4, 0(x1)
  csrr x5, mcycle
  # check result
  beq  x4, x0, die
  # check read latency, load after flush should be longer than 20 cycles?
  sub  x5, x5, x3
  li   x6, 20
  ble  x5, x6, die

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
