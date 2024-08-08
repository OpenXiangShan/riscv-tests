# See LICENSE for license details.

#*****************************************************************************
# cbo_inval.S
#-----------------------------------------------------------------------------
#
# Test if cbo.flush can work
# data should be correct
# make sure cbo.inval has invalidated the cache block
# TODO: ensure cbo.inval comply with spec:
# - If an invalidate operation i precedes a load r and operates on a byte x returned by r, and no store to x
#   appears between i and r in program order or in the global memory order, then r returns any of the following
#   values for x:
#     1. If no clean or flush operations on x precede i in the global memory order, either the initial value of x or
#        the value of any store to x that precedes i
#     2. If no store to x precedes a clean or flush operation on x in the global memory order and if the clean or
#        flush operation on x precedes i in the global memory order, either the initial value of x or the value of
#        any store to x that precedes i
#     3. If a store to x precedes a clean or flush operation on x in the global memory order and if the clean or
#        flush operation on x precedes i in the global memory order, either the value of the latest store to x that
#        precedes the latest clean or flush operation on x or the value of any store to x that both precedes i and
#        succeeds the latest clean or flush operation on x that precedes i
#     4. The value of any store to x by a non-coherent agent regardless of the above conditions
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64M
RVTEST_CODE_BEGIN

  la   x1, tdat
  li   x2, 0xdead
  sd   x2, 0(x1)
  .word 0x0000A00F  # cbo.inval(x1)

  csrr x3, mcycle
  ld   x4, 0(x1)
  csrr x5, mcycle
  # check potential result
  beq  x4, x0, 1b
  beq  x4, x2, 1b
  j die
1:
  # check load latency, load after inval should be longer than 20 cycles?
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
