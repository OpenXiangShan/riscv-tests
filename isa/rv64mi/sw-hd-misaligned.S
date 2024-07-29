# See LICENSE for license details.

#*****************************************************************************
# sw-unaligned.S
#-----------------------------------------------------------------------------
#
# Test that misaligned stores work or raise the correct exception
# This test assumes the target is little-endian
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64M
RVTEST_CODE_BEGIN

  # not cross 16 bytes boundary
  TEST_ST_OP( 2, lw, sw, 0xffffffff9abcdef0, 1, tdat );
  TEST_ST_OP( 3, lw, sw, 0xffffffffdeadbeef, 2, tdat );
  TEST_ST_OP( 4, lw, sw, 0xfffffffffeed0011, 3, tdat );
  # cross 16 bytes boundary
  TEST_ST_OP( 5, lw, sw, 0xffffffff9abcdef0, 13, tdat );
  TEST_ST_OP( 6, lw, sw, 0xffffffffdeadbeef, 14, tdat );
  TEST_ST_OP( 7, lw, sw, 0xfffffffffeed0011, 15, tdat );
  # cross page
  TEST_ST_OP(  8, lw, sw, 0xffffffff9abcdef0, -3, newpg );
  TEST_ST_OP(  9, lw, sw, 0xffffffffdeadbeef, -2, newpg );
  TEST_ST_OP( 10, lw, sw, 0xfffffffffeed0011, -1, newpg );

2:
  TEST_PASSFAIL

  .align 2
  .global mtvec_handler
mtvec_handler:
  RVTEST_FAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

.align 4
tdat:
    .zero 32

.align 12
newpg:
    .zero 32

RVTEST_DATA_END
