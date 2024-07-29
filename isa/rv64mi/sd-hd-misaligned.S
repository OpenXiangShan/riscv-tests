# See LICENSE for license details.

#*****************************************************************************
# sd-unaligned.S
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
  TEST_ST_OP( 2, ld, sd, 0x090a0b0c0d0e0f10, 1, tdat );
  TEST_ST_OP( 3, ld, sd, 0x1112131415161718, 2, tdat );
  TEST_ST_OP( 4, ld, sd, 0x191a1b1c1d1e1f20, 3, tdat );
  TEST_ST_OP( 5, ld, sd, 0x2122232425262728, 4, tdat );
  TEST_ST_OP( 6, ld, sd, 0x292a2b2c2d2e2f30, 5, tdat );
  TEST_ST_OP( 7, ld, sd, 0x3132333435363738, 6, tdat );
  TEST_ST_OP( 8, ld, sd, 0x393a3b3c3d3e3f40, 7, tdat );
  # cross 16 bytes boundary
  TEST_ST_OP(  9, ld, sd, 0x090a0b0c0d0e0f10,  9, tdat );
  TEST_ST_OP( 10, ld, sd, 0x1112131415161718, 10, tdat );
  TEST_ST_OP( 11, ld, sd, 0x191a1b1c1d1e1f20, 11, tdat );
  TEST_ST_OP( 12, ld, sd, 0x2122232425262728, 12, tdat );
  TEST_ST_OP( 13, ld, sd, 0x292a2b2c2d2e2f30, 13, tdat );
  TEST_ST_OP( 14, ld, sd, 0x3132333435363738, 14, tdat );
  TEST_ST_OP( 15, ld, sd, 0x393a3b3c3d3e3f40, 15, tdat );
  # cross page
  TEST_ST_OP( 16, ld, sd, 0x090a0b0c0d0e0f10, -7, newpg );
  TEST_ST_OP( 17, ld, sd, 0x1112131415161718, -6, newpg );
  TEST_ST_OP( 18, ld, sd, 0x191a1b1c1d1e1f20, -5, newpg );
  TEST_ST_OP( 19, ld, sd, 0x2122232425262728, -4, newpg );
  TEST_ST_OP( 20, ld, sd, 0x292a2b2c2d2e2f30, -3, newpg );
  TEST_ST_OP( 21, ld, sd, 0x3132333435363738, -2, newpg );
  TEST_ST_OP( 22, ld, sd, 0x393a3b3c3d3e3f40, -1, newpg );

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
