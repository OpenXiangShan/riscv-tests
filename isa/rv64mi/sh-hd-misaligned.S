# See LICENSE for license details.

#*****************************************************************************
# sh-unaligned.S
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
  TEST_ST_OP(  2, lh, sh, 0x5678,  1, tdat );
  TEST_ST_OP(  3, lh, sh, 0x5678,  3, tdat );
  TEST_ST_OP(  4, lh, sh, 0x5678,  5, tdat );
  TEST_ST_OP(  5, lh, sh, 0x5678,  7, tdat );
  TEST_ST_OP(  6, lh, sh, 0x5678,  9, tdat );
  TEST_ST_OP(  7, lh, sh, 0x5678, 11, tdat );
  TEST_ST_OP(  8, lh, sh, 0x5678, 13, tdat );
  # cross 16 bytes boundary
  TEST_ST_OP(  9, lh, sh, 0x5678, 15, tdat );
  # cross page
  TEST_ST_OP( 10, lh, sh, 0x5678, -1, newpg );


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
