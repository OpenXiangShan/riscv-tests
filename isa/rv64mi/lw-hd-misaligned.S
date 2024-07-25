# See LICENSE for license details.

#*****************************************************************************
# lw-unaligned.S
#-----------------------------------------------------------------------------
#
# Test that misaligned loads work or raise the correct exception
# This test assumes the target is little-endian
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64M
RVTEST_CODE_BEGIN

  # not cross 16 bytes boundary
  TEST_LD_OP( 2, lw, 0x05040302,  1,  tdat );
  TEST_LD_OP( 3, lw, 0x06050403,  2,  tdat );
  TEST_LD_OP( 4, lw, 0x07060504,  3,  tdat );
  # cross 16 bytes boundary
  TEST_LD_OP( 5, lw, 0x01100f0e, 13,  tdat );
  TEST_LD_OP( 6, lw, 0x0201100f, 14,  tdat );
  TEST_LD_OP( 7, lw, 0x03020110, 15,  tdat );
2:
  TEST_PASSFAIL

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
    .byte 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    .byte 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    .byte 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    .byte 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10

RVTEST_DATA_END
