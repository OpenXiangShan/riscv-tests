# See LICENSE for license details.

#*****************************************************************************
# lh-unaligned.S
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
  TEST_LD_OP( 2, lh, 0x0302,  1,  tdat );
  # cross 16 bytes boundary
  TEST_LD_OP( 3, lh, 0x0110, 15,  tdat );

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
