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
#include "misalign_macros.h"

RVTEST_RV64M
RVTEST_CODE_BEGIN

  # map tdat -> tdat
  MAKE_PAGE_TABLE(tdat, tdat, page_table)
  
  TURN_ON_VM(page_table)
  USE_VA_IN_M_MODE

  # not cross 16 bytes boundary
  TEST_LD_OP( 2, lh, 0x0302,   1,  tdat );
  TEST_LD_OP( 3, lh, 0x0504,   3,  tdat );
  TEST_LD_OP( 4, lh, 0x0706,   5,  tdat );
  TEST_LD_OP( 5, lh, 0x0908,   7,  tdat );
  TEST_LD_OP( 6, lh, 0x0b0a,   9,  tdat );
  TEST_LD_OP( 7, lh, 0x0d0c,  11,  tdat );
  TEST_LD_OP( 8, lh, 0x0f0e,  13,  tdat );
  # cross 16 bytes boundary
  TEST_LD_OP( 9, lh, 0x0110,  15,  tdat );

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

# 2MB align
.align 21
page_table: .dword 0

# align to 4KB * 8, to make room for page_table
.align 15
tdat:
    .byte 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    .byte 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    .byte 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    .byte 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10

RVTEST_DATA_END
