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
#include "misalign_macros.h"

RVTEST_RV64M
RVTEST_CODE_BEGIN

  # map tdat -> tdat
  MAKE_PAGE_TABLE(tdat, tdat, page_table)
  
  TURN_ON_VM(page_table)
  USE_VA_IN_M_MODE

  # not cross 16 bytes boundary
  TEST_LD_OP( 2, ld, 0x0908070605040302,  1, tdat );
  TEST_LD_OP( 3, ld, 0x0a09080706050403,  2, tdat );
  TEST_LD_OP( 4, ld, 0x0b0a090807060504,  3, tdat );
  TEST_LD_OP( 5, ld, 0x0c0b0a0908070605,  4, tdat );
  TEST_LD_OP( 6, ld, 0x0d0c0b0a09080706,  5, tdat );
  TEST_LD_OP( 7, ld, 0x0e0d0c0b0a090807,  6, tdat );
  TEST_LD_OP( 8, ld, 0x0f0e0d0c0b0a0908,  7, tdat );
  # cross 16 bytes boundary
  TEST_LD_OP( 9, ld, 0x01100f0e0d0c0b0a,  9, tdat );
  TEST_LD_OP(10, ld, 0x0201100f0e0d0c0b, 10, tdat );
  TEST_LD_OP(11, ld, 0x030201100f0e0d0c, 11, tdat );
  TEST_LD_OP(12, ld, 0x04030201100f0e0d, 12, tdat );
  TEST_LD_OP(13, ld, 0x0504030201100f0e, 13, tdat );
  TEST_LD_OP(14, ld, 0x060504030201100f, 14, tdat );
  TEST_LD_OP(15, ld, 0x0706050403020110, 15, tdat );

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
