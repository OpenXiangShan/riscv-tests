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
#include "misalign_macros.h"

RVTEST_RV64M
RVTEST_CODE_BEGIN

  # map tdat -> tdat
  MAKE_PAGE_TABLE(tdat, tdat, page_table)
  # map newpg -> newpg
  MAKE_PAGE_TABLE(newpg, newpg, page_table)
  
  TURN_ON_VM(page_table)
  USE_VA_IN_M_MODE

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

# 2MB align
.align 21
page_table: .dword 0

# align to 4KB * 8, to make room for page_table
# WARNING: make sure tdat and newpg are in the same 2MB page if you use MAKE_PAGE_TABLE
.align 15
tdat:
    .zero 32

.align 12
newpg:
    .zero 32

RVTEST_DATA_END
