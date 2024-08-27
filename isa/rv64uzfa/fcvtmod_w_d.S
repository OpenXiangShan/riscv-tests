# See LICENSE for license details.

#*****************************************************************************
# fcvtmod_w_d.S
#-----------------------------------------------------------------------------
# author: yzy
# date: 2024-08-19
# This test verifies that the fcvtmod.w.d instructions.
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UF
RVTEST_CODE_BEGIN

#define TEST_FCVTMOD_W_D( testnum, flags, result, val1) \
test_ ## testnum: \
    li TESTNUM, testnum; \
    la  a0, test_ ## testnum ## _data; \
    fld ft0, 0(a0); \
    lw   a1, 8(a0); \
    fcvtmod.w.d a2, ft0, rtz; \
    fsflags a3, x0; \
    li  a4, flags; \
    bne a3, a4, fail; \
    bne a1, a2, fail; \
    .pushsection .data; \
    .align 3; \
    test_ ## testnum ## _data: \
    .double val1; \
    .word result; \
    .popsection;


  TEST_FCVTMOD_W_D(2,  0x1,  3,  3.6);
  TEST_FCVTMOD_W_D(3,  0x1, -3, -3.6);
  TEST_FCVTMOD_W_D(4,    0,  0, -0.0);
  TEST_FCVTMOD_W_D(5,    0,  0, +0.0);
  TEST_FCVTMOD_W_D(6, 0x10,  0, +inf);
  TEST_FCVTMOD_W_D(7, 0x10,  0, -inf);
  TEST_FCVTMOD_W_D(8, 0x10,  0, sNaN);

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END