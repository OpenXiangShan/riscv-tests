# See LICENSE for license details.

#*****************************************************************************
# fround.S
#-----------------------------------------------------------------------------
# author: yzy
# date: 2024-08-19
# This test verifies that the fround.{s.d} instructions.
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UF
RVTEST_CODE_BEGIN

#define TEST_FROUNDS_RM( testnum, flags, result, val1, frmdata, rm) \
test_ ## testnum: \
    li  TESTNUM, testnum; \
    csrwi frm, frmdata; \
    la  a0, test_ ## testnum ## _data; \
    flw ft0, 0(a0); \
    flw ft1, 4(a0); \
    fround.s ft2, ft0, rm; \
    fmv.x.w a1, ft1; \
    fmv.x.w a2, ft2; \
    fsflags a3, x0; \
    li  a4, flags; \
    bne a3, a4, fail; \
    bne a1, a2, fail; \
    .pushsection .data; \
    .align 2; \
    test_ ## testnum ## _data: \
    .float val1; \
    .float result; \
    .popsection;

#define TEST_FROUNDD_RM( testnum, flags, result, val1, frmdata, rm) \
test_ ## testnum: \
    li  TESTNUM, testnum; \
    csrwi frm, frmdata; \
    la  a0, test_ ## testnum ## _data; \
    fld ft0, 0(a0); \
    fld ft1, 8(a0); \
    fround.d ft2, ft0, rm; \
    fmv.x.d a1, ft1; \
    fmv.x.d a2, ft2; \
    fsflags a3, x0; \
    li  a4, flags; \
    bne a3, a4, fail; \
    bne a1, a2, fail; \
    .pushsection .data; \
    .align 3; \
    test_ ## testnum ## _data: \
    .double val1; \
    .double result; \
    .popsection;

  /* fround.s */
  TEST_FROUNDS_RM(2,     0,   4.0,  3.6,  0, rne);
  TEST_FROUNDS_RM(3,     0,   3.0,  3.6,  0, rtz);
  TEST_FROUNDS_RM(4,     0,   3.0,  3.6,  0, rdn);
  TEST_FROUNDS_RM(5,     0,   4.0,  3.6,  0, rup);
  TEST_FROUNDS_RM(6,     0,   4.0,  3.6,  0, rmm);

  TEST_FROUNDS_RM(7,     0,   4.0,  3.6,  0, dyn);
  TEST_FROUNDS_RM(8,     0,   3.0,  3.6,  1, dyn);
  TEST_FROUNDS_RM(9,     0,   3.0,  3.6,  2, dyn);
  TEST_FROUNDS_RM(10,    0,   4.0,  3.6,  3, dyn);
  TEST_FROUNDS_RM(11,    0,   4.0,  3.6,  4, dyn);
  TEST_FROUNDS_RM(12,    0,  -0.0, -0.0,  0, dyn);
  TEST_FROUNDS_RM(13,    0,  +0.0, +0.0,  0, dyn);
  TEST_FROUNDS_RM(14,    0,  +inf, +inf,  0, dyn);
  TEST_FROUNDS_RM(15,    0,  -inf, -inf,  0, dyn);
  TEST_FROUNDS_RM(16, 0x10, qNaNf, sNaNf, 0, dyn);

  /* fround.d */
  TEST_FROUNDD_RM(17,    0,   4.0,  3.6,  0, rne);
  TEST_FROUNDD_RM(18,    0,   3.0,  3.6,  0, rtz);
  TEST_FROUNDD_RM(19,    0,   3.0,  3.6,  0, rdn);
  TEST_FROUNDD_RM(20,    0,   4.0,  3.6,  0, rup);
  TEST_FROUNDD_RM(21,    0,   4.0,  3.6,  0, rmm);

  TEST_FROUNDD_RM(22,    0,   4.0,  3.6,  0, dyn);
  TEST_FROUNDD_RM(23,    0,   3.0,  3.6,  1, dyn);
  TEST_FROUNDD_RM(24,    0,   3.0,  3.6,  2, dyn);
  TEST_FROUNDD_RM(25,    0,   4.0,  3.6,  3, dyn);
  TEST_FROUNDD_RM(26,    0,   4.0,  3.6,  4, dyn);
  TEST_FROUNDD_RM(27,    0,  -0.0, -0.0,  0, dyn);
  TEST_FROUNDD_RM(28,    0,  +0.0, +0.0,  0, dyn);
  TEST_FROUNDD_RM(29,    0,  +inf, +inf,  0, dyn);
  TEST_FROUNDD_RM(30,    0,  -inf, -inf,  0, dyn);
  TEST_FROUNDD_RM(31, 0x10,  qNaN, sNaN,  0, dyn);

  TEST_FROUNDS_RM(32,    0,  -4.0, -3.6,  0, rne);
  TEST_FROUNDS_RM(33,    0,  -3.0, -3.6,  0, rtz);
  TEST_FROUNDS_RM(34,    0,  -4.0, -3.6,  0, rdn);
  TEST_FROUNDS_RM(35,    0,  -3.0, -3.6,  0, rup);
  TEST_FROUNDS_RM(36,    0,  -4.0, -3.6,  0, rmm);

  TEST_FROUNDS_RM(37,    0,   3.0,  2.6,  0, rne);
  TEST_FROUNDS_RM(38,    0,   2.0,  2.6,  0, rtz);
  TEST_FROUNDS_RM(39,    0,   2.0,  2.6,  0, rdn);
  TEST_FROUNDS_RM(40,    0,   3.0,  2.6,  0, rup);
  TEST_FROUNDS_RM(41,    0,   3.0,  2.6,  0, rmm);

  TEST_FROUNDS_RM(42,    0,  -3.0, -2.6,  0, rne);
  TEST_FROUNDS_RM(43,    0,  -2.0, -2.6,  0, rtz);
  TEST_FROUNDS_RM(44,    0,  -3.0, -2.6,  0, rdn);
  TEST_FROUNDS_RM(45,    0,  -2.0, -2.6,  0, rup);
  TEST_FROUNDS_RM(46,    0,  -3.0, -2.6,  0, rmm);

  TEST_FROUNDS_RM(47,    0,   2.0,  2.5,  0, rne);
  TEST_FROUNDS_RM(48,    0,   3.0,  2.5,  0, rmm);
  TEST_FROUNDS_RM(49,    0,  -2.0, -2.5,  0, rne);
  TEST_FROUNDS_RM(50,    0,  -3.0, -2.5,  0, rmm);

  TEST_FROUNDS_RM(51,    0,   1.0,  0.6,  0, rne);
  TEST_FROUNDS_RM(52,    0,  +0.0,  0.6,  0, rtz);
  TEST_FROUNDS_RM(53,    0,   2.0,  2.6,  0, rdn);
  TEST_FROUNDS_RM(54,    0,   3.0,  2.6,  0, rup);
  TEST_FROUNDS_RM(55,    0,   3.0,  2.6,  0, rmm);

  TEST_FROUNDS_RM(56,    0,  -1.0, -0.6,  0, rne);
  TEST_FROUNDS_RM(57,    0,  -0.0, -0.6,  0, rtz);
  TEST_FROUNDS_RM(58,    0,  -3.0, -2.6,  0, rdn);
  TEST_FROUNDS_RM(59,    0,  -2.0, -2.6,  0, rup);
  TEST_FROUNDS_RM(60,    0,  -3.0, -2.6,  0, rmm);

  TEST_FROUNDS_RM(61,    0, 8388608.0, 8388608.1, 0, rne);
  TEST_FROUNDS_RM(62,    0, 8388610.0, 8388610.1, 0, rne);
  TEST_FROUNDS_RM(63,    0, 8388610.0, 8388610.1, 0, rup);

  TEST_FROUNDD_RM(64,    0,   2.0,  2.5,  0, rne);
  TEST_FROUNDD_RM(65,    0,   3.0,  2.5,  0, rmm);
  TEST_FROUNDD_RM(66,    0,  -2.0, -2.5,  0, rne);
  TEST_FROUNDD_RM(67,    0,  -3.0, -2.5,  0, rmm);

  TEST_FROUNDD_RM(68,    0,   1.0,  0.6,  0, rne);
  TEST_FROUNDD_RM(69,    0,  +0.0,  0.6,  0, rtz);
  TEST_FROUNDD_RM(70,    0,   2.0,  2.6,  0, rdn);
  TEST_FROUNDD_RM(71,    0,   3.0,  2.6,  0, rup);
  TEST_FROUNDD_RM(72,    0,   3.0,  2.6,  0, rmm);

  TEST_FROUNDD_RM(73,    0,  -1.0, -0.6,  0, rne);
  TEST_FROUNDD_RM(74,    0,  -0.0, -0.6,  0, rtz);
  TEST_FROUNDD_RM(75,    0,  -3.0, -2.6,  0, rdn);
  TEST_FROUNDD_RM(76,    0,  -2.0, -2.6,  0, rup);
  TEST_FROUNDD_RM(77,    0,  -3.0, -2.6,  0, rmm);

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END