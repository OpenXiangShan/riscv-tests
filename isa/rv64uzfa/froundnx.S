# See LICENSE for license details.

#*****************************************************************************
# froundnx.S
#-----------------------------------------------------------------------------
# author: yzy
# date: 2024-08-19
# This test verifies that the froundnx.{s|d} instructions.
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UF
RVTEST_CODE_BEGIN


#define TEST_FROUNDNXS_RM( testnum, flags, result, val1, frmdata, rm) \
test_ ## testnum: \
    li  TESTNUM, testnum; \
    csrwi frm, frmdata; \
    la  a0, test_ ## testnum ## _data; \
    flw ft0, 0(a0); \
    flw ft1, 4(a0); \
    froundnx.s ft2, ft0, rm; \
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

#define TEST_FROUNDNXD_RM( testnum, flags, result, val1, frmdata, rm) \
test_ ## testnum: \
    li  TESTNUM, testnum; \
    csrwi frm, frmdata; \
    la  a0, test_ ## testnum ## _data; \
    fld ft0, 0(a0); \
    fld ft1, 8(a0); \
    froundnx.d ft2, ft0, rm; \
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

  /* froundnx.s */
  TEST_FROUNDNXS_RM(2,   0x1,   4.0,   3.6,  0, rne);
  TEST_FROUNDNXS_RM(3,   0x1,   3.0,   3.6,  0, rtz);
  TEST_FROUNDNXS_RM(4,   0x1,   3.0,   3.6,  0, rdn);
  TEST_FROUNDNXS_RM(5,   0x1,   4.0,   3.6,  0, rup);
  TEST_FROUNDNXS_RM(6,   0x1,   4.0,   3.6,  0, rmm);

  TEST_FROUNDNXS_RM(7,   0x1,   4.0,   3.6,  0, dyn);
  TEST_FROUNDNXS_RM(8,   0x1,   3.0,   3.6,  1, dyn);
  TEST_FROUNDNXS_RM(9,   0x1,   3.0,   3.6,  2, dyn);
  TEST_FROUNDNXS_RM(10,  0x1,   4.0,   3.6,  3, dyn);
  TEST_FROUNDNXS_RM(11,  0x1,   4.0,   3.6,  4, dyn);
  TEST_FROUNDNXS_RM(12,    0,  -0.0,  -0.0,  0, dyn);
  TEST_FROUNDNXS_RM(13,    0,  +0.0,  +0.0,  0, dyn);
  TEST_FROUNDNXS_RM(14,    0,  +inf,  +inf,  0, dyn);
  TEST_FROUNDNXS_RM(15,    0,  -inf,  -inf,  0, dyn);
  TEST_FROUNDNXS_RM(16, 0x10, qNaNf, sNaNf,  0, dyn);

  /* froundnx.d */
  TEST_FROUNDNXD_RM(17,  0x1,   4.0,  3.6,  0, rne);
  TEST_FROUNDNXD_RM(18,  0x1,   3.0,  3.6,  0, rtz);
  TEST_FROUNDNXD_RM(19,  0x1,   3.0,  3.6,  0, rdn);
  TEST_FROUNDNXD_RM(20,  0x1,   4.0,  3.6,  0, rup);
  TEST_FROUNDNXD_RM(21,  0x1,   4.0,  3.6,  0, rmm);

  TEST_FROUNDNXD_RM(22,  0x1,   4.0,  3.6,  0, dyn);
  TEST_FROUNDNXD_RM(23,  0x1,   3.0,  3.6,  1, dyn);
  TEST_FROUNDNXD_RM(24,  0x1,   3.0,  3.6,  2, dyn);
  TEST_FROUNDNXD_RM(25,  0x1,   4.0,  3.6,  3, dyn);
  TEST_FROUNDNXD_RM(26,  0x1,   4.0,  3.6,  4, dyn);
  TEST_FROUNDNXD_RM(27,    0,  -0.0, -0.0,  0, dyn);
  TEST_FROUNDNXD_RM(28,    0,  +0.0, +0.0,  0, dyn);
  TEST_FROUNDNXD_RM(29,    0,  +inf, +inf,  0, dyn);
  TEST_FROUNDNXD_RM(30,    0,  -inf, -inf,  0, dyn);
  TEST_FROUNDNXD_RM(31, 0x10,  qNaN, sNaN,  0, dyn);

  TEST_FROUNDNXS_RM(32,   0x1,   2.0,   2.5,  0, rne);
  TEST_FROUNDNXS_RM(33,   0x1,   2.0,   2.5,  0, rtz);
  TEST_FROUNDNXS_RM(34,   0x1,   2.0,   2.5,  0, rdn);
  TEST_FROUNDNXS_RM(35,   0x1,   3.0,   2.5,  0, rup);
  TEST_FROUNDNXS_RM(36,   0x1,   3.0,   2.5,  0, rmm);

  TEST_FROUNDNXS_RM(37,   0x1,  -2.0,  -2.5,  0, rne);
  TEST_FROUNDNXS_RM(38,   0x1,  -2.0,  -2.5,  0, rtz);
  TEST_FROUNDNXS_RM(39,   0x1,  -3.0,  -2.5,  0, rdn);
  TEST_FROUNDNXS_RM(40,   0x1,  -2.0,  -2.5,  0, rup);
  TEST_FROUNDNXS_RM(41,   0x1,  -3.0,  -2.5,  0, rmm);

  TEST_FROUNDNXS_RM(42,   0x1,  +0.0,   0.5,  0, rne);
  TEST_FROUNDNXS_RM(43,   0x1,  +0.0,   0.5,  0, rtz);
  TEST_FROUNDNXS_RM(44,   0x1,  +0.0,   0.5,  0, rdn);
  TEST_FROUNDNXS_RM(45,   0x1,   1.0,   0.5,  0, rup);
  TEST_FROUNDNXS_RM(46,   0x1,   1.0,   0.5,  0, rmm);

  TEST_FROUNDNXS_RM(47,   0x1,  -0.0,  -0.5,  0, rne);
  TEST_FROUNDNXS_RM(48,   0x1,  -0.0,  -0.5,  0, rtz);
  TEST_FROUNDNXS_RM(49,   0x1,  -1.0,  -0.5,  0, rdn);
  TEST_FROUNDNXS_RM(50,   0x1,  -0.0,  -0.5,  0, rup);
  TEST_FROUNDNXS_RM(51,   0x1,  -1.0,  -0.5,  0, rmm);

  TEST_FROUNDNXD_RM(52,   0x1,   2.0,   2.5,  0, rne);
  TEST_FROUNDNXD_RM(53,   0x1,   2.0,   2.5,  0, rtz);
  TEST_FROUNDNXD_RM(54,   0x1,   2.0,   2.5,  0, rdn);
  TEST_FROUNDNXD_RM(55,   0x1,   3.0,   2.5,  0, rup);
  TEST_FROUNDNXD_RM(56,   0x1,   3.0,   2.5,  0, rmm);

  TEST_FROUNDNXD_RM(57,   0x1,  -2.0,  -2.5,  0, rne);
  TEST_FROUNDNXD_RM(58,   0x1,  -2.0,  -2.5,  0, rtz);
  TEST_FROUNDNXD_RM(59,   0x1,  -3.0,  -2.5,  0, rdn);
  TEST_FROUNDNXD_RM(60,   0x1,  -2.0,  -2.5,  0, rup);
  TEST_FROUNDNXD_RM(61,   0x1,  -3.0,  -2.5,  0, rmm);

  TEST_FROUNDNXD_RM(62,   0x1,  +0.0,   0.5,  0, rne);
  TEST_FROUNDNXD_RM(63,   0x1,  +0.0,   0.5,  0, rtz);
  TEST_FROUNDNXD_RM(64,   0x1,  +0.0,   0.5,  0, rdn);
  TEST_FROUNDNXD_RM(65,   0x1,   1.0,   0.5,  0, rup);
  TEST_FROUNDNXD_RM(66,   0x1,   1.0,   0.5,  0, rmm);

  TEST_FROUNDNXD_RM(67,   0x1,  -0.0,  -0.5,  0, rne);
  TEST_FROUNDNXD_RM(68,   0x1,  -0.0,  -0.5,  0, rtz);
  TEST_FROUNDNXD_RM(69,   0x1,  -1.0,  -0.5,  0, rdn);
  TEST_FROUNDNXD_RM(70,   0x1,  -0.0,  -0.5,  0, rup);
  TEST_FROUNDNXD_RM(71,   0x1,  -1.0,  -0.5,  0, rmm);


  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END