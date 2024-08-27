# See LICENSE for license details.

#*****************************************************************************
# fminm.S
#-----------------------------------------------------------------------------
# author: yzy
# date: 2024-08-16
# This test verifies that the f{minm|maxm}.{s|d} instructions.
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UF
RVTEST_CODE_BEGIN

#if __riscv_xlen == 32
    # Replace the function with the 32-bit variant defined in test_macros.h
    #undef TEST_FP_OP2_D
    #define TEST_FP_OP2_D TEST_FP_OP2_D32
#endif

  #-------------------------------------------------------------
  # Arithmetic tests
  #-------------------------------------------------------------

  /* fminm.s fmaxm.s*/
  TEST_FP_OP2_S( 2,  fminm.s, 0,        1.0,        2.5,        1.0 );
  TEST_FP_OP2_S( 3,  fminm.s, 0,    -1235.1,    -1235.1,        1.1 );
  TEST_FP_OP2_S( 4,  fminm.s, 0,    -1235.1,        1.1,    -1235.1 );
  TEST_FP_OP2_S( 5,  fminm.s, 0,      qNaNf,        NaN,    -1235.1 );
  TEST_FP_OP2_S( 6,  fminm.s, 0, 0.00000001, 3.14159265, 0.00000001 );
  TEST_FP_OP2_S( 7,  fminm.s, 0,       -2.0,       -1.0,       -2.0 );

  TEST_FP_OP2_S( 8,  fmaxm.s, 0,        2.5,        2.5,        1.0 );
  TEST_FP_OP2_S( 9,  fmaxm.s, 0,        1.1,    -1235.1,        1.1 );
  TEST_FP_OP2_S(10,  fmaxm.s, 0,        1.1,        1.1,    -1235.1 );
  TEST_FP_OP2_S(11,  fmaxm.s, 0,      qNaNf,        NaN,    -1235.1 );
  TEST_FP_OP2_S(12,  fmaxm.s, 0, 3.14159265, 3.14159265, 0.00000001 );
  TEST_FP_OP2_S(13,  fmaxm.s, 0,       -1.0,       -1.0,       -2.0 );

  TEST_FP_OP2_S(14,  fmaxm.s, 0x10, qNaNf, sNaNf, 1.0);
  TEST_FP_OP2_S(15,  fmaxm.s, 0x00, qNaNf, NaN, NaN);

  TEST_FP_OP2_S(16,  fminm.s, 0,       -0.0,       -0.0,        0.0 );
  TEST_FP_OP2_S(17,  fminm.s, 0,       -0.0,        0.0,       -0.0 );
  TEST_FP_OP2_S(18,  fmaxm.s, 0,        0.0,       -0.0,        0.0 );
  TEST_FP_OP2_S(19,  fmaxm.s, 0,        0.0,        0.0,       -0.0 );

  /* fminm.d fmaxm.d */
  TEST_FP_OP2_D(20,  fminm.d, 0,        1.0,        2.5,        1.0 );
  TEST_FP_OP2_D(21,  fminm.d, 0,    -1235.1,    -1235.1,        1.1 );
  TEST_FP_OP2_D(22,  fminm.d, 0,    -1235.1,        1.1,    -1235.1 );
  TEST_FP_OP2_D(23,  fminm.d, 0,       qNaN,        NaN,    -1235.1 );
  TEST_FP_OP2_D(24,  fminm.d, 0, 0.00000001, 3.14159265, 0.00000001 );
  TEST_FP_OP2_D(25,  fminm.d, 0,       -2.0,       -1.0,       -2.0 );

  TEST_FP_OP2_D(26,  fmaxm.d, 0,        2.5,        2.5,        1.0 );
  TEST_FP_OP2_D(27,  fmaxm.d, 0,        1.1,    -1235.1,        1.1 );
  TEST_FP_OP2_D(28,  fmaxm.d, 0,        1.1,        1.1,    -1235.1 );
  TEST_FP_OP2_D(29,  fmaxm.d, 0,       qNaN,        NaN,    -1235.1 );
  TEST_FP_OP2_D(30,  fmaxm.d, 0, 3.14159265, 3.14159265, 0.00000001 );
  TEST_FP_OP2_D(31,  fmaxm.d, 0,       -1.0,       -1.0,       -2.0 );

  TEST_FP_OP2_D(32,  fmaxm.d, 0x10, qNaN, sNaN, 1.0);
  TEST_FP_OP2_D(33,  fmaxm.d, 0x00, qNaN,  NaN, NaN);

  TEST_FP_OP2_D(34,  fminm.d, 0,       -0.0,       -0.0,        0.0 );
  TEST_FP_OP2_D(35,  fminm.d, 0,       -0.0,        0.0,       -0.0 );
  TEST_FP_OP2_D(36,  fmaxm.d, 0,        0.0,       -0.0,        0.0 );
  TEST_FP_OP2_D(37,  fmaxm.d, 0,        0.0,        0.0,       -0.0 );

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END