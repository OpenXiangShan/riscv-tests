# See LICENSE for license details.

#*****************************************************************************
# fleq.S
#-----------------------------------------------------------------------------
#
# Test f{ltq|leq}.{s|d} instructions.
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UF
RVTEST_CODE_BEGIN

#if __riscv_xlen == 32
    # Replace the function with the 32-bit variant defined in test_macros.h
    #undef TEST_FP_CMP_OP_D
    #define TEST_FP_CMP_OP_D TEST_FP_CMP_OP_D32
#endif

  #-------------------------------------------------------------
  # Arithmetic tests
  #-------------------------------------------------------------

  /* fleq.s fltq.s */
  TEST_FP_CMP_OP_S( 3, fleq.s, 0x00, 1, -1.36, -1.36);
  TEST_FP_CMP_OP_S( 4, fltq.s, 0x00, 0, -1.36, -1.36);

  TEST_FP_CMP_OP_S( 5, fleq.s, 0x00, 1, -1.37, -1.36);
  TEST_FP_CMP_OP_S( 6, fltq.s, 0x00, 1, -1.37, -1.36);

  TEST_FP_CMP_OP_S( 7, fltq.s, 0x00, 0,   NaN,   0);
  TEST_FP_CMP_OP_S( 8, fltq.s, 0x00, 0,   NaN, NaN);
  TEST_FP_CMP_OP_S( 9, fltq.s, 0x10, 0, sNaNf,   0);
  TEST_FP_CMP_OP_S(10, fleq.s, 0x00, 0,   NaN,   0);
  TEST_FP_CMP_OP_S(11, fleq.s, 0x00, 0,   NaN, NaN);
  TEST_FP_CMP_OP_S(12, fleq.s, 0x10, 0, sNaNf,   0);

  /* fleq.d fltq.d */
  TEST_FP_CMP_OP_D(13, fleq.d, 0x00, 1, -1.36, -1.36);
  TEST_FP_CMP_OP_D(14, fltq.d, 0x00, 0, -1.36, -1.36);

  TEST_FP_CMP_OP_D(15, fleq.d, 0x00, 1, -1.37, -1.36);
  TEST_FP_CMP_OP_D(16, fltq.d, 0x00, 1, -1.37, -1.36);

  TEST_FP_CMP_OP_D(17, fltq.d, 0x00, 0,  NaN,    0);
  TEST_FP_CMP_OP_D(18, fltq.d, 0x00, 0,  NaN,  NaN);
  TEST_FP_CMP_OP_D(19, fltq.d, 0x10, 0, sNaN,    0);
  TEST_FP_CMP_OP_D(20, fleq.d, 0x00, 0,  NaN,    0);
  TEST_FP_CMP_OP_D(21, fleq.d, 0x00, 0,  NaN,  NaN);
  TEST_FP_CMP_OP_D(22, fleq.d, 0x10, 0, sNaN,    0);


  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END
