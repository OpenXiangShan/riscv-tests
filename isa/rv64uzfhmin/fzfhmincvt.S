# See LICENSE for license details.

#*****************************************************************************
# fzfhmincvt.S
#-----------------------------------------------------------------------------
#
# Test fcvt.h.s, fcvt.s.h, fcvt.h.d, and fcvt.d.h instructions.
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UF
RVTEST_CODE_BEGIN

  #-------------------------------------------------------------
  # Arithmetic tests
  #-------------------------------------------------------------
  
  TEST_FCVT_H_S( 10, -0, -0, 0)
  TEST_FCVT_H_S( 11, 0, 0, 0)
  TEST_FCVT_H_S( 12, -100.5, -100.5, 0)
  TEST_FCVT_H_S( 13, 125.5, 125.5, 0)
  TEST_FCVT_H_S( 14, 65504.0, 65504.0, 0)
  TEST_FCVT_H_S( 15, +inf, +inf, 0)
  TEST_FCVT_H_S( 16, -inf, -inf, 0)
  TEST_FCVT_H_S( 17, 0.0000000003, 0.0000000003, 0)
  TEST_FCVT_H_S( 18, qNaNh, qNaNh, 0)
  TEST_FCVT_H_S( 19, qNaNh, sNaNh, 0x10)


#if __riscv_xlen >= 64
  TEST_FCVT_H_D( 20, -0, -0, 0)
  TEST_FCVT_H_D( 21, 0, 0, 0)
  TEST_FCVT_H_D( 22, -100.5, -100.5, 0)
  TEST_FCVT_H_D( 23, 125.5, 125.5, 0)
  TEST_FCVT_H_D( 24, 65504.0, 65504.0, 0)
  TEST_FCVT_H_D( 25, +inf, +inf, 0)
  TEST_FCVT_H_D( 26, -inf, -inf, 0)
  TEST_FCVT_H_D( 27, 0.0000000003, 0.0000000003, 0)
  TEST_FCVT_H_D( 28, qNaNh, qNaNh, 0)
  TEST_FCVT_H_D( 29, qNaNh, sNaNh, 0x10)
#endif
  
  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END
