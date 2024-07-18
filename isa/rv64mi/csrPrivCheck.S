# See LICENSE for license details.

#*****************************************************************************
# csrPrivCheck.S
#-----------------------------------------------------------------------------
#
# Test different priv csr access in m mode.
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64MV
RVTEST_CODE_BEGIN

  .align 2
  .option norvc

  li TESTNUM, 1

test:
  csrr t0, mstatus
  csrr t0, vsstatus
  csrr t0, sstatus
  csrr t0, vcsr
  j pass

.align 8
.global mtvec_handler
mtvec_handler:
  j fail

  TEST_PASSFAIL

RVTEST_CODE_END

  .data

RVTEST_DATA_BEGIN
    
  TEST_DATA

RVTEST_DATA_END
