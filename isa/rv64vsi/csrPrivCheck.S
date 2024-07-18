# See LICENSE for license details.

#*****************************************************************************
# csrPrivCheck.S
#-----------------------------------------------------------------------------
#
# Test different priv csr access in vs mode.
#

#include "riscv_test.h"
#include "test_macros.h"

#define EX_II 2
#define EX_VI 22

RVTEST_RV64VSV
RVTEST_CODE_BEGIN

  .align 2
  .option norvc

  li TESTNUM, 1

test:
1:
  li t1, 1
  csrr t0, mstatus
  li t3, 1
  beq t1, t3, fail
2:
  li t1, 2
  csrr t0, vsstatus
  li t3, 2
  beq t1, t3, fail
3:
  li t1, 3
  csrr t0, sstatus

4:
  li t1, 4
  csrr t0, vcsr
  j pass

.align 8
.global mtvec_handler
mtvec_handler:
  csrr t0, mcause 
  li t4, EX_II
  beq t0, t4, handle_illegal_instruction  # EX_II
  li t4, EX_VI
  beq t0, t4, handle_virtual_instruction  # EX_VI
  j fail  

handle_illegal_instruction:
  li t2, 1
  beq t2, t1, recover

  li t2, 2
  beq t2, t1, fail

  li t2, 3
  beq t2, t1, fail

  li t2, 4
  beq t2, t1, fail

handle_virtual_instruction:
  li t2, 1
  beq t2, t1, fail

  li t2, 2
  beq t2, t1, recover

  li t2, 3
  beq t2, t1, fail

  li t2, 4
  beq t2, t1, fail
  
recover:
  csrr t2, mepc
  addi t2, t2, 4  
  csrw mepc, t2
  li t1, 0
  mret

  TEST_PASSFAIL

RVTEST_CODE_END

  .data

RVTEST_DATA_BEGIN
    
  TEST_DATA

RVTEST_DATA_END
