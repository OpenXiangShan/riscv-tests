# See LICENSE for license details.

#*****************************************************************************
# svinval.S
#-----------------------------------------------------------------------------
#
# Test svinval instructions
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64M
RVTEST_CODE_BEGIN

#define SET_HU \
  li a0, MSTATUS_MPP; \
  csrc mstatus, a0; \
  li a0, MSTATUS_MPP & (MSTATUS_MPP >> 2); \
  csrs mstatus, a0;

test_begin:

  la a0, mtvec_handler
  csrw mtvec, a0

  // sfence.w.inval/sinval.vma/sfence.inval.ir will illegal instruction exception in HU mode
  SET_HU
  la a0, flush0
  csrw mepc, a0
  mret

flush0:
  fence

  li gp, 1
  li tp, 1
  .word 0b00011000000000000000000001110011 # SFENCE_W_INVAL
  bne tp, zero, die
  fence

  SET_HU
  la a0, flush1
  csrw mepc, a0
  mret

flush1:
  fence

  li gp, 2
  li tp, 1
  .word 0b00010110000000001000000001110011 # SINVAL_VMA x1
  bne tp, zero, die
  fence

  SET_HU
  la a0, flush2
  csrw mepc, a0
  mret

flush2:
  fence
  
  li gp, 3
  li tp, 1
  .word 0b00011000000100000000000001110011 # SFENCE_INVAL_IR
  bne tp, zero, die
  
  j success

fail:
  RVTEST_FAIL

success:
  RVTEST_PASS

  .align 2
  .global mtvec_handler
mtvec_handler:
  beq tp, zero, die
  mv tp, zero
  li a1, 2
  csrr a0, mcause
  bne a0, a1, die
  csrr a1, mepc
  addi a1, a1, 4
  jr a1

die:
  RVTEST_FAIL

RVTEST_CODE_END

  .data

RVTEST_DATA_BEGIN

  TEST_DATA


RVTEST_DATA_END
