# See LICENSE for license details.

#*****************************************************************************
# loadTrigger.S
#-----------------------------------------------------------------------------
#
# Test loadTrigger, if they are implemented.
#

#include "riscv_test.h"
#include "test_macros.h"
RVTEST_RV64M
RVTEST_CODE_BEGIN

  li TESTNUM, 2

  csrw tcontrol, 8

  # test0: mmio mem access begin
  # triggr adder
  li t2, 0x3A000000
  li a1, 0x11223344

  # store
  csrw tselect, 0
  csrw tdata2, t2
  li t1, (2 << (__riscv_xlen - 4)) | MCONTROL_M | MCONTROL_STORE
  csrw tdata1, t1
  SW a1, 0(t2)

  # load
  csrw tselect, 0
  csrw tdata2, t2
  li t1, (2 << (__riscv_xlen - 4)) | MCONTROL_M | MCONTROL_LOAD 
  csrw tdata1, t1
  LWU a2, 0(t2)

  # check
  bne a1, a2, fail
  # test0: mmio mem access end

  #test1: misaligned mem access begin
  la t2, data1
  addi t2, t2, 1
  li a1, 0xaabbccdd

  # store
  csrw tselect, 0
  csrw tdata2, t2
  li t1, (2 << (__riscv_xlen - 4)) | MCONTROL_M | MCONTROL_STORE
  csrw tdata1, t1
  SW a1, 0(t2)

  # load trigger
  csrw tselect, 0
  csrw tdata2, t2
  li t1, (2 << (__riscv_xlen - 4)) | MCONTROL_M | MCONTROL_LOAD 
  csrw tdata1, t1

  LWU a2, 0(t2)
  # check
  bne a1, a2, fail
  #test1: misaligned mem access end

  TEST_PASSFAIL

  .align 2
  .global mtvec_handler

mtvec_handler:
  li t0, CAUSE_BREAKPOINT
  csrr t1, mcause
  bne t0, t1, fail
  # mret
  csrw tdata1, x0
  mret

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN
 .align 4
 TEST_DATA

data1: .word 0

RVTEST_DATA_END
