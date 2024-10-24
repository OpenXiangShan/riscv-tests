# See LICENSE for license details.

#*****************************************************************************
# hpm-overflow.S
#-----------------------------------------------------------------------------
#
# Test hpmevent.OF use backend perfevent rob.commitInstr:81

#include "riscv_test.h"
#include "test_macros.h"


RVTEST_RV64M

RVTEST_CODE_BEGIN


# set mhpmevent 11 : event0:81, op_type :or

li t0, 0x51
csrw mhpmevent11, t0
li t0, 0xFFFFFFFFFFFFFF9B
csrw mhpmcounter11, t0

li a0, 0
li a1, 100
flag:

add a0, a0, 1
bne a0, a1, flag

j pass



TEST_PASSFAIL

    .align 4
    .global mtvec_handler

mtvec_handler:
  csrr a0, mhpmevent11
  li t0, 0x8000000000000000
  and a0, a0, t0
  beqz a0, fail
  csrr a0, mip
  li t0, 2000
  and a0, a0, t0
  beqz a0, fail
  j pass

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END

