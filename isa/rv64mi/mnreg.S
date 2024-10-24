# See LICENSE for license details.

#*****************************************************************************
# nmi.S
#-----------------------------------------------------------------------------
#
# Test mnstatus_reg
# test mnscratch, mnstatus, mnepc, mncause Read write
# test menvcfg.DTE influence SDT and SIE

#include "riscv_test.h"
#include "test_macros.h"


RVTEST_RV64M

RVTEST_CODE_BEGIN

# mnstatus
li a0, 0xffffffffffffffff
csrw 0x744, a0
csrr t0, 0x744
li t1, MNSTATUS_NMIE | MNSTATUS_MNPV  | MNSTATUS_MNPP_M
bne t0, t1, fail
# li a0, MNSTATUS_NMIE
# csrc 0x744 , a0
# csrr t0, 0x744
# li t1, MNSTATUS_NMIE | MNSTATUS_MNPV | MNSTATUS_MNPP_M
bne t0, t1, fail
li a0, 0xffffffffffffffff
# mncause
csrw 0x742, a0
csrr t0, 0x742
bne t0, a0, fail

#mnscratch
csrw 0x740, a0
csrr t0, 0x740
bne t0, a0, fail

#mnepc
csrw 0x741, a0
csrr t0, 0x741
li t1, 0xffffffffffffffff & (~0x1)
bne t0, t1, fail

j pass



TEST_PASSFAIL

    .align 4
    .global mtvec_handler

mtvec_handler:
  // reset deleg to S/VS
  li t0, MNSTATUS_MNPP_M
  csrr t1, 0x744
  bne t0, t1, fail
  li t0, (1<<63)
  csrr t1, 0x742
  bne t0, t1, fail
  .word 0x70200073

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END
