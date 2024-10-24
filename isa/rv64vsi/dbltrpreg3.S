# See LICENSE for license details.

#*****************************************************************************
# nmi.S
#-----------------------------------------------------------------------------
#
# Test mnstatus_reg
# test vsstatus sdt when menvcfg DTE close and menvcfg DTE open henvcfg close

#include "riscv_test.h"
#include "test_macros.h"


RVTEST_RV64VS

RVTEST_CODE_BEGIN


csrw 0x7B0, 0  // only for trap to M
## check menvcfg.DTE close

#check SDT when menvcfg DTE close
li t0, SSTATUS_SDT
csrs sstatus, t0

li t0, SSTATUS_SIE
csrs sstatus, t0
csrr t1, sstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail

# MDT 0 same write mie can write 1
li t0, SSTATUS_SIE
csrw sstatus, t0
csrr t1, sstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail

# spliciltly write MDT 1, clear mie
li t0, SSTATUS_SDT
csrs sstatus, t0
csrr t1, sstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail

# MDT set 0, then write mie
csrc sstatus, t0
li t0, SSTATUS_SIE
csrs sstatus, t0
csrr t1, sstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail

j pass



TEST_PASSFAIL

    .align 4
    .global mtvec_handler

mtvec_handler:
  // reset deleg to S/VS
  li t0, ENVCFG_DTE
  csrs menvcfg, t0
  csrc henvcfg, t0
  csrr t0, mepc
  addi t0, t0, 4
  csrw mepc, t0
  mret

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END
