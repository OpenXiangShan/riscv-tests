# See LICENSE for license details.

#*****************************************************************************
# nmi.S
#-----------------------------------------------------------------------------
#
# test menvcfg.DTE influence SDT and SIE

#include "riscv_test.h"
#include "test_macros.h"


RVTEST_RV64M

RVTEST_CODE_BEGIN

li t0, MSTATUS_MDT
csrs mstatus, t0

#MDT MIE mDT init 1
li t0, MSTATUS_MIE
csrs mstatus, t0
csrr t1, mstatus
li t3, MSTATUS_MIE
and t2, t1, t3
bnez t2, fail

# MDT 0 same write mie can write 1
li t0, MSTATUS_MIE
csrw mstatus, t0
csrr t1, mstatus
li t3, MSTATUS_MIE
and t2, t1, t3
beqz t2, fail

# spliciltly write MDT 1,clear mie
li t0, MSTATUS_MDT
csrs mstatus, t0
csrr t1, mstatus
li t3, MSTATUS_MIE
and t2, t1, t3
bnez t2, fail

# MDT set 0, then write mie
csrc mstatus, t0
li t0, MSTATUS_MIE
csrs mstatus, t0
csrr t1, mstatus
li t3, MSTATUS_MIE
and t2, t1, t3
beqz t2, fail

# check SDT SIE / DTE open

li t0, ENVCFG_DTE
csrs menvcfg, t0
li t0, SSTATUS_SDT
csrs sstatus, t0


li t0, SSTATUS_SIE
csrs sstatus, t0
csrr t1, sstatus
li t3, SSTATUS_SIE
and t2, t1, t3
bnez t2, fail

# MDT 0 same write mie can write 1
li t0, SSTATUS_SIE
csrw sstatus, t0
csrr t1, sstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail

# spliciltly write MDT 1,clear mie
li t0, SSTATUS_SDT
csrs sstatus, t0
csrr t1, sstatus
li t3, SSTATUS_SIE
and t2, t1, t3
bnez t2, fail

# MDT set 0, then write mie
csrc sstatus, t0
li t0, SSTATUS_SIE
csrs sstatus, t0
csrr t1, sstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail

li t0, ENVCFG_DTE
csrs henvcfg, t0
li t0, SSTATUS_SDT
csrs vsstatus, t0

# check vsstatus DTE open

li t0, SSTATUS_SIE
csrs vsstatus, t0
csrr t1, vsstatus
li t3, SSTATUS_SIE
and t2, t1, t3
bnez t2, fail

# MDT 0 same write mie can write 1
li t0, SSTATUS_SIE
csrw vsstatus, t0
csrr t1, vsstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail

# spliciltly write MDT 1,clear mie
li t0, SSTATUS_SDT
csrs vsstatus, t0
csrr t1, vsstatus
li t3, SSTATUS_SIE
and t2, t1, t3
bnez t2, fail

# MDT set 0, then write mie
csrc vsstatus, t0
li t0, SSTATUS_SIE
csrs vsstatus, t0
csrr t1, vsstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail


### check DTE

li t0, ENVCFG_DTE
csrc menvcfg, t0

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

# spliciltly write MDT 1,clear mie
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

li t0, SSTATUS_SDT
csrs vsstatus, t0

# check vsstatus DTE menvcfg DTE close

li t0, SSTATUS_SIE
csrs vsstatus, t0
csrr t1, vsstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail

# MDT 0 same write mie can write 1
li t0, SSTATUS_SIE
csrw vsstatus, t0
csrr t1, vsstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail

# spliciltly write MDT 1,clear mie
li t0, SSTATUS_SDT
csrs vsstatus, t0
csrr t1, vsstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail

# MDT set 0, then write mie
csrc vsstatus, t0
li t0, SSTATUS_SIE
csrs vsstatus, t0
csrr t1, vsstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail

## check menvcfg.DTE open henvcfg.DTE close 
li t0, ENVCFG_DTE
csrs menvcfg, t0
csrc henvcfg, t0

li t0, SSTATUS_SDT
csrs vsstatus, t0

# check vsstatus DTE henvcfg DTE close

li t0, SSTATUS_SIE
csrs vsstatus, t0
csrr t1, vsstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail

# MDT 0 same write mie can write 1
li t0, SSTATUS_SIE
csrw vsstatus, t0
csrr t1, vsstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail

# spliciltly write MDT 1,clear mie
li t0, SSTATUS_SDT
csrs vsstatus, t0
csrr t1, vsstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail

# MDT set 0, then write mie
csrc vsstatus, t0
li t0, SSTATUS_SIE
csrs vsstatus, t0
csrr t1, vsstatus
li t3, SSTATUS_SIE
and t2, t1, t3
beqz t2, fail

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
