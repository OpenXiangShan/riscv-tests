# See LICENSE for license details.

#*****************************************************************************
# vldst_trigger.S
#-----------------------------------------------------------------------------
#
# Test vector load/store trigger.
#

#include "riscv_test.h"
#include "test_macros.h"

#define __riscv_xlen 64
#define MCONTROL6_M          (1<<6)
#define MCONTROL6_LOAD       (1<<0)
#define MCONTROL6_STORE       (1<<1)
#define TDATA1_TYPE 6ULL
#define CAUSE_NONE 0
#define CAUSE_BP   3

#define SETTRIGGER(tdata2_value, op) \
    csrwi tselect, 1; \
    li a0, ((TDATA1_TYPE << (__riscv_xlen - 4)) | MCONTROL6_M | op); \
    csrw tdata1, a0; \
    li a0, tdata2_value; \
    csrw tdata2, a0; \
    csrs mstatus, 8;

#define PREPARE(mcause_value, vl_value, vstart_value, access_addr) \
    li a0, access_addr; \
    li t1, mcause_value; \
    li t2, vl_value; \
    li t3, vstart_value;

#define CHECK \
    csrr t4, mcause; \
    csrr t5, vl; \
    csrr t6, vstart; \
    bne t4, t1, fail; \
    bne t5, t2, fail; \
    bne t6, t3, fail; \
    li t0, 0; \
    csrw mcause, t0; \
    csrw tdata1, t0;

RVTEST_RV64M
RVTEST_CODE_BEGIN
  .align 2
  .option norvc

set_env:
    lui a0,0x2
    addiw a0,a0,512
    csrs mstatus,a0
    csrwi vcsr,0

# 1. test vle
vle_test:
    li s0, 1

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vle8.v v0, (a0)
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vle8.v v0, (a0)
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 1, 0x81000000-1)
    vsetivli zero,8,e8,m1
    vle8.v v0, (a0)
    CHECK

    li TESTNUM, 4
    SETTRIGGER(0x82000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 4, 0x82000000-4)
    vsetivli zero,8,e8,m1
    vle8.v v0, (a0)
    CHECK

    li TESTNUM, 5
    PREPARE(CAUSE_NONE, 8, 0, 0x82000000-4)
    vsetivli zero,8,e8,m1
    vle8.v v0, (a0)
    CHECK

    li TESTNUM, 6
    SETTRIGGER(0x82000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_NONE, 8, 0, 0x82000000-8)
    vsetivli zero,8,e8,m1
    vle8.v v0, (a0)
    CHECK

# 2. test vlm
vlm_test:
    li s0, 2

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vlm.v v0, (a0)
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vlm.v v0, (a0)
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 16, 1, 0x81000000-1)
    vsetivli zero,16,e8,m1
    vlm.v v0, (a0)
    CHECK

    li TESTNUM, 4
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 12, 1, 0x81000000-1)
    vsetivli zero,12,e8,m1
    vlm.v v0, (a0)
    CHECK

# 3. test vlse
vlse_test:
    li s0, 3

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    li a1, 2
    vlse8.v v0, (a0), a1
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    li a1, 2
    vlse8.v v0, (a0), a1
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 1, 0x81000000-2)
    vsetivli zero,8,e8,m1
    li a1, 2
    vlse8.v v0, (a0), a1
    CHECK

    li TESTNUM, 4
    SETTRIGGER(0x82000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 4, 0x82000000-8)
    vsetivli zero,8,e8,m1
    li a1, 2
    vlse8.v v0, (a0), a1
    CHECK

    li TESTNUM, 5
    PREPARE(CAUSE_NONE, 8, 0, 0x82000000-8)
    vsetivli zero,8,e8,m1
    li a1, 2
    vlse8.v v0, (a0), a1
    CHECK

    li TESTNUM, 6
    SETTRIGGER(0x82000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_NONE, 8, 0, 0x82000000-16)
    vsetivli zero,8,e8,m1
    li a1, 2
    vlse8.v v0, (a0), a1
    CHECK

# 4. test vlxe
vlxe_test:
    li s0, 4

    vsetivli zero,8,e8,m1
    la a0, idx1
    vle8.v v1, (a0)

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vloxei8.v v0, (a0), v1
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vloxei8.v v0, (a0), v1
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x82000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 6, 0x82000000-7)
    vsetivli zero,8,e8,m1
    vloxei8.v v0, (a0), v1
    CHECK

    li TESTNUM, 4
    PREPARE(CAUSE_NONE, 8, 0, 0x82000000-7)
    vsetivli zero,8,e8,m1
    vloxei8.v v0, (a0), v1
    CHECK

    li TESTNUM, 5
    SETTRIGGER(0x82000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_NONE, 8, 0, 0x82000000-8)
    vsetivli zero,8,e8,m1
    vloxei8.v v0, (a0), v1
    CHECK

# 5. test vleff
vleff_test:
    li s0, 5

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 16, 0, 0x81000000)
    vsetivli zero,16,e8,m1
    vle8ff.v v0, (a0)
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 16, 0, 0x81000000)
    vsetivli zero,16,e8,m1
    vle8ff.v v0, (a0)
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_NONE, 3, 0, 0x81000000-3)
    vsetivli zero,16,e8,m1
    vle8ff.v v0, (a0)
    CHECK

# 6. test vlseg
vlseg_test:
    li s0, 6

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vlseg2e8.v v0,(a0)
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vlseg2e8.v v0,(a0)
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 1, 0x81000000-2)
    vsetivli zero,8,e8,m1
    vlseg2e8.v v0,(a0)
    CHECK

    li TESTNUM, 4
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000-1)
    vsetivli zero,8,e8,m1
    vlseg2e8.v v0,(a0)
    CHECK

# 7. test vlsegff
vlsegff_test:
    li s0, 7

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vlseg2e8ff.v v0,(a0)
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vlseg2e8ff.v v0,(a0)
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_NONE, 2, 0, 0x81000000-4)
    vsetivli zero,8,e8,m1
    vlseg2e8ff.v v0,(a0)
    CHECK

    li TESTNUM, 4
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000-1)
    vsetivli zero,8,e8,m1
    vlseg2e8ff.v v0,(a0)
    CHECK

    li TESTNUM, 5
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_NONE, 1, 0, 0x81000000-3)
    vsetivli zero,8,e8,m1
    vlseg2e8ff.v v0,(a0)
    CHECK


# 8. test vlsseg
vlsseg_test:
    li s0, 8

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    li a1, 10
    vlsseg2e8.v v0,(a0),a1
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    li a1, 10
    vlsseg2e8.v v0,(a0),a1
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 1, 0x81000000-10)
    vsetivli zero,8,e8,m1
    li a1, 10
    vlsseg2e8.v v0,(a0),a1
    CHECK

    li TESTNUM, 4
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 1, 0x81000000-11)
    vsetivli zero,8,e8,m1
    li a1, 10
    vlsseg2e8.v v0,(a0),a1
    CHECK

# 9. test vlxseg
vlxseg_test:
    li s0, 9

    vsetivli zero,8,e8,m1
    la a0, idx2
    vle8.v v1, (a0)

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vloxseg2ei8.v v4,(a0),v1
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vloxseg2ei8.v v4,(a0),v1
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 2, 0x81000000-40)
    vsetivli zero,8,e8,m1
    vloxseg2ei8.v v4,(a0),v1
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 6, 0x81000000-71)
    vsetivli zero,8,e8,m1
    vloxseg2ei8.v v4,(a0),v1
    CHECK

# 10. test vlr
vlr_test:
    li s0, 10

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vl1re8.v v0,(a0)
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vl1re8.v v0,(a0)
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_LOAD)
    PREPARE(CAUSE_BP, 8, 16, 0x81000000-16)
    vsetivli zero,8,e8,m1
    vl4re8.v v0,(a0)
    CHECK

# 11. test vse
vse_test:
    li s0, 11

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vse8.v v0, (a0)
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vse8.v v0, (a0)
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 1, 0x81000000-1)
    vsetivli zero,8,e8,m1
    vse8.v v0, (a0)
    CHECK

    li TESTNUM, 4
    SETTRIGGER(0x82000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 4, 0x82000000-4)
    vsetivli zero,8,e8,m1
    vse8.v v0, (a0)
    CHECK

    li TESTNUM, 5
    PREPARE(CAUSE_NONE, 8, 0, 0x82000000-4)
    vsetivli zero,8,e8,m1
    vse8.v v0, (a0)
    CHECK

    li TESTNUM, 6
    SETTRIGGER(0x82000000, MCONTROL6_STORE)
    PREPARE(CAUSE_NONE, 8, 0, 0x82000000-8)
    vsetivli zero,8,e8,m1
    vse8.v v0, (a0)
    CHECK

# 12. test vsm
vsm_test:
    li s0, 12

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vsm.v v0, (a0)
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vsm.v v0, (a0)
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 16, 1, 0x81000000-1)
    vsetivli zero,16,e8,m1
    vsm.v v0, (a0)
    CHECK

    li TESTNUM, 4
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 14, 1, 0x81000000-1)
    vsetivli zero,14,e8,m1
    vsm.v v0, (a0)
    CHECK

# 13. test vsse
vsse_test:
    li s0, 13

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    li a1, 2
    vsse8.v v0, (a0), a1
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    li a1, 2
    vsse8.v v0, (a0), a1
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 1, 0x81000000-2)
    vsetivli zero,8,e8,m1
    li a1, 2
    vsse8.v v0, (a0), a1
    CHECK

    li TESTNUM, 4
    SETTRIGGER(0x82000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 4, 0x82000000-8)
    vsetivli zero,8,e8,m1
    li a1, 2
    vsse8.v v0, (a0), a1
    CHECK

    li TESTNUM, 5
    PREPARE(CAUSE_NONE, 8, 0, 0x82000000-8)
    vsetivli zero,8,e8,m1
    li a1, 2
    vsse8.v v0, (a0), a1
    CHECK

    li TESTNUM, 6
    SETTRIGGER(0x82000000, MCONTROL6_STORE)
    PREPARE(CAUSE_NONE, 8, 0, 0x82000000-16)
    vsetivli zero,8,e8,m1
    li a1, 2
    vsse8.v v0, (a0), a1
    CHECK

# 14. test vsxe
vsxe_test:
    li s0, 14

    vsetivli zero,8,e8,m1
    la a0, idx1
    vle8.v v1, (a0)

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vsoxei8.v v0, (a0), v1
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vsoxei8.v v0, (a0), v1
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x82000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 6, 0x82000000-7)
    vsetivli zero,8,e8,m1
    vsoxei8.v v0, (a0), v1
    CHECK

    li TESTNUM, 4
    PREPARE(CAUSE_NONE, 8, 0, 0x82000000-7)
    vsetivli zero,8,e8,m1
    vsoxei8.v v0, (a0), v1
    CHECK

    li TESTNUM, 5
    SETTRIGGER(0x82000000, MCONTROL6_STORE)
    PREPARE(CAUSE_NONE, 8, 0, 0x82000000-8)
    vsetivli zero,8,e8,m1
    vsoxei8.v v0, (a0), v1
    CHECK

# 15. test vsseg
vsseg_test:
    li s0, 6

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vsseg2e8.v v0,(a0)
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vsseg2e8.v v0,(a0)
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 1, 0x81000000-2)
    vsetivli zero,8,e8,m1
    vsseg2e8.v v0,(a0)
    CHECK

    li TESTNUM, 4
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000-1)
    vsetivli zero,8,e8,m1
    vsseg2e8.v v0,(a0)
    CHECK

# 16. test vssseg
vssseg_test:
    li s0, 8

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    li a1, 10
    vssseg2e8.v v0,(a0),a1
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    li a1, 10
    vssseg2e8.v v0,(a0),a1
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 1, 0x81000000-10)
    vsetivli zero,8,e8,m1
    li a1, 10
    vssseg2e8.v v0,(a0),a1
    CHECK

    li TESTNUM, 4
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 1, 0x81000000-11)
    vsetivli zero,8,e8,m1
    li a1, 10
    vssseg2e8.v v0,(a0),a1
    CHECK

# 17. test vsxseg
vsxseg_test:
    li s0, 17

    vsetivli zero,8,e8,m1
    la a0, idx2
    vle8.v v1, (a0)

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vsoxseg2ei8.v v4,(a0),v1
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vsoxseg2ei8.v v4,(a0),v1
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 2, 0x81000000-40)
    vsetivli zero,8,e8,m1
    vsoxseg2ei8.v v4,(a0),v1
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 6, 0x81000000-71)
    vsetivli zero,8,e8,m1
    vsoxseg2ei8.v v4,(a0),v1
    CHECK

# 18. test vsr
vsr_test:
    li s0, 10

    li TESTNUM, 1
    PREPARE(CAUSE_NONE, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vs1r.v v0,(a0)
    CHECK

    li TESTNUM, 2
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 0, 0x81000000)
    vsetivli zero,8,e8,m1
    vs1r.v v0,(a0)
    CHECK

    li TESTNUM, 3
    SETTRIGGER(0x81000000, MCONTROL6_STORE)
    PREPARE(CAUSE_BP, 8, 16, 0x81000000-16)
    vsetivli zero,8,e8,m1
    vs4r.v v0,(a0)
    CHECK

test_end:
    j pass

.align 4
.global mtvec_handler
mtvec_handler:
    csrr t0, mepc
    addi t0, t0, 4
    csrw mepc, t0
    mret

  TEST_PASSFAIL

RVTEST_CODE_END

  .data

RVTEST_DATA_BEGIN
    
  TEST_DATA

idx1:
    .byte 0, 5, 4, 3, 1, 2, 7, 6

idx2:
    .byte 0, 50, 40, 30, 10, 20, 70, 60

RVTEST_DATA_END