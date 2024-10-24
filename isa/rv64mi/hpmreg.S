# See LICENSE for license details.

#*****************************************************************************
# hpmreg.S
#-----------------------------------------------------------------------------
#
# Test mhpmevent3-31, mcountinhibit 

#include "riscv_test.h"
#include "test_macros.h"

#define INSERT_INSTRUCTIONS(start, end, step)                           \
        .set current, start;                                            \
        .set current2, 0x323022f3;                                      \
        .rept ((end) - (start)) / (0x100000 * step) + 1;                \
        .word current;                                                  \
        .word current2;                                                 \
        bne t0, t1, fail;                                               \
        .set current, current + 0x100000 * step;                        \
        .set current2, current2 + 0x100000 * step;                      \
        .endr;                                                          \

#define INSERT_INSTRUCTIONS2(start, end, step)                          \
    .set op0, 0x10000000000;                                            \
    .set op1, 0x200000000000;                                           \
    .set op2, 0x4000000000000;                                          \
    .rept 3;                                                            \
    li a0, op0;                                                         \
    li t1, op1;                                                         \
    add a0, a0, t1;                                                     \
    li t1, op2;                                                         \
    add a0, a0, t1;                                                     \
    mv t1, a0;                                                          \
        .set current, start;                                            \
        .set current2, 0x323022f3;                                      \
        .rept ((end) - (start)) / (0x100000 * step) + 1;                \
        .word current;                                                  \
        .word current2;                                                 \
        bne t0, t1, fail;                                               \
        .set current, current + 0x100000 * step;                        \
        .set current2, current2 + 0x100000 * step;                      \
        .endr;                                                          \
    .set op0, op0 * 2;                                                  \
    .set op1, op1 * 2;                                                  \
    .set op2, op2 * 2;                                                  \
    .endr;                                                              \    


RVTEST_RV64M

RVTEST_CODE_BEGIN

# mhpmevent3-31
li a0, 0xffffffffffffffff
li t1, 0xFC0000FFFFFFFFFF

# test normal read/write
INSERT_INSTRUCTIONS(0x32351073, 0x33f51073, 1) 

li a0, 0xFC0000FFFFFFFFFF
li t1, 0xFC0000FFFFFFFFFF
INSERT_INSTRUCTIONS(0x32351073, 0x33f51073, 1) 

INSERT_INSTRUCTIONS2(0x32351073, 0x33f51073, 1) 

li a0, 0x7FFF0000000000
li t1, 0x0010840000000000
INSERT_INSTRUCTIONS(0x32351073, 0x33f51073, 1) 

li a0, 0xffffffffffffffff
li t1, 0xFFFFFFFD

csrw mcountinhibit, a0
csrr t0, mcountinhibit
bne t0, t1, fail

j pass



TEST_PASSFAIL

    .align 4
    .global mtvec_handler

mtvec_handler:
  j fail

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END

