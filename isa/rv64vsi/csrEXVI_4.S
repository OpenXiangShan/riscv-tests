# See LICENSE for license details.

#*****************************************************************************
# csrEXVI_4.S
#-----------------------------------------------------------------------------
#
# Test csr virtual instruction and check nemu tval
# mcounteren open , hcounteren open, henvcfg close menvcfg open get stimecfg
#


#include "riscv_test.h"
#include "test_macros.h"


#define INSERT_INSTRUCTIONS(start, end, step)                           \
        .set current, start;                                            \
        .rept ((end) - (start)) / (0x100000 * step) + 1;                      \
        .word current;                                                  \
        .set current, current + 0x100000 * step;                               \
        .endr;         
RVTEST_RV64VS

RVTEST_CODE_BEGIN


  li TESTNUM, 2
  csrw 0x7B0, 0  // only for trap to M
test_1:
  la t4, instr_array 
  li t2, 0x14D05073
  sw t2, 0(t4)
  addi t4, t4, 4

  li t2, 0x14D02073
  sw t2, 0(t4)
  addi t4, t4, 4

  j test_csr


test_csr:
  la t2, instr_array
  csrw stimecmp, 0
  csrr x0, stimecmp
  j pass


  TEST_PASSFAIL

  .align 4
  .global stvec_handler
  .global mtvec_handler
## !!!!notice EX_VI cannot deleg to VS
stvec_handler:
  lwu t1, 0(t2)
    li a2, 0x80001 
  csrr t0, stval
  bne t0, t1, fail
  csrr t0, sepc
  addi t0, t0, 4
  csrw sepc, t0
  addi t2, t2, 4
  sret

mtvec_handler:
  // reset deleg to S/VS
  RVTEST_MTVEC_HANDLER_INIT
  // set TVM
  li a0, 0xffffffffffffffff
  csrs mcounteren, a0  
  csrs hcounteren, a0
  csrs menvcfg, a0
  li a0, 0x7fffffffffffffff
  csrs henvcfg, a0

  mret
           

RVTEST_CODE_END

  # .pushsection .text_exec_writable,"awx",@progbits
  #   .align 4
  #   instr_array: .word 64
  # .popsection
  
  .data
  .global nodeleg

nodeleg:
  .word 0

RVTEST_DATA_BEGIN

  TEST_DATA

  .align 4
  instr_array: 
    .word 128

RVTEST_DATA_END

