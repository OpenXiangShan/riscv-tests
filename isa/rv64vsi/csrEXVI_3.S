# See LICENSE for license details.

#*****************************************************************************
# csrEXVI_3.S
#-----------------------------------------------------------------------------
#
# Test csr virtual instruction and check nemu tval
# mcounteren open , hcounteren open, get HPMC c00-c1f, menvcfg open,henvcfg open, get stimecmp
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


  li TESTNUM, 4
  csrw 0x7B0, 0  // only for trap to M
test_1: 
  li t2, 0xC00 // CSR组起始地址
  li t3, 32  // 总共个数
  la t4, instr_array 
  li a0, 0x2073 // csrw
  li a3, 1 // csr地址步长
  j generate_inst

generate_inst:
  slli t2, t2, 20
  or a1, a0, t2

  sw a1, 0(t4)
  

  srli t2, t2, 20
  add t2, t2, a3

  addi t4, t4, 4

  addi t3, t3, -1
  bnez t3, generate_inst

test_csr:
  la t2, instr_array
  INSERT_INSTRUCTIONS(0xc0002073, 0xc1f02073, 1) // 访问0xc00-0Xc1F地址
  j pass


  TEST_PASSFAIL

  .align 4
  .global stvec_handler
  .global mtvec_handler
stvec_handler:
  lwu t1, 0(t2)
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
  li a0, 0xffffffff
  csrs mcounteren, a0  
  csrs hcounteren, a0
  csrr a1, mcounteren
  csrr a2, hcounteren
  li a2, 0x80001 
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
