# See LICENSE for license details.

#*****************************************************************************
# csrEXVI_2.S
#-----------------------------------------------------------------------------
#
# Test csr virtual instruction and check nemu tval
# mcounteren open , hcounteren close, get HPMC c00-c1f; menvcfg open , henvcfg open get stimecmp
# mcounteren open, hcounteren close, write HPMC (should be EX_II)


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


  li TESTNUM, 3
  csrw 0x7B0, 0  // only for trap to M
test_1: 
  li t2, 0xC00 // CSR组起始地址
  li t3, 32  // 总共个数
  la t4, instr_array 
  li a0, 0x2073 // csrw
  li a3, 1 // csr地址步长
  j generate_inst

test_2:
  li t2, 0xC00 // CSR组起始地址
  li t3, 32  // 总共个数
  li a0, 0x5073 // csrw
  li a3, 1 // csr地址步长
  j generate_inst

test_3:
  li t2, 0x14D05073
  li a2, 0x80003
  sw t2, 0(t4)
  addi t4, t4, 4

  li t2, 0x14D02073
  sw t2, 0(t4)
  addi t4, t4, 4

  j test_csr

generate_inst:
  slli t2, t2, 20
  or a1, a0, t2

  sw a1, 0(t4)
  

  srli t2, t2, 20
  add t2, t2, a3

  addi t4, t4, 4

  addi t3, t3, -1
  bnez t3, generate_inst
  addi TESTNUM, TESTNUM, -1
  li a2, 2
  beq TESTNUM, a2, test_2
  bnez TESTNUM, test_3

test_csr:
  la t2, instr_array
  INSERT_INSTRUCTIONS(0xc0002073, 0xc1f02073, 1) // 访问0xc00-0Xc1F地址
  INSERT_INSTRUCTIONS(0xc0005073, 0xc1f05073, 1) // 访问0xc00-0Xc1F地址
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
  csrs menvcfg, a0
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
    .word 264 // 32*2+2

RVTEST_DATA_END
