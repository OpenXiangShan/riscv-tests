# See LICENSE for license details.

#*****************************************************************************
# csrEXII_1.S
#-----------------------------------------------------------------------------
#
# Test csr illegal instruction and check nemu tval
# 访问 0x7B0-0x7BF, 访问 0x7A0-0x7AF, 访问奇数PMPCFG when XLEN=64
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64S
RVTEST_CODE_BEGIN

#define INSERT_INSTRUCTIONS(start, end, step)                           \
        .set current, start;                                            \
        .rept ((end) - (start)) / (0x100000 * step) + 1;                      \
        .word current;                                                  \
        .set current, current + 0x100000 * step;                               \
        .endr;                                                          \

#ifdef __MACHINE_MODE
  #define sscratch mscratch
  #define sstatus mstatus
  #define scause mcause
  #define sepc mepc
  #define sret mret
  #define stval mtval
  #define stvec_handler mtvec_handler
#endif

#ifdef __HYPERVISOR_MODE
  #define stvec_handler vstvec_handler
#endif


  li TESTNUM, 3
test_1: 
  li t2, 0x7B0 // CSR组起始地址
  li t3, 16  // 总共个数
  la t4, instr_array 
  li a0, 0x5073 // csrw
  li a3, 1 // csr地址步长
  j generate_inst

test_2:
  li t2, 0x7A0
  li t3, 16
  li a0, 0x5073
  li a3, 1
  j generate_inst

test_3:
  li t2, 0x3A1
  li t3, 8
  li a0, 0x2073
  li a3, 2
  j generate_inst





generate_inst:
   #generate inst code from 0x7B005073 - 0x7BF05073/ 0x7A005073-0X7AF05073
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
  li a1, 0x0
  la t2, instr_array
  INSERT_INSTRUCTIONS(0x7b005073, 0x7bf05073, 1) // 访问0x7B0-0X7BF地址
  INSERT_INSTRUCTIONS(0x7a005073, 0x7af05073, 1) // 访问0x7A0-0X7AF地址
  INSERT_INSTRUCTIONS(0x3a102073, 0x3af02073, 2) // 访问奇数pmpcfg
  j pass


  TEST_PASSFAIL

  .align 4
  .global stvec_handler
stvec_handler:
  lwu t1, 0(t2)
  csrr t0, stval
  bne t0, t1, fail
  csrr t0, sepc
  addi t0, t0, 4
  csrw sepc, t0
  addi t2, t2, 4
  sret


RVTEST_CODE_END

  # .pushsection .text_exec_writable,"awx",@progbits
  #   .align 4
  #   instr_array: .word 64
  # .popsection
  
  .data

RVTEST_DATA_BEGIN

  TEST_DATA

  .align 4
  instr_array: .word 160 // 16 + 16 + 8

RVTEST_DATA_END
