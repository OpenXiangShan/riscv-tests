# See LICENSE for license details.

#*****************************************************************************
# csrEXII_3.S
#-----------------------------------------------------------------------------
#
# Test csr illegal instruction and check nemu tval
# 写入香山实现的只读的csr
# 在mcounteren没有打开(默认)，读hpmc
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


  li TESTNUM, 4
test_1: 
  li t2, 0xC00 // CSR组起始地址
  li t3, 32  // 总共个数
  la t4, instr_array 
  li a0, 0x5073 // csrw
  li a3, 1 // csr地址步长
  j generate_inst

test_2:
  li t2, 0xF11
  li t3, 5
  li a0, 0x5073
  li a3, 1
  j generate_inst

test_3:
  li t2, 0xC00
  li t3, 32
  li a0, 0x2073 // csrr
  li a3, 1
  j generate_inst

test_4:
  li t2, 0xDB005073
  sw t2, 0(t4)
  addi t4, t4, 4

  li t2, 0xE1205073
  sw t2, 0(t4)
  addi t4, t4, 4

  li t2, 0xEB005073
  sw t2, 0(t4)
  addi t4, t4, 4

  li t2, 0xFB005073
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
  li a2, 3
  beq TESTNUM, a2, test_2
  li a2, 2
  beq TESTNUM, a2, test_3
  bnez TESTNUM, test_4


test_csr:
  la t2, instr_array
  INSERT_INSTRUCTIONS(0xc0005073, 0xc1f05073, 1) // 访问0xc00-0Xc1F地址
  INSERT_INSTRUCTIONS(0xf1105073, 0xf1505073, 1) // 访问0xf11-0Xf15地址
  INSERT_INSTRUCTIONS(0xc0002073, 0xc1f02073, 1)
  .word 0xDB005073
  .word 0xE1205073
  .word 0xEB005073
  .word 0xFB005073
  j pass


  TEST_PASSFAIL

  .align 4
  .global stvec_handler
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


RVTEST_CODE_END

  # .pushsection .text_exec_writable,"awx",@progbits
  #   .align 4
  #   instr_array: .word 64
  # .popsection
  
  .data

RVTEST_DATA_BEGIN

  TEST_DATA

  .align 4
  instr_array: .word 292 // 32 + 5 + 4 + 32

RVTEST_DATA_END
