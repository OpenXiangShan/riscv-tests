#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1
  vsetvli t1, t0, e8, m1, ta, ma
  la a0, data0+0
  vle8.v v3, (a0)
  vsetvli t1, t0, e8, m1, ta, ma
  la a1, data1+0
  vle8.v v29, (a1)
  vsetvli t1, t0, e8, m1, ta, ma
  la a2, data2+0
  vle8.v v30, (a2)
  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v30, v3, v29

  li t0, -1
  vsetvli t1, t0, e16, m1, ta, ma
  la a0, data0+16
  vle16.v v18, (a0)
  vsetvli t1, t0, e16, m1, ta, ma
  la a1, data1+16
  vle16.v v25, (a1)
  vsetvli t1, t0, e16, m1, ta, ma
  la a2, data2+16
  vle16.v v26, (a2)
  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v26, v18, v25

  li t0, -1
  vsetvli t1, t0, e32, m1, ta, ma
  la a0, data0+32
  vle32.v v9, (a0)
  vsetvli t1, t0, e32, m1, ta, ma
  la a1, data1+32
  vle32.v v5, (a1)
  vsetvli t1, t0, e32, m1, ta, ma
  la a2, data2+32
  vle32.v v6, (a2)
  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v6, v9, v5

  li t0, -1
  vsetvli t1, t0, e64, m1, ta, ma
  la a0, data0+48
  vle64.v v23, (a0)
  vsetvli t1, t0, e64, m1, ta, ma
  la a1, data1+48
  vle64.v v10, (a1)
  vsetvli t1, t0, e64, m1, ta, ma
  la a2, data2+48
  vle64.v v7, (a2)
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v7, v23, v10
  
  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 128
data0:
  .quad 0xac1fbe37374cfbc2
  .quad 0xaead6cc01df0d589
  .quad 0x3c43262a554c9f9c
  .quad 0x6d51af33f098eaa9
  .quad 0xb58b104edccbe21f
  .quad 0xe882598e3a44bc8b
  .quad 0xd1ebe0202625dcb2
  .quad 0x0d5f0b9c8241114d
data1:
  .quad 0x017c5871a1d44206
  .quad 0xfe916c3c093f0ed9
  .quad 0xe5a89fdbcda6a4c6
  .quad 0x4c59b9183a161851
  .quad 0x4dc60663223574cb
  .quad 0xd4517eb07f1fafd8
  .quad 0x8fd753f35672a32f
  .quad 0x47f4aef8100ec8e2
data2:
  .quad 0x0000000000000000
  .quad 0x0000000000000000
  .quad 0x0000000000000000
  .quad 0x0000000000000000
  .quad 0x0000000000000000
  .quad 0x0000000000000000
  .quad 0x0000000000000000
  .quad 0x0000000000000000
mask:
  .quad 0xffffffffffffffff
  .quad 0xffffffffffffffff
  .quad 0xffffffffffffffff
  .quad 0xffffffffffffffff
  .quad 0xffffffffffffffff
  .quad 0xffffffffffffffff
  .quad 0xffffffffffffffff
  .quad 0xffffffffffffffff

RVTEST_DATA_END
