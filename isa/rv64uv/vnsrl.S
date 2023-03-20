#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vnsrl.wv v26, v20, v22

  li t2, 0x53144222931d85a2
  vsetvli t1, t0, e8, m1, ta, ma
  vnsrl.wx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnsrl.wi v10, v6, 25

  vsetvli t1, t0, e8, m2, ta, ma
  vnsrl.wv v16, v28, v4

  li t2, 0x37327adc59c664ac
  vsetvli t1, t0, e8, m2, ta, ma
  vnsrl.wx v8, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnsrl.wi v20, v28, 12

  vsetvli t1, t0, e8, m4, ta, ma
  vnsrl.wv v16, v8, v24

  li t2, 0x4c254f0978e8273b
  vsetvli t1, t0, e8, m4, ta, ma
  vnsrl.wx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnsrl.wi v16, v24, 13

  vsetvli t1, t0, e16, m1, ta, ma
  vnsrl.wv v14, v20, v8

  li t2, 0xcdb2c5b0d5c5191b
  vsetvli t1, t0, e16, m1, ta, ma
  vnsrl.wx v18, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnsrl.wi v14, v26, 25

  vsetvli t1, t0, e16, m2, ta, ma
  vnsrl.wv v20, v24, v12

  li t2, 0xd0bd62a5f2240d89
  vsetvli t1, t0, e16, m2, ta, ma
  vnsrl.wx v16, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnsrl.wi v4, v28, 6

  vsetvli t1, t0, e16, m4, ta, ma
  vnsrl.wv v24, v16, v8

  li t2, 0x0b2a3e40d4551c50
  vsetvli t1, t0, e16, m4, ta, ma
  vnsrl.wx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnsrl.wi v8, v16, 30

  vsetvli t1, t0, e32, m1, ta, ma
  vnsrl.wv v12, v24, v16

  li t2, 0x97be156c1442a3da
  vsetvli t1, t0, e32, m1, ta, ma
  vnsrl.wx v2, v26, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnsrl.wi v26, v4, 16

  vsetvli t1, t0, e32, m2, ta, ma
  vnsrl.wv v4, v24, v12

  li t2, 0xa8626dca1cdd7ce7
  vsetvli t1, t0, e32, m2, ta, ma
  vnsrl.wx v28, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnsrl.wi v16, v20, 11

  vsetvli t1, t0, e32, m4, ta, ma
  vnsrl.wv v16, v8, v24

  li t2, 0x8ab342b32794176a
  vsetvli t1, t0, e32, m4, ta, ma
  vnsrl.wx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnsrl.wi v16, v8, 25

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
