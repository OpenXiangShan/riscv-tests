#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vnsra.wv v30, v28, v26

  li t2, 0x32286f28e1cfbb62
  vsetvli t1, t0, e8, m1, ta, ma
  vnsra.wx v30, v26, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnsra.wi v30, v22, 4

  vsetvli t1, t0, e8, m2, ta, ma
  vnsra.wv v28, v8, v20

  li t2, 0xd8133fd10729d0cb
  vsetvli t1, t0, e8, m2, ta, ma
  vnsra.wx v8, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnsra.wi v8, v4, 21

  vsetvli t1, t0, e8, m4, ta, ma
  vnsra.wv v24, v8, v16

  li t2, 0x7aa158c2094d7a67
  vsetvli t1, t0, e8, m4, ta, ma
  vnsra.wx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnsra.wi v16, v8, 23

  vsetvli t1, t0, e16, m1, ta, ma
  vnsra.wv v4, v24, v12

  li t2, 0x1cf62c675e6ed01f
  vsetvli t1, t0, e16, m1, ta, ma
  vnsra.wx v2, v14, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnsra.wi v18, v14, 27

  vsetvli t1, t0, e16, m2, ta, ma
  vnsra.wv v8, v24, v20

  li t2, 0x54bcca55d9ccd415
  vsetvli t1, t0, e16, m2, ta, ma
  vnsra.wx v4, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnsra.wi v4, v8, 27

  vsetvli t1, t0, e16, m4, ta, ma
  vnsra.wv v16, v24, v8

  li t2, 0x1c7aa341a7e843df
  vsetvli t1, t0, e16, m4, ta, ma
  vnsra.wx v8, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnsra.wi v24, v16, 5

  vsetvli t1, t0, e32, m1, ta, ma
  vnsra.wv v26, v4, v20

  li t2, 0x00a5a6eed27cdf5e
  vsetvli t1, t0, e32, m1, ta, ma
  vnsra.wx v20, v30, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnsra.wi v4, v6, 23

  vsetvli t1, t0, e32, m2, ta, ma
  vnsra.wv v8, v4, v16

  li t2, 0x23e97290b68a0705
  vsetvli t1, t0, e32, m2, ta, ma
  vnsra.wx v8, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnsra.wi v20, v4, 28

  vsetvli t1, t0, e32, m4, ta, ma
  vnsra.wv v16, v24, v8

  li t2, 0x7e56582f973940e4
  vsetvli t1, t0, e32, m4, ta, ma
  vnsra.wx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnsra.wi v24, v16, 27

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
