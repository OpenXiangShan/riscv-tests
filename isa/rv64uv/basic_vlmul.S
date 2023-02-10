#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v21, v8, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v26, v19, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v27, v17, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v1, v12, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v8, v15, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v29, v28, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v21, v20, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v12, v13, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v22, v20, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v29, v7, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v30, v15, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v16, v17, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v12, v18, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v4, v29, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v26, v20, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v22, v23, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v4, v20, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v28, v15, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v26, v21, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v6, v18, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v29, v4, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v12, v1, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v5, v1, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v4, v22, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v6, v8, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v26, v24, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v10, v26, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v10, v24, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v6, v12, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v26, v10, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v24, v20, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v20, v16, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v12, v14, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v16, v28, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v8, v4, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v28, v24, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v2, v16, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v16, v30, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v28, v24, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v14, v18, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v20, v10, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v30, v12, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v30, v22, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v18, v2, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v26, v4, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v26, v12, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v30, v28, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v14, v16, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v6, v4, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v6, v2, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v12, v28, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v16, v12, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v8, v4, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v20, v8, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v16, v28, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v28, v16, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v28, v12, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v4, v28, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v20, v4, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v4, v8, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v24, v4, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v4, v24, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v24, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v8, v16, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v28, v16, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v16, v4, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v8, v24, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v16, v28, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v12, v4, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v4, v28, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v12, v8, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v24, v16, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v20, v12, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v16, v4, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v8, v20, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v8, v24, v16

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
