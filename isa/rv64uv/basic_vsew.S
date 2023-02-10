#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v2, v18, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v3, v11, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v3, v26, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v6, v12, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v30, v2, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v2, v15, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v7, v10, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v7, v8, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v8, v12, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v29, v15, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v9, v17, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v24, v16, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v15, v31, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v10, v12, v31

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v8, v21, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v6, v22, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v16, v3, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v15, v22, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v30, v20, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v15, v25, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v28, v4, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v29, v5, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v10, v12, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v16, v26, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v18, v26, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v4, v29, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v17, v5, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v4, v1, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v16, v1, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v19, v5, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v19, v16, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v13, v22, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v21, v18, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v19, v14, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v13, v16, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v11, v25, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v14, v1, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v30, v24, v9

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v25, v31, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v18, v8, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v7, v6, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v3, v10, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v28, v23, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v27, v14, v29

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v21, v1, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v29, v19, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v1, v10, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v2, v8, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v27, v6, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v11, v28, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v15, v30, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v2, v20, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v23, v5, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v3, v24, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v16, v17, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v26, v8, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v19, v1, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v29, v30, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v14, v10, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v9, v26, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v4, v9, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v28, v17, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v16, v30, v5

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v2, v29, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v21, v24, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v4, v1, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v22, v27, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v22, v29, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v2, v11, v5

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v6, v7, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v1, v2, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v17, v8, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v14, v25, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v18, v29, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v7, v19, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v27, v9, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v9, v15, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v30, v21, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v29, v25, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v6, v4, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v6, v16, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v1, v28, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v30, v10, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v31, v23, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v23, v12, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v15, v9, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v5, v28, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v11, v10, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v21, v31, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v28, v23, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v2, v14, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v25, v9, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v6, v11, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v8, v16, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v2, v11, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v30, v7, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v23, v14, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v26, v22, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v30, v27, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v3, v17, v28

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
