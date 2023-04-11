#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v21, v5, v23, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v17, v11, v21, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v17, v28, v27, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v4, v20, v19, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v22, v14, v4, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v4, v23, v1, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v22, v31, v16, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v15, v4, v22, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v23, v19, v29, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v11, v20, v21, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v28, v6, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v29, v10, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v7, v8, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v21, v14, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v16, v17, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v24, v25, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v2, v3, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v24, v4, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v2, v1, v21

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsumu.vs v29, v30, v11

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v10, v18, v6, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v4, v22, v20, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v18, v22, v8, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v4, v18, v8, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v22, v14, v18, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v12, v2, v26, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v22, v18, v2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v2, v30, v10, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v4, v10, v8, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v20, v26, v12, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v20, v22, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v20, v26, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v2, v18, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v20, v24, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v10, v8, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v10, v12, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v22, v26, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v26, v16, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v18, v28, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsumu.vs v10, v24, v18

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v8, v20, v4, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v8, v24, v28, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v28, v12, v16, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v16, v20, v28, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v24, v4, v8, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v24, v8, v4, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v12, v28, v20, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v12, v24, v20, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v4, v12, v28, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v28, v4, v16, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v4, v8, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v24, v16, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v16, v20, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v20, v4, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v12, v20, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v4, v24, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v16, v24, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v8, v4, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v28, v12, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsumu.vs v20, v4, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v20, v22, v3, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v3, v10, v4, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v25, v13, v24, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v6, v13, v5, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v17, v1, v29, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v14, v22, v12, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v20, v28, v16, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v3, v20, v4, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v20, v22, v12, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v24, v17, v25, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v28, v26, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v9, v25, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v27, v26, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v23, v1, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v25, v10, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v7, v6, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v19, v10, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v15, v9, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v13, v10, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsumu.vs v19, v6, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v12, v30, v10, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v28, v24, v30, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v6, v16, v22, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v6, v16, v28, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v30, v2, v26, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v12, v14, v2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v16, v26, v10, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v22, v18, v4, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v14, v12, v20, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v18, v4, v30, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v22, v24, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v28, v12, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v30, v6, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v14, v20, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v28, v26, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v14, v8, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v24, v4, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v24, v16, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v6, v20, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsumu.vs v22, v14, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v8, v4, v16, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v12, v20, v28, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v28, v4, v20, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v12, v20, v8, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v20, v28, v4, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v20, v16, v24, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v12, v20, v4, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v4, v16, v24, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v28, v16, v24, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v4, v28, v24, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v16, v8, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v12, v20, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v4, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v16, v4, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v24, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v8, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v8, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v20, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v28, v8, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsumu.vs v20, v24, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v30, v22, v11, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v7, v2, v17, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v10, v30, v20, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v15, v12, v16, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v18, v14, v8, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v15, v5, v6, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v14, v6, v18, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v4, v10, v1, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v5, v15, v11, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v13, v31, v11, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v1, v7, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v10, v15, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v4, v12, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v8, v24, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v19, v11, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v25, v2, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v8, v31, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v15, v25, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v25, v11, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsumu.vs v2, v10, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v18, v28, v30, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v12, v30, v28, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v30, v12, v2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v4, v22, v8, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v18, v26, v30, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v22, v18, v16, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v28, v24, v8, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v8, v26, v16, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v22, v8, v16, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v14, v8, v4, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v30, v18, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v12, v6, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v2, v10, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v22, v30, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v6, v4, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v20, v26, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v6, v24, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v28, v14, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v14, v16, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsumu.vs v8, v20, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v24, v4, v20, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v24, v20, v8, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v16, v28, v4, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v28, v20, v8, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v4, v8, v28, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v20, v24, v28, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v16, v4, v24, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v12, v8, v16, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v12, v16, v4, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v20, v28, v24, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v28, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v24, v20, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v8, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v20, v4, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v28, v12, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v16, v8, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v24, v20, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v4, v20, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v8, v16, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsumu.vs v4, v24, v12

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
