#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v1, v12, v15, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v18, v30, v28, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v3, v28, v23, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v18, v8, v12, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v26, v25, v21, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v26, v8, v25, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v22, v11, v26, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v8, v18, v1, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v13, v3, v25, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v20, v10, v24, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v2, v12, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v20, v16, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v17, v31, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v16, v22, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v13, v18, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v21, v25, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v22, v11, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v21, v11, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v16, v3, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vwredsum.vs v5, v26, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v16, v14, v30, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v4, v6, v24, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v14, v6, v24, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v14, v6, v18, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v16, v2, v26, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v8, v12, v2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v12, v4, v30, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v24, v18, v6, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v12, v26, v22, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v10, v2, v12, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v8, v14, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v8, v30, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v26, v4, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v2, v14, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v26, v4, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v16, v24, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v10, v24, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v10, v26, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v28, v22, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vwredsum.vs v4, v16, v18

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v12, v16, v20, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v12, v4, v20, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v24, v20, v8, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v16, v4, v12, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v8, v24, v20, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v16, v12, v28, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v4, v12, v16, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v12, v28, v24, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v8, v12, v28, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v24, v12, v28, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v8, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v8, v20, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v8, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v16, v28, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v20, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v28, v8, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v12, v24, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v4, v28, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v16, v4, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vwredsum.vs v8, v16, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v31, v10, v9, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v1, v2, v9, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v31, v11, v14, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v4, v20, v1, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v10, v26, v27, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v13, v4, v23, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v30, v10, v1, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v22, v27, v31, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v11, v15, v7, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v18, v11, v31, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v5, v1, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v5, v17, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v25, v23, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v29, v30, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v5, v19, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v7, v26, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v10, v11, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v21, v15, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v26, v2, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwredsum.vs v4, v2, v19

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v14, v28, v30, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v4, v24, v16, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v24, v8, v20, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v10, v16, v8, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v24, v20, v2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v28, v4, v12, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v12, v10, v26, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v8, v12, v14, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v30, v8, v20, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v18, v12, v2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v4, v6, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v12, v20, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v6, v28, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v26, v14, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v8, v24, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v6, v30, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v6, v8, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v10, v12, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v6, v30, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vwredsum.vs v20, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v16, v20, v28, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v24, v8, v4, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v28, v8, v12, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v20, v4, v8, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v16, v28, v12, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v8, v24, v4, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v24, v12, v20, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v20, v28, v8, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v20, v8, v4, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v16, v24, v12, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v12, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v20, v12, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v16, v8, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v24, v28, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v20, v28, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v8, v16, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v28, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwredsum.vs v4, v24, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v21, v30, v22, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v14, v24, v21, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v12, v22, v27, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v31, v14, v28, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v28, v4, v30, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v25, v24, v28, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v25, v17, v10, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v10, v13, v28, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v1, v15, v7, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v31, v27, v18, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v29, v18, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v25, v20, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v21, v11, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v16, v22, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v22, v9, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v5, v19, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v10, v1, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v6, v22, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v11, v1, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vwredsum.vs v13, v23, v19

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v28, v14, v4, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v20, v30, v8, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v22, v16, v8, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v10, v8, v4, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v8, v28, v30, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v6, v26, v14, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v20, v12, v30, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v8, v12, v24, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v14, v10, v16, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v16, v30, v14, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v22, v4, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v26, v30, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v20, v18, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v6, v14, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v26, v16, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v4, v24, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v26, v12, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v30, v2, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v2, v6, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vwredsum.vs v18, v16, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v24, v4, v16, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v8, v20, v4, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v28, v12, v24, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v16, v12, v28, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v16, v12, v20, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v12, v28, v8, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v20, v8, v12, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v4, v12, v8, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v12, v20, v8, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v24, v28, v8, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v28, v8, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v8, v20, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v28, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v8, v20, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v8, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v4, v12, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v8, v28, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v24, v20, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v20, v28, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwredsum.vs v24, v20, v12

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
