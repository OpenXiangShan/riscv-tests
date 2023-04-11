#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v2, t2, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v10, t2, v30, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v6, t2, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v5, t2, v6, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v21, t2, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v16, t2, v30, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v18, t2, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v4, t2, v21, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v8, t2, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v5, t2, v31, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v15, t2, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v28, t2, v6, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v17, t2, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v12, t2, v2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v28, t2, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v11, t2, v18, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v25, t2, v31

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v11, t2, v8, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v27, t2, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v7, t2, v28, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v2, t2, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v10, t2, v6, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v8, t2, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v28, t2, v8, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v8, t2, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v4, t2, v12, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v4, t2, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v6, t2, v10, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v4, t2, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v10, t2, v22, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v20, t2, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v6, t2, v26, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v30, t2, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v30, t2, v28, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v12, t2, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v2, t2, v6, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v8, t2, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v22, t2, v4, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v20, t2, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v18, t2, v30, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v20, t2, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v24, t2, v8, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v12, t2, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v24, t2, v8, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v16, t2, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v8, t2, v16, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v20, t2, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v16, t2, v20, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v16, t2, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v16, t2, v4, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v20, t2, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v12, t2, v4, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v4, t2, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v4, t2, v16, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v28, t2, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v28, t2, v4, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v16, t2, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v12, t2, v4, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v24, t2, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v24, t2, v28, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v16, t2, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v24, t2, v8, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v16, t2, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v24, t2, v8, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v24, t2, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v24, t2, v16, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v16, t2, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v24, t2, v8, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v8, t2, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v8, t2, v24, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v24, t2, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v16, t2, v24, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v16, t2, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v8, t2, v24, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v24, t2, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v24, t2, v8, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v16, t2, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v16, t2, v8, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v24, t2, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v24, t2, v8, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v31, t2, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v27, t2, v22, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v17, t2, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v16, t2, v5, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v31, t2, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v3, t2, v13, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v25, t2, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v6, t2, v3, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v17, t2, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v15, t2, v27, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v20, t2, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v25, t2, v3, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v23, t2, v9

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v19, t2, v1, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v23, t2, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v26, t2, v29, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v4, t2, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v1, t2, v21, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v1, t2, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v23, t2, v13, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v22, t2, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v6, t2, v2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v14, t2, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v16, t2, v30, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v8, t2, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v4, t2, v6, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v20, t2, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v20, t2, v10, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v22, t2, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v6, t2, v2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v30, t2, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v8, t2, v14, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v26, t2, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v22, t2, v26, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v6, t2, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v26, t2, v16, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v30, t2, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v28, t2, v6, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v12, t2, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v24, t2, v26, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v16, t2, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v8, t2, v24, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v12, t2, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v28, t2, v12, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v24, t2, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v4, t2, v12, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v4, t2, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v8, t2, v24, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v4, t2, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v16, t2, v4, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v16, t2, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v12, t2, v4, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v20, t2, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v24, t2, v20, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v24, t2, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v4, t2, v20, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v20, t2, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v20, t2, v28, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v20, t2, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v24, t2, v8, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v8, t2, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v16, t2, v8, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v24, t2, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v24, t2, v16, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v24, t2, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v16, t2, v8, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v8, t2, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v24, t2, v8, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v8, t2, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v24, t2, v16, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v16, t2, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v8, t2, v16, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v16, t2, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v8, t2, v24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v24, t2, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v8, t2, v16, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v24, t2, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v8, t2, v24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v8, t2, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v24, t2, v8, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v18, t2, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v18, t2, v4, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v27, t2, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v24, t2, v28, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v27, t2, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v10, t2, v30, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v16, t2, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v5, t2, v22, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v6, t2, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v29, t2, v3, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v22, t2, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v23, t2, v30, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v24, t2, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v6, t2, v22, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v12, t2, v25

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v22, t2, v11, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v7, t2, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v18, t2, v8, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v13, t2, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v26, t2, v20, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v22, t2, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v12, t2, v10, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v10, t2, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v8, t2, v6, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v22, t2, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v20, t2, v2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v12, t2, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v6, t2, v12, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v24, t2, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v10, t2, v24, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v12, t2, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v2, t2, v30, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v16, t2, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v30, t2, v10, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v18, t2, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v18, t2, v26, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v28, t2, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v26, t2, v24, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v28, t2, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v28, t2, v10, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v12, t2, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v8, t2, v28, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v4, t2, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v12, t2, v20, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v28, t2, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v24, t2, v12, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v16, t2, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v20, t2, v24, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v20, t2, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v12, t2, v4, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v24, t2, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v16, t2, v8, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v4, t2, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v16, t2, v8, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v8, t2, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v4, t2, v8, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v4, t2, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v4, t2, v8, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v24, t2, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v24, t2, v20, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v16, t2, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v24, t2, v16, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v16, t2, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v8, t2, v24, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v24, t2, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v24, t2, v16, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v24, t2, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v16, t2, v24, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v16, t2, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v16, t2, v24, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v16, t2, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v8, t2, v16, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v8, t2, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v24, t2, v16, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v24, t2, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v8, t2, v24, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v16, t2, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v16, t2, v8, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v24, t2, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v8, t2, v24, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v25, t2, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v22, t2, v2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v28, t2, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v26, t2, v31, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v10, t2, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v10, t2, v21, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v26, t2, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v21, t2, v5, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v3, t2, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v14, t2, v9, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v9, t2, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v5, t2, v13, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v5, t2, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v19, t2, v10, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v10, t2, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v7, t2, v23, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v23, t2, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v4, t2, v13, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v11, t2, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v6, t2, v30, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v16, t2, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v30, t2, v8, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v22, t2, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v26, t2, v8, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v16, t2, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v6, t2, v20, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v14, t2, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v16, t2, v26, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v18, t2, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v6, t2, v30, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v8, t2, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v2, t2, v28, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v14, t2, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v14, t2, v4, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v16, t2, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v28, t2, v10, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v24, t2, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v28, t2, v14, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v16, t2, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v4, t2, v22, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v12, t2, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v8, t2, v28, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v4, t2, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v12, t2, v8, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v12, t2, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v24, t2, v4, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v4, t2, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v28, t2, v4, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v16, t2, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v12, t2, v16, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v16, t2, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v28, t2, v12, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v12, t2, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v16, t2, v24, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v24, t2, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v28, t2, v4, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v16, t2, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v8, t2, v20, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v28, t2, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v28, t2, v24, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v16, t2, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v8, t2, v16, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v16, t2, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v16, t2, v8, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v8, t2, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v16, t2, v8, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v8, t2, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v16, t2, v24, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v16, t2, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v16, t2, v24, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v16, t2, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v8, t2, v24, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v16, t2, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v16, t2, v8, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v24, t2, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v8, t2, v24, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v8, t2, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v24, t2, v8, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v8, t2, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v8, t2, v24, v0.t

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
