#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v26, v14, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v31, v26, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v4, v19, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v8, v20, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v8, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v28, v26, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v15, v13, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v4, v3, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v27, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v22, v28, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v18, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v9, v14, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v2, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v28, v16, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v5, v13, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v13, v3, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v3, v30, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v1, v7, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v19, v2, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v12, v26, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v28, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v20, v28, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v30, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v12, v20, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v20, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v4, v6, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v4, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v8, v10, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v22, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v22, v24, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v20, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v28, v16, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v4, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v12, v30, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v30, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v30, v22, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v10, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v22, v16, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v20, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v26, v10, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v20, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v20, v28, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v24, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v20, v24, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v4, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v4, v12, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v16, v28, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v28, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v12, v20, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v28, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v24, v4, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v16, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v20, v8, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v12, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v8, v28, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v24, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v16, v28, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v27, v31, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v3, v2, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v21, v27, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v31, v22, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v24, v6, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v12, v10, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v20, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v25, v28, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v12, v3, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v1, v2, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v18, v12, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v19, v10, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v21, v12, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v27, v21, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v24, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v8, v7, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v22, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v19, v9, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v30, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v5, v4, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v10, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v26, v14, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v4, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v12, v14, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v28, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v6, v30, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v8, v22, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v12, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v2, v18, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v2, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v28, v18, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v12, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v2, v12, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v30, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v6, v22, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v30, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v8, v26, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v20, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v20, v12, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v8, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v4, v24, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v24, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v28, v24, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v16, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v20, v12, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v28, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v4, v24, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v24, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v24, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v20, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v4, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v4, v8, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v4, v8, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v4, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v24, v4, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v22, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v8, v14, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v29, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v21, v25, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v9, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v26, v15, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v20, v30, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v3, v15, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v9, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v27, v28, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v3, v14, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v16, v3, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v19, v11, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v30, v25, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v9, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v18, v1, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v2, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v5, v31, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v18, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v26, v4, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v22, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v8, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v6, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v24, v14, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v6, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v6, v24, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v24, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v18, v16, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v26, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v18, v30, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v14, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v4, v8, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v18, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v18, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v24, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v30, v24, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v8, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v4, v8, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v20, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v14, v8, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v8, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v28, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v20, v24, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v4, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v16, v28, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v28, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v16, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v24, v12, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v12, v16, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v20, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v24, v12, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v4, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v12, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v28, v12, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v4, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v20, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v10, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v24, v5, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v27, v12, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v2, v29, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v27, v4, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v31, v11, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v18, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v16, v5, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v19, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v2, v8, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v7, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v20, v19, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v17, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v6, v20, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v1, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v11, v16, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v22, v28, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v8, v30, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v24, v17, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v27, v22, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v4, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v28, v2, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v8, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v10, v12, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v22, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v2, v6, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v8, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v2, v30, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v26, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v4, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v2, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v10, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v2, v22, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v24, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v26, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v6, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v26, v28, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v18, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v18, v28, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v12, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v4, v20, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v28, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v28, v16, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v4, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v20, v4, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v4, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v20, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v16, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v4, v20, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v4, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v8, v4, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v12, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v4, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v12, v28, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v28, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v12, v4, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v12, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v24, v16, t2, v0.t

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
