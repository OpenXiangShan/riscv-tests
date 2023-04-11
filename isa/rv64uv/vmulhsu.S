#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v11, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v18, v16, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v23, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v19, v17, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v20, v3, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v9, v21, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v14, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v30, v8, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v26, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v27, v5, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v3, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v1, v25, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v6, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v4, v15, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v16, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v21, v14, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v6, v23, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v15, v7, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v20, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v8, v12, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v16, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v16, v22, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v6, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v30, v24, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v12, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v4, v26, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v6, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v20, v28, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v10, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v20, v6, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v16, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v16, v2, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v26, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v18, v12, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v8, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v30, v10, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v26, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v22, v18, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v20, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v18, v26, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v4, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v12, v28, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v12, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v20, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v24, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v12, v20, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v16, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v4, v16, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v28, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v16, v28, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v16, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v8, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v4, v8, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v12, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v12, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v28, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v25, v9, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v10, v23, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v26, v29, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v15, v5, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v24, v5, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v3, v26, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v13, v17, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v18, v13, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v14, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v14, v7, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v16, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v10, v2, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v19, v29, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v28, v24, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v26, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v31, v17, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v26, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v7, v24, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v2, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v3, v21, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v10, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v8, v26, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v30, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v12, v4, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v26, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v2, v26, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v24, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v26, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v6, v12, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v22, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v28, v4, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v20, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v6, v10, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v10, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v26, v30, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v8, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v18, v6, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v6, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v26, v12, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v16, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v16, v12, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v8, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v20, v8, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v24, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v16, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v24, v12, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v8, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v20, v8, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v8, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v28, v20, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v8, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v12, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v16, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v4, v24, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v20, v28, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v12, v2, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v5, v16, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v9, v30, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v21, v24, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v11, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v23, v31, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v28, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v28, v13, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v27, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v23, v25, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v19, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v27, v18, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v9, v14, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v4, v15, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v23, v28, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v30, v21, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v25, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v23, v5, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v15, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v19, v5, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v18, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v2, v14, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v24, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v24, v12, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v28, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v14, v20, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v28, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v4, v18, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v28, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v6, v4, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v10, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v2, v24, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v20, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v6, v16, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v14, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v18, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v4, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v12, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v22, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v4, v24, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v16, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v20, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v20, v24, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v20, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v28, v8, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v28, v20, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v16, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v4, v16, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v24, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v24, v28, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v20, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v24, v20, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v28, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v28, v12, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v20, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v28, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v15, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v25, v21, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v17, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v22, v3, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v26, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v3, v12, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v18, v9, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v12, v24, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v30, v14, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v29, v18, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v10, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v2, v25, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v7, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v14, v1, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v12, v29, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v4, v29, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v14, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v20, v13, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v19, v13, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v3, v6, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v30, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v10, v8, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v10, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v24, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v10, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v28, v20, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v28, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v14, v20, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v22, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v22, v30, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v24, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v8, v12, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v10, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v2, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v2, v8, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v20, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v10, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v22, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v8, v18, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v12, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v8, v12, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v4, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v12, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v20, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v12, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v24, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v4, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v4, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v28, v4, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v24, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v24, v12, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v28, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v20, v8, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v12, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v28, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v8, t2, v0.t

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
