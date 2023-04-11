#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v1, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v30, v5, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v16, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v3, v30, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v13, v2, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v25, v26, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v19, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v10, v4, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v13, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v15, v11, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v30, v3, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v17, v27, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v5, v13, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v11, v8, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v14, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v7, v4, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v21, v27, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v12, v2, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v28, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v12, v3, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v30, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v6, v22, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v6, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v4, v22, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v26, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v10, v16, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v20, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v14, v18, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v26, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v26, v4, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v4, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v2, v16, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v6, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v28, v20, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v10, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v12, v22, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v2, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v26, v20, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v4, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v4, v14, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v20, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v28, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v28, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v20, v16, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v8, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v28, v16, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v16, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v16, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v4, v20, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v28, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v12, v16, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v28, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v4, v16, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v12, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v28, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v25, v6, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v27, v14, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v22, v10, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v18, v4, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v30, v6, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v9, v17, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v28, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v8, v26, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v17, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v3, v13, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v11, v14, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v1, v2, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v26, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v29, v2, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v31, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v10, v11, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v5, v9, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v8, v1, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v21, v30, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v29, v17, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v20, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v12, v24, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v2, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v4, v2, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v22, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v2, v4, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v14, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v28, v4, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v12, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v18, v30, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v2, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v30, v2, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v2, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v18, v24, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v14, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v6, v24, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v12, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v12, v16, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v24, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v6, v24, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v4, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v4, v12, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v8, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v28, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v24, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v28, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v16, v4, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v28, v8, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v12, v24, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v20, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v28, v8, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v16, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v8, v12, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v20, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v8, v4, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v16, v14, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v19, v21, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v21, v19, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v2, v7, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v13, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v17, v14, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v4, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v29, v2, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v9, v27, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v4, v12, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v7, v30, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v25, v26, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v7, v1, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v24, v4, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v3, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v19, v6, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v8, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v20, v25, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v21, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v30, v10, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v26, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v8, v4, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v18, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v20, v16, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v24, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v12, v4, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v6, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v8, v14, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v2, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v6, v12, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v10, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v4, v8, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v8, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v30, v4, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v26, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v6, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v30, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v26, v14, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v6, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v26, v30, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v8, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v12, v8, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v16, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v12, v8, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v4, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v12, v20, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v20, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v16, v12, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v8, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v8, v12, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v24, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v20, v28, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v24, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v16, v28, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v12, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v8, v12, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v20, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v28, v8, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v8, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v23, v10, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v25, v26, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v31, v30, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v17, v10, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v2, v3, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v26, v6, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v15, v31, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v6, v17, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v12, v6, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v20, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v6, v18, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v14, v6, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v16, v10, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v1, v6, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v13, v11, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v13, v23, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v29, v17, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v1, v3, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v7, v16, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v4, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v4, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v12, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v8, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v18, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v18, v6, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v24, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v10, v26, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v24, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v30, v20, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v8, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v20, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v2, v6, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v4, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v8, v18, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v14, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v28, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v4, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v26, v2, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v20, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v4, v28, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v8, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v20, v8, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v4, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v28, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v12, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v8, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v8, v12, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v16, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v28, v20, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v28, v4, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v12, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v12, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v16, v24, t2, v0.t

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
