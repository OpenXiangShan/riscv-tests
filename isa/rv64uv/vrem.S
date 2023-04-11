#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v9, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v5, v15, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v16, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v25, v29, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v15, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v26, v21, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v16, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v21, v10, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v18, v10, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v4, v24, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v5, v23, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v10, v6, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v7, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v19, v23, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v20, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v30, v2, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v10, v3, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v1, v22, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v24, v19, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v4, v28, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v24, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v12, v6, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v2, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v26, v22, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v6, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v16, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v22, v18, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v10, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v24, v12, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v6, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v12, v8, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v8, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v4, v28, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v20, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v8, v10, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v12, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v8, v22, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v18, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v10, v8, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v28, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v20, v24, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v24, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v8, v12, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v8, v28, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v20, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v16, v4, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v16, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v12, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v4, v24, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v12, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v16, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v24, v28, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v28, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v16, v28, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v15, v17, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v21, v5, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v23, v31, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v23, v2, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v7, v27, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v10, v16, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v23, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v28, v19, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v16, v1, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v26, v27, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v31, v17, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v28, v26, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v29, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v10, v31, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v6, v9, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v19, v25, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v30, v12, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v3, v30, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v31, v3, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v28, v20, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v14, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v20, v14, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v26, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v4, v16, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v24, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v14, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v14, v4, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v16, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v16, v28, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v12, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v6, v14, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v20, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v30, v28, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v16, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v4, v10, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v22, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v14, v2, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v12, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v26, v12, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v28, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v28, v24, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v28, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v24, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v12, v16, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v20, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v4, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v16, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v4, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v28, v4, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v28, v4, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v12, v24, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v24, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v28, v20, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v21, v19, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v3, v4, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v11, v27, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v30, v26, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v20, v26, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v11, v26, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v27, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v22, v28, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v16, v15, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v14, v28, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v29, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v27, v22, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v24, v31, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v4, v26, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v11, v3, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v30, v10, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v20, v1, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v14, v25, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v9, v30, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v3, v15, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v10, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v20, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v30, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v10, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v4, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v20, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v22, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v22, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v14, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v24, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v20, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v8, v12, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v24, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v22, v6, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v28, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v20, v6, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v24, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v24, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v24, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v28, v2, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v16, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v28, v8, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v12, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v4, v28, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v28, v8, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v12, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v8, v4, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v8, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v28, v24, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v12, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v12, v16, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v12, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v20, v8, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v4, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v16, v28, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v24, v20, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v3, v10, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v2, v5, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v5, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v17, v9, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v6, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v24, v13, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v28, v15, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v10, v27, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v15, v5, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v25, v6, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v17, v5, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v25, v6, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v8, v5, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v17, v30, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v1, v11, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v6, v8, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v11, v26, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v17, v19, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v16, v13, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v25, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v28, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v26, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v20, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v10, v20, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v14, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v10, v26, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v28, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v18, v20, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v6, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v22, v12, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v12, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v16, v12, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v6, v4, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v24, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v30, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v12, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v2, v6, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v14, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v26, v22, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v4, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v20, v8, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v12, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v4, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v12, v28, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v12, v4, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v8, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v8, v4, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v4, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v4, v16, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v28, v8, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v16, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v12, v4, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v4, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v4, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v24, v4, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v16, t2, v0.t

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
