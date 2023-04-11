#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v17, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v16, v1, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v29, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v14, v9, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v5, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v3, v5, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v24, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v29, v17, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v31, v15, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v21, v20, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v3, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v28, v3, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v30, v13, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v25, v4, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v1, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v10, v30, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v19, v1, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v20, v28, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v1, v30, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v4, v31, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v4, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v22, v16, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v30, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v28, v26, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v20, v10, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v24, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v26, v4, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v20, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v18, v24, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v10, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v16, v30, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v20, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v10, v14, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v14, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v8, v14, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v14, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v10, v24, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v10, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v14, v8, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v16, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v16, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v16, v12, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v4, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v12, v24, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v4, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v20, v4, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v20, v4, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v12, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v4, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v4, v24, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v4, v24, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v28, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v24, v12, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v12, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v23, v12, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v17, v24, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v31, v10, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v6, v13, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v21, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v12, v21, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v12, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v12, v14, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v5, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v30, v9, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v1, v12, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v20, v18, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v18, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v3, v18, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v1, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v30, v31, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v27, v1, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v15, v11, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v17, v26, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v7, v28, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v18, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v4, v24, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v18, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v6, v18, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v12, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v6, v20, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v12, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v22, v14, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v28, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v18, v22, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v22, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v6, v20, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v18, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v4, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v20, v2, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v18, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v12, v4, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v20, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v24, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v20, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v20, v8, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v8, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v20, v12, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v16, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v20, v12, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v20, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v28, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v24, v20, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v4, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v20, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v4, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v4, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v12, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v28, v12, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v2, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v1, v29, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v23, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v7, v23, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v19, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v3, v8, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v2, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v13, v26, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v12, v15, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v26, v28, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v28, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v10, v17, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v10, v19, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v15, v4, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v10, v19, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v12, v28, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v16, v25, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v11, v20, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v10, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v4, v2, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v30, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v16, v18, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v24, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v16, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v20, v30, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v30, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v24, v14, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v22, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v18, v4, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v6, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v26, v10, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v4, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v6, v2, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v22, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v14, v8, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v16, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v26, v2, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v22, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v2, v4, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v4, v28, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v8, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v4, v12, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v24, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v16, v28, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v20, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v20, v24, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v20, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v20, v28, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v20, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v24, v20, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v8, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v24, v12, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v8, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v8, v28, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v8, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v16, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v4, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v1, v14, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v25, v24, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v26, v3, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v11, v29, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v12, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v28, v5, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v22, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v19, v9, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v3, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v23, v16, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v14, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v24, v11, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v16, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v1, v16, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v14, v11, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v21, v1, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v14, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v16, v18, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v9, v13, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v31, v12, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v8, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v28, v30, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v24, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v14, v28, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v2, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v4, v28, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v14, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v8, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v30, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v18, v4, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v16, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v8, v6, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v26, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v22, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v24, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v26, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v6, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v22, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v24, v4, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v8, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v8, v20, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v28, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v12, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v8, v4, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v12, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v4, v16, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v8, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v24, v28, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v4, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v8, v12, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v24, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v16, v28, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v4, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v12, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v24, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v20, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v24, v16, t2, v0.t

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
