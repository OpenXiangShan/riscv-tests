#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v24, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v26, v14, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v16, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v23, v21, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v2, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v27, v29, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v24, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v21, v13, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v4, v14, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v8, v11, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v13, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v12, v18, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v27, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v17, v25, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v4, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v27, v30, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v16, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v7, v18, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v8, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v23, v14, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v28, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v8, v28, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v2, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v24, v18, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v2, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v28, v14, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v4, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v14, v20, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v22, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v20, v24, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v14, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v24, v14, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v14, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v6, v10, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v20, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v6, v14, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v16, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v16, v30, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v30, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v24, v18, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v28, v20, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v28, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v20, v12, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v24, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v12, v24, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v20, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v12, v8, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v24, v4, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v28, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v8, v28, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v28, v20, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v20, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v4, v28, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v28, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v12, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v24, v5, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v21, v15, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v16, v10, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v31, v10, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v20, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v21, v29, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v24, v13, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v22, v24, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v24, v13, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v27, v2, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v1, v9, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v13, v8, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v31, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v23, v9, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v27, v26, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v6, v2, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v1, v13, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v6, v11, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v31, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v5, v30, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v6, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v2, v10, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v2, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v16, v14, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v8, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v4, v30, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v16, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v2, v24, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v18, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v22, v12, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v26, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v18, v20, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v20, v24, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v12, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v10, v26, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v22, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v20, v2, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v12, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v26, v18, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v20, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v8, v12, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v8, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v8, v4, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v12, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v24, v12, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v28, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v12, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v16, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v20, v4, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v28, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v16, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v8, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v12, v4, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v12, v16, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v8, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v24, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v24, v20, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v15, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v27, v19, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v2, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v16, v9, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v22, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v5, v6, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v21, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v19, v6, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v13, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v9, v27, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v28, v15, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v10, v5, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v30, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v27, v1, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v11, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v19, v6, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v4, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v8, v13, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v16, v2, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v12, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v4, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v24, v4, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v10, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v12, v4, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v18, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v20, v30, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v24, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v6, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v10, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v22, v12, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v2, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v2, v6, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v8, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v28, v6, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v12, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v24, v6, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v14, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v22, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v30, v22, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v20, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v4, v8, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v4, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v20, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v20, v4, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v28, v24, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v4, v12, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v16, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v24, v12, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v8, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v4, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v4, v16, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v12, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v24, v28, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v16, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v28, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v19, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v11, v29, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v2, v25, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v10, v23, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v27, v6, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v20, v17, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v16, v23, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v25, v20, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v22, v10, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v8, v13, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v10, v29, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v25, v4, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v17, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v25, v22, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v12, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v10, v24, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v15, v2, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v4, v7, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v28, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v12, v5, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v28, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v2, v12, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v22, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v12, v18, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v28, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v14, v26, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v6, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v26, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v22, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v30, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v20, v26, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v28, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v22, v2, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v4, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v8, v6, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v6, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v2, v26, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v14, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v4, v14, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v8, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v4, v16, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v4, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v8, v20, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v28, v20, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v4, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v4, v28, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v8, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v24, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v16, v12, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v4, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v4, v20, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v20, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v8, v4, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v28, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v16, v4, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v24, v16, t2, v0.t

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
