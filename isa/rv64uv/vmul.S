#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v29, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v11, v4, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v12, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v31, v24, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v30, v26, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v1, v22, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v2, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v18, v22, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v25, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v21, v4, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v31, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v24, v14, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v10, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v17, v11, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v12, v27, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v22, v2, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v5, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v7, v2, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v27, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v9, v13, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v14, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v2, v4, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v10, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v8, v6, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v30, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v12, v10, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v16, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v24, v20, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v30, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v26, v28, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v28, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v2, v16, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v22, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v16, v6, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v12, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v28, v2, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v28, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v12, v10, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v30, v6, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v12, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v12, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v28, v12, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v16, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v20, v8, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v20, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v28, v20, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v24, v20, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v4, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v20, v4, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v24, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v24, v20, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v16, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v24, v28, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v16, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v16, v12, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v4, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v16, v28, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v28, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v30, v24, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v18, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v6, v19, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v31, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v22, v5, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v26, v5, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v8, v15, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v18, v1, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v19, v7, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v9, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v3, v16, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v19, v12, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v9, v8, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v8, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v20, v3, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v20, v7, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v23, v10, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v2, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v24, v27, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v20, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v26, v20, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v30, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v14, v22, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v24, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v18, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v4, v10, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v6, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v10, v14, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v22, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v22, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v30, v10, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v30, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v26, v2, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v2, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v16, v12, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v24, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v10, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v12, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v8, v20, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v20, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v4, v12, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v8, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v20, v24, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v24, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v28, v16, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v28, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v8, v4, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v8, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v4, v24, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v8, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v12, v8, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v24, v20, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v20, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v8, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v8, v20, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v26, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v12, v6, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v18, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v28, v30, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v4, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v10, v28, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v9, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v27, v7, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v19, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v19, v27, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v30, v22, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v8, v22, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v22, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v15, v4, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v27, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v23, v4, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v24, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v25, v3, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v2, v15, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v30, v21, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v26, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v22, v10, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v2, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v28, v14, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v18, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v12, v4, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v12, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v2, v18, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v20, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v16, v26, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v22, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v8, v12, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v26, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v8, v6, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v12, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v16, v10, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v2, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v10, v30, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v20, v4, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v24, v12, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v20, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v20, v12, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v16, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v12, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v8, v12, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v4, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v4, v16, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v20, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v12, v28, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v16, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v28, v8, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v20, v12, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v16, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v8, v4, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v28, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v4, v22, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v14, v4, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v26, v23, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v9, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v4, v7, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v25, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v5, v9, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v21, v7, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v23, v25, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v22, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v12, v26, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v2, v5, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v29, v12, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v31, v9, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v12, v19, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v18, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v5, v20, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v22, v5, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v1, v24, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v22, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v14, v22, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v10, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v6, v18, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v22, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v26, v20, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v10, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v6, v16, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v24, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v14, v18, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v28, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v22, v6, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v12, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v24, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v24, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v30, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v8, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v4, v16, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v14, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v2, v26, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v20, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v20, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v24, v4, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v12, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v20, v12, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v20, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v12, v4, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v28, v4, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v24, v28, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v28, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v4, v8, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v20, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v20, v8, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v24, v12, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v24, v16, t2, v0.t

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
