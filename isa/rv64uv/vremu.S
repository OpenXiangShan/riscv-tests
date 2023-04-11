#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v23, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v7, v11, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v16, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v30, v7, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v22, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v5, v16, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v6, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v23, v10, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v6, v23, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v22, v10, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v15, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v24, v21, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v1, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v8, v20, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v11, v15, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v18, v11, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v21, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v17, v14, t2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v12, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v14, v7, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v26, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v28, v30, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v16, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v16, v2, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v22, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v2, v28, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v28, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v16, v14, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v2, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v30, v16, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v14, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v8, v18, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v12, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v18, v8, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v4, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v20, v18, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v6, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v14, v28, t2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v20, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v4, v6, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v20, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v24, v20, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v24, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v8, v4, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v4, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v28, v16, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v4, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v28, v16, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v20, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v24, v28, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v8, v28, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v4, v20, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v20, v16, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v16, v4, t2, v0.t

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v20, v12, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v24, v30, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v23, v17, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v7, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v15, v26, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v20, v5, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v16, v19, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v17, v29, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v8, v19, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v4, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v21, v15, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v28, v31, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v12, v20, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v20, v6, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v10, v8, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v22, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v6, v13, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v26, v5, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v9, v18, t2, v0.t

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v21, v3, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v29, v22, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v8, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v2, v4, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v20, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v8, v26, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v30, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v28, v8, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v18, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v2, v30, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v26, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v14, v18, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v12, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v16, v18, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v30, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v22, v20, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v2, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v28, v22, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v12, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v22, v2, t2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v14, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v2, v12, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v8, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v24, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v28, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v16, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v20, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v20, v24, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v20, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v8, v28, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v28, v24, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v20, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v24, v12, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v20, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v4, v20, t2, v0.t

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v28, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v28, v4, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v23, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v25, v7, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v14, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v17, v18, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v30, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v13, v10, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v24, v28, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v8, v26, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v14, v15, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v16, v14, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v31, v27, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v6, v12, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v22, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v26, v1, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v5, v3, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v3, v10, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v18, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v17, v2, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v20, v28, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v11, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v26, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v26, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v2, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v20, v4, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v30, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v26, v10, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v26, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v16, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v20, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v16, v14, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v16, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v26, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v20, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v10, v20, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v12, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v20, v14, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v6, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v8, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v6, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v6, v26, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v24, v28, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v12, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v20, v24, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v24, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v24, v20, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v12, v16, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v28, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v8, v4, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v20, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v8, v4, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v28, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v8, v28, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v16, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v4, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v13, v28, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v14, v7, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v30, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v19, v28, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v6, v10, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v4, v9, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v16, v29, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v19, v13, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v21, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v20, v25, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v6, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v25, v18, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v19, v3, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v11, v25, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v14, v13, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v24, v1, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v15, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v5, v26, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v8, v26, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v13, v4, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v14, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v12, v20, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v18, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v28, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v16, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v12, v18, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v14, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v28, v16, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v4, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v12, v18, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v24, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v2, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v12, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v6, v18, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v10, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v28, v24, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v2, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v14, v26, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v18, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v18, v4, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v28, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v4, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v28, v8, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v24, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v12, v20, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v20, v24, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v20, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v28, v20, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v28, v12, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v8, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v12, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v16, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v4, v28, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v24, v8, t2, v0.t

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
