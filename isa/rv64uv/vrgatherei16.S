#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v26, v15, v7, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v16, v3, v23, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v21, v27, v8, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v13, v31, v26, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v28, v17, v5, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v31, v14, v30, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v25, v27, v19, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v2, v15, v4, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v26, v24, v27, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v19, v26, v6, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v12, v26, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v21, v26, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v11, v16, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v2, v29, v21

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v4, v12, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v21, v28, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v26, v23, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v4, v31, v7

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v11, v5, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v5, v4, v27

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v12, v10, v6, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v8, v26, v6, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v16, v30, v2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v14, v30, v20, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v12, v2, v18, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v8, v16, v12, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v22, v12, v20, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v10, v30, v16, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v14, v30, v12, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v18, v28, v20, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v18, v8, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v30, v22, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v26, v8, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v28, v4, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v22, v10, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v22, v4, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v16, v30, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v8, v6, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v18, v16, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vrgatherei16.vv v30, v6, v18

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v16, v20, v28, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v28, v20, v4, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v12, v4, v8, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v28, v8, v12, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v24, v16, v20, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v24, v16, v4, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v20, v16, v8, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v24, v16, v12, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v28, v24, v16, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v20, v28, v8, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v16, v12, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v28, v4, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v20, v24, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v28, v4, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v8, v20, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v4, v20, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v16, v4, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v8, v20, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v4, v16, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vrgatherei16.vv v28, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v24, v16, v8, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v16, v8, v24, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v16, v8, v24, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v24, v16, v8, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v24, v16, v8, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v24, v16, v8, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v16, v8, v24, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v24, v8, v16, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrgatherei16.vv v16, v8, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v23, v12, v22, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v13, v11, v24, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v15, v22, v29, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v15, v4, v18, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v13, v11, v30, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v1, v15, v29, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v3, v24, v30, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v19, v20, v5, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v4, v31, v14, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v21, v29, v10, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v17, v14, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v23, v8, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v27, v31, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v13, v19, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v10, v28, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v8, v13, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v22, v6, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v26, v9, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v28, v29, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v9, v27, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v4, v8, v10, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v6, v12, v22, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v4, v12, v24, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v14, v22, v18, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v10, v6, v12, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v24, v14, v22, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v12, v16, v4, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v20, v10, v26, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v2, v26, v14, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v30, v4, v20, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v24, v4, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v8, v16, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v16, v6, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v22, v12, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v4, v6, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v28, v30, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v26, v4, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v4, v30, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v14, v12, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vrgatherei16.vv v26, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v20, v12, v8, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v28, v4, v8, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v28, v12, v24, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v12, v24, v28, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v28, v12, v8, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v16, v28, v20, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v8, v12, v16, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v24, v16, v28, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v24, v8, v20, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v20, v4, v24, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v28, v24, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v4, v24, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v20, v24, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v4, v20, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v28, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v8, v28, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v20, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vrgatherei16.vv v12, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v24, v16, v8, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v8, v24, v16, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v16, v24, v8, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v16, v8, v24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v16, v8, v24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v16, v8, v24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v24, v8, v16, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v16, v8, v24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vrgatherei16.vv v24, v16, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v25, v7, v17, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v10, v1, v16, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v15, v1, v29, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v4, v31, v7, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v7, v2, v26, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v4, v19, v7, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v26, v4, v12, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v25, v12, v1, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v27, v3, v31, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v19, v28, v3, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v16, v27, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v18, v9, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v25, v11, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v27, v17, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v30, v3, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v23, v21, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v1, v6, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v17, v1, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v1, v19, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v24, v30, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v2, v26, v30, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v18, v8, v28, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v28, v18, v14, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v8, v6, v30, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v10, v18, v12, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v30, v12, v14, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v4, v10, v20, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v24, v12, v4, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v10, v18, v28, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v28, v16, v6, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v30, v28, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v12, v22, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v14, v30, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v20, v24, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v22, v2, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v26, v10, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v30, v24, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v18, v2, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v4, v14, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vrgatherei16.vv v8, v24, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v16, v12, v4, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v4, v20, v16, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v16, v28, v8, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v24, v8, v28, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v12, v28, v24, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v8, v16, v20, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v16, v24, v20, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v28, v8, v16, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v20, v12, v24, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v24, v28, v4, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v16, v20, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v4, v12, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v12, v8, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v16, v20, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v12, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v16, v4, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v28, v4, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v4, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v12, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vrgatherei16.vv v20, v12, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v24, v8, v16, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v24, v8, v16, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v24, v16, v8, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v24, v16, v8, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v8, v24, v16, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v24, v8, v16, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v24, v8, v16, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vrgatherei16.vv v24, v16, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v28, v19, v22, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v21, v9, v30, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v17, v25, v13, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v29, v7, v1, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v11, v17, v20, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v9, v16, v18, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v18, v27, v3, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v21, v16, v10, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v11, v6, v26, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v20, v25, v23, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v8, v16, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v5, v29, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v8, v18, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v27, v24, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v16, v9, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v15, v10, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v18, v30, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v30, v22, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v25, v12, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v7, v3, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v14, v30, v8, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v22, v6, v30, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v30, v28, v18, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v4, v18, v24, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v14, v24, v16, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v22, v4, v16, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v10, v20, v6, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v24, v18, v20, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v28, v18, v20, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v28, v2, v30, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v18, v8, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v6, v12, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v10, v24, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v12, v14, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v18, v30, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v22, v4, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v4, v16, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v26, v6, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v8, v18, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vrgatherei16.vv v24, v8, v22

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v12, v16, v4, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v28, v16, v4, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v4, v28, v8, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v8, v28, v20, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v4, v8, v24, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v28, v24, v20, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v28, v16, v24, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v4, v16, v28, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v12, v4, v28, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v12, v24, v20, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v20, v24, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v28, v20, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v12, v16, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v4, v28, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v12, v28, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v16, v12, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v16, v20, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v12, v4, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v16, v20, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vrgatherei16.vv v20, v28, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v8, v24, v16, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v16, v8, v24, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v24, v8, v16, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v16, v24, v8, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v16, v24, v8, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v24, v8, v16, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v16, v8, v24, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v8, v24, v16, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vrgatherei16.vv v24, v8, v16

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
