#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v16, v27, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v4, v24, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v2, v7, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v17, v16, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v1, v6, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v17, v22, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v9, v14, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v12, v27, v7

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v19, v13, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v16, v31, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v30, v18, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v12, v24, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v22, v10, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v8, v10, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v30, v18, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v28, v12, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v30, v16, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v30, v24, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v20, v18, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v18, v20, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v20, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v8, v20, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v20, v16, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v12, v24, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v8, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v8, v20, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v20, v16, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v16, v8, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v20, v8, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v20, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v22, v29, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v24, v18, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v2, v25, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v9, v16, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v12, v8, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v27, v15, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v26, v17, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v3, v12, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v1, v14, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v19, v28, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v10, v22, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v14, v26, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v10, v8, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v16, v6, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v24, v12, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v4, v28, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v12, v6, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v8, v4, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v16, v14, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v12, v18, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v20, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v16, v8, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v28, v20, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v16, v20, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v20, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v28, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v24, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v24, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v8, v12, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v28, v20, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v16, v8, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v16, v26, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v17, v8, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v3, v8, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v9, v25, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v4, v15, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v3, v23, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v13, v15, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v18, v29, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v14, v7, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v12, v24, v25

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v6, v10, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v8, v30, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v18, v16, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v14, v20, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v10, v4, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v22, v26, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v28, v24, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v26, v22, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v6, v10, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v12, v24, v10

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v20, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v16, v12, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v24, v28, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v8, v24, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v8, v20, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v28, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v24, v20, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v20, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v12, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v16, v20, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v16, v8, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v4, v14, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v30, v22, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v31, v19, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v11, v23, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v29, v16, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v18, v12, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v22, v7, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v30, v7, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v6, v8, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v23, v29, v27

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v24, v2, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v24, v14, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v18, v14, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v12, v30, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v28, v24, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v30, v24, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v28, v26, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v6, v26, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v16, v26, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v8, v18, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v16, v4, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v8, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v28, v16, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v8, v4, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v24, v20, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v16, v4, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v4, v20, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v24, v28, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v8, v24, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v20, v12, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v23, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v24, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v5, v27, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v6, v13, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v8, v26, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v27, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v9, v10, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v18, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v23, v15, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v16, v15, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v20, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v26, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v10, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v8, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v10, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v30, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v16, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v26, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v16, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v16, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v28, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v4, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v12, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v20, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v4, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v12, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v4, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v28, v4, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v27, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v1, v23, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v3, v26, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v16, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v30, v18, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v9, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v6, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v20, v30, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v18, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v22, v19, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v28, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v28, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v8, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v24, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v24, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v26, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v4, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v22, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v14, v22, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v16, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v28, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v12, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v28, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v28, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v24, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v24, v12, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v16, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v27, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v30, v2, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v14, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v6, v27, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v2, v1, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v11, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v10, v29, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v31, v1, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v18, v14, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v16, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v20, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v20, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v22, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v12, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v28, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v30, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v14, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v24, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v30, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v10, v6, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v4, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v12, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v20, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v4, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v28, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v12, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v8, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v16, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v4, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v16, v28, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v16, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v18, v26, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v12, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v7, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v12, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v1, v3, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v8, v5, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v20, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v19, v17, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v18, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v30, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v2, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v28, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v28, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v30, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v16, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v28, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v8, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v18, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v30, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v26, v6, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v20, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v20, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v20, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v12, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v12, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v28, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v4, v20, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v16, v8, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
