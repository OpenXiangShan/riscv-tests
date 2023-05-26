#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v3, v9, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v17, v7, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v23, v19, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v21, v18, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v24, v15, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v17, v9, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v14, v22, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v29, v14, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v27, v13, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v13, v20, v17

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v8, v20, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v14, v28, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v30, v12, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v28, v20, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v16, v12, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v24, v4, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v8, v2, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v18, v28, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v2, v28, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v8, v28, v18

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v24, v4, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v24, v28, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v16, v12, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v12, v8, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v4, v20, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v28, v12, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v16, v20, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v28, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v20, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v12, v16, v28

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v10, v26, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v13, v28, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v21, v7, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v3, v21, v27

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v21, v7, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v29, v8, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v8, v4, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v18, v30, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v25, v31, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v30, v7, v3

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v14, v12, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v16, v6, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v16, v10, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v22, v18, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v8, v30, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v18, v30, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v26, v6, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v30, v18, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v2, v18, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v22, v8, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v4, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v28, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v4, v12, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v20, v8, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v16, v24, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v24, v20, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v8, v28, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v16, v8, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v24, v4, v20

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v8, v24, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v14, v29, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v16, v4, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v20, v14, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v10, v9, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v5, v3, v31

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v8, v3, v17

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v31, v1, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v8, v15, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v22, v1, v31

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v29, v19, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v16, v20, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v12, v10, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v22, v16, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v26, v30, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v16, v24, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v14, v26, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v16, v26, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v12, v30, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v6, v4, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v22, v20, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v12, v20, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v8, v4, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v16, v12, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v16, v12, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v24, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v16, v28, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v20, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v28, v20, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v20, v28, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v28, v20, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v16, v24, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v24, v6, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v14, v11, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v4, v9, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v5, v25, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v22, v6, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v28, v10, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v27, v23, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v24, v7, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v15, v31, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v2, v22, v7

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v28, v4, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v20, v10, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v8, v26, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v30, v6, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v12, v16, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v8, v20, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v22, v18, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v12, v24, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v6, v22, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v2, v22, v6

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v20, v16, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v8, v12, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v24, v20, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v28, v12, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v24, v12, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v24, v28, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v8, v12, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v12, v24, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v12, v4, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v24, v8, v4

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v24, v16, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v11, v24, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v13, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v22, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v9, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v9, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v10, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v10, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v14, v24, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v27, v3, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v30, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v28, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v28, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v22, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v22, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v2, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v18, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v22, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v26, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v24, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v12, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v12, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v20, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v28, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v20, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v16, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v28, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v8, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v19, v9, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v29, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v2, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v5, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v4, v10, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v21, v27, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v2, v10, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v7, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v23, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v19, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v6, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v2, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v20, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v8, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v12, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v4, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v4, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v14, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v4, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v8, v14, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v8, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v28, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v8, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v12, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v12, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v12, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v16, v28, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v23, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v20, v2, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v7, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v14, v28, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v13, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v11, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v6, v14, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v28, v26, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v7, v23, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v30, v21, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v26, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v16, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v22, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v30, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v16, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v8, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v22, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v2, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v10, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v16, v2, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v4, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v12, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v28, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v8, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v24, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v4, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v8, v28, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v14, v10, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v5, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v31, v11, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v24, v14, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v17, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v28, v21, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v22, v12, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v2, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v6, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v24, v9, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v2, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v12, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v12, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v2, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v18, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v22, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v24, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v14, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v14, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v14, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v20, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v20, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v20, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v12, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v28, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v20, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v20, v28, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v24, v8, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
