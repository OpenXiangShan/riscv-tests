#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v7, v20, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v21, v19, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v31, v29, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v29, v11, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v27, v28, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v13, v1, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v17, v29, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v27, v25, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v27, v28, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v14, v19, v29

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v12, v2, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v2, v20, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v18, v2, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v18, v12, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v28, v6, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v24, v4, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v26, v20, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v6, v18, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v2, v24, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v12, v24, v14

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v24, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v16, v4, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v16, v12, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v12, v28, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v20, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v12, v8, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v24, v12, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v12, v4, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v12, v20, v28

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v8, v24, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v4, v29, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v29, v5, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v10, v6, v27

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v14, v3, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v10, v31, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v5, v11, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v27, v13, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v12, v6, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v4, v12, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v13, v2, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v28, v22, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v16, v8, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v4, v10, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v10, v2, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v6, v20, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v8, v2, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v30, v14, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v14, v2, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v10, v18, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v6, v30, v2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v12, v4, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v8, v28, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v12, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v4, v24, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v24, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v4, v28, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v8, v20, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v16, v24, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v4, v16, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v16, v4, v20

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v15, v27, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v19, v6, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v24, v29, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v1, v27, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v2, v15, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v7, v18, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v4, v30, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v9, v17, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v6, v9, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v22, v12, v15

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v24, v8, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v30, v2, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v2, v4, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v18, v14, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v8, v20, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v6, v14, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v28, v24, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v20, v18, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v10, v14, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v14, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v4, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v4, v20, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v16, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v4, v24, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v12, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v28, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v16, v8, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v12, v28, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v4, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v4, v24, v28

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v24, v16, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v1, v15, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v16, v5, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v26, v29, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v28, v31, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v27, v17, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v31, v28, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v29, v25, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v19, v14, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v27, v12, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v19, v8, v15

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v20, v18, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v22, v10, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v12, v28, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v10, v28, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v30, v24, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v2, v4, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v18, v26, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v26, v2, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v22, v18, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v2, v10, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v24, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v8, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v16, v4, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v8, v12, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v28, v4, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v20, v12, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v12, v28, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v20, v4, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v28, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v24, v8, v20

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v11, v15, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v9, v10, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v6, v27, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v31, v27, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v19, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v28, v14, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v4, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v17, v10, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v19, v26, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v26, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v30, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v14, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v20, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v26, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v28, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v10, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v12, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v24, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v8, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v10, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v8, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v4, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v24, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v24, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v4, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v8, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v20, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v28, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v24, v20, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v13, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v26, v13, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v22, v30, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v13, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v2, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v18, v13, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v10, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v8, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v29, v3, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v25, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v2, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v8, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v2, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v4, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v6, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v18, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v8, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v12, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v2, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v10, v22, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v20, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v8, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v16, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v12, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v24, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v8, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v8, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v20, v28, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v17, v11, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v20, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v31, v19, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v17, v30, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v10, v31, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v7, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v10, v22, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v4, v25, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v26, v29, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v7, v9, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v12, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v8, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v18, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v10, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v20, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v14, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v10, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v18, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v30, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v16, v30, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v12, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v28, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v20, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v4, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v20, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v20, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v16, v28, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v8, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v13, v2, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v3, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v11, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v12, v15, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v6, v13, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v30, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v2, v22, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v29, v4, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v29, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v1, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v16, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v20, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v2, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v26, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v2, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v18, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v14, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v18, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v16, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v14, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v28, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v28, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v20, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v16, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v16, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v4, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v28, v20, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v8, v24, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
