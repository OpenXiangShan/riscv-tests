#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v31, v30, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v23, v5, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v17, v8, v7

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v20, v1, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v3, v16, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v18, v1, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v17, v21, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v13, v16, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v3, v9, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v3, v28, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v18, v2, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v6, v30, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v16, v24, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v28, v18, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v14, v4, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v28, v22, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v8, v12, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v24, v20, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v12, v4, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v28, v2, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v20, v4, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v20, v4, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v28, v16, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v28, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v4, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v8, v4, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v20, v28, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v20, v8, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v20, v24, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v4, v28, v12

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v16, v24, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v19, v24, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v25, v24, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v29, v28, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v7, v12, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v9, v22, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v4, v25, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v14, v29, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v21, v18, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v21, v16, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v16, v11, v7

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v4, v8, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v18, v22, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v4, v10, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v2, v6, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v2, v28, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v14, v22, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v24, v12, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v12, v2, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v24, v8, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v24, v4, v18

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v12, v24, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v16, v24, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v4, v16, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v16, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v28, v8, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v8, v24, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v20, v8, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v4, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v28, v16, v4

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v8, v16, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v19, v11, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v20, v26, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v10, v23, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v24, v29, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v18, v12, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v24, v12, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v6, v19, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v4, v31, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v4, v25, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v9, v18, v29

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v4, v30, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v18, v14, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v24, v8, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v2, v16, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v2, v30, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v10, v2, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v16, v18, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v28, v6, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v4, v26, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v28, v14, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v20, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v28, v8, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v24, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v8, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v8, v20, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v28, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v28, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v24, v8, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v28, v20, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v12, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v8, v16, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v31, v4, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v17, v31, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v13, v26, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v29, v13, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v7, v17, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v10, v20, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v17, v11, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v9, v25, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v4, v20, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v29, v15, v25

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v8, v24, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v22, v30, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v12, v22, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v20, v28, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v6, v22, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v24, v2, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v18, v20, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v14, v16, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v8, v30, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v6, v2, v22

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v8, v4, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v20, v4, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v16, v8, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v16, v24, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v8, v4, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v4, v16, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v8, v16, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v4, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v20, v8, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v24, v16, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v14, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v28, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v29, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v30, v2, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v10, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v12, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v28, v17, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v28, v30, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v30, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v2, v7, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v12, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v30, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v6, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v2, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v24, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v22, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v30, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v4, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v28, v30, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v20, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v12, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v12, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v4, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v8, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v28, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v12, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v4, v12, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v14, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v19, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v29, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v26, v6, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v1, v18, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v6, v5, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v27, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v25, v27, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v18, v31, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v11, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v6, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v26, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v2, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v8, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v24, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v14, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v14, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v26, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v22, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v6, v22, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v28, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v8, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v24, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v20, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v4, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v24, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v20, v12, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v28, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v9, v1, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v5, v3, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v22, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v11, v23, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v30, v31, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v14, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v17, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v25, v14, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v28, v9, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v30, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v12, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v28, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v12, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v4, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v8, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v26, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v18, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v4, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v20, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v20, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v12, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v12, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v28, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v12, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v16, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v12, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v20, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v3, v25, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v16, v11, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v20, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v13, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v14, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v4, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v17, v11, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v6, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v6, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v17, v3, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v4, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v30, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v10, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v8, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v20, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v20, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v12, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v2, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v28, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v20, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v28, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v4, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v4, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v20, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v4, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
