#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v20, v31, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v30, v22, v21

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v8, v10, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v24, v5, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v11, v12, v31

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v15, v10, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v16, v21, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v13, v12, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v1, v4, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v13, v10, v17

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v20, v28, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v12, v16, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v12, v14, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v2, v30, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v24, v22, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v16, v22, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v2, v20, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v20, v14, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v26, v8, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v2, v8, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v20, v16, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v24, v12, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v20, v4, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v16, v12, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v8, v12, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v28, v8, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v8, v28, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v20, v12, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v4, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v16, v12, v4

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v24, v16, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v20, v21, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v4, v16, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v1, v23, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v2, v11, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v28, v4, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v3, v15, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v26, v12, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v4, v3, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v10, v1, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v13, v23, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v26, v18, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v2, v24, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v6, v30, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v10, v4, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v10, v2, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v18, v14, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v28, v4, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v26, v6, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v14, v2, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v8, v2, v26

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v28, v8, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v16, v28, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v16, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v4, v28, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v24, v8, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v4, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v28, v24, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v4, v16, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v16, v20, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v16, v12, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v8, v24, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v21, v24, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v25, v26, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v25, v16, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v6, v4, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v4, v14, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v21, v14, v25

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v10, v2, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v6, v29, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v2, v28, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v23, v3, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v20, v26, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v12, v2, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v20, v16, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v24, v22, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v12, v6, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v8, v4, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v8, v30, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v22, v26, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v30, v22, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v12, v18, v26

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v16, v8, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v12, v24, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v20, v12, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v4, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v12, v20, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v24, v28, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v28, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v20, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v24, v16, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v20, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v9, v21, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v5, v18, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v2, v22, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v23, v2, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v6, v15, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v27, v21, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v4, v29, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v21, v4, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v18, v20, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v22, v3, v13

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v4, v16, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v28, v24, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v28, v12, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v30, v8, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v16, v8, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v30, v4, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v24, v8, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v30, v28, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v16, v22, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v12, v2, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v20, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v12, v16, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v28, v8, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v12, v24, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v28, v12, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v8, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v20, v12, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v28, v16, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v28, v4, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v28, v20, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v16, v8, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v13, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v26, v13, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v18, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v28, v19, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v8, v2, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v1, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v25, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v13, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v4, v17, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v1, v5, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v10, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v10, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v6, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v14, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v20, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v24, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v20, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v18, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v28, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v28, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v16, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v28, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v20, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v16, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v4, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v28, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v4, v12, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v24, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v10, v29, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v26, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v10, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v26, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v31, v3, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v5, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v9, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v7, v23, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v26, v5, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v6, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v8, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v26, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v28, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v28, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v20, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v30, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v10, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v26, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v14, v10, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v8, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v20, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v12, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v16, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v8, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v12, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v1, v22, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v19, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v3, v15, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v14, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v30, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v21, v3, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v10, v2, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v12, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v29, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v5, v29, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v30, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v10, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v6, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v6, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v22, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v18, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v8, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v16, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v16, v18, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v12, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v4, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v20, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v12, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v20, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v28, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v12, v28, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v26, v6, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v1, v6, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v15, v12, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v26, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v13, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v6, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v13, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v30, v29, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v3, v15, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v9, v1, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v30, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v10, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v8, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v22, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v22, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v26, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v10, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v18, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v22, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v8, v22, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v28, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v20, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v28, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v20, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v8, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v24, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v4, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v4, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
