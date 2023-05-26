#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v21, v13, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v26, v19, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v13, v16, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v30, v8, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v22, v14, v31

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v1, v23, v21

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v27, v5, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v13, v4, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v25, v29, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v30, v26, v1

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v20, v6, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v18, v28, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v10, v26, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v28, v6, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v30, v16, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v14, v10, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v22, v14, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v8, v4, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v22, v24, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v16, v14, v18

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v12, v8, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v20, v4, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v16, v12, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v8, v28, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v24, v12, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v28, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v20, v28, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v24, v20, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v28, v20, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v24, v16, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v10, v1, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v18, v4, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v21, v1, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v12, v26, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v9, v3, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v4, v5, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v27, v6, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v5, v17, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v24, v21, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v6, v26, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v16, v30, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v6, v28, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v6, v12, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v24, v12, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v18, v4, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v24, v8, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v4, v8, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v14, v16, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v22, v2, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v4, v12, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v12, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v4, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v16, v12, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v28, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v20, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v8, v24, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v16, v8, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v20, v12, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v28, v23, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v16, v3, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v12, v8, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v24, v1, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v15, v22, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v26, v31, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v27, v4, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v14, v10, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v29, v9, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v6, v25, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v16, v22, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v6, v24, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v14, v18, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v18, v24, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v16, v20, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v2, v30, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v8, v24, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v2, v18, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v24, v20, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v20, v4, v26

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v28, v4, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v4, v20, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v28, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v28, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v24, v12, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v12, v16, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v24, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v20, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v16, v28, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v28, v12, v4

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v24, v16, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v19, v23, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v20, v26, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v2, v6, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v24, v28, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v9, v17, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v24, v4, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v13, v8, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v29, v21, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v15, v30, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v22, v4, v13

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v22, v18, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v8, v24, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v6, v24, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v6, v18, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v30, v16, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v20, v12, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v6, v10, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v14, v4, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v26, v4, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v24, v18, v26

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v16, v4, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v20, v12, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v4, v16, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v24, v4, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v4, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v4, v12, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v20, v24, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v16, v8, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v16, v8, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v16, v12, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v8, v16, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v7, v2, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v2, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v23, v1, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v2, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v17, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v28, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v6, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v16, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v7, v30, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v5, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v20, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v10, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v10, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v4, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v30, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v14, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v20, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v4, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v28, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v24, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v16, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v28, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v4, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v12, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v28, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v4, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v28, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v8, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v8, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v28, v4, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v9, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v23, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v3, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v4, v29, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v25, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v27, v1, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v20, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v6, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v6, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v5, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v10, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v6, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v6, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v10, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v4, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v4, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v6, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v24, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v2, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v10, v14, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v4, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v4, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v4, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v20, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v16, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v24, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v28, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v12, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v12, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v4, v28, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v1, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v26, v31, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v29, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v27, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v4, v17, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v13, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v28, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v2, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v15, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v26, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v2, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v2, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v10, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v20, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v14, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v6, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v26, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v4, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v30, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v12, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v8, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v24, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v24, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v4, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v8, v4, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v24, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v19, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v13, v2, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v27, v12, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v6, v10, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v10, v2, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v16, v17, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v22, v7, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v11, v6, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v30, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v4, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v4, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v10, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v12, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v26, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v12, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v8, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v14, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v28, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v30, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v8, v2, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v20, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v8, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v4, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v24, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v20, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v28, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v8, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
