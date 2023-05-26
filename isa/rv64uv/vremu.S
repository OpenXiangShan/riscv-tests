#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v29, v27, v7

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v25, v2, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v1, v25, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v28, v5, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v17, v13, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v7, v25, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v5, v19, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v5, v11, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v12, v15, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v17, v14, v19

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v6, v24, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v4, v22, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v4, v22, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v4, v26, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v14, v8, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v4, v12, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v12, v30, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v18, v4, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v26, v22, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v12, v6, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v20, v24, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v4, v28, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v12, v8, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v20, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v20, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v20, v16, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v4, v20, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v20, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v20, v8, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v16, v12, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v7, v9, v29

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v26, v22, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v18, v4, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v28, v12, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v2, v31, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v6, v12, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v8, v19, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v7, v25, v9

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v17, v3, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v9, v19, v1

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v10, v2, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v28, v12, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v10, v24, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v6, v2, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v30, v10, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v18, v2, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v24, v16, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v22, v12, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v20, v8, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v24, v18, v30

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v28, v16, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v8, v28, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v20, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v4, v12, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v4, v24, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v8, v16, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v4, v24, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v8, v28, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v4, v8, v12

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v8, v24, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v6, v16, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v11, v14, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v17, v14, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v2, v19, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v9, v3, v5

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v28, v4, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v27, v17, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v31, v23, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v8, v9, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v16, v14, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v2, v28, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v26, v12, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v10, v8, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v12, v20, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v10, v12, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v20, v26, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v12, v22, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v30, v18, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v26, v18, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v14, v18, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v12, v16, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v16, v8, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v16, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v4, v20, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v4, v12, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v28, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v16, v12, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v24, v20, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v16, v8, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v20, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v8, v24, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v21, v5, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v31, v18, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v4, v5, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v16, v25, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v15, v12, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v13, v21, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v11, v23, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v18, v3, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v20, v6, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v25, v13, v31

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v8, v22, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v12, v18, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v26, v22, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v4, v2, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v14, v10, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v2, v24, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v22, v16, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v30, v10, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v28, v6, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v12, v20, v22

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v24, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v8, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v4, v20, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v28, v24, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v24, v20, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v12, v24, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v16, v24, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v8, v4, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v16, v24, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v16, v28, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v23, v13, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v7, v13, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v12, v13, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v3, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v16, v17, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v10, v3, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v31, v26, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v18, v15, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v8, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v2, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v30, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v28, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v8, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v20, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v4, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v22, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v22, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v4, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v20, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v22, v26, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v4, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v12, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v4, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v4, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v24, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v4, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v28, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v12, v28, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v8, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v9, v13, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v2, v18, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v16, v17, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v20, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v24, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v27, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v27, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v7, v23, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v4, v18, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v13, v21, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v6, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v2, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v18, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v22, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v10, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v4, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v28, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v22, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v14, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v26, v30, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v4, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v12, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v24, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v8, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v20, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v8, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v16, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v28, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v28, v4, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v8, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v20, v31, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v3, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v7, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v14, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v19, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v28, v3, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v30, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v4, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v3, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v19, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v20, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v28, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v2, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v16, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v26, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v28, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v10, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v30, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v14, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v18, v22, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v28, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v12, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v12, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v20, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v28, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v28, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v28, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v24, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v28, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v8, v28, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v24, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v23, v22, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v12, v10, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v22, v14, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v22, v2, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v6, v21, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v5, v6, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v28, v25, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v8, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v7, v22, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v18, v29, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v24, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v24, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v18, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v16, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v24, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v8, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v10, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v24, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v24, v2, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v4, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v4, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v8, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v4, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v12, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v28, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v4, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v16, v12, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v24, v8, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
