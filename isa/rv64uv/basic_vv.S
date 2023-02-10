#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v26, v4, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v24, v2, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v31, v20, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v27, v12, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v23, v16, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v18, v29, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v2, v6, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v22, v17, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v1, v17, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v7, v31, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v23, v29, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v1, v23, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v18, v2, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v6, v9, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v31, v3, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v7, v22, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v25, v29, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v15, v25, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v7, v3, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v18, v25, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v7, v5, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v16, v25, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v13, v6, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v28, v6, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v5, v21, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v22, v19, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v29, v14, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v24, v16, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v1, v22, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v21, v7, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v14, v30, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v16, v10, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v3, v6, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v2, v28, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v5, v26, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v10, v28, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v19, v28, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v15, v24, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v3, v23, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v3, v13, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v9, v2, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v11, v18, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v27, v7, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v7, v31, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v10, v26, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v5, v15, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v6, v11, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v15, v13, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v27, v30, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v22, v12, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v4, v27, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v27, v17, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v13, v14, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v23, v30, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v15, v8, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v15, v26, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v13, v29, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v26, v20, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v13, v11, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v29, v6, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v17, v18, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v16, v5, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v23, v25, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v26, v8, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v27, v22, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v21, v14, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v24, v16, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v20, v5, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v4, v9, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v19, v20, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v25, v22, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v3, v20, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v26, v25, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v31, v28, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v29, v30, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v28, v8, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v16, v1, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v6, v8, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v24, v18, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v18, v26, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v22, v20, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v31, v1, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v16, v9, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v23, v26, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v24, v30, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v8, v2, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v8, v22, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v31, v28, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v8, v22, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v25, v9, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v9, v11, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v25, v16, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v30, v11, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v26, v6, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v25, v11, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v6, v20, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v19, v23, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v3, v19, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v29, v9, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v13, v3, v9

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
