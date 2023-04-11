#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vcompress.vm v24, v6, v21

  vsetvli t1, t0, e8, m1, ta, ma
  vcompress.vm v1, v25, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vcompress.vm v5, v18, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vcompress.vm v3, v10, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vcompress.vm v22, v25, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vcompress.vm v27, v1, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vcompress.vm v18, v10, v31

  vsetvli t1, t0, e8, m1, ta, ma
  vcompress.vm v22, v31, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vcompress.vm v13, v24, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vcompress.vm v4, v29, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vcompress.vm v28, v24, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vcompress.vm v12, v10, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vcompress.vm v30, v8, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vcompress.vm v26, v14, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vcompress.vm v26, v14, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vcompress.vm v24, v20, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vcompress.vm v30, v20, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vcompress.vm v22, v8, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vcompress.vm v2, v12, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vcompress.vm v20, v14, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vcompress.vm v24, v16, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vcompress.vm v12, v20, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vcompress.vm v16, v28, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vcompress.vm v24, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vcompress.vm v4, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vcompress.vm v20, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vcompress.vm v24, v4, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vcompress.vm v12, v20, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vcompress.vm v12, v20, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vcompress.vm v4, v8, v12

  vsetvli t1, t0, e8, m8, ta, ma
  vcompress.vm v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vcompress.vm v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vcompress.vm v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vcompress.vm v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vcompress.vm v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vcompress.vm v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vcompress.vm v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vcompress.vm v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vcompress.vm v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vcompress.vm v16, v8, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vcompress.vm v22, v18, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vcompress.vm v4, v21, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vcompress.vm v14, v8, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vcompress.vm v7, v13, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vcompress.vm v26, v9, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vcompress.vm v22, v29, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vcompress.vm v4, v8, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vcompress.vm v18, v16, v29

  vsetvli t1, t0, e16, m1, ta, ma
  vcompress.vm v30, v6, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vcompress.vm v7, v3, v1

  vsetvli t1, t0, e16, m2, ta, ma
  vcompress.vm v8, v30, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vcompress.vm v8, v6, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vcompress.vm v28, v20, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vcompress.vm v10, v4, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vcompress.vm v26, v16, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vcompress.vm v20, v10, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vcompress.vm v22, v4, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vcompress.vm v26, v30, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vcompress.vm v30, v6, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vcompress.vm v8, v24, v30

  vsetvli t1, t0, e16, m4, ta, ma
  vcompress.vm v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vcompress.vm v24, v8, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vcompress.vm v24, v28, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vcompress.vm v16, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vcompress.vm v4, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vcompress.vm v20, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vcompress.vm v4, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vcompress.vm v24, v8, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vcompress.vm v12, v16, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vcompress.vm v16, v28, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vcompress.vm v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vcompress.vm v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vcompress.vm v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vcompress.vm v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vcompress.vm v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vcompress.vm v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vcompress.vm v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vcompress.vm v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vcompress.vm v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vcompress.vm v16, v24, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vcompress.vm v4, v13, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vcompress.vm v29, v4, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vcompress.vm v5, v12, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vcompress.vm v13, v10, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vcompress.vm v5, v13, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vcompress.vm v6, v10, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vcompress.vm v9, v21, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vcompress.vm v20, v9, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vcompress.vm v9, v5, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vcompress.vm v23, v15, v25

  vsetvli t1, t0, e32, m2, ta, ma
  vcompress.vm v14, v22, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vcompress.vm v26, v4, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vcompress.vm v12, v22, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vcompress.vm v18, v24, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vcompress.vm v18, v14, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vcompress.vm v18, v30, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vcompress.vm v30, v20, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vcompress.vm v2, v28, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vcompress.vm v10, v24, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vcompress.vm v14, v6, v22

  vsetvli t1, t0, e32, m4, ta, ma
  vcompress.vm v4, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vcompress.vm v12, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vcompress.vm v4, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vcompress.vm v8, v24, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vcompress.vm v8, v24, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vcompress.vm v28, v20, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vcompress.vm v8, v28, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vcompress.vm v16, v12, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vcompress.vm v16, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vcompress.vm v28, v20, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vcompress.vm v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vcompress.vm v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vcompress.vm v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vcompress.vm v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vcompress.vm v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vcompress.vm v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vcompress.vm v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vcompress.vm v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vcompress.vm v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vcompress.vm v24, v16, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vcompress.vm v20, v5, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vcompress.vm v16, v11, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vcompress.vm v22, v21, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vcompress.vm v3, v7, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vcompress.vm v6, v18, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vcompress.vm v22, v11, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vcompress.vm v12, v17, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vcompress.vm v11, v3, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vcompress.vm v13, v1, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vcompress.vm v5, v3, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vcompress.vm v16, v2, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vcompress.vm v12, v24, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vcompress.vm v4, v24, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vcompress.vm v30, v8, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vcompress.vm v24, v28, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vcompress.vm v8, v30, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vcompress.vm v24, v14, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vcompress.vm v20, v26, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vcompress.vm v26, v2, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vcompress.vm v30, v26, v14

  vsetvli t1, t0, e64, m4, ta, ma
  vcompress.vm v20, v24, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vcompress.vm v12, v8, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vcompress.vm v28, v4, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vcompress.vm v12, v24, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vcompress.vm v8, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vcompress.vm v8, v16, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vcompress.vm v16, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vcompress.vm v8, v16, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vcompress.vm v12, v16, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vcompress.vm v4, v12, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vcompress.vm v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vcompress.vm v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vcompress.vm v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vcompress.vm v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vcompress.vm v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vcompress.vm v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vcompress.vm v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vcompress.vm v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vcompress.vm v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vcompress.vm v24, v8, v16

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
