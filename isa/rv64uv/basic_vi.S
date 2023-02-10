#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v21, v12, -13

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v9, v7, -9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v14, v20, -16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v14, v1, 5

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v5, v20, -16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v9, v19, -8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v17, v6, -12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v28, v4, -9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v12, v5, 8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v24, v6, 7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v29, v24, 4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v7, v17, 12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v21, v24, 3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v11, v23, 9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v2, v12, 9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v21, v5, 8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v17, v16, -9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v4, v11, -12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v3, v15, -7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v30, v26, 2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v18, v23, 3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v7, v20, 7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v3, v19, 12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v20, v9, 10

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v7, v6, 0

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v2, v24, 10

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v18, v1, -4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v16, v9, 14

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v19, v4, 8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v11, v5, 9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v3, v6, 11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v6, v14, -15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v14, v22, -9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v4, v23, 15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v12, v5, 2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v22, v30, 9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v31, v27, 9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v5, v1, -1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v13, v27, 11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v2, v23, 1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v12, v25, -13

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v26, v8, 7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v19, v21, 3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v13, v7, -12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v7, v11, -16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v18, v29, 9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v3, v29, 11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v1, v7, -13

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v6, v2, 8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v15, v18, -5

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v26, v3, -6

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v25, v26, -3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v17, v19, 11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v22, v12, -15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v18, v9, 0

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v17, v12, -4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v4, v25, -4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v18, v9, 7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v25, v10, -8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v11, v17, -8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v2, v11, -15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v15, v7, 5

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v27, v11, 6

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v21, v23, -5

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v21, v8, -12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v11, v15, -1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v5, v1, -9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v23, v3, -2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v8, v25, -14

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v27, v1, -8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v26, v23, -7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v2, v11, 2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v5, v6, -10

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v27, v1, -7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v7, v24, -16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v1, v27, -16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v25, v29, 15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v27, v6, 3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v14, v11, -7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v29, v31, 5

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v24, v18, 3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v9, v27, 3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v5, v13, -12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v7, v4, 10

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v7, v25, 3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v10, v11, 10

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v20, v24, -2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v5, v22, -1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v7, v19, -16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v13, v28, 15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v25, v4, -8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v18, v23, 4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v9, v8, 3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v19, v2, -1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v10, v14, 6

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v30, v4, 14

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v28, v9, 9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v2, v28, 15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v12, v4, 13

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v4, v29, -16

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
