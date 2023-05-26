#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v27, v30, -15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v25, v9, -10

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v6, v10, -11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v28, v14, 0

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v10, v15, -9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v2, v10, -3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v6, v31, -3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v21, v3, -2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v2, v30, 6

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v18, v24, 2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v28, v23, -11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v14, v24, -12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v24, v21, 1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v8, v22, -2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v29, v27, 13

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v30, v31, -7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v30, v4, -4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v26, v4, -10

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v9, v26, -2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v24, v20, 8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v27, v11, 12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v22, v21, -4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v29, v15, 13

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v10, v15, -15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v9, v20, -15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v28, v5, -3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v24, v11, 12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v31, v13, 9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v25, v11, -6

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v30, v12, -9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v24, v6, -3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v31, v4, 5

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v2, v15, -10

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v19, v23, -13

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v18, v29, 11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v4, v19, -9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v26, v19, 6

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v2, v13, 12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v16, v6, -3

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v30, v27, 15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v13, v28, -5

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v17, v20, -7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v29, v15, 6

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v16, v18, 8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v8, v19, -2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v21, v23, 8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v16, v24, -11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v6, v30, 1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v17, v23, -8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v9, v24, 0

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v20, v3, -9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v31, v19, -11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v3, v16, -11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v28, v16, 7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v6, v14, -9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v26, v11, -16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v30, v12, -7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v10, v25, 4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v30, v15, 0

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v31, v9, -15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v11, v7, 14

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v20, v6, 11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v3, v16, 13

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v8, v14, 2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v29, v14, 14

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v13, v22, -12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v1, v13, -11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v6, v9, 11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v4, v27, -4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v5, v19, 6

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v6, v31, -1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v16, v8, -13

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v18, v31, -14

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v21, v4, -5

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v3, v26, -6

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v7, v9, 2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v31, v2, 4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v25, v23, 15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v25, v27, -14

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v27, v11, 13

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v26, v27, 4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v31, v14, 13

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v3, v21, 8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v22, v6, -4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v16, v14, 7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v26, v20, -11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v11, v25, 10

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v15, v6, -7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v23, v11, 1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v28, v17, 5

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v23, v26, -4

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v11, v5, 1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v3, v27, 12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v7, v20, -14

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v17, v27, 7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v14, v26, -11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v27, v9, 15

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v8, v29, -9

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v28, v5, 0

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v29, v2, -1

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v20, v12, 12

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v28, v16, 6

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v10, v14, -6

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v28, v16, -5

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v30, v22, 13

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v24, v4, -16

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v28, v6, 10

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v26, v18, -11

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v26, v30, 5

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v18, v16, 7

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v2, v6, 2

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v6, v28, 1

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v4, v16, 9

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v8, v10, -15

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v10, v22, 13

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v10, v26, 12

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v26, v18, 9

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v24, v8, -5

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v14, v16, 15

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v12, v16, -14

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v28, v20, -11

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v28, v20, 7

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v2, v16, -2

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v30, v8, 7

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v4, v14, 15

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v26, v8, -13

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v28, v12, -11

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v12, v26, -4

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v18, v10, 8

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v2, v30, 15

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v16, v10, 2

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v6, v30, 4

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v20, v10, 3

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v4, v22, -16

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v2, v10, -8

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v24, v2, -9

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v6, v18, 1

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v2, v4, 14

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v2, v24, 4

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v18, v20, 7

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v12, v22, 2

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v2, v28, -3

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v26, v24, 10

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v2, v10, 11

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v2, v22, 7

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v8, v22, -7

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v12, v28, 13

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v26, v8, 13

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v20, v2, 12

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v6, v18, 8

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v28, v26, 10

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v26, v12, 5

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v16, v30, 7

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v8, v10, 7

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v20, v10, 3

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v8, v30, 13

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v24, v12, 13

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v28, v30, -14

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v8, v24, 0

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v24, v6, -13

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v24, v26, 7

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v28, v12, -8

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v4, v20, -10

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v12, v22, -10

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v10, v8, 4

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v20, v26, 2

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v30, v10, 0

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v2, v16, -7

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v30, v12, 13

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v10, v8, 9

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v20, v26, 0

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v22, v20, 3

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v14, v18, 3

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v6, v16, -10

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v28, v10, 8

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v6, v22, -8

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v16, v14, -12

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v10, v18, -16

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v12, v2, 6

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v24, v20, -16

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v12, v8, 11

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v30, v6, -1

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v30, v26, -14

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v12, v26, 1

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v18, v4, -4

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v22, v14, 7

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v22, v18, -3

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v26, v4, -13

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v10, v2, -12

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v12, v14, -3

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v14, v16, 14

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v12, v2, -13

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v6, v14, -7

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v16, v14, 12

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v16, v2, -4

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v22, v24, 15

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v2, v30, 15

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v24, v10, -3

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v18, v22, -1

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v28, v12, -9

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v20, v24, -7

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v4, v20, 9

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v8, v28, -3

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v4, 1

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v8, v28, -14

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v20, v4, -13

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v8, -14

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v4, v12, -9

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v4, v24, -2

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v4, -8

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v28, -4

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v20, v24, -2

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v12, -11

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v12, 3

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v4, v20, -15

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v16, -3

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v4, -15

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v20, 1

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v8, -16

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v12, -14

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v20, v12, 8

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v20, -16

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v4, v24, 10

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v20, v12, -16

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v24, 14

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v8, -6

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v8, 11

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v20, v24, -8

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v8, 14

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v8, v20, -3

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v4, 4

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v12, 3

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v20, v16, 1

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v8, v28, 6

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v4, -4

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v24, -1

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v4, v8, -11

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v24, 13

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v12, -7

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v4, -11

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v20, v28, 6

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v20, -11

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v24, -5

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v20, v4, 0

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v8, v16, 4

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v28, 8

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v20, -3

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v12, -16

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v4, -8

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v4, v24, -14

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v8, 13

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v28, -11

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v20, 12

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v4, v12, 5

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v16, 7

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v28, -5

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v4, v16, 14

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v8, v16, 15

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v20, 11

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v20, 10

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v12, 2

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v12, -14

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v24, -8

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v20, v24, 5

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v8, v4, -16

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v16, -6

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v8, v16, 14

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v4, -14

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v20, -7

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v4, -1

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v8, v4, -15

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v12, -13

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v16, 2

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v20, v24, -1

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v8, v20, 14

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v8, v16, 8

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v4, v16, -2

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v8, -6

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v20, v24, 4

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v16, 0

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v16, 12

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v12, 4

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v12, -9

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v24, 2

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v28, -5

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v24, -4

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v12, 1

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v8, v24, -10

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v16, -7

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v28, 9

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v8, -10

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v20, v8, -15

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v16, -1

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v20, -7

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v8, 15

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v24, 8

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v12, 1

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v12, v20, -13

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v28, v12, -5

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v24, -10

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, -11

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v24, 5

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, -12

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, 7

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, 9

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, -7

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 2

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 12

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, -16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 5

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v8, -13

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, -9

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v24, -9

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 9

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, -5

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, -10

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, 0

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, -16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v8, 0

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, -7

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, -14

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, 9

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, -8

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v8, 0

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 4

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v24, 4

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, 11

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, -11

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, -9

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 10

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, 8

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, -8

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, 8

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v24, 9

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 14

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 8

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v8, -10

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, 11

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, 5

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v8, -10

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, 1

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, -7

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, -10

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v24, 12

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 10

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v24, 3

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, 2

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v8, 4

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, -10

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v8, -5

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, -2

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v8, -1

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 0

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, 10

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, 7

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, -6

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v24, 3

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, 9

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, -14

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 15

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v8, 13

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, -14

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, -13

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, 11

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 12

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, 12

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, 12

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, -15

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, -8

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, -5

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v8, 3

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 5

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, -5

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, -4

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, 15

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 11

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, 8

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v8, -12

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v24, -7

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, 6

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v24, 3

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, 12

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, -14

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, 12

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, -2

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, -2

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, -6

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, -1

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, 2

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v24, -10

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, 3

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, -14

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v24, 7

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 15

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, -10

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, 8

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, -4

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, 15

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v8, -3

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, -11

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v12, v20, 4

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v31, v10, -11

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v5, v29, 12

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v16, v27, 1

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v27, v21, 3

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v23, v26, 13

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v20, v5, -16

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v10, v4, -10

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v3, v14, -6

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v29, v6, -5

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v30, v5, 2

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v1, v22, 13

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v1, v3, -15

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v17, v22, 9

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v23, v13, 9

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v23, v12, 8

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v16, v29, 7

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v16, v8, 5

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v18, v3, 0

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v31, v4, 9

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v7, v26, -9

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v17, v31, 5

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v4, v27, 7

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v27, v21, -7

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v12, v7, 10

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v10, v2, -1

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v16, v22, -5

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v9, v3, 15

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v18, v9, -6

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v3, v25, 11

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v21, v20, 14

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v2, v7, -1

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v5, v27, -14

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v7, v13, 1

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v19, v3, 9

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v25, v22, 6

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v5, v10, -16

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v16, v19, -16

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v20, v21, 14

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v30, v27, -10

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v27, v30, 9

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v29, v12, -7

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v18, v6, -3

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v3, v10, -2

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v13, v17, -7

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v28, v21, 14

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v20, v17, -6

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v9, v11, 12

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v15, v12, 5

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v29, v23, 6

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v25, v7, -7

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v22, v23, -15

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v10, v7, -16

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v12, v29, -11

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v11, v12, 10

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v5, v19, -2

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v31, v25, -15

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v9, v4, 5

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v15, v5, 7

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v21, v13, -2

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v11, v5, 2

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v20, v16, -5

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v18, v1, -2

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v5, v4, -10

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v12, v9, -12

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v27, v5, 10

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v30, v28, -13

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v1, v8, -2

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v19, v21, -5

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v29, v12, 15

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v6, v20, -7

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v21, v26, -3

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v2, v9, -5

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v2, v30, -3

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v13, v19, 3

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v15, v14, -16

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v4, v14, 7

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v12, v2, -1

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v25, v20, -10

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v19, v29, 15

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v16, v1, 10

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v13, v26, 0

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v18, v26, -6

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v30, v10, -4

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v4, v8, -1

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v29, v26, 0

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v3, v7, -3

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v6, v2, 3

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v13, v9, -7

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v25, v14, 14

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v7, v15, -10

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v18, v23, 2

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v21, v1, -2

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v31, v8, 4

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v11, v2, -2

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v1, v26, 1

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v31, v23, 9

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v17, v19, 1

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v11, v19, -15

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v17, v20, -6

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v10, v28, 14

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v16, v24, 0

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v10, v4, -8

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v14, v16, -14

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v22, v14, 8

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v2, v18, 12

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v20, v18, 7

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v26, v14, 0

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v18, v30, -16

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v18, v14, -8

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v28, v24, 11

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v12, v8, -1

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v6, v16, -4

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v24, v12, -12

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v24, v14, -10

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v12, v14, -7

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v24, v26, -15

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v30, v26, 1

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v30, v28, -13

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v14, v30, 9

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v2, v12, 4

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v8, v26, 7

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v28, v10, -13

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v22, v28, 14

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v18, v16, -13

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v28, v30, -16

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v14, v28, -5

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v10, v24, -3

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v2, v28, -11

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v26, v12, 9

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v22, v10, 0

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v20, v18, -7

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v24, v28, 9

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v28, v22, 3

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v18, v4, 14

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v22, v16, 1

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v2, v20, 10

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v20, v16, -15

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v16, v30, -8

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v10, v14, 10

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v26, v8, -4

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v28, v30, -7

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v26, v18, -15

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v12, v2, 0

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v20, v4, 8

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v4, v22, 15

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v8, v30, -3

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v10, v26, 3

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v8, v20, -2

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v14, v6, 4

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v8, v20, -5

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v6, v14, 10

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v10, v8, 11

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v14, v26, -9

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v8, v20, -10

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v18, v16, 8

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v8, v4, -1

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v10, v6, -3

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v14, v24, 10

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v2, v24, -8

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v4, v16, 2

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v8, v30, -12

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v16, v22, -11

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v18, v20, -16

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v16, v2, 15

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v4, v6, -10

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v8, v22, 11

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v12, v16, 7

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v2, v6, 1

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v22, v16, 10

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v12, v26, -13

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v22, v14, -3

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v14, v16, -4

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v14, v18, 7

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v30, v8, -7

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v20, v22, 6

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v16, v10, 7

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v30, v12, -5

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v24, v2, -3

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v24, v4, 14

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v14, v10, -8

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v30, v28, -7

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v20, v14, -2

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v30, v10, 14

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v2, v8, 5

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v26, v30, 2

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v12, v24, -15

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v20, v12, 11

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v6, v22, -10

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v30, v20, 12

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v26, v16, -16

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v12, v4, 4

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v12, v14, -7

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v10, v24, -10

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v28, v12, 15

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v2, v4, -11

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v16, v12, -7

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v24, v4, -10

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v26, v28, -6

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v20, v28, -9

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v24, 10

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v28, -6

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v8, v12, 9

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v8, 0

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v20, -14

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v20, -1

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v16, -5

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v8, v12, -13

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v8, -1

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v8, v12, -14

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v8, -7

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v8, 12

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v16, 1

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v4, 5

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v20, 2

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v16, v8, -15

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v28, 12

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v24, v12, -3

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v28, v16, -16

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v8, v16, 9

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v28, v20, -11

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v8, v16, -5

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v8, 1

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v8, -16

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v8, 9

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v8, v4, -14

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v16, v4, -7

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v4, -16

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v28, v8, -11

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v8, v20, 8

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v24, v4, 7

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v28, 8

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v8, -13

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v24, v28, -5

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v28, -3

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v8, 1

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v28, v20, 10

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v8, v28, -2

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v28, v20, 4

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v20, 2

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v28, v20, 14

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v28, -16

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v28, -16

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v20, -7

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v4, 11

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v28, 1

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v16, 1

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v28, 2

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v12, 13

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v24, v8, -8

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v24, -12

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v16, -14

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v24, 7

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v8, 4

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v24, v28, 13

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v16, 12

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v24, v12, 15

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v8, -5

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v28, v24, 1

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v16, v12, 11

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v24, -5

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v16, v28, 7

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v16, -12

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v24, -9

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v8, v4, -1

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v28, v12, 4

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v16, v24, -12

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v28, 6

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v16, v12, -11

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v24, 10

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v4, 14

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v28, v12, -5

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v8, 2

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v16, -7

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v16, v12, 3

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v24, 5

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v28, v16, 15

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v8, v4, 11

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v28, v24, -1

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v28, -4

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v16, v4, -11

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v16, v8, 1

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v28, -13

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v16, v28, -6

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v24, v16, 15

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v8, v4, -6

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v20, -9

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v24, -12

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v8, v24, 11

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v24, v20, -8

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v12, -6

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v8, v20, 4

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v24, v8, 0

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v16, v20, 4

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v8, 7

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v16, v20, -11

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v28, 15

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v4, -9

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v4, v20, -5

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v28, v12, 14

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, 12

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v16, 14

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, -2

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, -12

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, 1

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, 3

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v8, 0

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, -14

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, -11

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, -8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, -6

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v8, 7

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, -9

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, -9

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, 3

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, -8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v16, -2

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v8, -9

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v16, -16

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, 8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, -4

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, -12

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, -2

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, 14

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, 1

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v8, 7

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v8, -8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, 8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, -15

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, 4

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, -8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, -7

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, 1

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, -9

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, -8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v8, 8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, -8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, -2

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, 5

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, -14

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, 8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, 3

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, 1

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, -16

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, -14

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, 10

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v16, 6

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, -12

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v8, -1

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, -11

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, -4

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, -9

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, 14

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v8, 15

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v8, 14

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, 6

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, 10

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, 15

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v16, -4

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v8, -9

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, -3

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v16, 1

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v8, -5

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, -4

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, 10

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, -1

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, 14

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, 13

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, 9

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v16, 12

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v16, -2

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v16, -14

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, -9

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v16, 1

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, 1

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v8, -11

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, 12

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, 14

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, 13

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v8, 5

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v16, 11

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, 10

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, -14

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, 12

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, -7

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, -10

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v8, 6

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, -15

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, -9

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, 5

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, 15

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, -8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, 14

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, -13

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, -6

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v8, -10

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, 9

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, -6

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v16, 12

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v16, v24, -2

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v17, v12, 11

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v25, v29, 6

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v2, v29, -8

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v10, v31, -4

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v22, v21, -2

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v11, v18, -9

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v16, v18, -5

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v16, v29, -8

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v20, v23, -5

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v25, v5, -5

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v26, v19, -1

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v21, v26, -12

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v22, v19, -14

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v16, v24, 8

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v2, v29, 8

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v5, v28, -9

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v9, v21, -6

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v15, v8, -3

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v6, v4, -2

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v12, v10, -2

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v30, v16, -1

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v5, v6, 10

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v16, v5, -5

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v13, v27, 15

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v4, v28, -1

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v21, v11, -7

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v4, v11, -16

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v12, v16, -3

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v12, v8, 1

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v20, v15, 6

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v14, v8, 7

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v16, v11, -14

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v9, v31, 6

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v5, v21, 12

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v21, v14, -15

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v10, v3, -4

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v24, v17, -13

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v31, v6, -15

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v4, v22, 3

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v28, v11, 6

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v26, v14, 2

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v14, v5, -8

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v26, v27, 4

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v23, v11, -7

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v5, v28, -8

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v7, v27, 15

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v11, v26, -13

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v15, v3, 10

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v22, v11, -3

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v29, v6, 8

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v17, v6, 8

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v7, v22, 11

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v13, v19, 11

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v3, v21, -10

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v10, v1, 12

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v11, v26, -10

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v16, v12, 9

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v3, v24, -12

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v4, v11, -5

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v11, v7, -9

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v3, v2, 14

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v25, v9, -14

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v11, v30, -16

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v29, v25, 0

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v25, v11, -15

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v11, v22, -15

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v18, v6, 2

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v15, v21, -13

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v11, v23, -12

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v14, v28, -6

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v13, v29, 5

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v30, v14, 10

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v4, v19, 12

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v24, v11, 5

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v18, v24, 0

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v9, v4, -7

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v30, v27, -11

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v25, v19, 13

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v1, v3, 5

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v29, v31, -11

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v9, v20, 3

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v5, v8, 10

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v16, v10, 7

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v16, v2, 5

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v2, v1, -2

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v19, v23, 0

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v6, v26, -10

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v22, v7, -12

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v24, v13, -2

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v16, v10, -14

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v11, v10, -13

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v7, v3, -2

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v31, v23, 13

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v12, v17, 6

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v13, v31, -3

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v21, v22, 8

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v20, v30, -3

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v31, v7, 12

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v30, v27, -9

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v21, v25, -3

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v6, v20, 15

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v18, v24, 1

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v8, v30, -7

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v18, v4, -11

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v26, v4, 10

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v4, v16, 2

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v18, v24, 0

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v2, v24, -1

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v12, v14, 14

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v8, v4, 13

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v2, v8, 13

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v2, v18, -6

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v6, v16, 7

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v12, v26, -10

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v10, v16, 8

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v10, v30, -12

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v22, v26, -5

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v22, v20, 0

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v20, v22, -4

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v24, v30, 13

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v16, v8, -6

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v22, v6, -9

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v18, v28, -3

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v22, v8, -5

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v16, v12, -7

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v20, v24, 2

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v10, v12, -12

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v22, v16, 0

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v2, v28, 5

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v20, v10, 4

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v4, v12, 10

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v16, v28, 6

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v16, v20, 1

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v26, v22, 13

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v14, v10, -13

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v22, v18, -5

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v4, v22, 11

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v10, v24, -15

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v18, v6, 12

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v10, v30, 7

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v22, v18, 11

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v18, v2, 4

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v26, v24, -9

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v6, v16, 12

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v10, v6, 3

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v4, v10, 8

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v6, v28, -13

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v26, v6, 11

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v26, v16, -6

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v22, v2, 8

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v12, v10, 10

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v10, v28, -7

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v12, v26, 1

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v2, v18, -1

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v18, v24, -8

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v18, v28, -1

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v30, v28, 8

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v10, v22, -14

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v28, v20, -9

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v8, v20, -9

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v4, v2, 14

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v18, v4, 2

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v18, v28, -1

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v18, v26, -12

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v14, v28, -3

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v14, v6, -1

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v10, v24, -2

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v4, v6, 2

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v8, v2, -3

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v24, v16, -9

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v2, v8, 0

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v10, v30, -16

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v16, v24, -8

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v12, v22, -1

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v14, v24, -9

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v12, v14, 4

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v8, v14, -10

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v26, v28, -1

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v2, v24, -4

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v4, v28, 1

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v16, v30, 12

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v6, v2, 2

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v6, v26, -4

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v30, v26, 13

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v24, v28, -15

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v2, v12, -15

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v28, v22, 6

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v30, v10, -9

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v22, v14, -11

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v10, v2, 4

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v4, v28, 11

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v24, v10, -14

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v26, v12, -15

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v28, v16, -11

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v22, v2, 6

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v18, v12, 12

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v2, v28, 3

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v2, v18, 10

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v16, v6, 6

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v10, v2, 3

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v20, v28, 4

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v4, v12, 5

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v24, 8

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v4, v12, -4

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v12, 4

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v8, 8

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v20, 13

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v28, -15

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v28, v24, -6

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v20, 6

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v24, -8

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v8, 14

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v20, v12, 5

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v28, -2

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v4, -11

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v8, 13

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v4, 11

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v20, 14

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v4, v12, -2

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v16, -10

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v24, -16

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v24, 5

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v4, v12, 13

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v24, -6

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v12, -8

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v20, v16, -7

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v28, 9

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v4, v20, 15

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v28, v12, 6

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v4, 15

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v24, -15

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v4, v8, -2

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v20, -3

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v4, -13

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v28, v20, 2

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v16, 4

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v4, v24, -13

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v8, -7

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v12, -6

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v28, 1

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v4, 15

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v20, v16, -16

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v4, 8

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v24, -14

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v8, -7

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v4, 3

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v4, v28, -11

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v28, v20, -1

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v28, v20, -6

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v24, 9

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v12, 13

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v20, v16, -16

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v8, -6

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v4, 1

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v20, -8

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v16, 6

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v20, v8, 5

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v8, -5

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v4, 4

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v8, -8

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v4, -7

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v20, v16, -1

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v28, v12, 1

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v24, 6

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v20, v24, 15

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v28, 15

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v28, -11

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v16, -13

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v28, v4, 13

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v4, -2

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v20, 8

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v28, -6

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v28, -1

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v8, 12

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v20, 12

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v20, v28, -1

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v4, 11

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v4, 8

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v16, -4

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v12, -11

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v12, -14

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v12, -12

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v16, -7

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v20, -6

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v4, -5

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v4, v28, -15

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v4, v16, -1

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v16, 13

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v28, -4

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v4, v8, 12

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v28, v4, -5

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v12, 0

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v4, v8, 9

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v20, -1

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v28, -7

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v16, -8

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v12, v4, -4

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v24, v16, -6

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v28, -13

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v20, -6

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, 11

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, -13

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v16, 1

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, 8

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, -6

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, -12

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v16, 11

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, -12

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v16, 0

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, 6

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, -3

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, 7

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v16, 13

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, -16

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, 15

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v16, -15

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, 15

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, -10

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, 11

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, -1

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, -2

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v16, -7

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, 2

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v16, -15

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v16, 15

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, -6

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v16, -11

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, -5

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, -14

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, -1

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, 10

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, 6

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, -11

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, 1

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, 6

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, -4

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, -11

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, 11

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, -1

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, -14

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, -15

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, -3

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v16, -1

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, 14

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v16, 14

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, -9

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v16, 6

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, -13

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, -1

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v16, -6

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v16, 14

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v16, 6

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, -2

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, -15

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, -15

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, -4

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, 8

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, 7

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, 6

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, -12

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v16, -5

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, 15

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v16, 14

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, 15

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, 5

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, -16

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, 13

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, 3

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, 11

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, -15

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, 10

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, -8

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, 9

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, -6

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v16, -9

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v16, 12

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, -15

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, -12

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, 15

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, 6

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, -10

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, -7

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v16, -15

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, 0

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, 0

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, 6

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, 12

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, -9

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, -11

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, 0

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, -8

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, -3

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, -9

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v16, 13

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, -10

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, 7

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, 2

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v16, -16

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v16, -4

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, 7

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v17, v9, 11

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v1, v29, 9

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v22, v7, -7

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v16, v27, -9

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v26, v27, -16

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v29, v16, 8

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v10, v11, 0

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v21, v23, 14

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v4, v28, -2

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v4, v10, -7

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v7, v25, 11

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v24, v26, -13

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v15, v3, 7

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v4, v16, -5

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v9, v2, 1

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v11, v20, 5

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v1, v25, 11

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v13, v14, -3

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v26, v10, 4

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v9, v23, 0

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v22, v11, 15

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v23, v4, 8

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v10, v3, -8

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v4, v26, 0

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v31, v12, 13

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v1, v9, 11

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v22, v2, 4

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v15, v8, -16

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v16, v10, -9

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v3, v31, 9

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v15, v12, -5

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v23, v8, 7

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v16, v17, -13

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v25, v20, 9

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v24, v17, 7

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v15, v21, -15

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v15, v27, 10

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v12, v3, 2

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v11, v1, 2

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v29, v6, -6

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v23, v31, 1

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v7, v9, 9

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v16, v6, -9

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v17, v31, 12

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v20, v26, -2

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v3, v8, -10

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v27, v5, 1

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v11, v26, -6

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v4, v17, -14

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v29, v17, -13

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v4, v30, 12

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v31, v15, -11

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v27, v22, -11

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v27, v8, 13

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v7, v15, 5

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v23, v10, 1

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v12, v20, 11

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v25, v30, -6

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v4, v22, -11

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v14, v16, 0

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v27, v15, -5

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v5, v25, 9

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v12, v21, 10

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v13, v18, -16

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v21, v23, 14

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v31, v18, 8

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v20, v26, -13

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v7, v26, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v14, v5, -8

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v27, v22, 15

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v30, v7, -3

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v13, v17, 15

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v10, v18, 12

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v20, v7, 7

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v20, v17, 3

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v6, v12, -16

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v16, v17, 10

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v27, v20, 12

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v10, v16, 13

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v4, v14, -12

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v13, v8, -3

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v20, v21, 15

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v18, v17, -11

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v22, v9, 9

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v7, v18, 2

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v23, v30, -5

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v31, v30, 6

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v11, v31, -8

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v31, v3, 10

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v24, v7, 3

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v27, v6, -2

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v8, v21, 5

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v6, v30, 10

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v6, v12, 14

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v17, v19, -14

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v16, v8, 6

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v23, v3, -3

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v2, v26, -15

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v31, v16, -6

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v3, v17, 0

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v14, v22, 0

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v10, v6, -15

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v18, v22, -7

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v10, v12, 9

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v30, v4, -7

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v4, v12, -9

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v12, v18, 1

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v12, v6, -3

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v16, v18, -10

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v6, v28, -16

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v16, v12, 6

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v24, v16, -14

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v24, v26, 4

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v10, v2, 1

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v18, v28, -7

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v18, v22, -9

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v30, v22, -13

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v6, v14, -16

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v28, v22, -14

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v12, v8, 12

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v2, v4, -7

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v26, v28, 13

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v8, v24, -1

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v6, v18, -3

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v4, v2, -10

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v12, v10, 15

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v26, v2, 7

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v16, v20, -13

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v6, v22, 1

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v26, v2, 15

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v16, v20, -9

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v4, v18, 2

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v6, v20, 9

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v20, v6, -3

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v10, v20, -3

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v16, v4, 9

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v22, v14, 7

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v2, v16, 14

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v26, v18, 8

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v16, v20, 14

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v22, v26, 9

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v20, v4, 15

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v28, v16, -13

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v22, v16, 8

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v22, v16, -5

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v24, v2, 3

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v30, v16, 10

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v6, v30, -16

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v6, v24, 7

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v12, v16, -11

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v10, v18, 5

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v16, v30, -3

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v18, v10, 8

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v22, v8, 15

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v2, v4, -12

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v26, v6, -5

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v16, v12, -10

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v28, v24, -5

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v16, v28, 13

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v8, v30, -6

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v4, v26, -3

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v2, v8, -9

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v2, v24, -12

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v22, v8, -10

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v28, v8, 3

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v24, v14, -11

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v14, v20, -16

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v22, v20, 7

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v18, v8, -2

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v6, v4, 2

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v14, v8, -16

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v30, v28, 13

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v24, v16, 5

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v2, v6, -13

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v14, v22, -14

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v2, v16, -1

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v12, v28, 0

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v6, v4, -4

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v24, v18, -7

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v8, v22, -10

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v2, v4, -2

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v10, v2, 3

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v24, v2, 0

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v26, v8, -2

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v30, v4, 7

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v6, v4, -14

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v26, v22, 7

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v18, v22, -9

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v28, v20, 1

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v12, v20, 12

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v28, v20, -15

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v6, v30, 2

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v6, v18, 11

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v24, v2, -3

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v28, v20, -2

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v12, v6, -11

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v4, v20, -9

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v10, v22, -11

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v14, v4, -10

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v2, v24, 11

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v16, -7

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v16, -6

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v4, -7

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v12, 8

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v12, -9

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v24, -7

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v24, v28, -15

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v8, 1

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v4, -11

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v4, 8

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v24, 7

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v24, v28, 15

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v8, 8

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v12, v16, 10

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v24, -2

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v12, -13

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v4, 5

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v24, -6

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v24, -11

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v16, 6

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v28, 1

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v4, -10

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v28, 11

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v8, 0

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v24, -3

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v12, v4, 15

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v12, v20, -6

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v24, 11

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v12, v28, 12

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v8, 14

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v12, -4

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v4, -4

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v16, -8

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v8, -9

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v12, v20, 0

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v8, -11

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v12, v20, -8

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v28, 9

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v8, -9

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v16, 14

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v16, 14

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v20, -2

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v12, v16, -6

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v12, 0

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v28, -10

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v24, 7

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v28, 9

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v28, -9

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v28, -12

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v16, -5

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v4, 3

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v20, 7

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v28, -8

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v16, -8

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v28, 13

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v12, v16, 0

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v12, -2

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v8, -8

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v12, v24, 9

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v8, -16

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v28, 11

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v12, v16, -7

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v12, v20, 6

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v24, -15

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v24, 15

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v28, -4

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v12, v24, -12

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v12, v28, 0

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v4, -8

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v24, -14

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v16, 0

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v4, -1

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v16, 5

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v12, 11

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v8, -11

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v12, 11

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v12, 6

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v12, -5

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v28, -8

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v12, 6

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v24, v4, -7

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v12, -2

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v28, 2

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v20, 3

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v20, -15

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v4, 5

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v28, -9

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v12, 11

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v4, v12, 2

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v28, -6

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v24, v8, -1

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v8, 7

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v4, -14

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v12, 4

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v24, v20, -7

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v28, -16

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v12, v16, 15

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v20, 2

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v24, v28, -5

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v12, 7

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, 2

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, 14

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, 0

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, -2

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, -7

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, 13

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, -12

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, -2

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, 13

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, 15

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, -15

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, -11

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, -2

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, -1

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, 3

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, -16

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, -9

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, -15

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, 7

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, -5

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, 15

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, -5

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, 3

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, 11

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, 8

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, -11

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, -12

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, 6

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, 4

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, 10

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, 11

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, -8

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, 3

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, -7

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, 11

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, -15

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, -14

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, 4

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, -13

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, -6

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, -13

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, -6

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, 2

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, -5

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, 4

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, 7

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, -12

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, 12

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, 11

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, -12

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, 9

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, 1

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, -7

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, -7

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, -10

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, -10

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, 12

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, -14

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, 8

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, -14

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, -14

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, 12

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, -15

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, -6

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, 4

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, 3

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, -3

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, 5

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, -6

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, 14

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, -13

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, -16

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, 13

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, 14

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, 15

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, -12

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, -3

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, -3

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, 4

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, 5

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, 6

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, 4

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, -6

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, -16

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, -5

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, -2

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, 14

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, 11

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, 7

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, -16

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, -9

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, -1

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, -10

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, -15

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, 6

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, 10

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, 11

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, -5

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, 14

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, 10

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
