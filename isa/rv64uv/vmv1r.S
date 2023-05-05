#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e64, m1, ta, ma
  vmv1r.v v1, v25

  vmv1r.v v8, v2

  vmv1r.v v16, v2

  vmv1r.v v4, v12

  vmv1r.v v29, v8

  vmv1r.v v18, v4

  vmv1r.v v10, v8

  vmv1r.v v26, v30

  vmv1r.v v29, v12

  vmv1r.v v11, v13

  vmv1r.v v22, v28

  vmv1r.v v23, v25

  vmv1r.v v11, v25

  vmv1r.v v9, v23

  vmv1r.v v22, v21

  vmv1r.v v26, v28

  vmv1r.v v6, v11

  vmv1r.v v22, v30

  vmv1r.v v24, v16

  vmv1r.v v9, v10

  vmv1r.v v5, v25

  vmv1r.v v26, v27

  vmv1r.v v10, v17

  vmv1r.v v20, v10

  vmv1r.v v11, v28

  vmv1r.v v5, v27

  vmv1r.v v2, v20

  vmv1r.v v3, v2

  vmv1r.v v2, v4

  vmv1r.v v21, v16

  vmv1r.v v26, v21

  vmv1r.v v7, v16

  vmv1r.v v12, v18

  vmv1r.v v30, v16

  vmv1r.v v9, v30

  vmv1r.v v14, v5

  vmv1r.v v22, v26

  vmv1r.v v17, v22

  vmv1r.v v3, v15

  vmv1r.v v23, v22

  vmv1r.v v26, v9

  vmv1r.v v11, v18

  vmv1r.v v29, v30

  vmv1r.v v8, v30

  vmv1r.v v20, v14

  vmv1r.v v11, v25

  vmv1r.v v12, v19

  vmv1r.v v31, v9

  vmv1r.v v30, v28

  vmv1r.v v12, v6

  vmv1r.v v8, v13

  vmv1r.v v6, v26

  vmv1r.v v14, v11

  vmv1r.v v27, v24

  vmv1r.v v26, v13

  vmv1r.v v23, v4

  vmv1r.v v3, v31

  vmv1r.v v8, v7

  vmv1r.v v18, v16

  vmv1r.v v7, v17

  vmv1r.v v27, v7

  vmv1r.v v12, v1

  vmv1r.v v16, v8

  vmv1r.v v26, v7

  vmv1r.v v31, v2

  vmv1r.v v20, v2

  vmv1r.v v19, v25

  vmv1r.v v31, v1

  vmv1r.v v23, v1

  vmv1r.v v24, v25

  vmv1r.v v14, v19

  vmv1r.v v24, v23

  vmv1r.v v23, v4

  vmv1r.v v21, v2

  vmv1r.v v11, v16

  vmv1r.v v18, v21

  vmv1r.v v7, v25

  vmv1r.v v16, v18

  vmv1r.v v14, v3

  vmv1r.v v6, v23

  vmv1r.v v7, v19

  vmv1r.v v1, v9

  vmv1r.v v24, v4

  vmv1r.v v4, v25

  vmv1r.v v28, v31

  vmv1r.v v29, v10

  vmv1r.v v30, v31

  vmv1r.v v17, v18

  vmv1r.v v16, v28

  vmv1r.v v30, v4

  vmv1r.v v8, v6

  vmv1r.v v14, v31

  vmv1r.v v20, v9

  vmv1r.v v4, v20

  vmv1r.v v13, v14

  vmv1r.v v12, v26

  vmv1r.v v5, v8

  vmv1r.v v27, v15

  vmv1r.v v27, v14

  vmv1r.v v31, v24

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
