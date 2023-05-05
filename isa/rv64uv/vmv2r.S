#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e64, m2, ta, ma
  vmv2r.v v12, v22

  vmv2r.v v26, v18

  vmv2r.v v18, v8

  vmv2r.v v22, v20

  vmv2r.v v22, v14

  vmv2r.v v30, v16

  vmv2r.v v8, v4

  vmv2r.v v30, v2

  vmv2r.v v20, v22

  vmv2r.v v30, v6

  vmv2r.v v16, v30

  vmv2r.v v8, v22

  vmv2r.v v10, v18

  vmv2r.v v14, v16

  vmv2r.v v4, v16

  vmv2r.v v30, v14

  vmv2r.v v2, v28

  vmv2r.v v24, v6

  vmv2r.v v6, v2

  vmv2r.v v12, v22

  vmv2r.v v30, v20

  vmv2r.v v14, v30

  vmv2r.v v20, v28

  vmv2r.v v8, v30

  vmv2r.v v6, v28

  vmv2r.v v14, v22

  vmv2r.v v4, v10

  vmv2r.v v12, v26

  vmv2r.v v22, v26

  vmv2r.v v4, v8

  vmv2r.v v24, v16

  vmv2r.v v30, v8

  vmv2r.v v2, v6

  vmv2r.v v12, v20

  vmv2r.v v14, v30

  vmv2r.v v14, v10

  vmv2r.v v2, v24

  vmv2r.v v14, v12

  vmv2r.v v14, v12

  vmv2r.v v6, v22

  vmv2r.v v30, v8

  vmv2r.v v6, v30

  vmv2r.v v24, v10

  vmv2r.v v2, v22

  vmv2r.v v20, v4

  vmv2r.v v18, v20

  vmv2r.v v6, v8

  vmv2r.v v16, v18

  vmv2r.v v12, v2

  vmv2r.v v18, v26

  vmv2r.v v28, v18

  vmv2r.v v14, v10

  vmv2r.v v12, v14

  vmv2r.v v20, v24

  vmv2r.v v22, v2

  vmv2r.v v24, v12

  vmv2r.v v4, v16

  vmv2r.v v8, v14

  vmv2r.v v14, v12

  vmv2r.v v10, v8

  vmv2r.v v6, v12

  vmv2r.v v12, v16

  vmv2r.v v2, v10

  vmv2r.v v14, v12

  vmv2r.v v14, v2

  vmv2r.v v16, v26

  vmv2r.v v20, v2

  vmv2r.v v18, v16

  vmv2r.v v18, v26

  vmv2r.v v22, v4

  vmv2r.v v12, v24

  vmv2r.v v30, v4

  vmv2r.v v6, v16

  vmv2r.v v20, v12

  vmv2r.v v4, v16

  vmv2r.v v10, v8

  vmv2r.v v14, v16

  vmv2r.v v16, v6

  vmv2r.v v16, v6

  vmv2r.v v26, v2

  vmv2r.v v8, v10

  vmv2r.v v24, v12

  vmv2r.v v2, v4

  vmv2r.v v20, v30

  vmv2r.v v10, v8

  vmv2r.v v10, v2

  vmv2r.v v18, v20

  vmv2r.v v6, v30

  vmv2r.v v24, v8

  vmv2r.v v6, v28

  vmv2r.v v30, v14

  vmv2r.v v24, v2

  vmv2r.v v2, v8

  vmv2r.v v14, v26

  vmv2r.v v12, v20

  vmv2r.v v30, v8

  vmv2r.v v26, v22

  vmv2r.v v18, v12

  vmv2r.v v18, v24

  vmv2r.v v6, v20

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
