#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e64, m4, ta, ma
  vmv4r.v v8, v16

  vmv4r.v v20, v4

  vmv4r.v v24, v8

  vmv4r.v v12, v24

  vmv4r.v v28, v16

  vmv4r.v v24, v16

  vmv4r.v v20, v28

  vmv4r.v v12, v8

  vmv4r.v v16, v8

  vmv4r.v v28, v24

  vmv4r.v v8, v16

  vmv4r.v v16, v4

  vmv4r.v v16, v28

  vmv4r.v v16, v20

  vmv4r.v v12, v4

  vmv4r.v v20, v24

  vmv4r.v v28, v16

  vmv4r.v v4, v20

  vmv4r.v v20, v8

  vmv4r.v v20, v8

  vmv4r.v v4, v12

  vmv4r.v v20, v12

  vmv4r.v v20, v8

  vmv4r.v v20, v4

  vmv4r.v v28, v4

  vmv4r.v v20, v12

  vmv4r.v v24, v16

  vmv4r.v v12, v8

  vmv4r.v v16, v20

  vmv4r.v v12, v20

  vmv4r.v v12, v16

  vmv4r.v v12, v16

  vmv4r.v v24, v4

  vmv4r.v v4, v8

  vmv4r.v v28, v20

  vmv4r.v v4, v12

  vmv4r.v v8, v28

  vmv4r.v v8, v16

  vmv4r.v v28, v12

  vmv4r.v v4, v20

  vmv4r.v v16, v4

  vmv4r.v v4, v20

  vmv4r.v v4, v24

  vmv4r.v v4, v12

  vmv4r.v v12, v20

  vmv4r.v v28, v4

  vmv4r.v v28, v20

  vmv4r.v v24, v20

  vmv4r.v v8, v24

  vmv4r.v v12, v28

  vmv4r.v v4, v12

  vmv4r.v v8, v28

  vmv4r.v v4, v24

  vmv4r.v v20, v4

  vmv4r.v v16, v12

  vmv4r.v v16, v12

  vmv4r.v v28, v12

  vmv4r.v v24, v16

  vmv4r.v v28, v20

  vmv4r.v v20, v12

  vmv4r.v v16, v24

  vmv4r.v v16, v24

  vmv4r.v v24, v8

  vmv4r.v v24, v8

  vmv4r.v v28, v12

  vmv4r.v v16, v4

  vmv4r.v v16, v4

  vmv4r.v v12, v24

  vmv4r.v v20, v8

  vmv4r.v v28, v24

  vmv4r.v v16, v8

  vmv4r.v v16, v8

  vmv4r.v v12, v28

  vmv4r.v v16, v20

  vmv4r.v v28, v20

  vmv4r.v v12, v20

  vmv4r.v v12, v20

  vmv4r.v v28, v24

  vmv4r.v v28, v24

  vmv4r.v v24, v12

  vmv4r.v v4, v8

  vmv4r.v v24, v8

  vmv4r.v v8, v28

  vmv4r.v v16, v20

  vmv4r.v v20, v16

  vmv4r.v v12, v16

  vmv4r.v v28, v24

  vmv4r.v v16, v28

  vmv4r.v v12, v20

  vmv4r.v v4, v16

  vmv4r.v v4, v16

  vmv4r.v v28, v20

  vmv4r.v v8, v24

  vmv4r.v v20, v4

  vmv4r.v v20, v28

  vmv4r.v v28, v24

  vmv4r.v v20, v4

  vmv4r.v v12, v24

  vmv4r.v v12, v4

  vmv4r.v v24, v12

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
