#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e64, m8, ta, ma
  vmv8r.v v16, v8

  vmv8r.v v24, v8

  vmv8r.v v24, v16

  vmv8r.v v8, v16

  vmv8r.v v8, v16

  vmv8r.v v24, v16

  vmv8r.v v8, v16

  vmv8r.v v8, v16

  vmv8r.v v24, v16

  vmv8r.v v16, v24

  vmv8r.v v16, v8

  vmv8r.v v16, v8

  vmv8r.v v24, v8

  vmv8r.v v8, v24

  vmv8r.v v16, v24

  vmv8r.v v8, v24

  vmv8r.v v24, v8

  vmv8r.v v8, v24

  vmv8r.v v16, v24

  vmv8r.v v24, v16

  vmv8r.v v8, v24

  vmv8r.v v16, v24

  vmv8r.v v24, v16

  vmv8r.v v16, v8

  vmv8r.v v16, v24

  vmv8r.v v8, v16

  vmv8r.v v8, v24

  vmv8r.v v8, v24

  vmv8r.v v24, v8

  vmv8r.v v16, v8

  vmv8r.v v16, v24

  vmv8r.v v16, v8

  vmv8r.v v16, v8

  vmv8r.v v8, v24

  vmv8r.v v8, v24

  vmv8r.v v24, v16

  vmv8r.v v16, v24

  vmv8r.v v8, v24

  vmv8r.v v8, v24

  vmv8r.v v24, v16

  vmv8r.v v24, v8

  vmv8r.v v16, v24

  vmv8r.v v8, v16

  vmv8r.v v24, v16

  vmv8r.v v8, v24

  vmv8r.v v16, v24

  vmv8r.v v24, v16

  vmv8r.v v16, v8

  vmv8r.v v24, v8

  vmv8r.v v16, v8

  vmv8r.v v16, v24

  vmv8r.v v8, v24

  vmv8r.v v24, v16

  vmv8r.v v8, v16

  vmv8r.v v24, v16

  vmv8r.v v24, v8

  vmv8r.v v24, v16

  vmv8r.v v8, v16

  vmv8r.v v8, v24

  vmv8r.v v16, v24

  vmv8r.v v16, v8

  vmv8r.v v16, v24

  vmv8r.v v8, v24

  vmv8r.v v24, v8

  vmv8r.v v24, v16

  vmv8r.v v16, v24

  vmv8r.v v8, v16

  vmv8r.v v16, v8

  vmv8r.v v16, v24

  vmv8r.v v24, v8

  vmv8r.v v24, v8

  vmv8r.v v8, v24

  vmv8r.v v24, v16

  vmv8r.v v24, v16

  vmv8r.v v16, v8

  vmv8r.v v24, v8

  vmv8r.v v16, v8

  vmv8r.v v24, v8

  vmv8r.v v8, v16

  vmv8r.v v24, v8

  vmv8r.v v24, v16

  vmv8r.v v24, v16

  vmv8r.v v16, v24

  vmv8r.v v8, v24

  vmv8r.v v8, v16

  vmv8r.v v8, v16

  vmv8r.v v16, v8

  vmv8r.v v24, v16

  vmv8r.v v16, v24

  vmv8r.v v8, v16

  vmv8r.v v16, v24

  vmv8r.v v8, v24

  vmv8r.v v24, v8

  vmv8r.v v24, v16

  vmv8r.v v16, v8

  vmv8r.v v16, v8

  vmv8r.v v16, v24

  vmv8r.v v24, v16

  vmv8r.v v24, v8

  vmv8r.v v24, v8

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
