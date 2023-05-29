#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v13, v18, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v20, v24, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v4, v17, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v15, v20, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v15, v9, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v8, v22, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v15, v11, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v22, v18, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v8, v5, v21

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vv v27, v31, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v18, v26, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v8, v20, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v2, v18, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v10, v16, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v24, v2, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v16, v8, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v28, v22, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v10, v28, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v10, v12, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vv v12, v6, v18

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v16, v4, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v8, v12, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v8, v20, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v24, v12, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v16, v8, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v20, v8, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v20, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v20, v28, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vv v12, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vv v16, v8, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v20, v16, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v2, v13, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v14, v13, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v29, v13, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v17, v19, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v21, v19, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v10, v13, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v2, v17, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v26, v14, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vv v26, v17, v7

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v24, v16, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v10, v2, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v4, v14, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v26, v30, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v22, v30, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v2, v26, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v16, v8, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v30, v10, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v24, v14, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vv v16, v20, v6

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v28, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v24, v20, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v28, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v12, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v24, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v8, v24, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v16, v20, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v20, v28, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v8, v16, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vv v4, v16, v28

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vv v24, v8, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v10, v20, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v25, v2, v31

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v21, v30, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v27, v17, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v2, v14, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v1, v30, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v28, v26, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v2, v7, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v1, v5, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vv v6, v13, v21

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v26, v14, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v16, v24, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v10, v26, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v22, v8, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v22, v14, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v28, v30, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v20, v16, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v22, v26, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v20, v18, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vv v12, v14, v2

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v12, v20, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v28, v12, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v8, v12, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v28, v12, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v20, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v12, v28, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v12, v24, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v8, v28, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v28, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vv v28, v4, v12

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vv v16, v8, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v28, v12, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v8, v4, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v6, v11, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v7, v25, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v14, v18, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v10, v7, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v16, v2, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v28, v13, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v30, v8, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vv v2, v3, v15

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v4, v28, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v14, v24, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v28, v24, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v14, v20, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v30, v10, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v4, v20, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v30, v6, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v2, v26, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v12, v2, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vv v8, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v16, v8, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v16, v8, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v28, v8, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v28, v20, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v20, v8, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v8, v24, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v4, v12, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v24, v28, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v16, v4, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vv v4, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vv v16, v8, v24

  li t2, 0xdfdff9d5c0ed4239
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v31, v13, t2

  li t2, 0x85de77c4f1358b89
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v20, v10, t2

  li t2, 0x7bc303898e780059
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v24, v12, t2

  li t2, 0x48c96185c6d7f64e
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v4, v17, t2

  li t2, 0x3527056f500e2079
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v3, v15, t2

  li t2, 0x9ab1d249a2b1d031
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v22, v8, t2

  li t2, 0xafec0f0c3a3fdaed
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v25, v9, t2

  li t2, 0xb278bc7838e28ad7
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v18, v1, t2

  li t2, 0x2b71b1f28f271a3f
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v3, v1, t2

  li t2, 0x0de49b7ebc803f34
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhsu.vx v6, v29, t2

  li t2, 0x99f95085e0c6e043
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v24, v16, t2

  li t2, 0x0428f013d7b96f8a
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v12, v28, t2

  li t2, 0xa13259a4935f55ff
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v2, v14, t2

  li t2, 0x7a1a26a645f5e276
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v30, v20, t2

  li t2, 0xf697be39c5ca578a
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v4, v20, t2

  li t2, 0x6fb37df47915fd78
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v6, v24, t2

  li t2, 0x7acaa5a5b841131c
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v2, v26, t2

  li t2, 0x55a6c1fd0992a063
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v30, v22, t2

  li t2, 0x7b409670a285b158
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v2, v28, t2

  li t2, 0xe03276fd81aeeaa6
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhsu.vx v12, v2, t2

  li t2, 0xfef701a9959037bc
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v20, v28, t2

  li t2, 0x8b079a7b964c15a6
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v12, v16, t2

  li t2, 0xae96a5eeb7a9835c
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v16, v24, t2

  li t2, 0xf63793fb5881a126
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v28, v16, t2

  li t2, 0xe5b21503434a09f3
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v28, v12, t2

  li t2, 0xc660354ff43dc2c9
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v28, v8, t2

  li t2, 0xf1389bdbb32e3018
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v12, v16, t2

  li t2, 0x0d5fff1b30eadb92
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v12, v28, t2

  li t2, 0x8698eb8407654c56
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v4, v28, t2

  li t2, 0xa79d509e08349794
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhsu.vx v24, v16, t2

  li t2, 0xd23e7b3ca6902059
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  li t2, 0x7ea0cf27c8a9ff31
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  li t2, 0x788a64951f0866eb
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  li t2, 0xa3a15161fecb389b
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  li t2, 0xb47fa70655961c81
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  li t2, 0x4f53813851c106e0
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  li t2, 0xa78fca83c6006284
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  li t2, 0x1830f42bdd6e207e
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v8, v16, t2

  li t2, 0xb6eaa6a991798a9a
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v8, v16, t2

  li t2, 0x7d068e4a1e7d364a
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  li t2, 0x0c8896d25545b68f
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v17, v10, t2

  li t2, 0x4399533cadeee39c
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v22, v9, t2

  li t2, 0x62647544a8b57992
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v8, v27, t2

  li t2, 0x19246f53c1712cf6
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v24, v5, t2

  li t2, 0xdf55e5e9276e41ef
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v9, v21, t2

  li t2, 0xf4a93a7a8acce4f8
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v8, v22, t2

  li t2, 0x72fd30252ce7ba4b
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v13, v24, t2

  li t2, 0x5949194d2072b7cd
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v10, v12, t2

  li t2, 0x269f523ac80d3f32
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v5, v6, t2

  li t2, 0x0ff7ea8e5c4636ab
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhsu.vx v18, v28, t2

  li t2, 0x3df2bc5de5e5a776
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v18, v4, t2

  li t2, 0x8b9f510bba2fd82b
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v22, v16, t2

  li t2, 0xc9c97695c5830fd3
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v20, v8, t2

  li t2, 0x49aff6c8d064db52
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v8, v14, t2

  li t2, 0x4f6507d9f93d58a0
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v6, v16, t2

  li t2, 0xf487a8043c6ce697
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v28, v10, t2

  li t2, 0xd3dd85af87cfb807
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v18, v10, t2

  li t2, 0xfcea5368aead88ae
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v6, v24, t2

  li t2, 0x5ecd0ed27086e3eb
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v30, v26, t2

  li t2, 0xc1d3b9cb2e229e3f
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhsu.vx v24, v16, t2

  li t2, 0x8b9bc75148df37ab
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v12, v24, t2

  li t2, 0x8cf7b5909cadf129
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v24, v4, t2

  li t2, 0x6b6262cf8faff808
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v8, v24, t2

  li t2, 0x3fb693b8fa7c1724
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v16, v20, t2

  li t2, 0x98e5895861b80b51
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v20, v8, t2

  li t2, 0x6847a84c37258ba4
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v28, v16, t2

  li t2, 0x134d6e6de622e920
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v4, v24, t2

  li t2, 0xe6bb50f60ef1c844
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v28, v16, t2

  li t2, 0xea2c238e319178fc
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v28, v12, t2

  li t2, 0x28f805449dd9f578
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhsu.vx v4, v20, t2

  li t2, 0x2ef73260025e872b
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  li t2, 0xa6b8057419eea266
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  li t2, 0x6ade3f66c0a9bbf7
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  li t2, 0xa63e5af6b29a44be
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v8, v16, t2

  li t2, 0x991e0f91765402b0
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  li t2, 0x9744d0d4172f704b
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  li t2, 0x4b7f60833ed36ca2
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v8, v16, t2

  li t2, 0xa3471ff8130f3a06
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  li t2, 0x14ac4a813827265e
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  li t2, 0x8103ba10fefe5cd1
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  li t2, 0xe8d8c69508d857c3
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v20, v30, t2

  li t2, 0x1d77eee03e149f97
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v7, v25, t2

  li t2, 0x9d1db2344d5e0812
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v13, v31, t2

  li t2, 0xc83bcedb9a7bdcc5
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v10, v26, t2

  li t2, 0x81fb7d47e0e680a1
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v26, v9, t2

  li t2, 0x63a288e4077c22e7
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v1, v3, t2

  li t2, 0x5abb5cbd6ede9975
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v7, v25, t2

  li t2, 0xcb98b925d6ecfe44
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v28, v22, t2

  li t2, 0x4f6e231a09626fdf
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v8, v11, t2

  li t2, 0x9a20f67a6a91bd87
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhsu.vx v27, v20, t2

  li t2, 0x3f46df9a46d2580c
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v6, v26, t2

  li t2, 0x806b33aa59fd684a
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v28, v20, t2

  li t2, 0x8fc1ef9195db2dc3
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v6, v24, t2

  li t2, 0x4c8b2fd930c53fe8
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v2, v14, t2

  li t2, 0xb801643121e9f3b8
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v24, v8, t2

  li t2, 0x5e6080573293faa3
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v10, v22, t2

  li t2, 0xaf183c0d84467e8e
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v26, v4, t2

  li t2, 0x31a00dce4ddf6979
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v16, v6, t2

  li t2, 0xeae3c8fb37798188
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v28, v24, t2

  li t2, 0xd61023f06dc3a864
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhsu.vx v24, v4, t2

  li t2, 0xbe132547de346297
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v12, v8, t2

  li t2, 0x9a00b2ec098e3370
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v28, v12, t2

  li t2, 0xb042d31fe591594a
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v28, v12, t2

  li t2, 0xd4c028adf5accabe
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v24, v8, t2

  li t2, 0x56a591abf150b40d
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v20, v28, t2

  li t2, 0xd4beac98ed926aa6
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v24, v16, t2

  li t2, 0x50a8b4b54428db74
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v28, v8, t2

  li t2, 0xb838d167028817f9
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v24, v8, t2

  li t2, 0x8b7c47df10b63c18
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v12, v16, t2

  li t2, 0x8c5a1b23afa8c537
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhsu.vx v12, v16, t2

  li t2, 0x7f5b375c9e120d70
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  li t2, 0x82e8342d606c90bf
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  li t2, 0x13a13d5fc732d7b3
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  li t2, 0x17ffa91dacbe1084
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v8, v16, t2

  li t2, 0xaaaccf541544152a
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  li t2, 0x85bc806b6f9fac4a
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  li t2, 0xc4874c5cd8a6873e
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  li t2, 0x222fbd54f3ccc2e9
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  li t2, 0x1fb694c67ef957c2
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  li t2, 0xdb6b267f5d26aed1
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  li t2, 0x892c9509f503ce70
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v18, v15, t2

  li t2, 0x92aeed1cdb8325d0
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v15, v6, t2

  li t2, 0x6de157ec7306da8f
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v17, v28, t2

  li t2, 0xffde4f6a4c30c238
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v6, v1, t2

  li t2, 0xbb5cae0c5b8c5cc5
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v18, v29, t2

  li t2, 0x36c22b927038eefd
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v18, v6, t2

  li t2, 0xdf50c25086847b19
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v18, v11, t2

  li t2, 0x6b5af6c83a478a8a
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v23, v5, t2

  li t2, 0x2b147c976f735fa9
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v7, v30, t2

  li t2, 0x534504e271185f08
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhsu.vx v1, v7, t2

  li t2, 0x0c0ea3215942a5a2
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v6, v20, t2

  li t2, 0xea239bd518042be9
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v20, v28, t2

  li t2, 0xa8c67d9f6cb2744f
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v14, v24, t2

  li t2, 0x87af30faf0deb0e4
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v12, v18, t2

  li t2, 0x0da4ecffeca20f93
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v30, v10, t2

  li t2, 0xc8d783ef003c2c89
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v10, v6, t2

  li t2, 0xf0578b82cc5a5e0d
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v28, v24, t2

  li t2, 0x6ff313893c014847
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v20, v14, t2

  li t2, 0x0d2a6c2aa9c331c5
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v4, v6, t2

  li t2, 0x69ef9ab278e1492b
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhsu.vx v18, v28, t2

  li t2, 0x8335da3ac21d763d
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v8, v16, t2

  li t2, 0x92674f32b2c5e3da
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v16, v8, t2

  li t2, 0x0d7d65a4e0a3f8f1
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v28, v12, t2

  li t2, 0x5663c166023ba5f3
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v8, v24, t2

  li t2, 0x47e30e41a6ab9da5
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v16, v24, t2

  li t2, 0x56f9b631b2ae651e
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v20, v8, t2

  li t2, 0x20c1155494ece676
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v20, v8, t2

  li t2, 0x678abeaf608c66b9
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v24, v8, t2

  li t2, 0x79d413337ad4d08d
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v8, v28, t2

  li t2, 0x0c64411ea6c34c3d
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhsu.vx v28, v20, t2

  li t2, 0x2c7260bff411f16a
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  li t2, 0x2de7d976a630c024
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  li t2, 0x16d823a7783145ab
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v8, v24, t2

  li t2, 0xd3ba24f06b7b7af8
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v24, v8, t2

  li t2, 0xe4edc197bb66e3a2
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v24, t2

  li t2, 0xcc7e083365bc463b
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  li t2, 0x77032581a3e1d1d5
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  li t2, 0xed0a79de323a6e75
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v24, v16, t2

  li t2, 0x52f3be227fdba895
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v16, v8, t2

  li t2, 0x1229f9920f470dba
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhsu.vx v8, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
