#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v5, v11, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v26, v28, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v23, v31, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v1, v3, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v20, v17, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v26, v29, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v9, v16, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v28, v22, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v6, v20, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vv v17, v8, v27

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v22, v26, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v22, v24, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v28, v22, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v12, v2, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v20, v26, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v24, v10, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v4, v14, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v30, v2, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v18, v26, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vv v24, v20, v2

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v24, v12, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v8, v20, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v16, v20, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v20, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v8, v24, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v16, v28, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v20, v4, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v16, v28, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vv v8, v24, v20

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vv v16, v24, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v2, v31, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v3, v2, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v7, v28, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v6, v31, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v25, v23, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v28, v23, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v10, v23, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v22, v14, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v18, v26, v9

  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vv v21, v5, v17

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v22, v12, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v10, v6, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v18, v30, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v30, v18, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v10, v18, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v20, v14, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v8, v24, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v24, v30, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v18, v28, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vv v16, v28, v22

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v8, v12, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v16, v24, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v28, v8, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v20, v28, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v4, v28, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v12, v24, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v16, v12, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v28, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v4, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vv v28, v16, v4

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vv v8, v24, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v1, v21, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v21, v29, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v7, v11, v5

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v25, v16, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v14, v8, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v5, v12, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v22, v20, v31

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v21, v28, v17

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v21, v16, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vv v6, v2, v15

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v2, v24, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v8, v10, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v8, v14, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v22, v4, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v22, v24, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v16, v30, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v20, v30, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v10, v8, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v10, v6, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vv v12, v14, v10

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v28, v12, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v8, v12, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v4, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v12, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v20, v4, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v12, v4, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v24, v4, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v20, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v24, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vv v16, v4, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vv v24, v8, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v24, v4, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v30, v7, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v31, v28, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v19, v27, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v10, v27, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v23, v4, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v31, v1, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v18, v15, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v16, v14, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vv v14, v27, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v26, v20, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v6, v28, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v10, v4, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v16, v12, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v2, v6, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v16, v2, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v14, v22, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v12, v26, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v8, v2, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vv v10, v12, v26

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v12, v24, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v20, v24, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v4, v16, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v20, v24, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v8, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v4, v20, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v8, v16, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v24, v20, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v12, v16, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vv v28, v12, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vv v24, v16, v8

  li t2, 0xf871fc788632634d
  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v20, v15, t2

  li t2, 0xd08d744a5b11fcbf
  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v28, v5, t2

  li t2, 0x72177c17067f5702
  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v13, v4, t2

  li t2, 0xe145bbca3e3c733c
  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v31, v23, t2

  li t2, 0x37adadf8713abc6d
  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v3, v27, t2

  li t2, 0x3258d3c01e175272
  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v28, v31, t2

  li t2, 0xaccc808eb52d1cd6
  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v13, v31, t2

  li t2, 0x600e5dabe141d4ab
  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v1, v17, t2

  li t2, 0xceeab8eca9e340d1
  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v25, v12, t2

  li t2, 0x7f2d4dd6490c05d2
  vsetvli t1, t0, e8, m1, ta, ma
  vrem.vx v31, v22, t2

  li t2, 0x83f34fcef6fce6ea
  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v14, v28, t2

  li t2, 0x30b524442700c9e0
  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v6, v2, t2

  li t2, 0xe5dd263d58a2aa36
  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v14, v4, t2

  li t2, 0x8b4dae44bbbcddab
  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v30, v2, t2

  li t2, 0xfcebdcacb4982d6f
  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v16, v30, t2

  li t2, 0x2d957809db21d118
  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v4, v26, t2

  li t2, 0x9e06513428315616
  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v28, v8, t2

  li t2, 0xc399521cba95462c
  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v24, v14, t2

  li t2, 0xdb4bab754fdffb8c
  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v22, v18, t2

  li t2, 0x4079aa3b7b49979f
  vsetvli t1, t0, e8, m2, ta, ma
  vrem.vx v2, v28, t2

  li t2, 0xe92c3833ba69c4fa
  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v16, v8, t2

  li t2, 0x6db74288aa63d02d
  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v4, v20, t2

  li t2, 0xe85c23bf4e95d988
  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v16, v20, t2

  li t2, 0x281d0cd66d77cf25
  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v20, v4, t2

  li t2, 0xc993601e5afd085c
  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v24, v20, t2

  li t2, 0x3e589d65a6d9687c
  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v20, v16, t2

  li t2, 0x5f13855daced7ea2
  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v8, v28, t2

  li t2, 0xdcc5f3f78460fdc8
  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v4, v20, t2

  li t2, 0xf9061cca7a2f1813
  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v8, v16, t2

  li t2, 0x40824ec4bbcd8d71
  vsetvli t1, t0, e8, m4, ta, ma
  vrem.vx v20, v4, t2

  li t2, 0xd8a09cbf30b76de1
  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v24, t2

  li t2, 0xde2afbd7d8b4c7db
  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v16, t2

  li t2, 0xf39014846708623e
  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v8, t2

  li t2, 0xcac333c7906c22c6
  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v8, v24, t2

  li t2, 0xa728ced13c228e8f
  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v24, v16, t2

  li t2, 0xf2389669583df559
  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v24, t2

  li t2, 0x353fb5f06efc1f05
  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v24, t2

  li t2, 0xc1e387f6f86c5735
  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v24, t2

  li t2, 0x8d46943f217d5b4f
  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v16, v24, t2

  li t2, 0xdf1685427de0043f
  vsetvli t1, t0, e8, m8, ta, ma
  vrem.vx v24, v8, t2

  li t2, 0x3875148bbb4acdc5
  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v6, v13, t2

  li t2, 0x372c183c80ec1f53
  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v20, v10, t2

  li t2, 0xcb56693eea4ac949
  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v15, v24, t2

  li t2, 0x0fe297722824a3ce
  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v4, v25, t2

  li t2, 0x0af3ce90c2e1d62b
  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v2, v21, t2

  li t2, 0x5d3856b3889b427f
  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v5, v29, t2

  li t2, 0xe3f65bcb4b5a2819
  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v24, v15, t2

  li t2, 0xfc53f82b12b169d0
  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v25, v6, t2

  li t2, 0xf6979ff4e144dbce
  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v3, v14, t2

  li t2, 0x6a35f0659689b814
  vsetvli t1, t0, e16, m1, ta, ma
  vrem.vx v6, v21, t2

  li t2, 0x3058dbfa52e3bc02
  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v6, v12, t2

  li t2, 0x07e8e47d473ea3c9
  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v16, v20, t2

  li t2, 0xd479b946d3e5fb29
  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v24, v4, t2

  li t2, 0xf1b1aa67453ce27d
  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v12, v18, t2

  li t2, 0x284b1316bef36afa
  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v26, v2, t2

  li t2, 0x98f4151f0a8c6dca
  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v24, v10, t2

  li t2, 0xc76084e326ea50c3
  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v20, v4, t2

  li t2, 0xc09f645ecc5918c9
  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v4, v20, t2

  li t2, 0xe36f4d2650f53b48
  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v30, v2, t2

  li t2, 0xfb50c1615c700bbc
  vsetvli t1, t0, e16, m2, ta, ma
  vrem.vx v2, v22, t2

  li t2, 0xb34313fe1e8ca595
  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v28, v12, t2

  li t2, 0xd62f5993b2ab46a3
  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v24, v20, t2

  li t2, 0x9774a53ac643baef
  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v28, v16, t2

  li t2, 0x61b22dc3a3537541
  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v16, v24, t2

  li t2, 0x96e387737bbda030
  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v12, v4, t2

  li t2, 0x0f7361b098ddc85d
  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v12, v8, t2

  li t2, 0xd32bffb64662472a
  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v28, v16, t2

  li t2, 0x8ac9ee5f34b91ccf
  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v4, v8, t2

  li t2, 0xa513673b62539e48
  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v28, v16, t2

  li t2, 0x267a11bff0082aae
  vsetvli t1, t0, e16, m4, ta, ma
  vrem.vx v4, v8, t2

  li t2, 0x68fbb2fc2446fbf9
  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v8, t2

  li t2, 0xd8ed458f1f58ff33
  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v24, t2

  li t2, 0x437a069b8e46b553
  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v24, t2

  li t2, 0x0e121a8039e9d9a5
  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v24, t2

  li t2, 0x7fe825e4feccc012
  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v24, t2

  li t2, 0x89608843ba2f89e5
  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v24, t2

  li t2, 0x8fcd9aa13afb4821
  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v8, v16, t2

  li t2, 0x03a1bb37ed2bbabf
  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v24, v8, t2

  li t2, 0x5e8d4c361b386b2e
  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v8, v16, t2

  li t2, 0xbcae0cb0c6acc7f3
  vsetvli t1, t0, e16, m8, ta, ma
  vrem.vx v16, v8, t2

  li t2, 0x52e77587f85fc7f0
  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v11, v28, t2

  li t2, 0x6d0c1a5e3a75ac53
  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v5, v11, t2

  li t2, 0xbe75ad12f783ff01
  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v12, v30, t2

  li t2, 0xe1ccd6e304ea48d7
  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v14, v29, t2

  li t2, 0xcafd90a254c61347
  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v24, v18, t2

  li t2, 0x7392febbdd1fcceb
  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v26, v6, t2

  li t2, 0x5e18a549f681f9d9
  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v9, v31, t2

  li t2, 0xcc7783a50ed6f589
  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v26, v13, t2

  li t2, 0x5930192581833a8f
  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v23, v9, t2

  li t2, 0xa2d1513224204e17
  vsetvli t1, t0, e32, m1, ta, ma
  vrem.vx v11, v5, t2

  li t2, 0x3f7163c1791e3f20
  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v24, v22, t2

  li t2, 0xe6924d88ee5be96b
  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v8, v16, t2

  li t2, 0xd6111d168d32b9dc
  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v12, v18, t2

  li t2, 0x518572f464024390
  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v20, v18, t2

  li t2, 0xdd8d722a34c4dad5
  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v4, v12, t2

  li t2, 0x6091c34aa93dfe29
  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v18, v2, t2

  li t2, 0xf2927e937a50afc0
  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v4, v2, t2

  li t2, 0xf925bb3960ef4591
  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v28, v4, t2

  li t2, 0xabfe93f9be5e04fb
  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v8, v10, t2

  li t2, 0x2bcb897e0f07e948
  vsetvli t1, t0, e32, m2, ta, ma
  vrem.vx v12, v28, t2

  li t2, 0x86b7486f90d72b6b
  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v4, v12, t2

  li t2, 0x96f5e9fd357d1cb5
  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v20, v8, t2

  li t2, 0x148619f2ca6bf40b
  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v24, v16, t2

  li t2, 0x80bcc303aee96895
  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v12, v24, t2

  li t2, 0xf0f242e3dddc3a16
  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v4, v16, t2

  li t2, 0x1621a03268070eed
  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v12, v28, t2

  li t2, 0x39236de460833e6b
  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v4, v16, t2

  li t2, 0x44f8af13ab6d6b24
  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v8, v12, t2

  li t2, 0x321456ba20268a49
  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v28, v12, t2

  li t2, 0x65c849f6674a697e
  vsetvli t1, t0, e32, m4, ta, ma
  vrem.vx v12, v20, t2

  li t2, 0x1357979e17447e27
  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v16, t2

  li t2, 0x48073ca3df930d4a
  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v16, t2

  li t2, 0xce992bb26d27e34e
  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v16, v24, t2

  li t2, 0xd6398f0a27141c6d
  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v24, t2

  li t2, 0x9cd2938af7e2cd41
  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v24, t2

  li t2, 0x7cd59c4a973edd54
  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v16, v8, t2

  li t2, 0xa0146dc522f1bc72
  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v24, v8, t2

  li t2, 0x8f60ff860bc80023
  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v8, v24, t2

  li t2, 0x944761d6b3234756
  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v24, v8, t2

  li t2, 0x9b27094de82430b6
  vsetvli t1, t0, e32, m8, ta, ma
  vrem.vx v24, v8, t2

  li t2, 0x0028452732923423
  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v31, v5, t2

  li t2, 0xfa0882a509abea30
  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v31, v20, t2

  li t2, 0x458fc6568acfd82f
  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v4, v31, t2

  li t2, 0xca4523578bb21ee1
  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v15, v27, t2

  li t2, 0x3d65734730b96b87
  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v4, v7, t2

  li t2, 0x108c25fdca8b7112
  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v21, v11, t2

  li t2, 0x0d6e0d477e9a6d7c
  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v11, v12, t2

  li t2, 0x376fc89d7c36aac4
  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v20, v8, t2

  li t2, 0x754c8dc984fc9121
  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v18, v2, t2

  li t2, 0xa2c21f0e376c9b01
  vsetvli t1, t0, e64, m1, ta, ma
  vrem.vx v7, v31, t2

  li t2, 0x19eb9b68c389284a
  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v24, v10, t2

  li t2, 0xb9084c3b286ded0e
  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v26, v20, t2

  li t2, 0xe7775f009fe74314
  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v30, v6, t2

  li t2, 0xc5d4083d7fc4b84b
  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v28, v4, t2

  li t2, 0xf9ae1c1902e3cb94
  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v28, v12, t2

  li t2, 0x3420d69e57f0b358
  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v4, v16, t2

  li t2, 0x03ce6816572a2a03
  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v20, v4, t2

  li t2, 0x4fe17e69b2c1602f
  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v12, v10, t2

  li t2, 0x47b2da372843dc60
  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v28, v22, t2

  li t2, 0x2a6d8bb1aa5aeaef
  vsetvli t1, t0, e64, m2, ta, ma
  vrem.vx v28, v2, t2

  li t2, 0xc2c51a97a920213c
  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v20, v28, t2

  li t2, 0x07d47af30454b96f
  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v8, v16, t2

  li t2, 0xf18d2eb61952667b
  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v12, v28, t2

  li t2, 0x46249ecde0a027dc
  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v4, v24, t2

  li t2, 0x05dac8a0793bb6bd
  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v4, v20, t2

  li t2, 0x3140b20edeee8377
  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v24, v16, t2

  li t2, 0xf5062a7e38fda020
  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v24, v28, t2

  li t2, 0x1a82d114ec7a9997
  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v20, v24, t2

  li t2, 0x9e737bd22ef53111
  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v4, v28, t2

  li t2, 0x9cfb1531bb802045
  vsetvli t1, t0, e64, m4, ta, ma
  vrem.vx v24, v8, t2

  li t2, 0xbe0a9904a9eddae8
  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v8, t2

  li t2, 0x32751303ce0b9f09
  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v16, v24, t2

  li t2, 0x60ff64e836150536
  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v8, v24, t2

  li t2, 0xcc84125dc34182bb
  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v16, v24, t2

  li t2, 0xe9bda51b5b830668
  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v16, v24, t2

  li t2, 0x60b6ee91aecdc50e
  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v8, t2

  li t2, 0xbadd9739070bfe5a
  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v16, t2

  li t2, 0x4b1b536cfb42b84b
  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v16, v24, t2

  li t2, 0x4b985fa994563f03
  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v16, t2

  li t2, 0x62a1e0046c1b4d56
  vsetvli t1, t0, e64, m8, ta, ma
  vrem.vx v24, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
