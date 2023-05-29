#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v2, v8, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v23, v3, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v24, v1, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v7, v3, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v22, v25, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v20, v31, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v30, v3, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v1, v8, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v11, v30, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vv v5, v29, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v26, v16, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v24, v10, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v14, v2, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v30, v22, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v18, v28, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v18, v12, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v20, v16, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v20, v28, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v26, v6, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vv v30, v18, v26

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v16, v4, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v16, v28, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v12, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v12, v24, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v4, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v20, v4, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v16, v24, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v4, v24, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v4, v8, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vv v24, v8, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v27, v3, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v16, v23, v27

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v1, v25, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v20, v30, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v11, v21, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v1, v24, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v8, v20, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v19, v27, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v6, v21, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vv v21, v18, v17

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v18, v26, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v26, v12, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v8, v16, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v8, v18, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v26, v8, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v12, v8, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v16, v2, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v28, v30, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v16, v30, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vv v16, v18, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v20, v16, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v12, v20, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v12, v4, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v20, v16, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v20, v16, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v12, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v28, v20, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v24, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v20, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vv v16, v28, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vv v24, v16, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v7, v9, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v16, v25, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v22, v28, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v24, v14, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v28, v24, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v28, v30, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v18, v11, v31

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v28, v6, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v11, v13, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vv v28, v23, v13

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v8, v26, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v22, v2, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v24, v16, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v8, v20, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v8, v6, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v20, v10, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v6, v24, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v30, v4, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v26, v24, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vv v4, v14, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v4, v20, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v28, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v8, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v12, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v16, v12, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v20, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v24, v8, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v20, v4, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vv v24, v28, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vv v24, v8, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v31, v1, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v18, v29, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v14, v20, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v6, v5, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v19, v28, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v10, v15, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v14, v19, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v25, v14, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v20, v19, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vv v13, v16, v3

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v30, v8, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v16, v4, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v12, v30, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v8, v22, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v14, v10, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v22, v2, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v4, v12, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v8, v6, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v30, v8, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vv v2, v28, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v20, v8, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v20, v28, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v12, v8, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v16, v4, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v16, v4, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v8, v12, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v4, v20, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v8, v28, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v4, v12, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vv v24, v20, v4

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vv v8, v24, v16

  li t2, 0x66bfc1744da5c3a3
  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v12, v9, t2

  li t2, 0x503fe80299245fcb
  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v5, v15, t2

  li t2, 0x1b0f4781eae7b5df
  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v31, v19, t2

  li t2, 0x347b234a936d6af0
  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v24, v5, t2

  li t2, 0xb7c00c6d2c9e023c
  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v7, v20, t2

  li t2, 0xd9db62ac3d5f70a3
  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v20, v6, t2

  li t2, 0x24b3087876a908d2
  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v6, v23, t2

  li t2, 0x7f859c08dc94359d
  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v20, v26, t2

  li t2, 0x05607029cc3a8cdf
  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v14, v22, t2

  li t2, 0xffd819339d8d530a
  vsetvli t1, t0, e8, m1, ta, ma
  vmul.vx v6, v11, t2

  li t2, 0x374f177b6a2d0cb1
  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v22, v2, t2

  li t2, 0xdbb31c747f923e75
  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v12, v28, t2

  li t2, 0x94d7d19aa27ba2ea
  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v20, v6, t2

  li t2, 0x6443dead0fc5fb77
  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v2, v22, t2

  li t2, 0x3c5430e354348b6c
  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v10, v24, t2

  li t2, 0xa0dee61b01b46dcb
  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v10, v28, t2

  li t2, 0xcb45815fc6ed2716
  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v22, v28, t2

  li t2, 0x870d20bf8ea924bf
  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v10, v18, t2

  li t2, 0x0a4c638bb3412fde
  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v18, v10, t2

  li t2, 0x30655fa8aec6180e
  vsetvli t1, t0, e8, m2, ta, ma
  vmul.vx v14, v10, t2

  li t2, 0xab18bf48bf6c49fd
  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v12, v24, t2

  li t2, 0x20b69d3444dfe445
  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v20, v12, t2

  li t2, 0x8c9804fb9696dc93
  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v20, v28, t2

  li t2, 0x9a37b944a09e6d07
  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v24, v12, t2

  li t2, 0x0165aac83d8c3102
  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v8, v16, t2

  li t2, 0x09f10e254f4729f6
  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v8, v16, t2

  li t2, 0x3b734d8d18b1683a
  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v16, v4, t2

  li t2, 0x3a0eedcc4cf2cae9
  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v24, v20, t2

  li t2, 0xff85705de9925647
  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v12, v8, t2

  li t2, 0xe683f5f5abffb671
  vsetvli t1, t0, e8, m4, ta, ma
  vmul.vx v24, v20, t2

  li t2, 0x1ca0336a182a5735
  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v8, v16, t2

  li t2, 0x5e4a3114c432494e
  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v16, v24, t2

  li t2, 0xbebf93f5fe8c3e85
  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v8, v24, t2

  li t2, 0x52dc1de30ff4f7e5
  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v8, v16, t2

  li t2, 0xe71f19de778b93cd
  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v24, v8, t2

  li t2, 0xf7f006ced723e63c
  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v16, v24, t2

  li t2, 0x4a27b677086b5450
  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v24, v16, t2

  li t2, 0x1117499b44e65cb9
  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v16, v24, t2

  li t2, 0x6f4a1ee9d79943ef
  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v8, v24, t2

  li t2, 0xe0c22dce4912f485
  vsetvli t1, t0, e8, m8, ta, ma
  vmul.vx v8, v24, t2

  li t2, 0x3f51f685a5613334
  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v5, v9, t2

  li t2, 0xbfa34254201a430e
  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v17, v29, t2

  li t2, 0x73270c7365531dc9
  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v8, v20, t2

  li t2, 0x4ead5a154be9723c
  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v2, v13, t2

  li t2, 0x133248cc8fc7e4d5
  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v17, v10, t2

  li t2, 0x5e1f583d67ce2c74
  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v27, v6, t2

  li t2, 0xc7bcee64ef5f52c1
  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v14, v11, t2

  li t2, 0x1cbb5755f52d6c67
  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v20, v11, t2

  li t2, 0xcf18eaf890d9367d
  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v17, v2, t2

  li t2, 0x0790a5f1612ef727
  vsetvli t1, t0, e16, m1, ta, ma
  vmul.vx v3, v13, t2

  li t2, 0xa11a759efbb8cfaa
  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v12, v28, t2

  li t2, 0x3e3ad9d8784560c6
  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v26, v10, t2

  li t2, 0xf44ebe227d456fd6
  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v8, v26, t2

  li t2, 0x14587cd34d3cc219
  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v28, v16, t2

  li t2, 0x4281337dfbe96637
  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v14, v8, t2

  li t2, 0x0077a14f63b1dc38
  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v26, v8, t2

  li t2, 0x6a0c9a86b5d7c150
  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v10, v6, t2

  li t2, 0x49dbc4330f0ffc25
  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v14, v16, t2

  li t2, 0xe62625b562fef60d
  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v12, v8, t2

  li t2, 0xe9c770413f60e5da
  vsetvli t1, t0, e16, m2, ta, ma
  vmul.vx v28, v2, t2

  li t2, 0x5ad1baa55d1b523c
  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v24, v28, t2

  li t2, 0xbb62c212d8cda96b
  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v28, v4, t2

  li t2, 0x75dcf2179b44bd65
  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v8, v28, t2

  li t2, 0x4b25c5fd98695613
  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v12, v24, t2

  li t2, 0x49522e9035b2fe2a
  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v28, v16, t2

  li t2, 0x27f3029614b15e52
  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v28, v16, t2

  li t2, 0xdf8995c4568a70f1
  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v4, v20, t2

  li t2, 0x7111acccc9416fe8
  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v16, v4, t2

  li t2, 0x28cbf23154f3d7a6
  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v4, v28, t2

  li t2, 0x198a62a31a736d9e
  vsetvli t1, t0, e16, m4, ta, ma
  vmul.vx v28, v24, t2

  li t2, 0x21b2777ff7b40ed5
  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v16, t2

  li t2, 0xf07900653457a126
  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v16, t2

  li t2, 0x36e0f17417d3f924
  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v24, v16, t2

  li t2, 0xd5670d3917bba826
  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v8, v16, t2

  li t2, 0x7e7e7bfeab5df856
  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v16, v8, t2

  li t2, 0x38f0715f8f1753e3
  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v8, v16, t2

  li t2, 0x02c8b1087bb9e59c
  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v8, v24, t2

  li t2, 0xab5f2fe286e5122a
  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v16, v24, t2

  li t2, 0xa7b9065a8eb34d50
  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v16, v8, t2

  li t2, 0x3bb5e8ee5a83a6fe
  vsetvli t1, t0, e16, m8, ta, ma
  vmul.vx v16, v24, t2

  li t2, 0x1e1115a2d27813ba
  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v31, v4, t2

  li t2, 0x9772c3b6361f5f08
  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v8, v19, t2

  li t2, 0x077f871087d16028
  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v13, v25, t2

  li t2, 0xb5363bbd8be4d513
  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v28, v11, t2

  li t2, 0xe1d9349795fc0321
  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v26, v30, t2

  li t2, 0x8587cca6b1f08ac9
  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v8, v22, t2

  li t2, 0x01253b87c0109a71
  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v9, v27, t2

  li t2, 0x92b70e0448d1a673
  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v2, v1, t2

  li t2, 0x8e8684017245b4de
  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v15, v25, t2

  li t2, 0x608d113e7fee475c
  vsetvli t1, t0, e32, m1, ta, ma
  vmul.vx v21, v19, t2

  li t2, 0xebdac0b8b5c1b428
  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v16, v22, t2

  li t2, 0xbd2a7ccae2480bce
  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v26, v30, t2

  li t2, 0xe8cf3b00f97fd7c8
  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v18, v26, t2

  li t2, 0x7753e4aa3b3b2b64
  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v20, v10, t2

  li t2, 0x126a3dbb708c16ce
  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v26, v20, t2

  li t2, 0x2eccdbe3289cfd83
  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v6, v26, t2

  li t2, 0x39877a02dd676107
  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v28, v20, t2

  li t2, 0xedca7e74d9accaba
  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v20, v10, t2

  li t2, 0xdf6e6239b1c9462b
  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v16, v24, t2

  li t2, 0x3e998d3d4b86e6ae
  vsetvli t1, t0, e32, m2, ta, ma
  vmul.vx v6, v26, t2

  li t2, 0x0c7ee155393edd2b
  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v12, v16, t2

  li t2, 0xcdde6340133b7959
  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v24, v8, t2

  li t2, 0xfbc33071e55505e0
  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v4, v12, t2

  li t2, 0xcd8d636fc87dd93b
  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v28, v16, t2

  li t2, 0x8a709cab5cf62716
  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v4, v24, t2

  li t2, 0x8e43325c6e420bb3
  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v8, v16, t2

  li t2, 0xd179d34c8c19ee71
  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v16, v4, t2

  li t2, 0xf81f851d9543b066
  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v12, v4, t2

  li t2, 0x7a23343d9cb60afd
  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v12, v4, t2

  li t2, 0x0f167950898415be
  vsetvli t1, t0, e32, m4, ta, ma
  vmul.vx v28, v16, t2

  li t2, 0xaba246e6c10cd150
  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v16, t2

  li t2, 0x66b6c869126c6841
  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v8, v16, t2

  li t2, 0x1e5c288863b2bec1
  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v8, v24, t2

  li t2, 0x5f8c17b4402ce4dd
  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v16, v24, t2

  li t2, 0x5322205e1cc88fa9
  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v16, v24, t2

  li t2, 0x26cec0342f8fbb71
  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v8, t2

  li t2, 0x29a2da460c5e07f4
  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v8, v16, t2

  li t2, 0xa5cbc2f284c22b3d
  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v8, t2

  li t2, 0xac79c052c398c99a
  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v8, t2

  li t2, 0xb4cd4eff74ba2cd9
  vsetvli t1, t0, e32, m8, ta, ma
  vmul.vx v24, v8, t2

  li t2, 0x69b60f062bca3305
  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v17, v9, t2

  li t2, 0x7019de3c83944c8a
  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v1, v16, t2

  li t2, 0xdf0e52557e6b33bb
  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v18, v30, t2

  li t2, 0xf6b5da6695e8b8ea
  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v25, v8, t2

  li t2, 0xa21516aa0ccc8473
  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v25, v24, t2

  li t2, 0x390f4fd1b265e85d
  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v8, v21, t2

  li t2, 0x4a1fdce058ec302a
  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v25, v28, t2

  li t2, 0xe6fd615548803228
  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v22, v16, t2

  li t2, 0x8b77373c5d359db3
  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v17, v9, t2

  li t2, 0xb5fcf5c5876cfdc3
  vsetvli t1, t0, e64, m1, ta, ma
  vmul.vx v5, v2, t2

  li t2, 0x87cb9cdb44042db8
  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v6, v4, t2

  li t2, 0x76f7a8e2e0e2dead
  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v14, v22, t2

  li t2, 0x6ce47144521e1dc6
  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v28, v8, t2

  li t2, 0xc1c87088d76bc1b7
  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v10, v28, t2

  li t2, 0xf4a1534001445dc4
  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v8, v24, t2

  li t2, 0x40cd7509b288690e
  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v20, v30, t2

  li t2, 0x360be7e38803aca2
  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v20, v18, t2

  li t2, 0x46e2212c163a81d2
  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v8, v30, t2

  li t2, 0xc024231b23de2f4e
  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v18, v26, t2

  li t2, 0xf99967f4b86db73c
  vsetvli t1, t0, e64, m2, ta, ma
  vmul.vx v16, v2, t2

  li t2, 0x7256905255caa789
  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v16, v12, t2

  li t2, 0x8027c517f98bc5d0
  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v8, v28, t2

  li t2, 0xe6eac842f0caed00
  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v12, v24, t2

  li t2, 0xc3f54486caaf2113
  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v12, v8, t2

  li t2, 0x3fb2919089e0e97d
  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v4, v8, t2

  li t2, 0x463ef9c8fe0271a3
  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v28, v20, t2

  li t2, 0xf5909da8635977bb
  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v12, v16, t2

  li t2, 0x2bcfdca8d5a6c230
  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v24, v12, t2

  li t2, 0x0ece6ea0d66bf4ef
  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v8, v16, t2

  li t2, 0xd29efd1a65da4d41
  vsetvli t1, t0, e64, m4, ta, ma
  vmul.vx v8, v16, t2

  li t2, 0x6d82dfe50e93ae44
  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v8, v24, t2

  li t2, 0xc2f54fb4437500d1
  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v24, t2

  li t2, 0xf4284b9b418bdc7d
  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v24, v8, t2

  li t2, 0xde4b51eb722aabae
  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v24, v16, t2

  li t2, 0x6d241e278cf74c29
  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v24, t2

  li t2, 0x2f72015b6590e812
  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v8, v24, t2

  li t2, 0x27397eb299dc8cf4
  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v16, v24, t2

  li t2, 0xb6ab99eff7bad9a3
  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v24, v8, t2

  li t2, 0x5fd4bf09efcf9b39
  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v24, v8, t2

  li t2, 0x26eb1bf5cfac0992
  vsetvli t1, t0, e64, m8, ta, ma
  vmul.vx v24, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
