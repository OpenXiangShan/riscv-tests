#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vv v9, v31, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vv v10, v25, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vv v29, v6, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vv v22, v17, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vv v7, v21, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vv v10, v12, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vv v1, v17, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vv v14, v31, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vv v14, v11, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vv v26, v6, v3

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vv v20, v26, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vv v8, v28, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vv v2, v10, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vv v8, v16, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vv v22, v6, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vv v10, v2, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vv v10, v12, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vv v22, v10, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vv v12, v10, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vv v26, v4, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vv v24, v28, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vv v24, v20, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vv v4, v20, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vv v24, v16, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vv v8, v4, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vv v28, v12, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vv v4, v24, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vv v16, v20, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vv v24, v4, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vv v24, v12, v28

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vv v24, v16, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vv v30, v7, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vv v8, v26, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vv v20, v14, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vv v15, v5, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vv v19, v1, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vv v23, v29, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vv v21, v14, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vv v15, v8, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vv v5, v15, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vv v30, v10, v21

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vv v8, v20, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vv v18, v24, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vv v6, v22, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vv v6, v16, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vv v16, v6, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vv v2, v4, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vv v14, v12, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vv v4, v12, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vv v12, v22, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vv v6, v26, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vv v20, v24, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vv v20, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vv v8, v16, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vv v8, v28, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vv v20, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vv v16, v20, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vv v8, v28, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vv v8, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vv v12, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vv v4, v12, v20

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vv v8, v16, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vv v26, v31, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vv v13, v2, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vv v3, v14, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vv v8, v5, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vv v27, v17, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vv v7, v14, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vv v8, v13, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vv v7, v23, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vv v1, v31, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vv v9, v16, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vv v8, v14, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vv v14, v24, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vv v6, v20, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vv v4, v8, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vv v26, v28, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vv v14, v10, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vv v18, v26, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vv v18, v2, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vv v20, v26, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vv v4, v2, v26

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vv v4, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vv v8, v16, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vv v20, v12, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vv v28, v24, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vv v28, v20, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vv v28, v4, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vv v8, v28, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vv v20, v4, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vv v28, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vv v20, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vv v8, v24, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vv v8, v5, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vv v24, v30, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vv v4, v3, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vv v29, v6, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vv v27, v25, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vv v9, v15, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vv v12, v24, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vv v7, v19, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vv v20, v18, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vv v15, v11, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vv v10, v14, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vv v2, v8, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vv v10, v22, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vv v24, v20, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vv v8, v24, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vv v26, v4, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vv v10, v20, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vv v12, v26, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vv v22, v18, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vv v28, v22, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vv v24, v4, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vv v8, v20, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vv v28, v4, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vv v12, v4, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vv v12, v24, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vv v16, v28, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vv v28, v20, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vv v16, v12, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vv v8, v12, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vv v12, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vv v16, v24, v8

  li t2, 0x022766a9d749d9e3
  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vx v13, v8, t2

  li t2, 0xef206267619cb109
  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vx v22, v14, t2

  li t2, 0x67037a98d2edc0ca
  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vx v24, v5, t2

  li t2, 0x4489cc4b830ba5b7
  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vx v12, v23, t2

  li t2, 0x14d9d0d913a23e66
  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vx v7, v16, t2

  li t2, 0xda6a24104d3213bc
  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vx v31, v29, t2

  li t2, 0xa98dc4a9f0b15f0d
  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vx v17, v31, t2

  li t2, 0x0d40ef4f89c44e53
  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vx v14, v8, t2

  li t2, 0x45e5526de6319d4f
  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vx v3, v28, t2

  li t2, 0x2378d943f8eb249b
  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vx v21, v30, t2

  li t2, 0x6f3cb016b87eff2d
  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vx v22, v14, t2

  li t2, 0xb28a8bc54c30edc6
  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vx v12, v10, t2

  li t2, 0x8d6db177152f2709
  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vx v26, v30, t2

  li t2, 0x812101390c3b680c
  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vx v16, v6, t2

  li t2, 0x149fa2d46b9ccc43
  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vx v20, v8, t2

  li t2, 0x6103d3a30dc0b882
  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vx v16, v8, t2

  li t2, 0x890becdb7a4b008b
  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vx v28, v30, t2

  li t2, 0xef6dc3cb27a393bc
  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vx v28, v24, t2

  li t2, 0xfc5802a15641117c
  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vx v10, v12, t2

  li t2, 0xea98dd75fa6102fe
  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vx v2, v6, t2

  li t2, 0x3dd2dcc98799b6cb
  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vx v16, v8, t2

  li t2, 0xa745b07e15106cee
  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vx v4, v20, t2

  li t2, 0x8708ad590819a41d
  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vx v28, v20, t2

  li t2, 0x590ced19f184df2e
  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vx v28, v12, t2

  li t2, 0xcb38fb60f08f781a
  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vx v4, v12, t2

  li t2, 0x55cd17b328cb47ac
  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vx v24, v16, t2

  li t2, 0xeb60d2647c67fc89
  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vx v4, v28, t2

  li t2, 0xfaea662389be5c0b
  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vx v28, v24, t2

  li t2, 0xc01b1ae8bfbce8a1
  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vx v28, v12, t2

  li t2, 0xe49e13266aa61493
  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vx v4, v24, t2

  li t2, 0x5c55f733f53f0653
  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vx v8, v24, t2

  li t2, 0x59220794b07206c1
  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vx v8, v24, t2

  li t2, 0x882a0cc2210c1191
  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vx v24, v8, t2

  li t2, 0xf74c70715f742375
  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vx v24, v16, t2

  li t2, 0xae92581fae80cc3a
  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vx v8, v16, t2

  li t2, 0x23ee4fc36583ffc3
  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vx v24, v16, t2

  li t2, 0x04ce0ca1b06baf18
  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vx v24, v8, t2

  li t2, 0x237857d8b05842b6
  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vx v16, v24, t2

  li t2, 0x170916cf453e11c7
  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vx v24, v16, t2

  li t2, 0xeda2c06ae28f8797
  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vx v16, v8, t2

  li t2, 0xf95d7c213ad34e14
  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vx v1, v9, t2

  li t2, 0xb14a74942032ad72
  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vx v19, v15, t2

  li t2, 0x70b790d336c555e9
  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vx v27, v13, t2

  li t2, 0x601b09793f2abdb1
  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vx v14, v5, t2

  li t2, 0x7d1ac03d17548142
  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vx v31, v16, t2

  li t2, 0x9a912431fdffe41f
  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vx v6, v30, t2

  li t2, 0x6dcb4ffd624f81c7
  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vx v28, v17, t2

  li t2, 0x573749c7ac28df52
  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vx v24, v1, t2

  li t2, 0xe6ceaf0ec6e51ced
  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vx v26, v2, t2

  li t2, 0x1cedc001dee36918
  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vx v16, v19, t2

  li t2, 0x73cac75fce604cb1
  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vx v26, v6, t2

  li t2, 0xbb731ba4db95ed11
  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vx v16, v10, t2

  li t2, 0x791d4c5f8fce61a5
  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vx v26, v14, t2

  li t2, 0x2cad9959d821e692
  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vx v28, v14, t2

  li t2, 0xdfb09ac6ab655b3f
  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vx v20, v6, t2

  li t2, 0x5623bb2b046ac691
  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vx v14, v2, t2

  li t2, 0x65f5271823ed867d
  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vx v8, v24, t2

  li t2, 0x11673aa9106859dd
  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vx v8, v6, t2

  li t2, 0xfdbfdaab8b110268
  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vx v26, v20, t2

  li t2, 0x0079ee3f386f2883
  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vx v14, v16, t2

  li t2, 0x164659d2c8db32f5
  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vx v8, v28, t2

  li t2, 0xe1f7213481c1fc93
  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vx v4, v12, t2

  li t2, 0x1891bc240bf69a22
  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vx v20, v28, t2

  li t2, 0x6a891254b9f89ab9
  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vx v16, v4, t2

  li t2, 0xeb46d267c0ad6f60
  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vx v12, v28, t2

  li t2, 0xddf1693c91b06e04
  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vx v4, v24, t2

  li t2, 0x314bb02c6a4b8fbb
  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vx v24, v4, t2

  li t2, 0xc06094f8a05ef48d
  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vx v8, v12, t2

  li t2, 0x72bb7c0458454d4e
  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vx v28, v12, t2

  li t2, 0xc84c11263d25202a
  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vx v4, v24, t2

  li t2, 0x72a608ba880fdc13
  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vx v8, v24, t2

  li t2, 0x48d47c44aa5f0ec4
  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vx v8, v16, t2

  li t2, 0x2045408bbff6e612
  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vx v8, v24, t2

  li t2, 0x178801a7da351417
  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vx v8, v24, t2

  li t2, 0x89fc6a852078ccd8
  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vx v16, v24, t2

  li t2, 0x2daeae5e920e2b02
  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vx v16, v8, t2

  li t2, 0xd3df84a6dfedcee0
  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vx v16, v8, t2

  li t2, 0x66f82ece54cc28e6
  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vx v16, v8, t2

  li t2, 0x4e7220a06ce809cf
  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vx v8, v16, t2

  li t2, 0x5a2a924cbf5d321c
  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vx v8, v16, t2

  li t2, 0xc4f8ffd9c91f9d30
  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vx v16, v30, t2

  li t2, 0x590235d4876dabed
  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vx v22, v30, t2

  li t2, 0x92a4f4972561d6a9
  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vx v10, v7, t2

  li t2, 0x5b9d06cba43d3701
  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vx v25, v14, t2

  li t2, 0xd579420550b72f0c
  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vx v5, v12, t2

  li t2, 0xcdf75468b662724e
  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vx v27, v23, t2

  li t2, 0xba720f8cbfa6a8df
  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vx v28, v15, t2

  li t2, 0x50289d70f1a978dd
  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vx v14, v4, t2

  li t2, 0x07f8be7b3b63327a
  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vx v13, v21, t2

  li t2, 0x2f77300eb579a9f7
  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vx v10, v14, t2

  li t2, 0xeae7f2b9b12c9630
  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vx v16, v10, t2

  li t2, 0xfa8d6d0baf13d583
  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vx v20, v4, t2

  li t2, 0xf44c51563af2c3d8
  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vx v26, v20, t2

  li t2, 0x57a30e3f7d907d91
  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vx v24, v10, t2

  li t2, 0x81804c6c2888974d
  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vx v26, v22, t2

  li t2, 0xfd72e05f0c072dcd
  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vx v8, v18, t2

  li t2, 0x0ba5596e7e233063
  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vx v30, v10, t2

  li t2, 0x29ba2d4f035dcebb
  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vx v6, v24, t2

  li t2, 0x6fb4c6bb08f934ab
  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vx v24, v20, t2

  li t2, 0xb4f1f3eaeaf5dbec
  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vx v12, v26, t2

  li t2, 0xdd0fa7e3460ceda7
  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vx v16, v4, t2

  li t2, 0xf12621fb150d5f1c
  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vx v16, v4, t2

  li t2, 0x7b41bf4093886f7a
  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vx v24, v16, t2

  li t2, 0xdb6a71dc83201fd4
  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vx v28, v8, t2

  li t2, 0xd6b533d21517c099
  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vx v12, v4, t2

  li t2, 0xfb5ffde2390f5261
  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vx v24, v8, t2

  li t2, 0x66bb68ccc1d344d0
  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vx v16, v8, t2

  li t2, 0xc15da01681a93d1c
  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vx v12, v4, t2

  li t2, 0x02aede83f89b6878
  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vx v12, v28, t2

  li t2, 0xedd571dce6f573d6
  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vx v28, v24, t2

  li t2, 0xa4f5837ed9495667
  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vx v16, v8, t2

  li t2, 0xb20fadfcd4553eb3
  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vx v16, v24, t2

  li t2, 0x1bc709547eb76076
  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vx v16, v24, t2

  li t2, 0x186271402f95de68
  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vx v8, v16, t2

  li t2, 0x2b9ed2ed79f94130
  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vx v24, v16, t2

  li t2, 0x866cbb42e6241474
  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vx v8, v24, t2

  li t2, 0x01ac8e561ddc9922
  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vx v24, v16, t2

  li t2, 0xb42aaf8070b8f16b
  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vx v8, v24, t2

  li t2, 0xf003778a57014d27
  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vx v8, v24, t2

  li t2, 0x23bbe8d2e6dba8c8
  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vx v24, v8, t2

  li t2, 0xb7c1945f04912ba5
  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vx v13, v26, t2

  li t2, 0x51c7a7b0b9706d1c
  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vx v1, v24, t2

  li t2, 0x96836e28b6610d12
  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vx v27, v31, t2

  li t2, 0xfda53bb1b7a51e9a
  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vx v23, v29, t2

  li t2, 0xa9b5e1a632531a0f
  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vx v17, v25, t2

  li t2, 0xb7007538581c6671
  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vx v1, v15, t2

  li t2, 0x59c2c194545ff4ca
  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vx v1, v7, t2

  li t2, 0x68611cf2b32b1ee4
  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vx v13, v10, t2

  li t2, 0x4f358751dad294cc
  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vx v20, v27, t2

  li t2, 0x78d8fc7d73b50d43
  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vx v29, v16, t2

  li t2, 0x45cb560dec3ad28a
  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vx v22, v6, t2

  li t2, 0xdf9eb513393655bf
  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vx v22, v30, t2

  li t2, 0xe361278237a5c0c3
  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vx v14, v10, t2

  li t2, 0x35f14e1fdedb8c02
  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vx v16, v10, t2

  li t2, 0x8713a3ee6adb759e
  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vx v18, v28, t2

  li t2, 0xe5108f9053492a00
  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vx v14, v2, t2

  li t2, 0xec698d42747a2610
  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vx v2, v6, t2

  li t2, 0xc94aea87434c88b0
  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vx v12, v20, t2

  li t2, 0xae5ed9ccdafc7199
  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vx v2, v24, t2

  li t2, 0xc9bfe4b07993630d
  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vx v28, v6, t2

  li t2, 0xfbe99dfa444fe9cb
  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vx v20, v8, t2

  li t2, 0xa03944c3907a2f5d
  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vx v8, v12, t2

  li t2, 0x28992fce71734d18
  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vx v28, v8, t2

  li t2, 0xb54ea5bd2049a3b2
  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vx v4, v12, t2

  li t2, 0x638b1a87d906a581
  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vx v12, v20, t2

  li t2, 0x7b74f0826d18a185
  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vx v16, v4, t2

  li t2, 0xcea6c9d299f46638
  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vx v24, v12, t2

  li t2, 0xd94bf33f7fc416d9
  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vx v20, v16, t2

  li t2, 0xa0d210322ba1e91d
  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vx v12, v8, t2

  li t2, 0xa21e2d58bc27e828
  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vx v28, v12, t2

  li t2, 0x26110545b36f0d92
  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vx v8, v24, t2

  li t2, 0xd247e7fc547ec9cd
  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vx v8, v24, t2

  li t2, 0xe2fa129252c539ec
  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vx v8, v24, t2

  li t2, 0x4ec83aebfa719a4a
  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vx v16, v24, t2

  li t2, 0x136c5d47ad42e771
  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vx v24, v16, t2

  li t2, 0xef3e7c4161f05d2e
  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vx v16, v8, t2

  li t2, 0xd1199748ace60eb6
  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vx v16, v8, t2

  li t2, 0x0e79b2f95d3052e0
  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vx v16, v8, t2

  li t2, 0xc257c229516217fd
  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vx v24, v16, t2

  li t2, 0xe77c687e49b29b3d
  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vx v24, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vi v2, v20, -5

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vi v18, v28, 4

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vi v16, v10, 7

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vi v2, v3, -3

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vi v4, v17, 8

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vi v4, v19, -10

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vi v5, v1, -12

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vi v28, v13, -13

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vi v25, v20, 2

  vsetvli t1, t0, e8, m1, ta, ma
  vxor.vi v11, v23, 15

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vi v12, v22, -5

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vi v16, v6, -7

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vi v24, v2, -8

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vi v8, v30, 12

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vi v10, v4, -7

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vi v14, v6, -15

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vi v8, v12, -10

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vi v12, v16, 4

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vi v24, v16, -1

  vsetvli t1, t0, e8, m2, ta, ma
  vxor.vi v16, v24, -12

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vi v16, v28, 5

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vi v20, v4, 10

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vi v12, v28, -1

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vi v24, v8, -13

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vi v4, v16, -8

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vi v4, v8, -13

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vi v16, v8, 14

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vi v16, v8, -5

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vi v24, v8, -8

  vsetvli t1, t0, e8, m4, ta, ma
  vxor.vi v4, v28, 5

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vi v8, v16, -9

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vi v16, v8, -3

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vi v16, v24, -11

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vi v16, v8, 15

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vi v8, v16, 6

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vi v8, v24, 9

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vi v24, v16, -8

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vi v24, v16, 14

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vi v16, v8, -3

  vsetvli t1, t0, e8, m8, ta, ma
  vxor.vi v16, v24, 9

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vi v22, v23, 0

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vi v21, v7, -7

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vi v14, v30, -14

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vi v31, v13, -3

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vi v27, v22, -10

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vi v17, v8, 8

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vi v26, v11, 1

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vi v14, v11, 5

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vi v4, v15, 7

  vsetvli t1, t0, e16, m1, ta, ma
  vxor.vi v13, v17, 10

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vi v4, v26, -6

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vi v2, v26, 11

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vi v18, v2, 2

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vi v16, v18, -12

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vi v20, v26, -5

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vi v6, v10, -15

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vi v12, v20, 9

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vi v8, v6, -3

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vi v6, v30, -8

  vsetvli t1, t0, e16, m2, ta, ma
  vxor.vi v10, v22, -13

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vi v20, v12, 9

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vi v12, v16, -6

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vi v8, v4, 9

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vi v20, v16, -11

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vi v4, v28, -15

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vi v28, v8, -7

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vi v4, v28, 5

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vi v12, v20, 2

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vi v16, v4, -12

  vsetvli t1, t0, e16, m4, ta, ma
  vxor.vi v8, v20, 11

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vi v16, v24, 2

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vi v24, v16, -1

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vi v24, v8, -6

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vi v8, v24, 14

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vi v16, v24, -11

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vi v8, v16, -13

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vi v8, v16, -9

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vi v16, v24, 4

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vi v24, v16, 15

  vsetvli t1, t0, e16, m8, ta, ma
  vxor.vi v16, v24, 0

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vi v20, v15, -2

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vi v10, v11, 7

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vi v31, v26, -6

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vi v23, v5, -7

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vi v2, v11, 5

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vi v8, v4, 2

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vi v17, v19, -5

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vi v4, v23, 11

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vi v7, v8, -12

  vsetvli t1, t0, e32, m1, ta, ma
  vxor.vi v8, v1, -4

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vi v12, v26, -8

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vi v6, v18, -6

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vi v2, v10, -7

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vi v14, v4, 3

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vi v2, v20, 12

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vi v16, v18, -16

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vi v14, v8, 1

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vi v12, v10, -13

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vi v30, v18, -10

  vsetvli t1, t0, e32, m2, ta, ma
  vxor.vi v24, v30, -4

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vi v20, v28, -13

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vi v4, v16, -1

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vi v24, v8, 11

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vi v16, v20, 14

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vi v28, v12, 13

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vi v16, v12, -7

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vi v8, v20, 2

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vi v16, v24, 0

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vi v28, v12, 7

  vsetvli t1, t0, e32, m4, ta, ma
  vxor.vi v4, v20, -8

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vi v16, v24, -11

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vi v8, v24, -4

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vi v16, v8, -4

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vi v8, v16, 14

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vi v24, v8, 13

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vi v8, v24, 3

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vi v16, v24, -11

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vi v16, v24, -4

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vi v24, v16, 0

  vsetvli t1, t0, e32, m8, ta, ma
  vxor.vi v8, v24, -7

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vi v13, v8, 6

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vi v7, v6, 4

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vi v16, v30, -3

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vi v26, v11, 3

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vi v21, v30, 6

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vi v16, v18, 14

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vi v19, v13, -15

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vi v8, v5, -7

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vi v10, v5, -13

  vsetvli t1, t0, e64, m1, ta, ma
  vxor.vi v15, v5, -6

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vi v12, v18, 5

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vi v2, v10, -12

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vi v28, v4, 4

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vi v2, v30, 13

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vi v4, v8, -2

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vi v28, v24, 15

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vi v6, v22, 4

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vi v26, v22, -14

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vi v28, v10, -2

  vsetvli t1, t0, e64, m2, ta, ma
  vxor.vi v14, v24, -2

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vi v4, v20, 5

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vi v20, v4, 6

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vi v12, v24, 4

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vi v8, v12, -10

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vi v24, v20, 12

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vi v20, v24, -14

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vi v8, v12, 8

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vi v16, v4, -1

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vi v20, v28, -15

  vsetvli t1, t0, e64, m4, ta, ma
  vxor.vi v24, v20, -14

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vi v24, v16, 13

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vi v8, v24, -5

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vi v16, v24, 7

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vi v24, v16, 3

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vi v16, v8, 0

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vi v8, v16, 6

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vi v8, v16, -15

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vi v24, v8, -4

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vi v24, v16, 15

  vsetvli t1, t0, e64, m8, ta, ma
  vxor.vi v24, v16, 15

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
