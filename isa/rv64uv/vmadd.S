#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vv v20, v1, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vv v12, v10, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vv v4, v10, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vv v25, v3, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vv v10, v29, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vv v17, v19, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vv v1, v11, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vv v25, v8, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vv v30, v2, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vv v22, v21, v5

  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vv v4, v22, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vv v26, v28, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vv v10, v20, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vv v12, v4, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vv v18, v28, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vv v24, v6, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vv v16, v28, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vv v24, v22, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vv v22, v4, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vv v16, v24, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vv v12, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vv v16, v24, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vv v28, v12, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vv v16, v24, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vv v8, v4, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vv v20, v4, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vv v12, v4, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vv v28, v20, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vv v4, v28, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vv v8, v12, v20

  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vv v24, v8, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vv v7, v12, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vv v29, v12, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vv v22, v27, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vv v17, v28, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vv v17, v6, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vv v1, v13, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vv v15, v7, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vv v16, v18, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vv v15, v29, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vv v1, v13, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vv v22, v12, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vv v28, v2, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vv v4, v22, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vv v4, v2, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vv v4, v10, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vv v14, v26, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vv v10, v22, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vv v12, v28, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vv v2, v26, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vv v4, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vv v12, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vv v16, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vv v8, v12, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vv v20, v28, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vv v24, v20, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vv v20, v28, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vv v16, v28, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vv v20, v4, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vv v4, v8, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vv v24, v28, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vv v24, v8, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vv v20, v23, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vv v22, v8, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vv v21, v11, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vv v23, v14, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vv v26, v20, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vv v16, v11, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vv v20, v21, v17

  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vv v3, v9, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vv v12, v21, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vv v20, v29, v21

  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vv v8, v24, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vv v16, v14, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vv v2, v16, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vv v18, v26, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vv v26, v4, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vv v6, v10, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vv v2, v14, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vv v8, v2, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vv v10, v18, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vv v22, v6, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vv v16, v8, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vv v24, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vv v8, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vv v4, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vv v28, v8, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vv v4, v28, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vv v8, v4, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vv v24, v12, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vv v20, v12, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vv v4, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vv v16, v24, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vv v16, v18, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vv v21, v1, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vv v14, v7, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vv v31, v5, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vv v27, v23, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vv v20, v28, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vv v24, v2, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vv v24, v13, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vv v14, v10, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vv v28, v27, v19

  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vv v8, v24, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vv v30, v28, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vv v30, v12, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vv v14, v28, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vv v6, v4, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vv v30, v22, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vv v12, v2, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vv v14, v12, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vv v24, v12, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vv v4, v16, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vv v12, v8, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vv v4, v28, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vv v28, v4, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vv v16, v28, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vv v8, v28, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vv v28, v4, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vv v28, v8, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vv v28, v20, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vv v28, v8, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vv v12, v16, v20

  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vv v24, v16, v8

  li t2, 0x29034f2c98a9b2fe
  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vx v11, t2, v25

  li t2, 0x395b7da0b1cba2e0
  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vx v28, t2, v11

  li t2, 0x3ac14d88f6aba88d
  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vx v6, t2, v19

  li t2, 0x76bd0d7f1165f2b9
  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vx v31, t2, v16

  li t2, 0x971acc85b4dacb1c
  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vx v4, t2, v31

  li t2, 0x4130c78c56fc6f21
  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vx v23, t2, v21

  li t2, 0x044e89ae521a8c38
  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vx v4, t2, v8

  li t2, 0xdd00f28be665527b
  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vx v11, t2, v10

  li t2, 0xff12fd18acab9da2
  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vx v12, t2, v15

  li t2, 0x215b1f09ae746c0c
  vsetvli t1, t0, e8, m1, ta, ma
  vmadd.vx v16, t2, v20

  li t2, 0x93ed4dbc8aae1172
  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vx v12, t2, v30

  li t2, 0xe8d863fc7969b6a4
  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vx v8, t2, v26

  li t2, 0x550258a0a5cd57e4
  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vx v18, t2, v6

  li t2, 0x08e02ac6d1c0109a
  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vx v16, t2, v10

  li t2, 0x03554ac73d2ce25c
  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vx v30, t2, v12

  li t2, 0x2f502d96782d1fa6
  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vx v16, t2, v12

  li t2, 0x15a0b9e002151634
  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vx v20, t2, v28

  li t2, 0x1c4d58c55cd5544c
  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vx v24, t2, v12

  li t2, 0xe4d8b49ce165f69e
  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vx v24, t2, v4

  li t2, 0x802a6e8b5c8bb515
  vsetvli t1, t0, e8, m2, ta, ma
  vmadd.vx v22, t2, v18

  li t2, 0x542d85cb78c1cb1e
  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vx v12, t2, v4

  li t2, 0xeb93955967b92dd3
  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vx v4, t2, v12

  li t2, 0x332ccb9001f310a0
  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vx v16, t2, v28

  li t2, 0xac694d5e91c10ac6
  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vx v20, t2, v4

  li t2, 0x449a97ecf51906e9
  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vx v28, t2, v16

  li t2, 0x399c2477de519853
  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vx v4, t2, v24

  li t2, 0x646eb2a6a78ad200
  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vx v16, t2, v4

  li t2, 0x9e9ebbd91e61e580
  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vx v20, t2, v8

  li t2, 0xc09d980142665e81
  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vx v28, t2, v4

  li t2, 0x1f8d582270b55652
  vsetvli t1, t0, e8, m4, ta, ma
  vmadd.vx v12, t2, v4

  li t2, 0x934f52b1a40b7927
  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vx v16, t2, v24

  li t2, 0x7ca6bfa1114d071a
  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vx v8, t2, v24

  li t2, 0x19fe213913095395
  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vx v16, t2, v8

  li t2, 0xe1923afb45a27b23
  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vx v24, t2, v16

  li t2, 0x571b8f91ec5b9cb3
  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vx v8, t2, v24

  li t2, 0xef6671b7e1103755
  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vx v24, t2, v8

  li t2, 0x126e46c4a54a6c17
  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vx v8, t2, v16

  li t2, 0xfb08562bca9bb908
  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vx v16, t2, v24

  li t2, 0x1d1f6555b5bc9fb2
  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vx v16, t2, v8

  li t2, 0x40772278b06bea82
  vsetvli t1, t0, e8, m8, ta, ma
  vmadd.vx v8, t2, v24

  li t2, 0xb6ddffecb46df5be
  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vx v29, t2, v17

  li t2, 0x8747daf839d240e4
  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vx v27, t2, v23

  li t2, 0x4073a02c48071460
  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vx v16, t2, v18

  li t2, 0x97fef74ae94fa6e3
  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vx v13, t2, v10

  li t2, 0xb845f6122fcf2c4f
  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vx v6, t2, v14

  li t2, 0x71cdfe05b54179d1
  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vx v26, t2, v31

  li t2, 0x4ef9fb1a640c9329
  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vx v4, t2, v16

  li t2, 0x7fe2d6f9d01af443
  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vx v12, t2, v27

  li t2, 0x58a98fe6a388619b
  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vx v12, t2, v1

  li t2, 0xb4148cab1011e12b
  vsetvli t1, t0, e16, m1, ta, ma
  vmadd.vx v14, t2, v24

  li t2, 0x27975c7faf606956
  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vx v4, t2, v10

  li t2, 0x2affb8edffd84d21
  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vx v30, t2, v24

  li t2, 0x891e18dcd913aa08
  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vx v30, t2, v16

  li t2, 0x0ea4f0a1759a0690
  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vx v2, t2, v12

  li t2, 0x87c198ba3b3865fa
  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vx v22, t2, v24

  li t2, 0x00562c23d3ed5bdd
  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vx v26, t2, v2

  li t2, 0xa7cf408da52bb620
  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vx v10, t2, v14

  li t2, 0x29d79a37c4016977
  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vx v18, t2, v4

  li t2, 0xff098fe1195cb52b
  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vx v4, t2, v10

  li t2, 0x9b743bddcf87060d
  vsetvli t1, t0, e16, m2, ta, ma
  vmadd.vx v8, t2, v12

  li t2, 0xc242af2b649e2304
  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vx v4, t2, v16

  li t2, 0x37bcd04dbdeb9258
  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vx v16, t2, v20

  li t2, 0x86c2d9ba81a8e303
  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vx v4, t2, v24

  li t2, 0xd1b90a2cddf2ec90
  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vx v4, t2, v12

  li t2, 0x522b1fc1b95a94fd
  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vx v16, t2, v20

  li t2, 0x95cd48e75df83743
  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vx v20, t2, v16

  li t2, 0x2d47e353faf3bb98
  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vx v20, t2, v16

  li t2, 0xbad3d01a64924ab7
  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vx v28, t2, v12

  li t2, 0x01f1fe3deee42307
  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vx v8, t2, v12

  li t2, 0xcb138de516e665c1
  vsetvli t1, t0, e16, m4, ta, ma
  vmadd.vx v28, t2, v12

  li t2, 0xee355876d2a9b93c
  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vx v24, t2, v8

  li t2, 0x1f3d70d51711682e
  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vx v8, t2, v16

  li t2, 0x8755a283e33ebf11
  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vx v24, t2, v16

  li t2, 0x42436a5d23951040
  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vx v24, t2, v8

  li t2, 0x90461057df3f8cf9
  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vx v8, t2, v16

  li t2, 0x4bd454277b304f1d
  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vx v8, t2, v24

  li t2, 0x4561acca105106a1
  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vx v16, t2, v24

  li t2, 0x36dbda87790020c7
  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vx v16, t2, v24

  li t2, 0xc88f12b705eec2e8
  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vx v16, t2, v24

  li t2, 0x2c7f6bde610a2530
  vsetvli t1, t0, e16, m8, ta, ma
  vmadd.vx v16, t2, v8

  li t2, 0xb68f9e93c8890fa7
  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vx v23, t2, v5

  li t2, 0x91dc8339cfc85273
  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vx v10, t2, v8

  li t2, 0x8da5a4017ebddc51
  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vx v12, t2, v13

  li t2, 0x6989d3bb7ceaccf7
  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vx v25, t2, v11

  li t2, 0x3d89a1346ac19ed5
  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vx v25, t2, v15

  li t2, 0x53bbbc2864e8fa1d
  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vx v13, t2, v3

  li t2, 0x3cf0875ae5d8078c
  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vx v21, t2, v15

  li t2, 0x1a1062a76e35385a
  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vx v13, t2, v5

  li t2, 0xb045690bb2411031
  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vx v28, t2, v3

  li t2, 0x5f69e8912cac27d8
  vsetvli t1, t0, e32, m1, ta, ma
  vmadd.vx v5, t2, v23

  li t2, 0xc3081d6dbf86b653
  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vx v12, t2, v10

  li t2, 0x68862043e7b2ae62
  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vx v30, t2, v28

  li t2, 0xaf0a36638d0c7579
  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vx v30, t2, v28

  li t2, 0x69e52997b76d1ce3
  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vx v28, t2, v24

  li t2, 0xa14143585da20274
  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vx v28, t2, v16

  li t2, 0x5d26094684fa2917
  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vx v30, t2, v8

  li t2, 0x1a87e96766f8cc9e
  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vx v2, t2, v12

  li t2, 0x0019590f3595dd32
  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vx v20, t2, v14

  li t2, 0x1afef26288709f7c
  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vx v20, t2, v2

  li t2, 0x4f0ebf03c96b23e4
  vsetvli t1, t0, e32, m2, ta, ma
  vmadd.vx v2, t2, v14

  li t2, 0x3798cd5c1dbb56ef
  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vx v24, t2, v12

  li t2, 0x98f0bcdcefd3012c
  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vx v28, t2, v24

  li t2, 0xab231912b4491154
  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vx v16, t2, v4

  li t2, 0x9ad36a0d8cb1b3e5
  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vx v12, t2, v4

  li t2, 0xc673efeeb72b1773
  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vx v8, t2, v4

  li t2, 0x03b5a42db18751bc
  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vx v20, t2, v12

  li t2, 0x2044402defcc42d1
  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vx v24, t2, v8

  li t2, 0x250cca5ae09eac31
  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vx v12, t2, v24

  li t2, 0x581de3eeeba4e040
  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vx v12, t2, v4

  li t2, 0x92ebebdd43c30e09
  vsetvli t1, t0, e32, m4, ta, ma
  vmadd.vx v4, t2, v16

  li t2, 0x937fa9dc7e2091e8
  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vx v8, t2, v16

  li t2, 0xa0dd123a8a09a6b5
  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vx v16, t2, v24

  li t2, 0x2c4c3024a5ee3909
  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vx v8, t2, v16

  li t2, 0xb639479f95d9bcdc
  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vx v24, t2, v16

  li t2, 0x473ef4e6838bc98f
  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vx v16, t2, v8

  li t2, 0xa1c9f37df1e7bc0a
  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vx v24, t2, v8

  li t2, 0xebe574674436965a
  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vx v8, t2, v24

  li t2, 0x7fdbe68f087ddb01
  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vx v16, t2, v8

  li t2, 0x56b92632e62901b1
  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vx v16, t2, v24

  li t2, 0xe037634004a9303d
  vsetvli t1, t0, e32, m8, ta, ma
  vmadd.vx v16, t2, v24

  li t2, 0x71199b5251fe9268
  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vx v11, t2, v21

  li t2, 0x0bc739683953038b
  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vx v9, t2, v2

  li t2, 0xaecca1ffd8693940
  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vx v4, t2, v9

  li t2, 0x5008a1f3b66e95b6
  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vx v9, t2, v5

  li t2, 0x11cf419820493a14
  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vx v11, t2, v12

  li t2, 0xf30fb8c1218803b9
  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vx v14, t2, v1

  li t2, 0xae987ca1a73562c8
  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vx v24, t2, v30

  li t2, 0x167ff66a2d8ee7cf
  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vx v31, t2, v13

  li t2, 0x7a33cb90b3c2fbe0
  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vx v12, t2, v15

  li t2, 0xf15efe63d8312f68
  vsetvli t1, t0, e64, m1, ta, ma
  vmadd.vx v16, t2, v22

  li t2, 0xdf4f5da896b5f6b7
  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vx v16, t2, v12

  li t2, 0x4fc91325901614b9
  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vx v2, t2, v6

  li t2, 0x83898ad3c1b4b958
  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vx v24, t2, v16

  li t2, 0xfb07ca1008f41e37
  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vx v22, t2, v20

  li t2, 0x2ba777a3c3aa72c3
  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vx v6, t2, v2

  li t2, 0x5eb8ebef6e6f0d30
  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vx v20, t2, v4

  li t2, 0xbb32990bbbac92aa
  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vx v6, t2, v18

  li t2, 0xa693c71b6defe7ee
  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vx v28, t2, v18

  li t2, 0xe032d24a6be44719
  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vx v8, t2, v24

  li t2, 0xcb611ae72aa9eae4
  vsetvli t1, t0, e64, m2, ta, ma
  vmadd.vx v2, t2, v18

  li t2, 0x3f86e8ae4b57e12f
  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vx v4, t2, v12

  li t2, 0xc158d492892d1749
  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vx v12, t2, v16

  li t2, 0xa9f87772d8072dd5
  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vx v12, t2, v20

  li t2, 0x7c88110ce5a69e81
  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vx v8, t2, v4

  li t2, 0xd824a63af8bca5f2
  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vx v24, t2, v8

  li t2, 0x207de47bbec5eac6
  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vx v16, t2, v12

  li t2, 0x6940066592b046bc
  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vx v20, t2, v28

  li t2, 0x959e3c84e44a12bb
  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vx v12, t2, v28

  li t2, 0x5bbc1cb8d9769875
  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vx v24, t2, v16

  li t2, 0x0f54accfa3dc52cc
  vsetvli t1, t0, e64, m4, ta, ma
  vmadd.vx v24, t2, v28

  li t2, 0xf53cb00ea75ff82e
  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vx v8, t2, v16

  li t2, 0x94816f8d965bd9e8
  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vx v24, t2, v8

  li t2, 0xa2485d2cd0bf515f
  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vx v24, t2, v8

  li t2, 0x0bd1783d88908f23
  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vx v8, t2, v24

  li t2, 0xd19b923c01a012d5
  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vx v24, t2, v8

  li t2, 0x4c8702cbc5120837
  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vx v8, t2, v24

  li t2, 0x36754a32d452b5bc
  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vx v16, t2, v24

  li t2, 0x6c147734a7eb4e8a
  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vx v8, t2, v24

  li t2, 0xb47fdaa5ad719e19
  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vx v24, t2, v8

  li t2, 0xeecee24c0a78e65b
  vsetvli t1, t0, e64, m8, ta, ma
  vmadd.vx v24, t2, v16

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
