#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vv v11, v29, v2

  li t2, 0x4a1ddee13a57f359
  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vx v18, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vi v17, v11, -4

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vv v23, v16, v20

  li t2, 0x3d823e7bedf0e6a2
  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vx v3, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vi v12, v7, 2

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vv v9, v12, v17

  li t2, 0x2cc614baae8c27da
  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vx v20, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vi v1, v2, 4

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vv v21, v26, v5

  li t2, 0x0e47759c2ea69cb2
  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vx v7, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vi v12, v24, -2

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vv v22, v1, v24

  li t2, 0x1cbac063ad36ca83
  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vx v25, v10, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vi v17, v26, -4

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vv v14, v3, v7

  li t2, 0x818e76dd2ef76745
  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vx v19, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vi v25, v7, 9

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vv v22, v2, v12

  li t2, 0xe79e6de46372b001
  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vx v8, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vi v3, v18, -8

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vv v7, v3, v10

  li t2, 0x437bb7260538d0b4
  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vx v12, v10, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vi v10, v17, 1

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vv v15, v24, v6

  li t2, 0x5efd2641747c2156
  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vx v6, v3, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vi v21, v3, -5

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vv v29, v8, v17

  li t2, 0x51ee1837f666e3bf
  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vx v13, v17, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsaddu.vi v14, v19, 4

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vv v8, v26, v30

  li t2, 0xafa9753e0e43be90
  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vx v24, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vi v8, v10, 3

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vv v6, v22, v24

  li t2, 0x041dda37112c110b
  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vx v18, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vi v6, v28, -7

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vv v28, v18, v26

  li t2, 0x29dec8d63d97cb2a
  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vx v16, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vi v10, v2, -10

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vv v18, v14, v20

  li t2, 0xbe7d0db82695a4fd
  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vx v26, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vi v26, v16, -3

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vv v18, v2, v6

  li t2, 0x69b49f31dd14e617
  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vx v30, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vi v28, v16, -7

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vv v30, v28, v20

  li t2, 0x86bcc15c97aa61fc
  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vx v4, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vi v22, v28, 2

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vv v10, v20, v8

  li t2, 0xd199f45e3b1482f6
  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vx v24, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vi v6, v26, -3

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vv v30, v8, v28

  li t2, 0xa05368b7a9e44717
  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vx v14, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vi v10, v18, -14

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vv v14, v18, v20

  li t2, 0x2903c5a0349f2f4f
  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vx v16, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vi v2, v14, -5

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vv v8, v6, v4

  li t2, 0x6cadde62926b8d1e
  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vx v22, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsaddu.vi v18, v20, 2

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vv v12, v24, v28

  li t2, 0x8da1018d1570a403
  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vi v20, v12, 11

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vv v28, v4, v20

  li t2, 0x6209d856d24419fb
  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vx v24, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vi v8, v4, -7

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vv v16, v24, v20

  li t2, 0xb6b2600bcd1dc88a
  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vx v8, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vi v4, v12, 2

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vv v12, v24, v28

  li t2, 0x2476d7acbac1b23b
  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vx v8, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vi v4, v12, 10

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vv v4, v20, v24

  li t2, 0x0a81708c72f5d2c1
  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vx v16, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vi v28, v24, 5

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vv v4, v8, v24

  li t2, 0xa59ba533c710625c
  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vx v16, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vi v4, v12, 1

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vv v16, v12, v24

  li t2, 0xa1c187ae7dbb072c
  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vi v12, v24, 5

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vv v16, v24, v28

  li t2, 0xf209fe4a40c1d9c6
  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vi v8, v20, -6

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vv v12, v8, v28

  li t2, 0x9bcada8a22216c55
  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vx v28, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vi v24, v8, 6

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vv v24, v8, v28

  li t2, 0x6a92e765ce9fdf48
  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsaddu.vi v8, v24, 0

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vv v24, v8, v16

  li t2, 0x9577c354a8d66efc
  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vi v8, v24, 10

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vv v24, v16, v8

  li t2, 0x044518db261f256d
  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vi v8, v24, 5

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vv v24, v16, v8

  li t2, 0xfd35680d23531993
  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vi v24, v8, -15

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vv v24, v16, v8

  li t2, 0x73e110b6ee10538f
  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vi v8, v16, -3

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vv v8, v16, v24

  li t2, 0xb7ab3872ea0dcc4d
  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vi v8, v24, -16

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vv v8, v16, v24

  li t2, 0x8453a8aeaeee5019
  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vi v8, v24, -12

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vv v8, v24, v16

  li t2, 0x16ad0e505c88f7ba
  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vi v24, v16, 13

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vv v24, v8, v16

  li t2, 0xeeb8d835999b7aaf
  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vi v16, v8, 7

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vv v8, v24, v16

  li t2, 0xc28d1dd74188d81e
  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vi v8, v16, -9

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vv v8, v16, v24

  li t2, 0xecfdf7e98a5d4d0b
  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsaddu.vi v8, v16, 9

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vv v16, v23, v22

  li t2, 0x3233749a07102d0b
  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vx v5, v9, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vi v23, v9, 5

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vv v8, v4, v14

  li t2, 0x3224e05ecfb74d23
  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vx v17, v3, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vi v21, v14, -11

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vv v2, v9, v3

  li t2, 0xab8847042587462a
  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vx v5, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vi v21, v9, 15

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vv v15, v17, v9

  li t2, 0x0fa9248bebfe6e63
  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vx v26, v13, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vi v8, v4, -4

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vv v24, v13, v11

  li t2, 0xde8e5da986347c4e
  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vx v29, v1, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vi v20, v8, 0

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vv v5, v15, v27

  li t2, 0xde6ee9cc950956e4
  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vx v4, v1, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vi v24, v3, 5

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vv v12, v23, v31

  li t2, 0xf8bba172bccc5955
  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vx v8, v12, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vi v28, v24, 11

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vv v31, v11, v6

  li t2, 0x1c49f80f4464b350
  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vx v10, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vi v10, v1, -10

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vv v2, v17, v25

  li t2, 0xa6e59743a8019196
  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vx v8, v13, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vi v31, v7, -10

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vv v8, v10, v7

  li t2, 0xfdde3c1372f93ab4
  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vx v31, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsaddu.vi v1, v20, -16

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vv v24, v4, v2

  li t2, 0x506da173d409df33
  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vx v12, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vi v30, v4, -1

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vv v24, v2, v22

  li t2, 0xf6db2279b1de031c
  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vx v20, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vi v22, v6, 4

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vv v12, v30, v14

  li t2, 0xc49fb845dec5251d
  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vx v14, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vi v30, v18, 10

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vv v26, v30, v10

  li t2, 0x39f6bf741142b46d
  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vx v20, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vi v30, v28, -10

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vv v26, v20, v24

  li t2, 0xfbf5e96c5bac9b80
  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vx v20, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vi v12, v14, -10

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vv v24, v16, v6

  li t2, 0x9bf74991ecc0201a
  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vx v28, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vi v4, v24, 7

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vv v18, v6, v10

  li t2, 0xdf4f04896affd319
  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vx v16, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vi v26, v10, 10

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vv v28, v18, v6

  li t2, 0xda4c12cda73ab71d
  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vx v14, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vi v14, v24, -11

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vv v16, v18, v14

  li t2, 0xf7958094951f5b2e
  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vx v14, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vi v10, v30, 5

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vv v26, v20, v4

  li t2, 0x26070c5aceb03cce
  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vx v30, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsaddu.vi v18, v28, -6

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vv v16, v12, v28

  li t2, 0x7d56d1dbd4c5b01d
  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vi v20, v28, 6

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vv v20, v28, v12

  li t2, 0x5d98bfd34f53f34e
  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vx v8, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vi v20, v28, -4

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vv v8, v28, v20

  li t2, 0x951056a1fa075a38
  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vx v8, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vi v20, v16, 9

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vv v20, v28, v4

  li t2, 0x2c7608557deae07d
  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vx v4, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vi v4, v12, 9

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vv v16, v28, v12

  li t2, 0x646f7b424281bbee
  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vx v20, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vi v4, v8, 1

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vv v20, v4, v12

  li t2, 0x89b729ff40c1b6d1
  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vx v16, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vi v12, v8, -6

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vv v24, v12, v28

  li t2, 0x7b4639ac2c01aced
  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vx v28, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vi v4, v24, 2

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vv v16, v20, v12

  li t2, 0x570b5881e2291286
  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vx v28, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vi v20, v12, 14

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vv v28, v4, v8

  li t2, 0x4076e80afba83141
  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vx v28, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vi v28, v20, 14

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vv v24, v16, v8

  li t2, 0xaaad5b3ab91aa09b
  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vx v16, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsaddu.vi v12, v28, -1

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vv v8, v24, v16

  li t2, 0xf530a340b80661ed
  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vi v16, v24, 6

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vv v16, v8, v24

  li t2, 0x9214414df24eb80f
  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vi v24, v16, -11

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vv v8, v24, v16

  li t2, 0xf482a145f8aa8b68
  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vi v24, v8, -2

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vv v16, v24, v8

  li t2, 0x0e69bf7555db97b3
  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vi v24, v8, -5

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vv v24, v8, v16

  li t2, 0x00062a1c032db41e
  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vi v8, v24, -12

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vv v8, v24, v16

  li t2, 0x250077e50668b189
  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vi v8, v16, -4

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vv v24, v16, v8

  li t2, 0x800b6ae9714ea0ef
  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vi v8, v24, 9

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vv v16, v24, v8

  li t2, 0xe471baf2b5913b17
  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vi v24, v8, 12

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vv v24, v16, v8

  li t2, 0xe301afe9c96d34c8
  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vi v8, v24, 12

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vv v24, v8, v16

  li t2, 0xdce03b42eba16673
  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsaddu.vi v8, v24, -9

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vv v26, v27, v2

  li t2, 0xa6de5b7331dd6754
  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vx v20, v27, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vi v30, v7, -9

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vv v13, v14, v26

  li t2, 0x43d8f6612dd1dd69
  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vx v20, v23, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vi v31, v27, 7

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vv v24, v6, v13

  li t2, 0x90865e6ee253de97
  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vx v25, v17, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vi v21, v16, -8

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vv v30, v28, v27

  li t2, 0x6734697d51ca4374
  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vx v15, v31, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vi v21, v7, -3

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vv v29, v5, v4

  li t2, 0x785058a5eff21264
  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vx v31, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vi v12, v5, 13

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vv v30, v15, v5

  li t2, 0xc0656e4327260a95
  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vx v20, v26, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vi v29, v17, 0

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vv v3, v7, v27

  li t2, 0xd488cea3c3878e50
  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vx v8, v19, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vi v13, v7, 3

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vv v3, v14, v21

  li t2, 0x6737d390ac4f4de4
  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vx v11, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vi v22, v1, -16

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vv v7, v15, v12

  li t2, 0x478cdd140b0562ea
  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vx v8, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vi v3, v13, 11

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vv v21, v12, v16

  li t2, 0x5af4fdb670774e18
  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vx v14, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsaddu.vi v26, v1, -1

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vv v10, v8, v30

  li t2, 0x9367f87572df87ff
  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vx v16, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vi v28, v26, 10

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vv v6, v18, v4

  li t2, 0x9b4a38a9c79c60ec
  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vx v16, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vi v10, v16, -15

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vv v4, v16, v22

  li t2, 0xd5c54e435614df4b
  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vx v12, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vi v18, v22, -9

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vv v16, v30, v4

  li t2, 0xb3f8fe5257e1d48b
  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vx v16, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vi v14, v10, 10

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vv v2, v18, v22

  li t2, 0x1715264d2ad0fa86
  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vx v14, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vi v30, v24, 13

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vv v8, v24, v12

  li t2, 0x751f9e9b6ae324e4
  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vx v30, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vi v18, v12, -1

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vv v2, v26, v8

  li t2, 0x54c57cb12d537b1b
  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vx v2, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vi v18, v6, 0

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vv v26, v18, v28

  li t2, 0x3262f12963a88a30
  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vx v14, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vi v20, v12, 2

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vv v12, v16, v24

  li t2, 0xe62372631d12285e
  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vx v26, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vi v8, v20, 3

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vv v22, v12, v18

  li t2, 0xe8cca230a3b57cf8
  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vx v10, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsaddu.vi v12, v10, -14

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vv v24, v16, v28

  li t2, 0x3b93ca27ddbe83e0
  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vx v12, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vi v8, v20, -13

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vv v12, v20, v8

  li t2, 0xe19184bb755ab32b
  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vx v28, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vi v4, v28, 13

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vv v24, v20, v28

  li t2, 0x1106106e3c608a46
  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vi v28, v4, 5

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vv v16, v20, v4

  li t2, 0xba4746d39a1e4316
  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vx v12, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vi v12, v24, 6

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vv v20, v12, v4

  li t2, 0x018a609432fe738a
  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vx v12, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vi v4, v12, -11

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vv v24, v8, v16

  li t2, 0xed16d18e48f2e2e4
  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vx v16, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vi v8, v12, -11

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vv v12, v16, v28

  li t2, 0x01b3b9d5670f34cd
  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vx v28, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vi v28, v16, -15

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vv v28, v8, v20

  li t2, 0x2303ecfbf1b24a69
  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vx v4, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vi v24, v8, 3

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vv v8, v4, v28

  li t2, 0xfa08180488c00ca0
  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vi v28, v8, 4

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vv v4, v8, v20

  li t2, 0x5cc4a1553218c1f5
  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vx v24, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsaddu.vi v12, v16, -4

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vv v16, v24, v8

  li t2, 0xd72132b805ff9ee0
  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vi v8, v24, 4

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vv v16, v8, v24

  li t2, 0xd081b212e4dd7719
  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vi v16, v8, 9

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vv v16, v24, v8

  li t2, 0x8de366090ec39256
  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vi v16, v8, -1

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vv v8, v24, v16

  li t2, 0x2a9dbd0613801c80
  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vi v16, v8, 11

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vv v24, v8, v16

  li t2, 0x2bbc9897b64624eb
  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vi v8, v16, 13

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vv v8, v24, v16

  li t2, 0x23fb580cab9088ee
  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vi v16, v8, -13

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vv v16, v24, v8

  li t2, 0xa3109b813d7f3fa7
  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vi v16, v24, -1

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vv v24, v16, v8

  li t2, 0x8b5d77f12321d288
  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vi v16, v8, -9

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vv v24, v8, v16

  li t2, 0x35ab66aeeabe6800
  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vi v24, v16, 0

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vv v8, v16, v24

  li t2, 0x1da6a10744c7bdba
  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsaddu.vi v8, v24, 1

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vv v28, v5, v14

  li t2, 0xf2fc088372ec1e19
  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vx v6, v14, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vi v16, v10, -11

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vv v2, v22, v13

  li t2, 0xa1c6da8f4fef4384
  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vx v2, v15, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vi v13, v30, -16

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vv v12, v7, v24

  li t2, 0xda5cc0284610e881
  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vx v14, v2, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vi v3, v11, 5

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vv v30, v11, v20

  li t2, 0x8d1edb808c95eed7
  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vx v19, v3, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vi v17, v7, -2

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vv v29, v8, v10

  li t2, 0xbd1b33cedfd91ace
  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vx v9, v28, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vi v30, v20, 10

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vv v23, v8, v14

  li t2, 0xb02f25daac2956de
  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vx v25, v13, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vi v25, v23, 2

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vv v6, v17, v14

  li t2, 0x49a8dc5aa6a98098
  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vx v3, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vi v18, v11, -6

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vv v12, v10, v31

  li t2, 0x97cbc60eff2750ec
  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vx v12, v2, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vi v18, v31, -15

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vv v23, v9, v16

  li t2, 0x1cb73b4722071c59
  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vx v13, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vi v19, v7, -2

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vv v2, v28, v3

  li t2, 0x1a170be111bb0b7f
  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vx v13, v28, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsaddu.vi v26, v25, -12

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vv v6, v24, v8

  li t2, 0x59de75b28444dea0
  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vx v26, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vi v26, v18, 5

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vv v4, v30, v14

  li t2, 0xc054fef8540e37f3
  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vx v16, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vi v12, v10, 3

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vv v16, v6, v14

  li t2, 0x80f81f8934f4d9f8
  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vx v22, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vi v12, v28, -7

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vv v22, v10, v28

  li t2, 0x1fa7c6bc4fd710cb
  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vx v14, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vi v16, v6, -12

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vv v4, v2, v16

  li t2, 0xc2209378094f119f
  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vx v22, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vi v8, v14, 15

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vv v24, v12, v30

  li t2, 0x3578fcb7ecdadeea
  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vx v14, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vi v18, v10, -2

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vv v12, v28, v20

  li t2, 0x87b42b06ae53c4a9
  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vx v2, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vi v20, v30, 11

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vv v8, v28, v12

  li t2, 0xe0be7871bff10aa7
  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vx v14, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vi v16, v6, 14

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vv v16, v10, v20

  li t2, 0x38243245a408b260
  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vx v2, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vi v10, v2, -7

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vv v20, v14, v26

  li t2, 0xe1d83ba9427a82e6
  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vx v22, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsaddu.vi v16, v18, -8

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vv v20, v24, v28

  li t2, 0x8ff86fbb21d61c64
  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vx v8, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vi v8, v24, 8

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vv v24, v12, v28

  li t2, 0x54687a574893022e
  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vx v24, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vi v8, v24, -14

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vv v12, v24, v28

  li t2, 0x00bdf5600ff581ef
  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vx v16, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vi v24, v20, -11

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vv v8, v16, v12

  li t2, 0xe889366085d10d11
  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vx v28, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vi v4, v28, -6

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vv v16, v4, v28

  li t2, 0xfeb3f0d75da8ec26
  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vi v16, v24, -16

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vv v8, v12, v20

  li t2, 0x9ae2ea824a435e23
  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vx v20, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vi v24, v16, -5

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vv v28, v20, v4

  li t2, 0xc89457db5cf08347
  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vx v8, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vi v8, v12, -16

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vv v12, v28, v20

  li t2, 0x13313039877bdf98
  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vx v12, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vi v16, v4, 1

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vv v12, v28, v4

  li t2, 0x98ab75592ae7390c
  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vx v20, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vi v20, v24, 3

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vv v12, v4, v8

  li t2, 0xbf4b3856d3e079f2
  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsaddu.vi v12, v24, -9

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vv v24, v16, v8

  li t2, 0x3a940ca676077d9c
  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vi v16, v8, -3

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vv v16, v24, v8

  li t2, 0x422df5b9274c448b
  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vi v24, v8, 15

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vv v16, v24, v8

  li t2, 0x5a0bffb2c3c3bbf2
  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vi v24, v16, -2

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vv v8, v24, v16

  li t2, 0xb9cd63839f6cfcf7
  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vi v8, v24, 3

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vv v24, v8, v16

  li t2, 0x7a5162f3ee1e3801
  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vi v8, v16, -2

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vv v8, v16, v24

  li t2, 0x24cec5301e6e4fe4
  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vi v16, v8, -10

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vv v24, v16, v8

  li t2, 0x9eb7e1aef2eb6405
  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vi v24, v8, 1

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vv v24, v8, v16

  li t2, 0x3dc10d5465a32ba9
  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vi v8, v24, 7

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vv v24, v16, v8

  li t2, 0x0100530c6d4db90c
  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vi v8, v24, 4

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vv v24, v8, v16

  li t2, 0x9fc438357daf774a
  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsaddu.vi v8, v24, 11

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
