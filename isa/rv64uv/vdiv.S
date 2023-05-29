#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v15, v28, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v8, v16, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v25, v23, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v1, v31, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v5, v23, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v14, v28, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v21, v6, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v5, v9, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v23, v18, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vv v25, v31, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v28, v22, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v6, v26, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v8, v10, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v14, v6, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v4, v10, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v2, v30, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v16, v14, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v22, v10, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v20, v16, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vv v18, v28, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v20, v4, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v16, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v16, v20, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v16, v28, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v8, v20, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v12, v4, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v20, v8, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v8, v12, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v8, v24, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vv v16, v20, v28

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v27, v29, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v10, v22, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v16, v19, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v23, v4, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v28, v14, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v15, v11, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v17, v20, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v4, v28, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v23, v25, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vv v14, v25, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v14, v10, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v30, v18, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v6, v26, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v2, v8, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v20, v10, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v6, v4, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v14, v22, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v6, v12, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v2, v22, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vv v10, v26, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v4, v12, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v8, v20, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v28, v16, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v20, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v24, v12, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v12, v28, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v24, v12, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v28, v4, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v28, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vv v20, v28, v4

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vv v16, v24, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v20, v2, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v17, v21, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v24, v6, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v18, v5, v25

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v25, v12, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v27, v19, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v18, v2, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v17, v30, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v25, v20, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vv v4, v14, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v22, v2, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v18, v16, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v16, v14, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v12, v2, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v12, v26, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v26, v30, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v26, v16, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v22, v24, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v12, v20, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vv v10, v16, v30

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v8, v16, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v24, v4, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v4, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v4, v20, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v20, v4, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v24, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v28, v24, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v28, v24, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v16, v4, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vv v16, v28, v20

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vv v8, v16, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v2, v30, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v29, v10, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v27, v15, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v14, v13, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v15, v8, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v3, v28, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v10, v3, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v23, v15, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v10, v24, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vv v7, v1, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v14, v8, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v24, v28, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v30, v26, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v8, v20, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v24, v18, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v28, v12, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v18, v30, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v6, v8, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v4, v22, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vv v28, v20, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v8, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v8, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v4, v28, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v24, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v28, v20, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v4, v28, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v8, v24, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v8, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v4, v8, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vv v16, v4, v28

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vv v24, v16, v8

  li t2, 0xcbb2c434b560df3a
  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v19, v13, t2

  li t2, 0xd21c261cbc47e2b5
  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v25, v17, t2

  li t2, 0xd7a7eabaeba2d835
  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v16, v25, t2

  li t2, 0x7064ca85c2f24f26
  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v22, v13, t2

  li t2, 0x6cd42ca9e1dc83e7
  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v20, v19, t2

  li t2, 0x5fbc207ee09d97e1
  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v14, v16, t2

  li t2, 0x1abf3b3921a45894
  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v22, v17, t2

  li t2, 0xdc63faa2415649ad
  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v9, v7, t2

  li t2, 0x980958f6c701ac1a
  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v16, v10, t2

  li t2, 0x9629a1ce28f5b4da
  vsetvli t1, t0, e8, m1, ta, ma
  vdiv.vx v24, v31, t2

  li t2, 0xf43e61c767522c09
  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v16, v4, t2

  li t2, 0x983e13c6488e3a6d
  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v24, v6, t2

  li t2, 0x69a8d027021c4d94
  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v30, v28, t2

  li t2, 0xc84764d16aa3377b
  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v28, v22, t2

  li t2, 0xf36301e02b434429
  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v16, v20, t2

  li t2, 0x319e6009b1321943
  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v22, v16, t2

  li t2, 0xa67d26d0e55e1f03
  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v22, v30, t2

  li t2, 0xaecefdbe01140067
  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v18, v24, t2

  li t2, 0x30cd1fc698ec5165
  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v28, v12, t2

  li t2, 0x73c6f7e57c242aa1
  vsetvli t1, t0, e8, m2, ta, ma
  vdiv.vx v2, v18, t2

  li t2, 0x0930df3486c7a3c5
  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v4, v24, t2

  li t2, 0xd32c6c9fda921989
  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v20, v4, t2

  li t2, 0xf2ca87479a0c45f1
  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v20, v12, t2

  li t2, 0x76b3a3379860e88e
  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v20, v16, t2

  li t2, 0xcea97fbc39deb848
  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v20, v24, t2

  li t2, 0x701e7e86aa6b1dc2
  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v8, v24, t2

  li t2, 0x8038de0f4ec491cf
  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v16, v4, t2

  li t2, 0xd4289fb61ed74821
  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v4, v24, t2

  li t2, 0x666c05f9395313ae
  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v16, v8, t2

  li t2, 0xdf3b61755bf2fb2b
  vsetvli t1, t0, e8, m4, ta, ma
  vdiv.vx v16, v28, t2

  li t2, 0x563f8f1e0db2a925
  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v16, v24, t2

  li t2, 0x46af7c1412db4b66
  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v8, v16, t2

  li t2, 0xb0e19fe59cbea813
  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v16, v8, t2

  li t2, 0x5e68553df3902b17
  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v8, v24, t2

  li t2, 0x56bd65fb39acb9b1
  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v16, v8, t2

  li t2, 0x53b04ce39f76091a
  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v16, v24, t2

  li t2, 0xb63c23a7ff9e762f
  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v24, v16, t2

  li t2, 0xd5f744fa879604a8
  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v24, v8, t2

  li t2, 0xfe8b07292b190030
  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v16, v24, t2

  li t2, 0x37dcc2117390cf9d
  vsetvli t1, t0, e8, m8, ta, ma
  vdiv.vx v16, v8, t2

  li t2, 0xbf7740aeebe36f2f
  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v28, v12, t2

  li t2, 0x14e0fc15e528cd8d
  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v28, v6, t2

  li t2, 0x92cda554c7ac26d8
  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v21, v29, t2

  li t2, 0x5d90eac3fcb08a12
  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v7, v28, t2

  li t2, 0x93408ff3e197a705
  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v11, v21, t2

  li t2, 0x079d0efc1b6fc808
  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v10, v9, t2

  li t2, 0xe6e777776ecb65af
  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v24, v21, t2

  li t2, 0x328abf57a7c30b59
  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v19, v25, t2

  li t2, 0x6c80c15fb7a99d67
  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v9, v20, t2

  li t2, 0x1c54ab47e064500e
  vsetvli t1, t0, e16, m1, ta, ma
  vdiv.vx v11, v19, t2

  li t2, 0x1727432c38f44b30
  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v8, v26, t2

  li t2, 0x38f3d0f1fe0a9f66
  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v22, v10, t2

  li t2, 0xb6aebcd3240467c8
  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v30, v16, t2

  li t2, 0x9541d51ebfef9066
  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v20, v16, t2

  li t2, 0x874fc19a11185dfb
  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v28, v12, t2

  li t2, 0x7c650b12d2656f63
  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v30, v22, t2

  li t2, 0xc492cf0f91baef54
  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v22, v28, t2

  li t2, 0x9853d4cb223bce94
  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v28, v24, t2

  li t2, 0x93f19e0f12b9e5c3
  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v24, v8, t2

  li t2, 0x6810be84e91b40a9
  vsetvli t1, t0, e16, m2, ta, ma
  vdiv.vx v24, v28, t2

  li t2, 0xa3727884dfe8f6ed
  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v16, v12, t2

  li t2, 0xc0864b50d68bd135
  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v24, v12, t2

  li t2, 0xa959e5004b580186
  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v16, v4, t2

  li t2, 0xc00a352722644ca6
  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v12, v16, t2

  li t2, 0x453a2ce6d3abc6ec
  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v8, v20, t2

  li t2, 0x702a894421cc5dd7
  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v24, v20, t2

  li t2, 0x3249f1963816d487
  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v16, v12, t2

  li t2, 0xdae347c74d7916e4
  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v20, v24, t2

  li t2, 0x4f8ac66a93d110dc
  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v8, v12, t2

  li t2, 0x1f44829a6c6ff27f
  vsetvli t1, t0, e16, m4, ta, ma
  vdiv.vx v24, v16, t2

  li t2, 0x90922b2ac2c1476b
  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v24, v8, t2

  li t2, 0x2f9930ce666f5344
  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v8, v24, t2

  li t2, 0x2c098a213d21b951
  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v24, v16, t2

  li t2, 0xd60678240fb213cf
  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v8, v16, t2

  li t2, 0x6ce3abe972947859
  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v24, t2

  li t2, 0xa417d5d43ddbbeba
  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v8, t2

  li t2, 0x3c2542fef60374b7
  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v8, t2

  li t2, 0x405c04c4ba1f5315
  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v24, t2

  li t2, 0xdfd527aa066c9481
  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v16, v8, t2

  li t2, 0x25f11dcbb397822b
  vsetvli t1, t0, e16, m8, ta, ma
  vdiv.vx v24, v8, t2

  li t2, 0xb0c20a7cc2fd2aed
  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v27, v3, t2

  li t2, 0xf81e3ae56736200f
  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v19, v4, t2

  li t2, 0x61dc017088f9a6e0
  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v8, v1, t2

  li t2, 0x9547b0766b0d4d0a
  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v3, v16, t2

  li t2, 0xaa7aee40789d2ce4
  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v27, v21, t2

  li t2, 0x5084be34fed8e691
  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v15, v17, t2

  li t2, 0x633791f487645faa
  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v5, v16, t2

  li t2, 0xc9319974bb41cd3a
  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v12, v19, t2

  li t2, 0x253243603e6af075
  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v2, v12, t2

  li t2, 0x3b74e4b064fc0af3
  vsetvli t1, t0, e32, m1, ta, ma
  vdiv.vx v14, v9, t2

  li t2, 0xd932b7de3a6772be
  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v6, v24, t2

  li t2, 0xda22796ba58375da
  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v6, v26, t2

  li t2, 0xaae39acfabb871a7
  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v22, v14, t2

  li t2, 0xbd83295056768df4
  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v22, v14, t2

  li t2, 0xfc103d674809e72c
  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v20, v4, t2

  li t2, 0x620caeff3993036b
  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v22, v26, t2

  li t2, 0x70c664c2cc528051
  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v14, v30, t2

  li t2, 0x37d9f24aeaba14c7
  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v2, v18, t2

  li t2, 0x7404526f4ef2f115
  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v14, v20, t2

  li t2, 0x81988b50b3737a4f
  vsetvli t1, t0, e32, m2, ta, ma
  vdiv.vx v20, v26, t2

  li t2, 0x3a572fc0c60cbcd3
  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v8, v20, t2

  li t2, 0xfb49d862badee52c
  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v12, v16, t2

  li t2, 0x7f8b8801c624a657
  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v20, v12, t2

  li t2, 0x83b806d8dadb9978
  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v28, v20, t2

  li t2, 0xc14b4d4cf20b52cd
  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v16, v24, t2

  li t2, 0xe3afc12a3e1669da
  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v8, v4, t2

  li t2, 0xca4ea82d942a3dab
  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v8, v12, t2

  li t2, 0x8c1b0b025537ef86
  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v24, v28, t2

  li t2, 0xb9eed9803836ab39
  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v28, v24, t2

  li t2, 0xfec04c9089d5d8c9
  vsetvli t1, t0, e32, m4, ta, ma
  vdiv.vx v24, v28, t2

  li t2, 0x9c8f62e33c030cab
  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v8, t2

  li t2, 0x7006f8603a045515
  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v8, v24, t2

  li t2, 0x2aa36d46192bdc9b
  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v16, t2

  li t2, 0x2f8b4dd78207bf29
  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v16, v24, t2

  li t2, 0x65c4264c3db1e0a5
  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v16, v8, t2

  li t2, 0xf7517f1e3d4cb1f1
  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v16, v8, t2

  li t2, 0xa6024f4b01334d85
  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v24, v8, t2

  li t2, 0x9330b3a277034148
  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v16, v24, t2

  li t2, 0x052d661de049ef10
  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v8, v24, t2

  li t2, 0x3232ee0a58ef1b0a
  vsetvli t1, t0, e32, m8, ta, ma
  vdiv.vx v16, v8, t2

  li t2, 0xea85651cb8542627
  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v8, v27, t2

  li t2, 0xda9b313585b69aa2
  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v12, v18, t2

  li t2, 0x7f04e7599f188f25
  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v20, v31, t2

  li t2, 0xe26fcae65724866f
  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v31, v23, t2

  li t2, 0xd1a4c91d8738e86e
  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v2, v18, t2

  li t2, 0xc1d21a3ba3bf04c1
  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v13, v19, t2

  li t2, 0x3860d02d21a3485d
  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v17, v2, t2

  li t2, 0xc6e7a8f11f08c24d
  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v4, v30, t2

  li t2, 0xea8450b16bf8a28b
  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v13, v24, t2

  li t2, 0x1921b8c40c3c14bd
  vsetvli t1, t0, e64, m1, ta, ma
  vdiv.vx v6, v23, t2

  li t2, 0x0ae47b9b5f67a4e7
  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v26, v16, t2

  li t2, 0x9bebe3ff13d2234c
  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v14, v22, t2

  li t2, 0x068bd3b29c44e3fb
  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v30, v26, t2

  li t2, 0x0eb07c01749d1ecd
  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v28, v18, t2

  li t2, 0x2ca78151a054f73e
  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v12, v4, t2

  li t2, 0xb0e55c76872ead7a
  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v8, v26, t2

  li t2, 0x54f2ef0102b6f44f
  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v10, v22, t2

  li t2, 0xc664bdf5b1dbc73f
  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v24, v30, t2

  li t2, 0xad6c486e0412e35a
  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v6, v16, t2

  li t2, 0x0733333795f626bf
  vsetvli t1, t0, e64, m2, ta, ma
  vdiv.vx v6, v26, t2

  li t2, 0xe49082ea65a56890
  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v4, v28, t2

  li t2, 0xabe175f9eefb2e15
  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v16, v24, t2

  li t2, 0x9d66d08dd85b55c1
  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v24, v16, t2

  li t2, 0x87ec2b74c065cf80
  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v24, v16, t2

  li t2, 0x1f596c052a92a664
  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v24, v28, t2

  li t2, 0x4031fa3af2225598
  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v20, v28, t2

  li t2, 0x08098b4c9ba1f4c5
  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v20, v28, t2

  li t2, 0x645a8515f91cc73f
  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v4, v28, t2

  li t2, 0x644212efc059e97b
  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v12, v20, t2

  li t2, 0x44f0ae404ba5855b
  vsetvli t1, t0, e64, m4, ta, ma
  vdiv.vx v12, v8, t2

  li t2, 0x8e52b677e97c31d3
  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v24, v16, t2

  li t2, 0x978dfd24ff256533
  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v8, v24, t2

  li t2, 0x99fa2fbe38c86042
  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v24, v8, t2

  li t2, 0x4b115db0c2400698
  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v16, v8, t2

  li t2, 0xcba339b4eabef587
  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v16, v8, t2

  li t2, 0x954041a61cae4f68
  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v8, v16, t2

  li t2, 0xc6467b46eb66bf5a
  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v8, v16, t2

  li t2, 0x7c208c35b245b261
  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v16, v8, t2

  li t2, 0x029e902384e31190
  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v16, v8, t2

  li t2, 0xfcf8969b0f71a220
  vsetvli t1, t0, e64, m8, ta, ma
  vdiv.vx v8, v24, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
