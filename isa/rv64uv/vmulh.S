#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v11, v14, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v21, v18, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v17, v18, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v28, v14, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v19, v18, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v3, v15, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v1, v24, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v29, v2, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v16, v7, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vv v29, v25, v1

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v22, v14, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v10, v14, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v10, v28, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v14, v8, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v28, v22, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v24, v14, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v22, v2, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v26, v30, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v18, v14, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vv v24, v6, v22

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v8, v12, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v28, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v16, v28, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v16, v4, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v12, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v4, v8, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v24, v4, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v16, v12, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v8, v24, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vv v20, v4, v28

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vv v16, v24, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v18, v16, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v16, v2, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v27, v12, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v11, v2, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v9, v6, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v30, v29, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v21, v15, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v27, v21, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v11, v5, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vv v21, v26, v31

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v10, v18, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v6, v24, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v10, v30, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v10, v30, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v4, v26, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v14, v2, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v12, v18, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v8, v24, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v18, v6, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vv v12, v2, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v28, v12, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v16, v20, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v20, v28, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v16, v28, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v16, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v24, v28, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v16, v24, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v8, v24, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vv v20, v28, v4

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vv v16, v24, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v11, v14, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v6, v1, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v14, v8, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v23, v4, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v14, v9, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v18, v31, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v19, v23, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v30, v22, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v3, v13, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vv v15, v28, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v22, v30, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v4, v22, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v12, v6, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v6, v24, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v4, v28, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v8, v6, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v30, v22, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v20, v22, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v24, v18, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vv v6, v4, v30

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v28, v8, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v28, v8, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v8, v12, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v16, v4, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v28, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v28, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v4, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v8, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v20, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vv v4, v20, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vv v8, v16, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v4, v8, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v2, v22, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v20, v3, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v24, v14, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v5, v24, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v2, v29, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v1, v8, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v20, v28, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v28, v20, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vv v23, v22, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v20, v24, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v28, v12, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v16, v18, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v16, v20, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v24, v14, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v24, v8, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v18, v12, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v30, v6, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v22, v14, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vv v4, v26, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v4, v12, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v20, v4, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v28, v16, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v20, v24, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v12, v20, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v24, v8, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v28, v4, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v4, v24, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v4, v8, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vv v20, v24, v12

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vv v16, v8, v24

  li t2, 0xd7249593f4c9581b
  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v10, v9, t2

  li t2, 0x2a17f7354d9f1a27
  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v15, v16, t2

  li t2, 0x66231b188401f1d2
  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v26, v4, t2

  li t2, 0x22e56c9ee47bcb5a
  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v16, v22, t2

  li t2, 0x14665130eb86d619
  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v30, v13, t2

  li t2, 0x6141f576bb1f5c2b
  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v1, v23, t2

  li t2, 0x1274345754d82b26
  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v17, v28, t2

  li t2, 0x6a7fd015a7a4ef4f
  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v1, v28, t2

  li t2, 0x7ad04fd32b6084ad
  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v20, v16, t2

  li t2, 0x58016b2ca0e77ed0
  vsetvli t1, t0, e8, m1, ta, ma
  vmulh.vx v19, v16, t2

  li t2, 0x2954dd92217cff9b
  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v28, v8, t2

  li t2, 0x5f6caf483ceee69e
  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v14, v20, t2

  li t2, 0xd89391ec6d0cc133
  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v10, v20, t2

  li t2, 0x64f107f29fd8a989
  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v28, v6, t2

  li t2, 0x376644f59513ef71
  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v18, v10, t2

  li t2, 0x03f76cb9eb033234
  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v14, v2, t2

  li t2, 0x9222a4534b219426
  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v18, v30, t2

  li t2, 0x371865cc0167d563
  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v10, v30, t2

  li t2, 0x04a87ba513ef954c
  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v20, v16, t2

  li t2, 0xbc20eb0ab8507f97
  vsetvli t1, t0, e8, m2, ta, ma
  vmulh.vx v30, v16, t2

  li t2, 0x6f05d82ceb39832e
  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v12, v8, t2

  li t2, 0x49f8cea3f802210c
  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v8, v20, t2

  li t2, 0x7328f1d1b4d9bd46
  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v4, v16, t2

  li t2, 0x023ecf5cdd8c68b6
  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v8, v4, t2

  li t2, 0xa5a7df4bd11fc289
  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v28, v8, t2

  li t2, 0x02a59e7732343bf2
  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v4, v8, t2

  li t2, 0xd17c31d5f3c543ba
  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v28, v4, t2

  li t2, 0x9e1dc06664d2bf88
  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v28, v24, t2

  li t2, 0xf8eea08c130b8c86
  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v4, v20, t2

  li t2, 0xa48c3d0d07b7020f
  vsetvli t1, t0, e8, m4, ta, ma
  vmulh.vx v8, v24, t2

  li t2, 0xd6a081facd043802
  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v8, v24, t2

  li t2, 0x8f08ab690f796d96
  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v8, v16, t2

  li t2, 0x5c38a657720343ca
  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v8, t2

  li t2, 0xadd31994813ab007
  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v16, v24, t2

  li t2, 0xd925b4dac42d60c5
  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v16, t2

  li t2, 0x76a75c0783188dfa
  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v8, t2

  li t2, 0xfe59e331613c0279
  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v8, v16, t2

  li t2, 0xa3df48afea0ca3bd
  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v24, v8, t2

  li t2, 0x9901e77577d2b2cf
  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v16, v24, t2

  li t2, 0x0255df0888c306e3
  vsetvli t1, t0, e8, m8, ta, ma
  vmulh.vx v8, v16, t2

  li t2, 0x8b2724193935ac1b
  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v29, v6, t2

  li t2, 0x655f2a7b5f2cb77d
  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v29, v15, t2

  li t2, 0x4b05d8b033eba020
  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v8, v17, t2

  li t2, 0xb298ac8f6f7fff0b
  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v29, v14, t2

  li t2, 0x697afb1105fa4cfc
  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v24, v13, t2

  li t2, 0xb4757becf0af042e
  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v25, v31, t2

  li t2, 0x478edf3607571eda
  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v20, v28, t2

  li t2, 0x6bce77afd5634d58
  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v14, v23, t2

  li t2, 0x1fea869b434a8738
  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v11, v21, t2

  li t2, 0xb4da90d299719b09
  vsetvli t1, t0, e16, m1, ta, ma
  vmulh.vx v11, v28, t2

  li t2, 0xfa7cd85dcebe7ab0
  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v2, v22, t2

  li t2, 0x798d2118effaa956
  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v30, v12, t2

  li t2, 0x2ce9595ca2b341a3
  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v8, v6, t2

  li t2, 0x68cff590766bdbaa
  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v20, v2, t2

  li t2, 0x1c06f3bec32fc1c0
  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v22, v30, t2

  li t2, 0xf262fbf84b4846fc
  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v30, v22, t2

  li t2, 0xd0781c29653a7514
  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v12, v4, t2

  li t2, 0xf0e0b462f497cd38
  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v6, v22, t2

  li t2, 0x177e56b763244a71
  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v30, v2, t2

  li t2, 0x55420397d108273c
  vsetvli t1, t0, e16, m2, ta, ma
  vmulh.vx v4, v12, t2

  li t2, 0xacacaf82a6683307
  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v16, v8, t2

  li t2, 0xeaf8cacfb55f1f90
  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v24, v4, t2

  li t2, 0xc38e584d0e27519d
  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v16, v28, t2

  li t2, 0x1afbf89d015da7f8
  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v20, v12, t2

  li t2, 0xa8096a624922fd51
  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v4, v16, t2

  li t2, 0x3987542dd17143e3
  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v28, v20, t2

  li t2, 0xd5a774e004a3165c
  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v16, v24, t2

  li t2, 0xdb7eae29369e8c7c
  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v28, v4, t2

  li t2, 0x7d5e576034ae3160
  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v8, v24, t2

  li t2, 0x372fed99fa1ac908
  vsetvli t1, t0, e16, m4, ta, ma
  vmulh.vx v8, v24, t2

  li t2, 0xe21fd4b4d9f3e004
  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v16, v8, t2

  li t2, 0xb84b4b858fd3a12f
  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v16, t2

  li t2, 0xa4ebf8fbe53a9479
  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v16, t2

  li t2, 0xde0e162b7004283c
  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v16, v24, t2

  li t2, 0x9f263a3e3731137e
  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v16, v24, t2

  li t2, 0xd2b546e468c0389f
  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v16, t2

  li t2, 0x58678594ea643a55
  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v8, v24, t2

  li t2, 0xe86c8167e9e1833b
  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v16, v8, t2

  li t2, 0xb7fb6fcb3e405ffd
  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v24, v8, t2

  li t2, 0x39830a15c3a75334
  vsetvli t1, t0, e16, m8, ta, ma
  vmulh.vx v16, v24, t2

  li t2, 0x3aab3be12ce67777
  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v4, v20, t2

  li t2, 0x336ec6dfa5bcf68c
  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v20, v9, t2

  li t2, 0xe9fec476044341ce
  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v27, v10, t2

  li t2, 0x8aaa985936866656
  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v30, v8, t2

  li t2, 0x0008f157c1c9818a
  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v18, v19, t2

  li t2, 0x6753def1c4a6895d
  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v3, v18, t2

  li t2, 0x5a7f4eb7d896d9c4
  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v6, v29, t2

  li t2, 0xc1dc788661e9469f
  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v15, v28, t2

  li t2, 0xd4a8d8735e72be92
  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v18, v31, t2

  li t2, 0x179617eb26a5d785
  vsetvli t1, t0, e32, m1, ta, ma
  vmulh.vx v11, v29, t2

  li t2, 0x77833c68404825d1
  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v28, v24, t2

  li t2, 0x58c81f737b4b8232
  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v26, v16, t2

  li t2, 0xa276704ae02fde20
  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v16, v28, t2

  li t2, 0x656e0db9b6d992ff
  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v28, v6, t2

  li t2, 0x94a21d41c652da23
  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v6, v12, t2

  li t2, 0x0c0f4eeb8110031f
  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v16, v26, t2

  li t2, 0x09320220d509296f
  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v22, v8, t2

  li t2, 0xf18d98e760ec6e6d
  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v4, v2, t2

  li t2, 0x67013a336f412cda
  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v14, v20, t2

  li t2, 0x9fa2bf9c4f14a6f5
  vsetvli t1, t0, e32, m2, ta, ma
  vmulh.vx v14, v2, t2

  li t2, 0x2a6e865996c25592
  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v16, v12, t2

  li t2, 0x0f48a9ddea7cd3d3
  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v12, v4, t2

  li t2, 0x84c6c63841f5a6ad
  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v12, v8, t2

  li t2, 0x515cb5d6616a8ad9
  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v28, v20, t2

  li t2, 0x76acc619f94463c1
  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v4, v24, t2

  li t2, 0x3f3160d872e84b6a
  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v4, v24, t2

  li t2, 0x1cb5e0614d3aab63
  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v28, v16, t2

  li t2, 0xa4fa91790462a96f
  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v12, v16, t2

  li t2, 0xabfcda3694f3016f
  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v28, v16, t2

  li t2, 0x00c073a2c5b53d2b
  vsetvli t1, t0, e32, m4, ta, ma
  vmulh.vx v20, v28, t2

  li t2, 0xa288603ec1e01ffb
  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v8, v24, t2

  li t2, 0x4e2a465c386663ff
  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v8, v24, t2

  li t2, 0xae2bab75a832bd4e
  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v16, v24, t2

  li t2, 0x74b9e9ed9d3ce6b8
  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v24, v8, t2

  li t2, 0xf5bd1ccd2cf2b2b5
  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v16, v24, t2

  li t2, 0xdb05e6441d85d62a
  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v8, v16, t2

  li t2, 0x59a986a8ead6276e
  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v8, v16, t2

  li t2, 0x221a7690558a5b35
  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v8, v16, t2

  li t2, 0xc5b0b88610158b3b
  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v8, v24, t2

  li t2, 0xef267b2e0081f215
  vsetvli t1, t0, e32, m8, ta, ma
  vmulh.vx v24, v8, t2

  li t2, 0xa84eebcec919b240
  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v4, v7, t2

  li t2, 0x3055c82bfd1716cc
  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v8, v30, t2

  li t2, 0x30d70fbf07658833
  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v18, v24, t2

  li t2, 0x0150c5d96085e1c5
  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v4, v7, t2

  li t2, 0xe6fd1ae84ee0c1ae
  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v6, v8, t2

  li t2, 0x20b10ba69708c17f
  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v14, v28, t2

  li t2, 0x1812c007337112d9
  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v22, v19, t2

  li t2, 0x155e51297664ea7d
  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v21, v29, t2

  li t2, 0xa69afd3bb05c8dd9
  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v11, v26, t2

  li t2, 0x253f4fd3e5ead021
  vsetvli t1, t0, e64, m1, ta, ma
  vmulh.vx v6, v19, t2

  li t2, 0x42a1ea93ca42c4ed
  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v6, v14, t2

  li t2, 0xe9bce97792de71da
  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v28, v6, t2

  li t2, 0xc39660d58476309b
  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v14, v26, t2

  li t2, 0xb5f7371306980b4f
  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v10, v26, t2

  li t2, 0xe29f87a8723ddc6f
  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v26, v24, t2

  li t2, 0x580589fdc2bbf254
  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v16, v2, t2

  li t2, 0x00fb22f9b6e369fd
  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v28, v2, t2

  li t2, 0x00b0cc7151db2e67
  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v24, v26, t2

  li t2, 0xca429f094be4f5a2
  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v4, v16, t2

  li t2, 0xe999bff85335c838
  vsetvli t1, t0, e64, m2, ta, ma
  vmulh.vx v22, v20, t2

  li t2, 0x9245a7a12fe344cf
  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v16, v24, t2

  li t2, 0xf29b89ea4a8e7dc5
  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v16, v20, t2

  li t2, 0x2f38c2755f42e62b
  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v24, v28, t2

  li t2, 0x6e91b43c4cca3e2c
  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v16, v20, t2

  li t2, 0x7831c59bd821f793
  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v12, v24, t2

  li t2, 0x302a6c1b472df0e1
  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v28, v4, t2

  li t2, 0x622686a7052571d6
  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v16, v24, t2

  li t2, 0x3c954be4dd914104
  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v24, v8, t2

  li t2, 0xdae3a8dad9b8bea5
  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v4, v28, t2

  li t2, 0xcd92b34a1e05abbf
  vsetvli t1, t0, e64, m4, ta, ma
  vmulh.vx v12, v20, t2

  li t2, 0xf125385fb715128f
  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v24, v16, t2

  li t2, 0xffc90a40254ce435
  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v16, v8, t2

  li t2, 0xf2cce1623ebfaa28
  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v16, v24, t2

  li t2, 0x6f8eefbb12adc56c
  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v16, v24, t2

  li t2, 0x2088dfbdb5e373c3
  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v16, v8, t2

  li t2, 0x1377385b79267bcf
  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v24, v8, t2

  li t2, 0x8a82d1ddf4cd3222
  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v8, v24, t2

  li t2, 0x9b2d13e03c47e0f7
  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v24, v16, t2

  li t2, 0x4052b30814bb3766
  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v8, v24, t2

  li t2, 0xe9173b55a703317c
  vsetvli t1, t0, e64, m8, ta, ma
  vmulh.vx v8, v24, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
