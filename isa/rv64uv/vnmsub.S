#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vv v1, v11, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vv v25, v19, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vv v9, v21, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vv v19, v6, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vv v24, v28, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vv v12, v7, v31

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vv v26, v19, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vv v14, v23, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vv v9, v31, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vv v27, v18, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vv v20, v8, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vv v26, v18, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vv v10, v20, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vv v2, v10, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vv v24, v4, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vv v14, v10, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vv v10, v8, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vv v22, v6, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vv v28, v6, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vv v18, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vv v20, v12, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vv v4, v8, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vv v12, v20, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vv v20, v16, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vv v28, v4, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vv v16, v20, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vv v4, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vv v24, v28, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vv v4, v28, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vv v28, v12, v20

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vv v24, v16, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vv v7, v29, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vv v23, v18, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vv v8, v10, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vv v23, v17, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vv v31, v13, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vv v19, v23, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vv v13, v27, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vv v31, v7, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vv v27, v24, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vv v19, v30, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vv v18, v16, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vv v6, v24, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vv v14, v2, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vv v8, v24, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vv v30, v18, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vv v18, v28, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vv v2, v10, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vv v12, v8, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vv v22, v10, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vv v18, v8, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vv v24, v20, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vv v8, v24, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vv v12, v8, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vv v4, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vv v28, v4, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vv v12, v4, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vv v24, v20, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vv v16, v28, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vv v12, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vv v8, v24, v28

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vv v16, v8, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vv v28, v13, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vv v27, v30, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vv v28, v25, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vv v6, v24, v5

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vv v26, v14, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vv v15, v18, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vv v15, v23, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vv v15, v20, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vv v19, v27, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vv v7, v16, v13

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vv v22, v28, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vv v14, v26, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vv v12, v30, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vv v2, v18, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vv v18, v28, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vv v6, v8, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vv v30, v24, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vv v26, v16, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vv v8, v14, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vv v28, v30, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vv v8, v24, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vv v12, v28, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vv v24, v4, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vv v4, v20, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vv v20, v4, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vv v24, v4, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vv v8, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vv v12, v20, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vv v16, v4, v28

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vv v16, v8, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vv v27, v26, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vv v8, v26, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vv v8, v1, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vv v31, v7, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vv v24, v17, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vv v23, v30, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vv v29, v5, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vv v7, v28, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vv v22, v15, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vv v27, v12, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vv v22, v4, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vv v14, v26, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vv v8, v2, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vv v20, v12, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vv v14, v6, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vv v26, v28, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vv v18, v24, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vv v8, v10, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vv v26, v10, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vv v20, v10, v2

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vv v24, v28, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vv v24, v28, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vv v28, v8, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vv v8, v28, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vv v16, v20, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vv v8, v16, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vv v8, v16, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vv v20, v4, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vv v20, v24, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vv v12, v20, v4

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vv v16, v24, v8

  li t2, 0x879fe7cd7f776027
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vx v6, t2, v5

  li t2, 0x56fc58d785f8b0d2
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vx v6, t2, v4

  li t2, 0x74eac9eff2191df4
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vx v15, t2, v22

  li t2, 0xb52fb5c21598ce5b
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vx v18, t2, v12

  li t2, 0xdd180ec77f406c13
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vx v23, t2, v26

  li t2, 0xeceb666cabfa589d
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vx v13, t2, v8

  li t2, 0xeef0f48145fa29a7
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vx v26, t2, v8

  li t2, 0x815c343c610b94cc
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vx v3, t2, v18

  li t2, 0x513d15ef328022c3
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vx v4, t2, v29

  li t2, 0x885a129827917564
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsub.vx v31, t2, v2

  li t2, 0x64a19d31a208aa70
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vx v24, t2, v2

  li t2, 0xa43a1f353154139c
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vx v28, t2, v4

  li t2, 0xa20d93cd18b67f42
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vx v6, t2, v30

  li t2, 0xab0a50a0dda6b35c
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vx v6, t2, v30

  li t2, 0x19b1687d2caedb21
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vx v10, t2, v18

  li t2, 0x5aa1342d0b4d78bb
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vx v28, t2, v22

  li t2, 0xf56239211d60e860
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vx v14, t2, v26

  li t2, 0xf83f11acbb6d0fa4
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vx v12, t2, v28

  li t2, 0xa13f3784a8b42659
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vx v26, t2, v28

  li t2, 0xfe281706b2fe584a
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsub.vx v10, t2, v28

  li t2, 0x75d8c9f4520eb241
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vx v20, t2, v16

  li t2, 0x8d831921bc5a081a
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vx v24, t2, v16

  li t2, 0xe3832adf17e1e5a9
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vx v12, t2, v28

  li t2, 0xa2942dfb7e0df142
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vx v28, t2, v4

  li t2, 0x685c8e82d6072e86
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vx v20, t2, v4

  li t2, 0xa141e4dc60c57d5f
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vx v8, t2, v28

  li t2, 0x9de78a510894fa0f
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vx v28, t2, v16

  li t2, 0x5fa2cdd51d8e2364
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vx v16, t2, v12

  li t2, 0xd5ec78279fd9b100
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vx v4, t2, v28

  li t2, 0x8b91852386bcf8eb
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsub.vx v24, t2, v12

  li t2, 0x7ba0623410caba36
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vx v24, t2, v8

  li t2, 0xef9f1cd1fe85c493
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vx v16, t2, v8

  li t2, 0x67c2bdc7be9e3fdd
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vx v16, t2, v8

  li t2, 0x4eb9a174ceb1d2ee
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vx v24, t2, v16

  li t2, 0xf4b856fcb8d06eb1
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vx v24, t2, v16

  li t2, 0x0fb36b7142bb7444
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vx v24, t2, v8

  li t2, 0x76c5a09784759c34
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vx v16, t2, v24

  li t2, 0x6b151326f7e3ffce
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vx v16, t2, v24

  li t2, 0x8593de003bb386fe
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vx v24, t2, v16

  li t2, 0x740df4cfd2ef0172
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsub.vx v8, t2, v16

  li t2, 0x19e11ac8bba4d525
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vx v23, t2, v9

  li t2, 0xf864c0a47f3d54ea
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vx v13, t2, v17

  li t2, 0x4037fa99afc178a5
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vx v30, t2, v12

  li t2, 0x520e4d57b2a209d5
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vx v2, t2, v30

  li t2, 0xc318756d9811266b
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vx v10, t2, v26

  li t2, 0x838877c65beb0f50
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vx v2, t2, v20

  li t2, 0x38c6db1fcedc36cb
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vx v8, t2, v19

  li t2, 0x66cef1a1d69864ba
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vx v8, t2, v9

  li t2, 0x9064726791f894b8
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vx v17, t2, v19

  li t2, 0x457d848fd7b41af0
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsub.vx v4, t2, v18

  li t2, 0x1cf7db699617db59
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vx v10, t2, v28

  li t2, 0x50e85c2fc2175c15
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vx v28, t2, v26

  li t2, 0xaf1502f824227939
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vx v22, t2, v28

  li t2, 0x90aed2a0e4dbddd4
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vx v18, t2, v6

  li t2, 0x2c13d4cb5d5198ad
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vx v24, t2, v10

  li t2, 0xc9b2e63a447dace3
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vx v22, t2, v10

  li t2, 0x9a4dd289c02fdf38
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vx v26, t2, v6

  li t2, 0xff031c37fb22849f
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vx v8, t2, v20

  li t2, 0x8d928d5fc398ff65
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vx v16, t2, v22

  li t2, 0x3569cfbf683ad962
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsub.vx v2, t2, v20

  li t2, 0xe9bdbd2bdf28264f
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vx v8, t2, v4

  li t2, 0x25189bc184e41778
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vx v8, t2, v4

  li t2, 0x70abf241130675d2
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vx v20, t2, v16

  li t2, 0xe4579fc36f8e30ab
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vx v16, t2, v4

  li t2, 0x040dd8a48c5f35a1
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vx v24, t2, v8

  li t2, 0xcc9feebccea9b868
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vx v4, t2, v24

  li t2, 0xd6c17d6e4b18fe3a
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vx v12, t2, v20

  li t2, 0xf61877d804b96fb1
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vx v12, t2, v20

  li t2, 0x81d3dad4fdc0974f
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vx v4, t2, v12

  li t2, 0x8fe78b5a0963a570
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsub.vx v20, t2, v12

  li t2, 0x94fb31b672aeef4e
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vx v16, t2, v8

  li t2, 0x6e9724d54d87d103
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vx v16, t2, v8

  li t2, 0x3c557f400f8019b9
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vx v8, t2, v24

  li t2, 0x7742744c53f24f47
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vx v16, t2, v24

  li t2, 0xf3e79d30cf286824
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vx v8, t2, v16

  li t2, 0xbb53f421e8a324e4
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vx v16, t2, v24

  li t2, 0x58ba8983418e3d36
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vx v16, t2, v24

  li t2, 0xd7edc910cd1c1725
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vx v16, t2, v8

  li t2, 0x8253c0697be97517
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vx v24, t2, v8

  li t2, 0x7a9329bc1362e3e4
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsub.vx v8, t2, v24

  li t2, 0x679e5c9115838bf9
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vx v20, t2, v15

  li t2, 0x72253e6bfc5ca2b2
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vx v27, t2, v21

  li t2, 0x9463f347e8980650
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vx v1, t2, v18

  li t2, 0x0461cc542f1cc8c5
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vx v4, t2, v5

  li t2, 0x5f6bbc25c52f4ff3
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vx v19, t2, v23

  li t2, 0x63438c561a9d133d
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vx v16, t2, v24

  li t2, 0x06958b435debf877
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vx v14, t2, v20

  li t2, 0xabeb7e234c4eff86
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vx v22, t2, v4

  li t2, 0x1367a5998fc619a5
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vx v9, t2, v3

  li t2, 0x5953d8ffdac98cbe
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsub.vx v7, t2, v26

  li t2, 0xbcda2e293b0697c2
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vx v10, t2, v4

  li t2, 0x5fb2aab0fb21d7b6
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vx v20, t2, v28

  li t2, 0x76509cb4a9272c38
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vx v14, t2, v6

  li t2, 0x77293c1354853c74
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vx v22, t2, v6

  li t2, 0x8f1567abbf87f5ef
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vx v6, t2, v12

  li t2, 0x62175a7b8d64e1a0
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vx v20, t2, v6

  li t2, 0x70ee0c6c04eb4c38
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vx v18, t2, v24

  li t2, 0x65bed61f719b116c
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vx v14, t2, v6

  li t2, 0xed7ff9ae333bd87f
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vx v14, t2, v4

  li t2, 0x83802751d15c2ed8
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsub.vx v20, t2, v10

  li t2, 0x5b51f2f7d1528691
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vx v24, t2, v4

  li t2, 0xe3385e4b83a26243
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vx v20, t2, v12

  li t2, 0x2ec401ad155cf412
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vx v28, t2, v12

  li t2, 0x47f975fb8bf0ef42
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vx v16, t2, v8

  li t2, 0xb946981bf63660cd
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vx v20, t2, v16

  li t2, 0xec65531f905a9df6
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vx v4, t2, v28

  li t2, 0x2ba6ccb681fbf6a3
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vx v4, t2, v8

  li t2, 0x530ebee4f01a8fad
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vx v24, t2, v4

  li t2, 0x62fb55f026bf4afe
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vx v8, t2, v16

  li t2, 0xbd4292e454c403be
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsub.vx v20, t2, v24

  li t2, 0xbf57437c2b51dea7
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vx v24, t2, v16

  li t2, 0x727526c5080fb783
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vx v24, t2, v16

  li t2, 0xb15553cb0437b6ad
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vx v8, t2, v16

  li t2, 0xe05ebc29e54ae043
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vx v24, t2, v8

  li t2, 0x27a97cda4f355489
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vx v16, t2, v24

  li t2, 0xa19e3645411119e9
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vx v16, t2, v8

  li t2, 0xe8ffca88412c3cc2
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vx v8, t2, v24

  li t2, 0x378827afcce852c6
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vx v24, t2, v16

  li t2, 0x353bd0a7202a8af5
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vx v8, t2, v16

  li t2, 0xf27c39a3488a27a0
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsub.vx v16, t2, v8

  li t2, 0x660a7ee34322d1e4
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vx v26, t2, v22

  li t2, 0x75eebc0154c68037
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vx v5, t2, v15

  li t2, 0xf3823847f82603f9
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vx v12, t2, v14

  li t2, 0xc1c7c84aba4a8201
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vx v13, t2, v10

  li t2, 0x7f343038f5f7003f
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vx v26, t2, v18

  li t2, 0xf00b34198a6849c3
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vx v29, t2, v19

  li t2, 0xabefcd47e0d87bf9
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vx v26, t2, v29

  li t2, 0x207623d32212a069
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vx v15, t2, v26

  li t2, 0x7a962860b79e838a
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vx v14, t2, v8

  li t2, 0xd3da279a54bec2b4
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsub.vx v26, t2, v27

  li t2, 0x0f975c5cef2db8be
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vx v18, t2, v20

  li t2, 0xe090e2c1ef39787d
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vx v28, t2, v2

  li t2, 0x52d5b7895be08fc0
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vx v30, t2, v22

  li t2, 0x988c3b49f76898b7
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vx v12, t2, v8

  li t2, 0xc5d167d98299604b
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vx v4, t2, v6

  li t2, 0x16019969051ab39f
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vx v28, t2, v4

  li t2, 0xaf87c5eef152f45c
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vx v14, t2, v26

  li t2, 0x5d2b0ebdedd67064
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vx v28, t2, v14

  li t2, 0x7d56ec5f59b86c76
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vx v2, t2, v28

  li t2, 0x2c49e3353c7a8fb5
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsub.vx v26, t2, v22

  li t2, 0x8018447899724620
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vx v28, t2, v4

  li t2, 0x3caf8d2f4997345a
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vx v24, t2, v8

  li t2, 0x70d12e61c6c35ee5
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vx v20, t2, v8

  li t2, 0x67649bdc336e5232
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vx v4, t2, v20

  li t2, 0xa86d0fc55d380888
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vx v28, t2, v4

  li t2, 0xa57f4914e39cbadc
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vx v24, t2, v12

  li t2, 0xea30a064f3354c0a
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vx v8, t2, v28

  li t2, 0x8def2b2751f9137b
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vx v20, t2, v4

  li t2, 0x7a24c26124785f7b
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vx v28, t2, v12

  li t2, 0xf39b0e15ceaa96cf
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsub.vx v28, t2, v16

  li t2, 0x2ff0d9ecc66b775b
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vx v24, t2, v8

  li t2, 0xae0b0984d279e818
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vx v8, t2, v16

  li t2, 0x2d8e080bfe7149ec
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vx v24, t2, v8

  li t2, 0x458ccfe5cb0d7b85
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vx v8, t2, v16

  li t2, 0xb64de26ef3227777
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vx v16, t2, v24

  li t2, 0x77b48a1f6e87419f
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vx v24, t2, v16

  li t2, 0xe3f781e5a66321aa
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vx v24, t2, v16

  li t2, 0x23b64a82655b4d80
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vx v8, t2, v24

  li t2, 0xf1bff22c7c970fd8
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vx v24, t2, v16

  li t2, 0x649121facd988f03
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsub.vx v24, t2, v16

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
