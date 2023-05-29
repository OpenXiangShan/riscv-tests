#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vv v18, v13, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vv v5, v22, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vv v21, v22, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vv v18, v3, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vv v15, v24, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vv v25, v5, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vv v30, v28, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vv v31, v6, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vv v23, v5, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vv v1, v22, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vv v26, v2, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vv v4, v12, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vv v4, v20, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vv v10, v12, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vv v24, v22, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vv v18, v24, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vv v28, v4, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vv v30, v28, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vv v26, v14, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vv v22, v4, v14

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vv v20, v4, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vv v8, v24, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vv v8, v24, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vv v16, v12, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vv v12, v28, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vv v28, v16, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vv v8, v16, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vv v16, v12, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vv v28, v24, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vv v20, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vv v25, v6, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vv v21, v15, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vv v5, v24, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vv v28, v2, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vv v30, v13, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vv v30, v10, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vv v16, v21, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vv v20, v5, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vv v8, v15, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vv v1, v7, v27

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vv v20, v18, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vv v16, v20, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vv v12, v24, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vv v28, v30, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vv v24, v8, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vv v28, v30, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vv v6, v8, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vv v20, v26, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vv v18, v16, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vv v22, v10, v18

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vv v28, v24, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vv v12, v16, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vv v8, v28, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vv v12, v28, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vv v16, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vv v20, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vv v28, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vv v4, v8, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vv v12, v24, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vv v24, v20, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vv v24, v8, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vv v8, v28, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vv v26, v18, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vv v16, v5, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vv v29, v8, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vv v12, v13, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vv v22, v30, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vv v31, v5, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vv v22, v19, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vv v29, v31, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vv v10, v3, v13

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vv v14, v18, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vv v18, v22, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vv v30, v6, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vv v8, v30, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vv v30, v20, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vv v10, v20, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vv v4, v6, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vv v22, v16, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vv v2, v12, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vv v22, v2, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vv v24, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vv v24, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vv v4, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vv v4, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vv v24, v12, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vv v12, v16, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vv v8, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vv v8, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vv v24, v16, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vv v16, v12, v28

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vv v16, v24, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vv v28, v2, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vv v17, v3, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vv v22, v31, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vv v23, v5, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vv v26, v5, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vv v31, v29, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vv v13, v24, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vv v8, v20, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vv v4, v28, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vv v1, v11, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vv v22, v26, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vv v2, v30, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vv v30, v6, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vv v2, v18, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vv v20, v24, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vv v16, v2, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vv v20, v2, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vv v30, v24, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vv v12, v20, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vv v20, v6, v30

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vv v28, v20, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vv v20, v28, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vv v16, v28, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vv v28, v16, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vv v8, v12, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vv v4, v28, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vv v16, v12, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vv v8, v24, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vv v12, v24, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vv v24, v4, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vv v8, v16, v24

  li t2, 0xb6a367c01763cb03
  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v14, t2, v11

  li t2, 0x5174503a10853648
  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v13, t2, v27

  li t2, 0x527c8641f74ff94f
  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v20, t2, v16

  li t2, 0x7a807482307a3200
  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v30, t2, v13

  li t2, 0x628e7d32134a3112
  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v7, t2, v3

  li t2, 0x562c7b42e1493090
  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v31, t2, v29

  li t2, 0xcbcf26ea86f65abe
  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v10, t2, v11

  li t2, 0xb70ac431146a7387
  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v26, t2, v12

  li t2, 0xb41b1e9fb0ab1738
  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v26, t2, v1

  li t2, 0xfd4c944da17c14c7
  vsetvli t1, t0, e8, m1, ta, ma
  vmacc.vx v5, t2, v12

  li t2, 0xd5881741387fb877
  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v28, t2, v16

  li t2, 0x87cfacc83e176412
  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v12, t2, v10

  li t2, 0x000849b7f6cff102
  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v12, t2, v14

  li t2, 0xf898745975d97391
  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v30, t2, v12

  li t2, 0xf50d5f80a3241cdc
  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v18, t2, v14

  li t2, 0x6e6e66fee571fdcc
  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v20, t2, v12

  li t2, 0x5884d71c2ceb56c0
  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v18, t2, v30

  li t2, 0x585fbdabb09a1188
  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v2, t2, v6

  li t2, 0x17db0f479b109785
  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v12, t2, v26

  li t2, 0x99dc8665d2cfd4f6
  vsetvli t1, t0, e8, m2, ta, ma
  vmacc.vx v10, t2, v2

  li t2, 0x6670631e49d99c89
  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v24, t2, v28

  li t2, 0xa6256130cfab1442
  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v8, t2, v24

  li t2, 0x787a6dd515559e74
  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v12, t2, v24

  li t2, 0xac00262ea1c0e6ec
  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v4, t2, v20

  li t2, 0x4b462d5d45c419e9
  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v12, t2, v16

  li t2, 0xdc8d5684ccfaf6e9
  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v12, t2, v24

  li t2, 0x3b42bae507842c12
  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v28, t2, v24

  li t2, 0x804a4524afd5506f
  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v12, t2, v20

  li t2, 0x3d90736c3a324f12
  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v8, t2, v4

  li t2, 0x4e422b0d17ca4c39
  vsetvli t1, t0, e8, m4, ta, ma
  vmacc.vx v12, t2, v4

  li t2, 0x4c854b37f70cedff
  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v16, t2, v8

  li t2, 0xef2035ddcd4544d7
  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v8, t2, v16

  li t2, 0xac531dc5118a402c
  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v16, t2, v24

  li t2, 0x1228382cbef63077
  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v16, t2, v8

  li t2, 0xd2d451b0375deb38
  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v16, t2, v24

  li t2, 0x4f7c9234efe4e74d
  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v8, t2, v24

  li t2, 0x9374d5a2af2a1576
  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v24, t2, v16

  li t2, 0x2f93256270210bf8
  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v16, t2, v8

  li t2, 0x0b550a65fce16587
  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v16, t2, v24

  li t2, 0x44cd5368be53e8f1
  vsetvli t1, t0, e8, m8, ta, ma
  vmacc.vx v16, t2, v24

  li t2, 0x3ad6099830e7934a
  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v23, t2, v27

  li t2, 0x62bad2964b31e93e
  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v27, t2, v22

  li t2, 0x3af7c5e7a8eefcdc
  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v4, t2, v21

  li t2, 0x47c5d6183c9e83da
  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v31, t2, v10

  li t2, 0x593b9c0e331d4518
  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v20, t2, v30

  li t2, 0x75eed1836b42458b
  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v7, t2, v5

  li t2, 0x546d2b990de9e9e6
  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v8, t2, v13

  li t2, 0xf6b5cb5c75e80ae2
  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v7, t2, v20

  li t2, 0xde02196785684e0f
  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v28, t2, v13

  li t2, 0x0b8a217c6d86e5d3
  vsetvli t1, t0, e16, m1, ta, ma
  vmacc.vx v12, t2, v28

  li t2, 0x1c6444fae29807dd
  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v6, t2, v18

  li t2, 0x76d561b227cb5848
  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v28, t2, v2

  li t2, 0xff408a592b23c37e
  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v4, t2, v20

  li t2, 0xb49d5ff62407c4a5
  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v30, t2, v26

  li t2, 0xca75760be1056b1a
  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v30, t2, v16

  li t2, 0xee6e469e5b590f93
  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v10, t2, v24

  li t2, 0xb71d0bbfe9b40520
  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v12, t2, v4

  li t2, 0x7f3473ba3317f9d2
  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v30, t2, v26

  li t2, 0x22b0d3bc335533de
  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v12, t2, v8

  li t2, 0x587a805030fed33c
  vsetvli t1, t0, e16, m2, ta, ma
  vmacc.vx v22, t2, v20

  li t2, 0xf0b8b49ec53edbf3
  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v4, t2, v16

  li t2, 0x276e7c4847898b5e
  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v12, t2, v20

  li t2, 0x463c4af5b96491b3
  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v4, t2, v12

  li t2, 0xb68368288bbea871
  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v12, t2, v24

  li t2, 0x74307f44c41f5d2d
  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v4, t2, v28

  li t2, 0x398254164ef36026
  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v28, t2, v16

  li t2, 0x6b847ae28fe03d32
  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v8, t2, v4

  li t2, 0x3c3f4d6c554ea153
  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v24, t2, v16

  li t2, 0xaf4c4034c58d568b
  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v24, t2, v16

  li t2, 0xafb857ab261ed09d
  vsetvli t1, t0, e16, m4, ta, ma
  vmacc.vx v20, t2, v28

  li t2, 0xaeb3ae1d1f9bd673
  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v8, t2, v16

  li t2, 0x280826e713d67d4f
  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v24, t2, v8

  li t2, 0xaaaf11a90e5f07c0
  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v8, t2, v24

  li t2, 0x074e0c6926af45ec
  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v16, t2, v8

  li t2, 0x90c10a27d49d89e7
  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v8, t2, v16

  li t2, 0x9fffb9744bfe75d7
  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v24, t2, v16

  li t2, 0x0cf7abcfbe716735
  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v8, t2, v24

  li t2, 0x54f6336a989fc1e6
  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v8, t2, v24

  li t2, 0x2d8d67549ce82b73
  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v24, t2, v8

  li t2, 0x5f882e3bbfff5519
  vsetvli t1, t0, e16, m8, ta, ma
  vmacc.vx v16, t2, v24

  li t2, 0x3f51a19ea53f2365
  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v3, t2, v11

  li t2, 0x6aaba7cf7ac56b84
  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v12, t2, v24

  li t2, 0x783eb0fcc2fd7844
  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v12, t2, v27

  li t2, 0x1f326a64165d34f1
  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v10, t2, v5

  li t2, 0x7bca456d6d656d10
  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v9, t2, v31

  li t2, 0xa5fb8eb52d379520
  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v15, t2, v18

  li t2, 0x328317d7c9fbedf6
  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v3, t2, v29

  li t2, 0x9f724796efd6775a
  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v12, t2, v4

  li t2, 0xbd4a511757cd74da
  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v7, t2, v31

  li t2, 0x45d8af1f2ced0a3b
  vsetvli t1, t0, e32, m1, ta, ma
  vmacc.vx v26, t2, v8

  li t2, 0x2092f3a3f8825e5e
  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v24, t2, v4

  li t2, 0xf94def2e1bf11e6e
  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v4, t2, v28

  li t2, 0x6688ed9f923fdfde
  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v14, t2, v22

  li t2, 0x8fabe21cd31d769a
  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v30, t2, v28

  li t2, 0x24115dcea53fae3e
  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v4, t2, v16

  li t2, 0xb4a8c0099cf461a0
  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v14, t2, v24

  li t2, 0x47eaf1708e31b48e
  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v14, t2, v30

  li t2, 0x4485395586721dda
  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v28, t2, v2

  li t2, 0x50ede0832cdcfea3
  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v12, t2, v20

  li t2, 0x2becfa0a12caf562
  vsetvli t1, t0, e32, m2, ta, ma
  vmacc.vx v30, t2, v14

  li t2, 0x12ce5ca63f8e5580
  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v20, t2, v28

  li t2, 0x375f98ce6f83f228
  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v8, t2, v12

  li t2, 0x3feceb0da17eab6f
  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v12, t2, v8

  li t2, 0x51f4d9aada52d847
  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v12, t2, v24

  li t2, 0x4dd671d394827f18
  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v28, t2, v16

  li t2, 0x7891734894da66c4
  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v4, t2, v16

  li t2, 0xe0bd94c49a892eae
  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v16, t2, v12

  li t2, 0x881151e8d5dec219
  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v24, t2, v28

  li t2, 0xa955716984241e40
  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v4, t2, v24

  li t2, 0x302037c88aa5a3d7
  vsetvli t1, t0, e32, m4, ta, ma
  vmacc.vx v4, t2, v28

  li t2, 0x29a7ffe28bf50596
  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v8, t2, v16

  li t2, 0x622e10d0b2670091
  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v24, t2, v16

  li t2, 0x4b320f42ed861340
  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v16, t2, v24

  li t2, 0xa4eb10465ac679a0
  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v16, t2, v24

  li t2, 0xc8e3cab733588c30
  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v8, t2, v16

  li t2, 0xac0f95d12a88e202
  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v24, t2, v8

  li t2, 0xdcc610dd58c8defd
  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v8, t2, v24

  li t2, 0xbf8a7bf8b61b4e08
  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v24, t2, v16

  li t2, 0x102d000340c6ae88
  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v24, t2, v8

  li t2, 0x9dd6c7f039887ee3
  vsetvli t1, t0, e32, m8, ta, ma
  vmacc.vx v16, t2, v8

  li t2, 0x28ed534413f81253
  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v24, t2, v3

  li t2, 0x245a54ce824221c6
  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v23, t2, v7

  li t2, 0xf6dd710601cb5bcf
  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v3, t2, v23

  li t2, 0x77469fa83c7d1a43
  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v8, t2, v30

  li t2, 0xb04bf9ddc23f7d6a
  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v7, t2, v1

  li t2, 0xe9d05e0081aaf95e
  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v5, t2, v22

  li t2, 0xbb941ba5657aa5e6
  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v11, t2, v17

  li t2, 0xe5a73ca03b5846a1
  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v13, t2, v26

  li t2, 0x0ef66784db0ec07c
  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v10, t2, v17

  li t2, 0x4e4dba7a5cb0e2e0
  vsetvli t1, t0, e64, m1, ta, ma
  vmacc.vx v29, t2, v23

  li t2, 0x3b432163e999ff73
  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v22, t2, v28

  li t2, 0xb5ea6ed2b9ce9f34
  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v20, t2, v24

  li t2, 0x4963f4eb72c5cdb5
  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v30, t2, v26

  li t2, 0x9c68e5ba60cee5fa
  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v6, t2, v12

  li t2, 0x58c08c50bdfec1d4
  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v30, t2, v20

  li t2, 0xecd80e71c8ef7f67
  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v30, t2, v6

  li t2, 0xc86d22cf659cfde9
  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v4, t2, v16

  li t2, 0x4413cf8d8eeaa02e
  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v30, t2, v24

  li t2, 0x370729f71817934f
  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v22, t2, v14

  li t2, 0x4b402419d39931a0
  vsetvli t1, t0, e64, m2, ta, ma
  vmacc.vx v18, t2, v24

  li t2, 0xacb4b6e8e22c6687
  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v12, t2, v4

  li t2, 0x81fc350ab0212a27
  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v4, t2, v12

  li t2, 0xce386b21bfb223ad
  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v24, t2, v4

  li t2, 0xf9c6a5eefc0d865a
  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v16, t2, v4

  li t2, 0x1afb3dd7e52b909c
  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v16, t2, v20

  li t2, 0xd36fc6e8a0f6f3cb
  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v16, t2, v24

  li t2, 0x0345ea709bb092af
  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v4, t2, v16

  li t2, 0x96ca37e0875673a7
  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v20, t2, v8

  li t2, 0xeb79612fc1c796ed
  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v4, t2, v8

  li t2, 0x1bfca106a7a6236d
  vsetvli t1, t0, e64, m4, ta, ma
  vmacc.vx v8, t2, v20

  li t2, 0x20eb7abac3a06855
  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v24, t2, v16

  li t2, 0x5df4547720b55e9b
  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v8, t2, v16

  li t2, 0x2420ba0affc2fc87
  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v16, t2, v8

  li t2, 0xf273dd8cb305131a
  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v16, t2, v8

  li t2, 0x7a2131d31b5b2250
  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v8, t2, v24

  li t2, 0xacc672d0bcc504ef
  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v24, t2, v8

  li t2, 0xdcb285ca078d9b47
  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v16, t2, v8

  li t2, 0xf05a3b54beecc4d5
  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v16, t2, v8

  li t2, 0x640f1a24d7e76fd4
  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v8, t2, v24

  li t2, 0xfce2462a8e186b87
  vsetvli t1, t0, e64, m8, ta, ma
  vmacc.vx v8, t2, v16

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
