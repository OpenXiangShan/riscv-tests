#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v25, v13, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v8, v4, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v22, v5, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v16, v9, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v26, v1, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v6, v23, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v29, v27, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v27, v9, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v13, v26, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v14, v21, v23

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v28, v4, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v24, v28, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v12, v16, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v6, v14, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v24, v30, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v30, v16, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v10, v18, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v18, v20, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v16, v22, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v30, v22, v14

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v12, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v24, v20, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v12, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v16, v28, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v20, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v24, v16, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v20, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v20, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v12, v20, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v20, v28, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v22, v8, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v10, v27, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v5, v14, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v20, v24, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v25, v1, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v31, v18, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v8, v29, v9

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v9, v18, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v9, v22, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v26, v8, v23

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v14, v20, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v20, v4, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v10, v14, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v4, v14, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v16, v14, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v12, v2, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v20, v16, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v12, v4, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v16, v12, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v20, v30, v10

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v28, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v28, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v28, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v28, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v16, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v8, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v4, v24, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v8, v28

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v6, v19, v17

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v23, v31, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v3, v17, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v24, v20, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v20, v29, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v25, v21, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v30, v29, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v14, v16, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v19, v4, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v21, v22, v3

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v8, v30, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v28, v20, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v4, v2, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v2, v16, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v30, v4, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v20, v10, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v16, v20, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v26, v24, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v28, v16, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v2, v6, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v24, v28, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v24, v8, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v20, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v16, v20, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v28, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v28, v4, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v12, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v24, v12, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v28, v20

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v21, v28, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v17, v19, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v23, v14, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v5, v27, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v23, v21, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v6, v15, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v14, v8, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v30, v23, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v17, v5, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v3, v22, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v6, v30, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v22, v16, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v2, v20, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v20, v6, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v4, v12, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v10, v8, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v20, v2, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v28, v26, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v12, v22, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v28, v10, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v16, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v24, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v24, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v12, v8, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v24, v12, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v8, v28, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v4, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v8, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v16, v8, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v8, v4, v12

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xdbdb92d585d70a34
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v11, v21, t2

  li t2, 0xd3d6fbef9ceb5672
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v12, v11, t2

  li t2, 0x6a22ad994740e848
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v23, v16, t2

  li t2, 0x5125a4fe9e9a2453
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v17, v20, t2

  li t2, 0x6b82b53a7274bfaa
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v7, v26, t2

  li t2, 0x08a308a1a832a646
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v5, v18, t2

  li t2, 0x7768a867f721a6b0
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v22, v23, t2

  li t2, 0xd11b3c4428fa7230
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v3, v29, t2

  li t2, 0x7543b8ef3f9c57ba
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v9, v30, t2

  li t2, 0x8c1d0eac7579f9ad
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v24, v13, t2

  li t2, 0xc46e9482e3a8ecce
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v26, v10, t2

  li t2, 0x66afb251d093bed4
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v12, v24, t2

  li t2, 0x4ae428e1a105c92e
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v26, v12, t2

  li t2, 0x126bcb63fec89533
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v12, v22, t2

  li t2, 0x6d61c9a474f7a5ea
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v14, v2, t2

  li t2, 0x7c246af55d4f120a
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v30, v24, t2

  li t2, 0xc069f1071720b9bb
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v12, v16, t2

  li t2, 0x3580753c5571ab1b
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v18, v2, t2

  li t2, 0x17aa3b2386956cb8
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v12, v26, t2

  li t2, 0x757f6fa6c5aa132f
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v26, v18, t2

  li t2, 0x35fd536e6a3ef950
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v24, t2

  li t2, 0x38fafa2be31c6bc8
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v12, t2

  li t2, 0xaa37cfb600612a32
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v20, v24, t2

  li t2, 0xa3d677f2f58ca52d
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v28, t2

  li t2, 0xf853d4307ecde23f
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v12, v28, t2

  li t2, 0x4db018e2c8595bf0
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v28, v12, t2

  li t2, 0xfc8502bc5cdd329c
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v8, t2

  li t2, 0x06b8729b0000beb3
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v28, v16, t2

  li t2, 0xbea791409d8d08e1
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v8, t2

  li t2, 0xf004d17412fdf8c6
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v20, t2

  li t2, 0x7b3045ec2de1109d
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  li t2, 0x60810b8498615cd2
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  li t2, 0x5d04f8052142f0c9
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  li t2, 0x181afafcb141f35b
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  li t2, 0x631aa893aea5c063
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v16, t2

  li t2, 0x4d062e2d12f0efae
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  li t2, 0x0ec688a95ad65af1
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  li t2, 0x9664dba2f1b433ba
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  li t2, 0xfbee80b05feb4b90
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  li t2, 0x5561d78418a106be
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  li t2, 0x7e2dd79c1b48a82b
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v21, v19, t2

  li t2, 0x2aa7e4423054c931
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v27, v26, t2

  li t2, 0x6419eeea6c7c370d
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v14, v28, t2

  li t2, 0xb9448d4660ca1022
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v11, v1, t2

  li t2, 0x1821e82ecb58781b
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v17, v25, t2

  li t2, 0x5dc41ba938076eae
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v30, v28, t2

  li t2, 0xd289114ae92cc869
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v27, v2, t2

  li t2, 0x572f12868d033947
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v2, v22, t2

  li t2, 0xb6db1cfba64f5866
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v4, v19, t2

  li t2, 0x506a227133a94a1c
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v25, v2, t2

  li t2, 0x924b61fc2ac8d73c
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v26, v12, t2

  li t2, 0xfadfbaf978a4f43b
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v4, v2, t2

  li t2, 0x597e64395332129f
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v18, v6, t2

  li t2, 0x8b59f7d19d867a1a
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v14, v28, t2

  li t2, 0x2e70f3b8afc2148c
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v22, v18, t2

  li t2, 0x1d27555779c04a7b
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v24, v8, t2

  li t2, 0xebad3d86156575d4
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v26, v6, t2

  li t2, 0xaa3275d774e8423d
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v22, v20, t2

  li t2, 0xcd8c2e7e7fcba44a
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v6, v8, t2

  li t2, 0xfdc93abfe218ff7b
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v18, v24, t2

  li t2, 0xca7eec6e279b472f
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v8, v28, t2

  li t2, 0xe91e05c8f0798295
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v4, t2

  li t2, 0xa5a0772d2dc2a332
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v12, t2

  li t2, 0x94f4a0230aa5da5e
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v12, v4, t2

  li t2, 0x5999a83bb7070802
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v8, v28, t2

  li t2, 0x041d814366c8930d
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v8, v16, t2

  li t2, 0xe25447354fc1c274
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v28, t2

  li t2, 0xa4613e5a178cbefe
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v4, t2

  li t2, 0xd293bbae55d96edf
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v4, t2

  li t2, 0x5f7cb69576f59a99
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v28, t2

  li t2, 0x1ec1ff28577d3e4e
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v8, t2

  li t2, 0x865e265b154f9327
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  li t2, 0xa690b9bf5725dda5
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v8, t2

  li t2, 0x0ddc7646f8ea66e1
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  li t2, 0x828056db15a0d18c
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  li t2, 0x1c5ddcca1127b7d1
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  li t2, 0x39638f37a20e00ab
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  li t2, 0x01fa09f626055e17
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  li t2, 0xe9f5c048054067d3
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  li t2, 0x068efe2693f5763d
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  li t2, 0x6214765009907512
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v13, v5, t2

  li t2, 0x1dbc06219ba578a8
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v6, v1, t2

  li t2, 0x95ee189d1c6b00bb
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v16, v17, t2

  li t2, 0xdc93df438110196a
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v12, v25, t2

  li t2, 0xca3ed6ebbb518e3e
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v20, v4, t2

  li t2, 0xe10bfd5686b58963
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v19, v2, t2

  li t2, 0xe12275fd4ca00379
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v31, v11, t2

  li t2, 0xe4e4a53a815d29f2
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v31, v16, t2

  li t2, 0x3dcbe9de1d9f190e
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v24, v25, t2

  li t2, 0x0ea68f0483558ff2
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v19, v26, t2

  li t2, 0x241a97aff50a3f53
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v6, v12, t2

  li t2, 0xf81c599417854aaa
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v8, v6, t2

  li t2, 0xfca3bc2751ebab93
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v18, v26, t2

  li t2, 0x6921e978157dae5b
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v4, v30, t2

  li t2, 0x11eee771410149aa
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v12, v22, t2

  li t2, 0x9a26038e30c0f47b
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v28, v22, t2

  li t2, 0xe55b83a93cd5fb4e
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v8, v22, t2

  li t2, 0x1b24655f9aa526b9
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v6, v22, t2

  li t2, 0x8bce43cfb7d33704
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v30, v12, t2

  li t2, 0xd1a272121c60234e
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v14, v12, t2

  li t2, 0x1008be29bc8766d5
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v12, t2

  li t2, 0x3d42b1832bb5935d
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v4, v24, t2

  li t2, 0xe65ed418a3e7ff76
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v20, t2

  li t2, 0xa75f9612de3ab903
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v12, t2

  li t2, 0xa65c0db54f3e4423
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v24, t2

  li t2, 0x1041e5b098c64a2d
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v12, t2

  li t2, 0x7b0ac2948310a168
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v28, t2

  li t2, 0x98837a1eb32eee45
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v4, v12, t2

  li t2, 0xc9830eb9194c06cd
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v12, t2

  li t2, 0x6dd6bbdd71274fd3
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v12, t2

  li t2, 0x8a7eb40bff479f4f
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  li t2, 0xec889a3e044a0f39
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  li t2, 0xe6f78af0f3f7787d
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  li t2, 0x0887885638ed3f82
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  li t2, 0xfca9aeaa685a114e
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  li t2, 0x550014c837e402c7
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  li t2, 0x08f259e0c4e401dc
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  li t2, 0x245eef854a71f3bb
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  li t2, 0xc96335a35381cde2
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  li t2, 0x2cd64e596bdf82bd
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  li t2, 0xaded9f249a4ef058
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v16, v8, t2

  li t2, 0x3a4f570f080d4ab4
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v29, v27, t2

  li t2, 0xc56d6f2f24b92eec
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v20, v22, t2

  li t2, 0xf361acff629fa82d
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v13, v23, t2

  li t2, 0xb54472faa23208d3
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v11, v18, t2

  li t2, 0x849d531f32a9551d
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v16, v28, t2

  li t2, 0xffa88dd753aed86b
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v28, v27, t2

  li t2, 0xe502e3c29a25437c
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v8, v28, t2

  li t2, 0xb64a0146ed6e1e9c
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v19, v3, t2

  li t2, 0xde7055498fcd0155
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v20, v2, t2

  li t2, 0xfd1a667e65d055f8
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v26, v28, t2

  li t2, 0xeb517d72c7a378a3
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v26, v10, t2

  li t2, 0x204cddb445e0c5b1
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v24, v26, t2

  li t2, 0x62edf603311a58bb
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v30, v10, t2

  li t2, 0xa3fbe303ec24660f
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v14, v16, t2

  li t2, 0x547f59fe8b13ab83
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v6, v30, t2

  li t2, 0x4ac2253628dc201a
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v16, v22, t2

  li t2, 0x4ba6c1007e08ec7f
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v30, v12, t2

  li t2, 0x6e6a32e1bc99fad0
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v12, v14, t2

  li t2, 0x73c8ea2ee9c9cac6
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v24, v4, t2

  li t2, 0x695eb6f1757f0b43
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v4, t2

  li t2, 0x09cfcbd988a9092f
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v4, t2

  li t2, 0xacd91ef3b71c48ed
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v16, t2

  li t2, 0x106771e2428736a7
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v8, v16, t2

  li t2, 0x76a0ae05f4e8a168
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v24, t2

  li t2, 0xb363af3e25111756
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v8, v12, t2

  li t2, 0xa0001d7c503eee85
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v16, t2

  li t2, 0x30dbc4272cc25dc0
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v8, v24, t2

  li t2, 0x8e94163170ec84ee
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v16, v24, t2

  li t2, 0x32e077cc8596eaa5
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v28, v12, t2

  li t2, 0xa8d7bc315be463cb
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  li t2, 0xeda6a15a87668408
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  li t2, 0x08611890341961a8
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  li t2, 0x11e74c0cfec91c60
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  li t2, 0x36495388bf6a3e9c
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  li t2, 0x32c40da7a495eb61
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v16, t2

  li t2, 0x749ce669f33e60a9
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  li t2, 0xb85e7c04c9a3220f
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  li t2, 0xb9fbaf2a1105ead2
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  li t2, 0xdf24e0a3bc2374a5
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
