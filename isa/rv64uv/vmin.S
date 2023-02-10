#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vv v3, v25, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vv v5, v23, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vv v26, v18, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vv v3, v20, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vv v9, v31, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vv v23, v13, v31

  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vv v16, v14, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vv v9, v21, v31

  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vv v1, v23, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vv v4, v15, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vv v24, v2, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vv v16, v4, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vv v16, v4, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vv v10, v4, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vv v14, v26, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vv v22, v14, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vv v16, v28, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vv v30, v2, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vv v18, v16, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vv v24, v12, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vv v24, v28, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vv v28, v16, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vv v16, v8, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vv v4, v24, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vv v4, v20, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vv v20, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vv v4, v24, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vv v8, v24, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vv v28, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vv v28, v4, v12

  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vv v16, v24, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vv v3, v19, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vv v18, v29, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vv v2, v4, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vv v16, v29, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vv v30, v31, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vv v5, v21, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vv v11, v2, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vv v29, v1, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vv v20, v24, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vv v8, v6, v19

  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vv v20, v6, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vv v8, v14, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vv v8, v26, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vv v22, v10, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vv v20, v4, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vv v20, v8, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vv v14, v20, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vv v30, v8, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vv v28, v26, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vv v4, v6, v30

  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vv v16, v12, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vv v8, v20, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vv v24, v8, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vv v28, v12, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vv v16, v12, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vv v16, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vv v8, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vv v16, v28, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vv v16, v24, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vv v6, v1, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vv v28, v25, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vv v2, v3, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vv v5, v25, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vv v15, v9, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vv v27, v25, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vv v28, v2, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vv v7, v28, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vv v20, v31, v5

  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vv v8, v25, v27

  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vv v6, v28, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vv v24, v16, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vv v24, v12, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vv v18, v4, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vv v10, v2, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vv v24, v4, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vv v18, v20, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vv v8, v16, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vv v2, v12, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vv v10, v24, v14

  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vv v16, v4, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vv v8, v20, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vv v16, v12, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vv v20, v24, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vv v28, v24, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vv v12, v28, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vv v12, v28, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vv v24, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vv v20, v28, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vv v12, v8, v28

  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vv v16, v24, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vv v22, v25, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vv v13, v29, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vv v29, v9, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vv v10, v25, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vv v13, v3, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vv v7, v31, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vv v29, v14, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vv v19, v9, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vv v19, v28, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vv v16, v10, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vv v20, v26, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vv v16, v8, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vv v22, v14, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vv v16, v8, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vv v14, v8, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vv v12, v28, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vv v10, v26, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vv v6, v26, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vv v2, v4, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vv v26, v4, v18

  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vv v12, v28, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vv v12, v24, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vv v16, v28, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vv v16, v20, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vv v20, v8, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vv v28, v12, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vv v8, v24, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vv v24, v8, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vv v16, v24, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vv v16, v8, v28

  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vv v24, v16, v8

  li t2, 0x038e1d24ecfb1cca
  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vx v22, v24, t2

  li t2, 0xb085598e227cd8a9
  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vx v31, v8, t2

  li t2, 0xb6a1af541f5a86ea
  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vx v27, v28, t2

  li t2, 0xb84fab46808224fe
  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vx v24, v12, t2

  li t2, 0xb01ea5ac9cc4a91c
  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vx v4, v29, t2

  li t2, 0x8b03a3c45663003b
  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vx v25, v4, t2

  li t2, 0xbedd95ad6df9378f
  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vx v1, v4, t2

  li t2, 0xd5250c15417481f6
  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vx v28, v5, t2

  li t2, 0x93ecb704344115f8
  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vx v26, v14, t2

  li t2, 0x0019aeac495c8d82
  vsetvli t1, t0, e8, m1, ta, ma
  vmin.vx v16, v19, t2

  li t2, 0xca14c7ab6ec13912
  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vx v24, v4, t2

  li t2, 0x7fe5807610bb19aa
  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vx v24, v26, t2

  li t2, 0xc96c40de4363692b
  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vx v28, v20, t2

  li t2, 0xa34ea5dec668f881
  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vx v4, v26, t2

  li t2, 0x5f5acffbfa32e640
  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vx v22, v10, t2

  li t2, 0x2e02d5ac7236f9de
  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vx v30, v2, t2

  li t2, 0x8dd43cf6fd3834d2
  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vx v4, v18, t2

  li t2, 0xcac8b37f61d22bf8
  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vx v2, v4, t2

  li t2, 0x6efa6b09dc0c6c71
  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vx v10, v18, t2

  li t2, 0x984f8f5c110c29af
  vsetvli t1, t0, e8, m2, ta, ma
  vmin.vx v26, v14, t2

  li t2, 0xbb0fe45f99ab4eef
  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vx v20, v4, t2

  li t2, 0xfb4dd19ad489ff54
  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vx v4, v8, t2

  li t2, 0xbaacaed946047680
  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vx v28, v20, t2

  li t2, 0x7af5faa8b47391cb
  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vx v28, v4, t2

  li t2, 0xe8d8b6aad817a5a2
  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vx v8, v20, t2

  li t2, 0x7624ef2dbadf0ab3
  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vx v12, v20, t2

  li t2, 0x2b5f7feda5f6738d
  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vx v24, v8, t2

  li t2, 0xdbc5497220751c0d
  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vx v28, v20, t2

  li t2, 0xee339106c5fa7294
  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vx v24, v20, t2

  li t2, 0x9ca1dae73ad09948
  vsetvli t1, t0, e8, m4, ta, ma
  vmin.vx v20, v8, t2

  li t2, 0x6a30575b346668ad
  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vx v16, v8, t2

  li t2, 0x5e4807c7da3d98a1
  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vx v16, v8, t2

  li t2, 0x00f524458c7ccfba
  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vx v8, v24, t2

  li t2, 0xc86f377d62c2999b
  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vx v8, v16, t2

  li t2, 0xfbb8528dafe7956c
  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vx v24, v8, t2

  li t2, 0x569c652e50833be0
  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vx v16, v24, t2

  li t2, 0xbd17fbb5e78ecd02
  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vx v24, v8, t2

  li t2, 0xfbc427136c194fc5
  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vx v8, v16, t2

  li t2, 0x60947043ce63b86b
  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vx v24, v8, t2

  li t2, 0x198debcb7fad393b
  vsetvli t1, t0, e8, m8, ta, ma
  vmin.vx v8, v16, t2

  li t2, 0x8c32dfc1153c75ea
  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vx v17, v1, t2

  li t2, 0xd5bd0bac8f497119
  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vx v17, v7, t2

  li t2, 0x8d6edbdd573d11e3
  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vx v26, v2, t2

  li t2, 0xdb0b936b2beeb877
  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vx v4, v2, t2

  li t2, 0xc032cfcd19b71534
  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vx v14, v28, t2

  li t2, 0x00517de69cf52f09
  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vx v30, v22, t2

  li t2, 0x7614bde9dffdcacf
  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vx v11, v5, t2

  li t2, 0xe679d5005c306723
  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vx v17, v15, t2

  li t2, 0xbd6e9280fcb16cc1
  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vx v27, v21, t2

  li t2, 0x9f9f3f89dfb088e1
  vsetvli t1, t0, e16, m1, ta, ma
  vmin.vx v7, v29, t2

  li t2, 0x9e49c9dab25a9ffa
  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vx v14, v30, t2

  li t2, 0x8322941f4be29527
  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vx v4, v10, t2

  li t2, 0xda1010a90ca50d27
  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vx v24, v14, t2

  li t2, 0xf11354b628e32548
  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vx v10, v30, t2

  li t2, 0x0fb4337aad079ccf
  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vx v8, v28, t2

  li t2, 0x12232236f259d56f
  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vx v28, v16, t2

  li t2, 0xcb95efb998aede8d
  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vx v4, v12, t2

  li t2, 0x58d06889cd967462
  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vx v18, v4, t2

  li t2, 0x79d7dce53077ba13
  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vx v2, v12, t2

  li t2, 0x008d54791f37ca8d
  vsetvli t1, t0, e16, m2, ta, ma
  vmin.vx v22, v26, t2

  li t2, 0x37cc43f0cc39a2ea
  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vx v12, v16, t2

  li t2, 0xc3d8eea4b7295151
  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vx v24, v4, t2

  li t2, 0x40ccfbc2c0c33742
  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vx v20, v28, t2

  li t2, 0x98a446e71c7a43a4
  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vx v16, v20, t2

  li t2, 0x512bf6947ccf009d
  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vx v24, v28, t2

  li t2, 0xe3e6179f0f1df896
  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vx v16, v4, t2

  li t2, 0x94a28c97c2613b7c
  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vx v28, v20, t2

  li t2, 0xb0a854ca2a76235e
  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vx v20, v24, t2

  li t2, 0x2f69521c1ce01f78
  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vx v12, v28, t2

  li t2, 0x8cd8e5dd2aab889c
  vsetvli t1, t0, e16, m4, ta, ma
  vmin.vx v24, v28, t2

  li t2, 0x09fcc07b9b0f6b1f
  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vx v24, v8, t2

  li t2, 0xfa253c57472891e2
  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vx v24, v16, t2

  li t2, 0xe2dc0403e67b6542
  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vx v24, v16, t2

  li t2, 0x7533f8c1d4b45d33
  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vx v8, v16, t2

  li t2, 0xe2eb2a1b655a4387
  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vx v8, v16, t2

  li t2, 0x92188bca87bad6a2
  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vx v8, v16, t2

  li t2, 0xe34cf937aa360418
  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vx v24, v8, t2

  li t2, 0x9ad2c1244a80ea4e
  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vx v16, v8, t2

  li t2, 0x2b99ba982e8c14cb
  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vx v16, v8, t2

  li t2, 0x2000ed47bd20b174
  vsetvli t1, t0, e16, m8, ta, ma
  vmin.vx v8, v16, t2

  li t2, 0xb639c056d15c35be
  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vx v11, v29, t2

  li t2, 0x165c2faa3c281abc
  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vx v4, v30, t2

  li t2, 0x44fcc7f025e3ab2d
  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vx v2, v14, t2

  li t2, 0x6c424c19af0c695f
  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vx v14, v1, t2

  li t2, 0x5847df515ab05e27
  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vx v17, v25, t2

  li t2, 0x5dcce03fe9aa501f
  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vx v7, v23, t2

  li t2, 0x85b7a66b61d31d33
  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vx v31, v17, t2

  li t2, 0xf5ecc1f6ded1d26a
  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vx v13, v29, t2

  li t2, 0x3bb4024d298febd7
  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vx v17, v10, t2

  li t2, 0x3ab8e7d448f38cfe
  vsetvli t1, t0, e32, m1, ta, ma
  vmin.vx v23, v27, t2

  li t2, 0x2e6ae5981234b9a1
  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vx v20, v10, t2

  li t2, 0x9d837b1a4ac97baa
  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vx v16, v20, t2

  li t2, 0x9b951db0251fdeff
  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vx v12, v18, t2

  li t2, 0x4044ba0ff36e8ec8
  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vx v6, v20, t2

  li t2, 0x11699fde3d5abb05
  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vx v30, v18, t2

  li t2, 0x3997817494b38dce
  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vx v28, v6, t2

  li t2, 0x7a02065ce48abf3a
  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vx v16, v18, t2

  li t2, 0xefa88b4c3cc605b3
  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vx v12, v14, t2

  li t2, 0xac46a34de49739bf
  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vx v20, v22, t2

  li t2, 0x2cd1da6e8cf15394
  vsetvli t1, t0, e32, m2, ta, ma
  vmin.vx v18, v4, t2

  li t2, 0xc869afc258235791
  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vx v16, v24, t2

  li t2, 0xf64d6a206626d7a6
  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vx v16, v20, t2

  li t2, 0xb92368a32afb6517
  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vx v4, v28, t2

  li t2, 0xe29a7d8363259b24
  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vx v16, v12, t2

  li t2, 0x8ebc6e5506fb9587
  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vx v4, v12, t2

  li t2, 0xa062b4b2c0a91dda
  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vx v16, v24, t2

  li t2, 0x582eb3d8b3445a2e
  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vx v12, v28, t2

  li t2, 0x7c6de7ee6912de9d
  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vx v28, v4, t2

  li t2, 0xc8372d0106c799e9
  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vx v28, v20, t2

  li t2, 0xa8fbc836b8d31fa0
  vsetvli t1, t0, e32, m4, ta, ma
  vmin.vx v16, v28, t2

  li t2, 0xe62d1d2559c4f21d
  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vx v16, v24, t2

  li t2, 0xbe981749e2b7f357
  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vx v16, v24, t2

  li t2, 0x48dd4042b5cdc496
  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vx v8, v24, t2

  li t2, 0x8f05443684832da9
  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vx v8, v24, t2

  li t2, 0x2568a0e6084a3583
  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vx v16, v8, t2

  li t2, 0xf8da7909da8c7339
  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vx v16, v8, t2

  li t2, 0xc95ba9b55f01e7a6
  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vx v24, v8, t2

  li t2, 0x768976069bd515e7
  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vx v8, v24, t2

  li t2, 0x6cf807a4e612f9d4
  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vx v16, v8, t2

  li t2, 0x024267bc10717a6c
  vsetvli t1, t0, e32, m8, ta, ma
  vmin.vx v8, v16, t2

  li t2, 0x9d5cf7b09edd7c55
  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vx v22, v13, t2

  li t2, 0x17d103b7b2dbdebe
  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vx v22, v27, t2

  li t2, 0x9b94e93bc15a9609
  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vx v28, v1, t2

  li t2, 0xd4fd9fa6dd168b5a
  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vx v16, v19, t2

  li t2, 0x7e52242f59796414
  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vx v6, v25, t2

  li t2, 0xe645efbb53ab92ca
  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vx v4, v24, t2

  li t2, 0x0bd9276dfecf3b54
  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vx v17, v29, t2

  li t2, 0x21e0a588753fa93e
  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vx v27, v12, t2

  li t2, 0x4102bd2078565941
  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vx v21, v15, t2

  li t2, 0x696c0a558d61b8d6
  vsetvli t1, t0, e64, m1, ta, ma
  vmin.vx v23, v18, t2

  li t2, 0x805cac7dc66ecfbd
  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vx v8, v28, t2

  li t2, 0x5fe0cdbb682994b5
  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vx v26, v10, t2

  li t2, 0xb3a060eaeb4bdd9e
  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vx v2, v10, t2

  li t2, 0xe343bf8065390773
  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vx v12, v20, t2

  li t2, 0x116ae0c326bb3561
  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vx v16, v4, t2

  li t2, 0x824208b09ebea220
  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vx v4, v2, t2

  li t2, 0xb0d6d6aab6d65534
  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vx v28, v16, t2

  li t2, 0x31d9c9ea3c8a7875
  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vx v18, v8, t2

  li t2, 0x9371199a2f338a2a
  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vx v18, v24, t2

  li t2, 0xf4600a06847db2d8
  vsetvli t1, t0, e64, m2, ta, ma
  vmin.vx v2, v24, t2

  li t2, 0x14bc1000e7df8f0d
  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vx v16, v4, t2

  li t2, 0x5747a58b36b81668
  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vx v24, v16, t2

  li t2, 0x85344326da8a34ef
  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vx v16, v8, t2

  li t2, 0x6faae6ac22610d4b
  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vx v12, v8, t2

  li t2, 0xe99a28fd560d9764
  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vx v4, v20, t2

  li t2, 0xcf33d637f3f4cad5
  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vx v12, v28, t2

  li t2, 0xab54c863aa8c8e07
  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vx v24, v4, t2

  li t2, 0x86a1ebb6e0b481f6
  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vx v20, v8, t2

  li t2, 0xaade119b04d93db5
  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vx v12, v24, t2

  li t2, 0xf74f3d6b835b877c
  vsetvli t1, t0, e64, m4, ta, ma
  vmin.vx v4, v8, t2

  li t2, 0x78cfd0f0d7504dbb
  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vx v24, v8, t2

  li t2, 0x22500f54e27eb47f
  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vx v8, v16, t2

  li t2, 0x63f68ceda5e0d9e9
  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vx v24, v16, t2

  li t2, 0x7f8856eb0a70e0f7
  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vx v8, v24, t2

  li t2, 0xf3ca656130fff0d3
  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vx v24, v16, t2

  li t2, 0x21fa72eeacd27c84
  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vx v8, v16, t2

  li t2, 0x6ecd07d995afbcc4
  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vx v8, v24, t2

  li t2, 0x0b4428e69fc79852
  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vx v16, v24, t2

  li t2, 0x603e0db924b1c934
  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vx v8, v16, t2

  li t2, 0x865d740855ee9a7a
  vsetvli t1, t0, e64, m8, ta, ma
  vmin.vx v16, v24, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
