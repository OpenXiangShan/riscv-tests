#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vv v12, v17, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vv v15, v7, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vv v17, v22, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vv v16, v14, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vv v23, v9, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vv v14, v9, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vv v30, v15, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vv v21, v18, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vv v18, v10, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vv v17, v31, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vv v30, v16, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vv v26, v30, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vv v24, v4, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vv v30, v12, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vv v22, v12, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vv v28, v6, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vv v30, v4, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vv v30, v16, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vv v2, v22, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vv v30, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vv v8, v24, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vv v24, v4, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vv v16, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vv v16, v28, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vv v12, v4, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vv v8, v24, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vv v28, v12, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vv v8, v20, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vv v24, v20, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vv v24, v8, v20

  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vv v24, v16, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vv v15, v13, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vv v20, v14, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vv v23, v22, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vv v13, v23, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vv v14, v6, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vv v2, v22, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vv v4, v24, v9

  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vv v6, v2, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vv v6, v12, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vv v3, v21, v23

  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vv v30, v16, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vv v12, v18, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vv v8, v18, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vv v16, v30, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vv v16, v22, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vv v10, v14, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vv v26, v22, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vv v26, v20, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vv v10, v22, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vv v28, v16, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vv v8, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vv v28, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vv v12, v8, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vv v16, v20, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vv v4, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vv v28, v20, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vv v8, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vv v4, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vv v12, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vv v20, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vv v8, v24, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vv v4, v24, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vv v12, v1, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vv v4, v26, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vv v26, v6, v17

  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vv v23, v12, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vv v16, v25, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vv v9, v15, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vv v16, v4, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vv v2, v13, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vv v23, v6, v3

  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vv v22, v14, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vv v20, v28, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vv v10, v6, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vv v12, v18, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vv v22, v24, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vv v26, v22, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vv v12, v10, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vv v14, v4, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vv v2, v30, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vv v10, v26, v14

  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vv v20, v16, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vv v16, v4, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vv v12, v16, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vv v12, v28, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vv v16, v12, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vv v28, v20, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vv v12, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vv v28, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vv v8, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vv v16, v4, v20

  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vv v8, v16, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vv v29, v11, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vv v25, v21, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vv v25, v10, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vv v2, v21, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vv v26, v21, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vv v3, v12, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vv v28, v30, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vv v7, v23, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vv v11, v15, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vv v6, v1, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vv v26, v4, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vv v8, v20, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vv v30, v12, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vv v16, v24, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vv v10, v16, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vv v16, v30, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vv v6, v12, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vv v4, v2, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vv v12, v16, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vv v8, v22, v30

  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vv v8, v4, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vv v16, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vv v28, v8, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vv v28, v12, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vv v28, v4, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vv v20, v4, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vv v28, v12, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vv v24, v12, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vv v20, v12, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vv v8, v28, v20

  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vv v24, v16, v8

  li t2, 0xad4ba637e7222c12
  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vx v17, v21, t2

  li t2, 0xe5ecd73a0f665350
  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vx v23, v25, t2

  li t2, 0x915dabdf1b2405aa
  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vx v4, v18, t2

  li t2, 0x847d26af069b6f37
  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vx v7, v9, t2

  li t2, 0x5049f6f832fefa68
  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vx v29, v13, t2

  li t2, 0xff68f20325fc91d8
  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vx v23, v7, t2

  li t2, 0x9817a45963755b26
  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vx v20, v1, t2

  li t2, 0x6b3ddc65cf79f159
  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vx v30, v1, t2

  li t2, 0x11cc8ba83edf0648
  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vx v16, v8, t2

  li t2, 0xb7b3653a4e3b6b84
  vsetvli t1, t0, e8, m1, ta, ma
  vmax.vx v29, v11, t2

  li t2, 0x9eddbf8663aaa838
  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vx v18, v20, t2

  li t2, 0x90430e7ed6f3f3cc
  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vx v18, v26, t2

  li t2, 0x3677077f9c484698
  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vx v10, v8, t2

  li t2, 0x9adb323a4eba595e
  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vx v2, v30, t2

  li t2, 0x6e115f3dcd073ec3
  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vx v4, v8, t2

  li t2, 0xe8b8318cb6aa9ec5
  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vx v18, v20, t2

  li t2, 0xc692df741660ae50
  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vx v12, v20, t2

  li t2, 0x753713a4c933663b
  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vx v18, v8, t2

  li t2, 0xaae1d86ddebcd5a5
  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vx v16, v22, t2

  li t2, 0xa27cc0179fdef9a1
  vsetvli t1, t0, e8, m2, ta, ma
  vmax.vx v20, v22, t2

  li t2, 0xd1277d295d165d91
  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vx v12, v4, t2

  li t2, 0x31afa17d22ea3da9
  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vx v12, v8, t2

  li t2, 0x0ad6281fe460e33b
  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vx v16, v8, t2

  li t2, 0xaa24b4b36f1e7f79
  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vx v12, v8, t2

  li t2, 0x3238ac9732163845
  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vx v4, v20, t2

  li t2, 0xaa5da06243f133d9
  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vx v28, v16, t2

  li t2, 0x94639ec083fa5c75
  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vx v8, v16, t2

  li t2, 0xfe36bcd103582e87
  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vx v28, v16, t2

  li t2, 0x9eb28f438d2b34b5
  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vx v8, v16, t2

  li t2, 0x71e9a91f0a52d30f
  vsetvli t1, t0, e8, m4, ta, ma
  vmax.vx v16, v24, t2

  li t2, 0x30722a100ce4adda
  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vx v16, v24, t2

  li t2, 0xb389c1b58925ea7e
  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vx v8, v24, t2

  li t2, 0x2fcd04072ffb434a
  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vx v8, v24, t2

  li t2, 0x4856d50a149c24ea
  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vx v24, v16, t2

  li t2, 0x48963040ba2ece0b
  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vx v16, v8, t2

  li t2, 0xd863572fe040d127
  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vx v16, v24, t2

  li t2, 0xd642e3e7b4e5f8af
  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vx v16, v8, t2

  li t2, 0x25dbb1ecf3ee45b5
  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vx v16, v24, t2

  li t2, 0x1e45ca8b06ee4092
  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vx v16, v24, t2

  li t2, 0x16fc5dda15755a69
  vsetvli t1, t0, e8, m8, ta, ma
  vmax.vx v16, v24, t2

  li t2, 0x8528b1ec46beec92
  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vx v28, v22, t2

  li t2, 0x969c2c71e0eb97de
  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vx v5, v24, t2

  li t2, 0xdfa1934465be247d
  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vx v14, v26, t2

  li t2, 0x8bce213dea976ba9
  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vx v21, v20, t2

  li t2, 0xeff751f40a94c776
  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vx v6, v3, t2

  li t2, 0x7d71248ac7c769c0
  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vx v24, v21, t2

  li t2, 0xb23adfe8b0518ca8
  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vx v30, v27, t2

  li t2, 0xed3835ffb4f0955a
  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vx v11, v13, t2

  li t2, 0xf4faa01d8601f776
  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vx v30, v4, t2

  li t2, 0xcffdc9e443739d0f
  vsetvli t1, t0, e16, m1, ta, ma
  vmax.vx v4, v14, t2

  li t2, 0xac33627e1f21344e
  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vx v22, v8, t2

  li t2, 0x58358af637061359
  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vx v10, v4, t2

  li t2, 0x60c5b1a12c95171d
  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vx v12, v30, t2

  li t2, 0x09a2257cf1b0916c
  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vx v24, v16, t2

  li t2, 0x033ce44078e1faa5
  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vx v26, v4, t2

  li t2, 0xe19b627d01cd59de
  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vx v24, v4, t2

  li t2, 0x86d6ce6bef48cd08
  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vx v12, v18, t2

  li t2, 0x5a0d99b5527a7b85
  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vx v10, v30, t2

  li t2, 0xee382bac1b5c04b3
  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vx v14, v30, t2

  li t2, 0x747e5c33b05d9ffe
  vsetvli t1, t0, e16, m2, ta, ma
  vmax.vx v12, v6, t2

  li t2, 0x029fb93a481e523c
  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vx v24, v4, t2

  li t2, 0x8a890bee8addc1eb
  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vx v16, v8, t2

  li t2, 0x28651bf540df2edc
  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vx v12, v16, t2

  li t2, 0x1ade2a14d2321ed4
  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vx v8, v4, t2

  li t2, 0x27b56330551d003f
  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vx v8, v24, t2

  li t2, 0xeefac81dafb06869
  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vx v24, v12, t2

  li t2, 0x64e8e3780b399269
  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vx v4, v12, t2

  li t2, 0x0b81ada81df044e0
  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vx v24, v8, t2

  li t2, 0x3e93bad5c9690924
  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vx v8, v4, t2

  li t2, 0xf052fe912cc9e012
  vsetvli t1, t0, e16, m4, ta, ma
  vmax.vx v12, v8, t2

  li t2, 0x1a29f8094733e9fd
  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vx v8, v24, t2

  li t2, 0x8195b5729f31f487
  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vx v24, v16, t2

  li t2, 0x91728693c00e55bf
  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vx v8, v24, t2

  li t2, 0xdbe73a9270cf128c
  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vx v8, v16, t2

  li t2, 0x03468524e99b407b
  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vx v24, v16, t2

  li t2, 0x15bbdd8faa5a5c3f
  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vx v16, v24, t2

  li t2, 0x6025759e40c0d263
  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vx v16, v8, t2

  li t2, 0x3948f55e3cf68817
  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vx v24, v16, t2

  li t2, 0x0c03f279686585c1
  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vx v16, v8, t2

  li t2, 0x4b8c36d84e7a8c00
  vsetvli t1, t0, e16, m8, ta, ma
  vmax.vx v16, v8, t2

  li t2, 0x2a35b86402001e6f
  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vx v21, v15, t2

  li t2, 0x176455b77336d9f7
  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vx v11, v4, t2

  li t2, 0xb6542974c0b523ad
  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vx v30, v9, t2

  li t2, 0xcbc7feeaf7b95304
  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vx v1, v11, t2

  li t2, 0xe39432ca78df8140
  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vx v31, v9, t2

  li t2, 0x513dbf80f7be8ce0
  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vx v31, v11, t2

  li t2, 0xf69fbc65c5429fc9
  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vx v14, v22, t2

  li t2, 0xbbd977d08aaa8fd8
  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vx v31, v2, t2

  li t2, 0xcdd383e156dd7535
  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vx v28, v14, t2

  li t2, 0x56652704987cbdf5
  vsetvli t1, t0, e32, m1, ta, ma
  vmax.vx v29, v6, t2

  li t2, 0x9cebfe520b0a0dc3
  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vx v16, v24, t2

  li t2, 0x518dcb1256d9700a
  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vx v12, v8, t2

  li t2, 0xde0e7d2ffc74923f
  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vx v2, v28, t2

  li t2, 0xd66a8d727aa13d85
  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vx v12, v18, t2

  li t2, 0x0cf8d298af7d96e1
  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vx v10, v22, t2

  li t2, 0xbe95feb504b94523
  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vx v10, v26, t2

  li t2, 0x2e384e39e10ef98f
  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vx v22, v8, t2

  li t2, 0x77ab71e72f7f9094
  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vx v4, v10, t2

  li t2, 0xdde124ac526deda9
  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vx v12, v16, t2

  li t2, 0x9be1929e5fa6c489
  vsetvli t1, t0, e32, m2, ta, ma
  vmax.vx v2, v30, t2

  li t2, 0xa0f28119cb07275b
  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vx v28, v20, t2

  li t2, 0xc92cb57e14d1db35
  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vx v4, v20, t2

  li t2, 0x0ce61203a988daa8
  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vx v20, v4, t2

  li t2, 0x166dad24d7a92368
  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vx v8, v24, t2

  li t2, 0x25b300ebf0931171
  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vx v20, v4, t2

  li t2, 0x456f8d341335f7bd
  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vx v24, v4, t2

  li t2, 0xc6357a1466c6d7ce
  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vx v4, v20, t2

  li t2, 0x256fcdd7948a1d1d
  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vx v16, v20, t2

  li t2, 0x37427a8b96fd3413
  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vx v28, v8, t2

  li t2, 0x04b389d79c2ca578
  vsetvli t1, t0, e32, m4, ta, ma
  vmax.vx v16, v20, t2

  li t2, 0x45157fb14cf5cad6
  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vx v24, v8, t2

  li t2, 0x28ac2351dc0f11e6
  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vx v8, v24, t2

  li t2, 0x206640f86a174b42
  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vx v16, v8, t2

  li t2, 0xbbe9f7e972370613
  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vx v16, v8, t2

  li t2, 0xa0b2bad30b96bb36
  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vx v24, v16, t2

  li t2, 0x7ee87d173544e410
  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vx v16, v8, t2

  li t2, 0x576127e3ea53de6c
  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vx v24, v8, t2

  li t2, 0xf474135545f5b77d
  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vx v16, v24, t2

  li t2, 0x3ad4e604d5f4ed74
  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vx v24, v8, t2

  li t2, 0x7028676a7a30d546
  vsetvli t1, t0, e32, m8, ta, ma
  vmax.vx v8, v16, t2

  li t2, 0x2a7b3eb1a3b90e11
  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vx v19, v14, t2

  li t2, 0x5dfa77148262cd6e
  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vx v21, v10, t2

  li t2, 0x747a6748fc6e5563
  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vx v6, v23, t2

  li t2, 0x6192600e8d26ad32
  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vx v14, v3, t2

  li t2, 0xe9771bc3f7363191
  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vx v25, v31, t2

  li t2, 0x2e2440bfcac18605
  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vx v3, v2, t2

  li t2, 0xd8c5c81d4ab4bcea
  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vx v4, v20, t2

  li t2, 0xd8e06d49b1643f23
  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vx v10, v16, t2

  li t2, 0xdb00fa14df77a045
  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vx v14, v28, t2

  li t2, 0x52cd672ab5d0a590
  vsetvli t1, t0, e64, m1, ta, ma
  vmax.vx v28, v26, t2

  li t2, 0xe81c2b0bb29858fd
  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vx v10, v8, t2

  li t2, 0x317b79e3f2bea11a
  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vx v2, v14, t2

  li t2, 0x18ebff8219ae662a
  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vx v24, v28, t2

  li t2, 0x3a40cb466fe95120
  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vx v18, v22, t2

  li t2, 0x69aa93ffaa1760f1
  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vx v8, v26, t2

  li t2, 0x93b91b252ab84b9b
  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vx v14, v2, t2

  li t2, 0x0a58c02c6ec069aa
  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vx v16, v8, t2

  li t2, 0xed0c3c51bfc9e2e1
  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vx v4, v24, t2

  li t2, 0xd9875a6cce8e0c52
  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vx v8, v12, t2

  li t2, 0x5856c0fc85b1270e
  vsetvli t1, t0, e64, m2, ta, ma
  vmax.vx v14, v24, t2

  li t2, 0x953b1816810c5395
  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vx v20, v12, t2

  li t2, 0xa52ea8b60b72b4c2
  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vx v4, v28, t2

  li t2, 0x4703b1075f13aa3d
  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vx v20, v8, t2

  li t2, 0xf7089725cbe8b093
  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vx v24, v16, t2

  li t2, 0xde7283dbf13bb0c9
  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vx v24, v12, t2

  li t2, 0x21893525bfd81a57
  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vx v12, v8, t2

  li t2, 0xaee7c4fd9e0ec1fd
  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vx v24, v4, t2

  li t2, 0x766b076ffdd937ce
  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vx v28, v12, t2

  li t2, 0xabfbb50ec5a6d331
  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vx v12, v4, t2

  li t2, 0x0313ab6d9c816dbc
  vsetvli t1, t0, e64, m4, ta, ma
  vmax.vx v8, v4, t2

  li t2, 0xc14db123033e66a8
  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vx v16, v24, t2

  li t2, 0x70511a1fd9dd41b7
  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vx v8, v24, t2

  li t2, 0xd91e7f6f4f89974a
  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vx v24, v16, t2

  li t2, 0x6d5f67dd4979a7a7
  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vx v24, v16, t2

  li t2, 0x3b43c06c8ef2a24b
  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vx v8, v24, t2

  li t2, 0xd468c86b386b9abe
  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vx v8, v16, t2

  li t2, 0xab44c010e99945a8
  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vx v24, v16, t2

  li t2, 0x3284bc12841489be
  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vx v8, v16, t2

  li t2, 0x24b4d13ad8168084
  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vx v24, v8, t2

  li t2, 0x837f89e66fd24c3e
  vsetvli t1, t0, e64, m8, ta, ma
  vmax.vx v24, v8, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
