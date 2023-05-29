#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vv v15, v19, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vv v10, v11, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vv v20, v26, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vv v31, v16, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vv v7, v19, v31

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vv v23, v15, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vv v24, v20, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vv v11, v27, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vv v13, v7, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vv v17, v26, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vv v30, v18, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vv v4, v26, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vv v6, v18, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vv v16, v20, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vv v20, v28, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vv v2, v10, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vv v8, v16, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vv v20, v16, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vv v6, v22, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vv v24, v28, v14

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vv v12, v20, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vv v12, v16, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vv v20, v16, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vv v16, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vv v20, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vv v4, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vv v12, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vv v20, v24, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vv v16, v8, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vv v24, v4, v28

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vv v16, v8, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vv v26, v13, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vv v2, v11, v27

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vv v19, v26, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vv v17, v6, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vv v25, v14, v27

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vv v1, v21, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vv v8, v7, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vv v31, v8, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vv v3, v27, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vv v30, v23, v29

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vv v8, v12, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vv v16, v24, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vv v26, v2, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vv v10, v4, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vv v28, v16, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vv v22, v26, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vv v24, v10, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vv v16, v12, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vv v30, v26, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vv v6, v10, v26

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vv v12, v28, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vv v16, v20, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vv v12, v8, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vv v20, v4, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vv v4, v24, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vv v28, v4, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vv v4, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vv v16, v24, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vv v12, v8, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vv v4, v12, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vv v24, v16, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vv v18, v14, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vv v19, v5, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vv v15, v10, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vv v6, v22, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vv v29, v8, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vv v16, v4, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vv v12, v23, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vv v20, v27, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vv v22, v28, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vv v17, v1, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vv v26, v10, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vv v18, v6, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vv v14, v20, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vv v28, v14, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vv v28, v10, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vv v24, v8, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vv v8, v24, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vv v18, v8, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vv v6, v28, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vv v10, v16, v2

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vv v4, v12, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vv v20, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vv v16, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vv v28, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vv v8, v16, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vv v8, v20, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vv v4, v20, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vv v20, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vv v8, v28, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vv v16, v8, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vv v13, v5, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vv v17, v19, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vv v13, v17, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vv v29, v21, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vv v16, v14, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vv v28, v17, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vv v28, v22, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vv v7, v20, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vv v30, v9, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vv v20, v26, v13

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vv v22, v16, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vv v14, v6, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vv v18, v16, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vv v14, v30, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vv v16, v2, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vv v16, v8, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vv v22, v28, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vv v2, v12, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vv v14, v30, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vv v6, v12, v30

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vv v12, v16, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vv v8, v20, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vv v8, v24, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vv v4, v20, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vv v8, v28, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vv v4, v24, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vv v8, v20, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vv v8, v20, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vv v4, v20, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vv v20, v24, v4

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vv v16, v24, v8

  li t2, 0x6a383e4e59531151
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vx v11, t2, v1

  li t2, 0xcdaffc735beb22e1
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vx v13, t2, v30

  li t2, 0x89a37a15478ff366
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vx v16, t2, v25

  li t2, 0x689de6200ef2babb
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vx v5, t2, v4

  li t2, 0x4e5f293f6c6f834f
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vx v4, t2, v28

  li t2, 0x05c26c9952e84a7f
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vx v29, t2, v5

  li t2, 0x2a82f7d89aad58e4
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vx v14, t2, v11

  li t2, 0x0b670333cd55dae8
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vx v15, t2, v6

  li t2, 0xbf671cf2124209cb
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vx v29, t2, v18

  li t2, 0xb0316d9eee64d24e
  vsetvli t1, t0, e8, m1, ta, ma
  vnmsac.vx v31, t2, v23

  li t2, 0x339b72f657966cff
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vx v20, t2, v16

  li t2, 0xda2dd7de32d2adfb
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vx v28, t2, v4

  li t2, 0x7c4cb38e71b527dd
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vx v24, t2, v6

  li t2, 0xbd339331745f9fa7
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vx v12, t2, v20

  li t2, 0x5cf8490b5f178d9a
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vx v16, t2, v22

  li t2, 0xa77e24ac3fd95365
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vx v28, t2, v8

  li t2, 0x03299cdef2eea943
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vx v8, t2, v10

  li t2, 0x39c75141a8c5919a
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vx v12, t2, v4

  li t2, 0x383c4b8f8526a08e
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vx v10, t2, v24

  li t2, 0xb236ae7cac41aabd
  vsetvli t1, t0, e8, m2, ta, ma
  vnmsac.vx v26, t2, v12

  li t2, 0x66ae427734c4afff
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vx v12, t2, v8

  li t2, 0x21c85982a874421d
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vx v16, t2, v12

  li t2, 0x8f12ca0bc02fbdec
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vx v16, t2, v12

  li t2, 0x8ec65b5029e73c25
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vx v4, t2, v8

  li t2, 0x9a0193c16a4c2425
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vx v12, t2, v16

  li t2, 0x47a7a721c1743012
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vx v12, t2, v28

  li t2, 0xfafda3a0dfe22f17
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vx v16, t2, v4

  li t2, 0x6ca006488afb3f84
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vx v24, t2, v20

  li t2, 0xb8535bd3973ef7d6
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vx v24, t2, v4

  li t2, 0xfd40213d9aa18373
  vsetvli t1, t0, e8, m4, ta, ma
  vnmsac.vx v28, t2, v20

  li t2, 0xc7fa7ff660a8bd4b
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vx v24, t2, v8

  li t2, 0xc8e54c7f9660d9be
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vx v8, t2, v24

  li t2, 0x97f56a8c43ec0517
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vx v8, t2, v16

  li t2, 0xa62150656df11677
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vx v8, t2, v24

  li t2, 0x8cf5bcca1282bfb1
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vx v8, t2, v24

  li t2, 0x62ca91dd26ba0579
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vx v24, t2, v8

  li t2, 0x8f630b11cfcd8933
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vx v8, t2, v16

  li t2, 0xdfe0f7c4c4ba11d9
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vx v8, t2, v16

  li t2, 0x85da521bff65f978
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vx v8, t2, v24

  li t2, 0xc3c649d609e8af56
  vsetvli t1, t0, e8, m8, ta, ma
  vnmsac.vx v24, t2, v8

  li t2, 0xaa2e6b8b41e3da95
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vx v22, t2, v4

  li t2, 0x72234092fc30d765
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vx v23, t2, v28

  li t2, 0x49dbaaac464d36d2
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vx v3, t2, v26

  li t2, 0x2db4096b25e0a936
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vx v27, t2, v22

  li t2, 0xac6584bb8487c6da
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vx v15, t2, v4

  li t2, 0xffae27a8cd7a4560
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vx v16, t2, v8

  li t2, 0xef8b104ae921b5cb
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vx v2, t2, v28

  li t2, 0x067453b2e71d4c9d
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vx v8, t2, v24

  li t2, 0xdff3a0c8e1c27502
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vx v7, t2, v31

  li t2, 0xb0a8e65e5bcf7b71
  vsetvli t1, t0, e16, m1, ta, ma
  vnmsac.vx v15, t2, v9

  li t2, 0x1bc7a989e82c04ee
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vx v18, t2, v30

  li t2, 0x0eaff51926596194
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vx v10, t2, v2

  li t2, 0xe5d9dfcf1d9e15bd
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vx v24, t2, v2

  li t2, 0x7e0c05546bdf9a36
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vx v14, t2, v24

  li t2, 0x4e9c33f3721ec81e
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vx v12, t2, v2

  li t2, 0xebbede2b12716c8f
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vx v8, t2, v30

  li t2, 0x162901adb2c44f55
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vx v6, t2, v16

  li t2, 0x8925bcf29cb9612a
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vx v18, t2, v4

  li t2, 0x6cc54d96e8826c1c
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vx v12, t2, v26

  li t2, 0x425e924333a7f907
  vsetvli t1, t0, e16, m2, ta, ma
  vnmsac.vx v16, t2, v2

  li t2, 0x0190f26cd65e3d4e
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vx v8, t2, v28

  li t2, 0x99449faf3735f853
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vx v16, t2, v28

  li t2, 0xc429dc0e08076d50
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vx v4, t2, v16

  li t2, 0x18084fe10ca15c09
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vx v20, t2, v28

  li t2, 0xb950d3b4c909bd1f
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vx v4, t2, v24

  li t2, 0x8f3fdc1c6c39cf2c
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vx v24, t2, v20

  li t2, 0xdc2d4b7f5c2c5daa
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vx v4, t2, v12

  li t2, 0x9d7d9ad18df82986
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vx v4, t2, v20

  li t2, 0x74300516c7898ea0
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vx v4, t2, v24

  li t2, 0xfbef3577f82faa53
  vsetvli t1, t0, e16, m4, ta, ma
  vnmsac.vx v4, t2, v24

  li t2, 0x4919a63203dd8d1a
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vx v24, t2, v16

  li t2, 0x3da2fb6a4d180b71
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vx v8, t2, v16

  li t2, 0x41cb59445b441404
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vx v8, t2, v24

  li t2, 0xd3ea143950fd53f5
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vx v24, t2, v8

  li t2, 0xca946544258a7f9d
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vx v8, t2, v24

  li t2, 0xc4cb5b36b86d42ea
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vx v8, t2, v24

  li t2, 0x69c0800983d661bd
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vx v8, t2, v24

  li t2, 0x5f96b34a0ca02375
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vx v8, t2, v24

  li t2, 0x4f4109bfd512d479
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vx v16, t2, v8

  li t2, 0x06fe56bfc9fee468
  vsetvli t1, t0, e16, m8, ta, ma
  vnmsac.vx v24, t2, v16

  li t2, 0x733e44f2096d3fc9
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vx v1, t2, v20

  li t2, 0xf788e8c0c0ee1ba8
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vx v11, t2, v27

  li t2, 0x0ca55e03f51d89b5
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vx v7, t2, v12

  li t2, 0x1a3956bf2c91844a
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vx v26, t2, v11

  li t2, 0xd4af6f1e5ca71eeb
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vx v23, t2, v20

  li t2, 0xfe8f21e99aa2e703
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vx v24, t2, v13

  li t2, 0x722110762cd77f29
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vx v7, t2, v1

  li t2, 0xfb5a6c248ccf82ec
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vx v24, t2, v31

  li t2, 0xa9e399953b1c1416
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vx v6, t2, v2

  li t2, 0x015e1c18dac54107
  vsetvli t1, t0, e32, m1, ta, ma
  vnmsac.vx v17, t2, v25

  li t2, 0x89b51bf747599cae
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vx v12, t2, v16

  li t2, 0xb4b5f41654073c39
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vx v8, t2, v6

  li t2, 0xb6d6c0c1f0501222
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vx v12, t2, v20

  li t2, 0x7750cdd1bd4b61bd
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vx v14, t2, v28

  li t2, 0xba37ad7bc50ff302
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vx v22, t2, v28

  li t2, 0xd7bc8be35931348b
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vx v16, t2, v14

  li t2, 0x9238fb1275588191
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vx v6, t2, v14

  li t2, 0xd7c9876a6eefc093
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vx v12, t2, v30

  li t2, 0x601f158c0da4c141
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vx v22, t2, v10

  li t2, 0x5144b55c11b399c5
  vsetvli t1, t0, e32, m2, ta, ma
  vnmsac.vx v4, t2, v26

  li t2, 0xf31f68d61b0d08bb
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vx v4, t2, v8

  li t2, 0xb03cd4e99de5bb8a
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vx v24, t2, v4

  li t2, 0xe64f53bfc88b7449
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vx v20, t2, v8

  li t2, 0x2ed753835fd5eb77
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vx v20, t2, v4

  li t2, 0x23abdaca8eade8ed
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vx v16, t2, v8

  li t2, 0x2e4d9fbf4f0c8ff2
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vx v24, t2, v28

  li t2, 0xd9874638d2b8ffa9
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vx v16, t2, v4

  li t2, 0xaa7f2398819248b6
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vx v24, t2, v8

  li t2, 0x00f650c14cf15671
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vx v12, t2, v20

  li t2, 0xd8e7844f33874919
  vsetvli t1, t0, e32, m4, ta, ma
  vnmsac.vx v8, t2, v16

  li t2, 0xd3b1aab18ba44780
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vx v16, t2, v24

  li t2, 0x82f9b6678c626145
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vx v16, t2, v8

  li t2, 0x0885ed4c2bd7a52f
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vx v16, t2, v8

  li t2, 0x2e015b39dd36312b
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vx v24, t2, v8

  li t2, 0xb3cb50840b1c2328
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vx v8, t2, v24

  li t2, 0xe9302a507f98079c
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vx v16, t2, v8

  li t2, 0xaef7a3e561c0c8b7
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vx v8, t2, v16

  li t2, 0x3728da8b220fc906
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vx v24, t2, v8

  li t2, 0xe8787ccf906e4a81
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vx v16, t2, v24

  li t2, 0x91760b6ba814f231
  vsetvli t1, t0, e32, m8, ta, ma
  vnmsac.vx v8, t2, v16

  li t2, 0x9d8ce7b17e1942f5
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vx v12, t2, v4

  li t2, 0x7296e2b1336e98e4
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vx v21, t2, v26

  li t2, 0xb5d7e33a49791cfa
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vx v7, t2, v21

  li t2, 0x21dfca6795a14acf
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vx v16, t2, v15

  li t2, 0x489aca697a95d10f
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vx v29, t2, v1

  li t2, 0x687cf903c493ce2d
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vx v31, t2, v6

  li t2, 0x99fbd44c64504567
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vx v13, t2, v20

  li t2, 0x1b89ebe123e7b56f
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vx v22, t2, v6

  li t2, 0xf81f733a3afc261c
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vx v4, t2, v18

  li t2, 0xe641875439a6c774
  vsetvli t1, t0, e64, m1, ta, ma
  vnmsac.vx v14, t2, v12

  li t2, 0x5cfab6d1fa5d8b05
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vx v6, t2, v10

  li t2, 0xa1665f3096e89d5d
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vx v30, t2, v2

  li t2, 0xf62140056e0cc3f3
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vx v12, t2, v20

  li t2, 0xe3c2014e34dff818
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vx v4, t2, v14

  li t2, 0x7cac5a546b669767
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vx v28, t2, v20

  li t2, 0xbc28aeebe824fcd3
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vx v4, t2, v10

  li t2, 0xbf7ea07c82719074
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vx v22, t2, v26

  li t2, 0xab1dad94c5e0cc72
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vx v30, t2, v2

  li t2, 0x0e9f90a949ce3b8f
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vx v14, t2, v18

  li t2, 0x8f827234b8bae355
  vsetvli t1, t0, e64, m2, ta, ma
  vnmsac.vx v14, t2, v24

  li t2, 0x282d971c45c9570e
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vx v16, t2, v4

  li t2, 0xef6d2896c69d7367
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vx v4, t2, v20

  li t2, 0x1894c74e5088023e
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vx v12, t2, v24

  li t2, 0xa8873959d6867384
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vx v16, t2, v8

  li t2, 0x791fa5475e0f6a7a
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vx v16, t2, v8

  li t2, 0x0f5659051161a6f4
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vx v4, t2, v8

  li t2, 0xabf8453c00bcf50d
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vx v28, t2, v12

  li t2, 0x0c47cfab730fdd3f
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vx v4, t2, v12

  li t2, 0x2ae99a85c639ed38
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vx v16, t2, v8

  li t2, 0xdcc487436c8a8d7a
  vsetvli t1, t0, e64, m4, ta, ma
  vnmsac.vx v24, t2, v28

  li t2, 0x41dd5ff06106f6e2
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vx v8, t2, v24

  li t2, 0x527bf4fc9170bdec
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vx v8, t2, v16

  li t2, 0x398337a163a7e2c2
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vx v16, t2, v8

  li t2, 0xda0006e3ea0710f5
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vx v24, t2, v8

  li t2, 0xfa87e094fe1779f1
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vx v16, t2, v24

  li t2, 0x92291706b6667a60
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vx v24, t2, v8

  li t2, 0x2bfd9310803c7324
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vx v8, t2, v24

  li t2, 0x524b9eeff5951dd1
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vx v24, t2, v16

  li t2, 0x576d6376b8bb11e8
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vx v24, t2, v16

  li t2, 0x2847720ef763cd37
  vsetvli t1, t0, e64, m8, ta, ma
  vnmsac.vx v8, t2, v16

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
