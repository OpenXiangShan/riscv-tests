#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vv v4, v17, v31

  li t2, 0xba9cb593ba2312fb
  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vx v23, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vi v3, v13, 3

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vv v18, v23, v15

  li t2, 0xd4c23e0d0d4ff71f
  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vx v16, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vi v3, v1, 26

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vv v16, v17, v21

  li t2, 0xb2f04d41318910f7
  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vx v3, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vi v3, v12, 5

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vv v28, v10, v14

  li t2, 0x8f0da60e9fe479d6
  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vx v31, v14, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vi v8, v4, 28

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vv v31, v4, v5

  li t2, 0x1dec86d340709443
  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vx v8, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vi v6, v24, 12

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vv v8, v29, v20

  li t2, 0x9cac212a5fff822f
  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vx v14, v13, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vi v26, v23, 31

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vv v3, v1, v23

  li t2, 0x6907d8390cd91e4f
  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vx v16, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vi v31, v12, 5

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vv v3, v19, v28

  li t2, 0xbf618f4188e2eca5
  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vx v29, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vi v31, v6, 18

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vv v31, v4, v19

  li t2, 0x9d988f1ee72d0fa5
  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vx v5, v17, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vi v18, v21, 26

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vv v30, v24, v1

  li t2, 0x2414b4f31b083be1
  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vx v2, v10, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssrl.vi v17, v23, 28

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vv v24, v4, v2

  li t2, 0xdbec2d8f414dba04
  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vx v24, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vi v14, v26, 12

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vv v4, v8, v16

  li t2, 0x922abd56e3a0ba82
  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vx v28, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vi v8, v10, 22

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vv v14, v18, v28

  li t2, 0xd8d75c442f80a93e
  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vx v2, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vi v12, v24, 16

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vv v2, v10, v8

  li t2, 0xe6daf09f8a01817e
  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vx v14, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vi v16, v2, 5

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vv v4, v26, v14

  li t2, 0xa4b95d4f11429c56
  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vx v16, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vi v24, v22, 13

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vv v24, v4, v8

  li t2, 0xf2921de414b02a9d
  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vx v18, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vi v6, v28, 28

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vv v14, v26, v18

  li t2, 0xc61e782a5c9c1cc1
  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vx v30, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vi v24, v4, 16

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vv v14, v16, v26

  li t2, 0x21fb3cf79034c314
  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vx v28, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vi v12, v14, 9

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vv v28, v16, v30

  li t2, 0x38731c34efe68238
  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vx v24, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vi v22, v18, 8

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vv v22, v28, v30

  li t2, 0xb2060e403e6f317f
  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vx v22, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssrl.vi v14, v26, 16

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vv v12, v4, v8

  li t2, 0x087baf7639fc2711
  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vx v8, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vi v8, v20, 11

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vv v28, v20, v24

  li t2, 0x2758aed1bb22e8cd
  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vx v28, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vi v16, v28, 31

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vv v20, v4, v24

  li t2, 0x4358283b2726333b
  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vx v24, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vi v4, v12, 6

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vv v8, v28, v20

  li t2, 0x3fbd6254538f5bfc
  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vx v4, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vi v16, v4, 11

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vv v20, v16, v4

  li t2, 0x5e2b1370a87cb76e
  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vx v8, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vi v12, v8, 27

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vv v12, v4, v8

  li t2, 0x208c785e4abf8163
  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vx v20, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vi v16, v24, 31

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vv v8, v16, v28

  li t2, 0xbdcd297fea033cb9
  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vx v24, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vi v20, v28, 2

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vv v24, v28, v8

  li t2, 0xc40af4d89cbf5ec6
  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vx v20, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vi v16, v28, 1

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vv v12, v28, v8

  li t2, 0xced92966883ae94b
  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vi v8, v20, 22

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vv v12, v20, v16

  li t2, 0x1994b60a17491ea3
  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssrl.vi v16, v24, 17

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vv v24, v16, v8

  li t2, 0x0e023813b22c6d87
  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vi v16, v24, 16

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vv v8, v16, v24

  li t2, 0x46aad739825a7981
  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vi v16, v24, 7

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vv v24, v16, v8

  li t2, 0xd3bb1638a80d93c0
  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vi v24, v8, 15

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vv v8, v24, v16

  li t2, 0xeb8fcd9ec9eccb5c
  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vi v16, v24, 6

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vv v16, v8, v24

  li t2, 0xee0cb4d1bd096238
  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vi v8, v24, 30

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vv v16, v8, v24

  li t2, 0x372b9c6117bdf076
  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vi v16, v24, 25

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vv v16, v24, v8

  li t2, 0xc214e1df69801d5c
  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vi v24, v16, 2

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vv v24, v16, v8

  li t2, 0x4f6b9bf7350c2932
  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vi v24, v16, 19

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vv v16, v24, v8

  li t2, 0xdeb4386310c9f2b4
  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vi v24, v16, 20

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vv v8, v16, v24

  li t2, 0x3d677e06b43d5bc9
  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssrl.vi v16, v24, 25

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vv v7, v17, v1

  li t2, 0xb7e96f112db53ee7
  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vx v15, v31, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vi v7, v18, 7

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vv v1, v17, v28

  li t2, 0x643dfaa71fc6c24a
  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vx v4, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vi v20, v22, 2

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vv v4, v13, v23

  li t2, 0x58dba79ca29b865e
  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vx v27, v7, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vi v23, v5, 15

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vv v4, v11, v9

  li t2, 0xff5199ae2b7f3fdc
  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vx v12, v14, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vi v15, v2, 22

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vv v8, v29, v13

  li t2, 0x0bfd362c39e48d20
  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vx v15, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vi v6, v14, 23

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vv v18, v24, v21

  li t2, 0x31ecefa44fdc30a1
  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vx v10, v3, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vi v29, v5, 19

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vv v29, v26, v9

  li t2, 0xb4b624db5a1523de
  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vx v28, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vi v29, v15, 30

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vv v28, v17, v29

  li t2, 0x89777cbc265d1438
  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vx v3, v23, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vi v14, v22, 30

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vv v24, v30, v16

  li t2, 0x1d895414c345c9d5
  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vx v19, v17, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vi v17, v7, 31

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vv v21, v10, v6

  li t2, 0x868e68296d72b54a
  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vx v23, v17, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssrl.vi v13, v8, 19

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vv v2, v4, v8

  li t2, 0x032c01bb46904ebd
  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vx v10, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vi v18, v12, 2

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vv v6, v14, v24

  li t2, 0x888a5c9c7bef790a
  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vx v30, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vi v22, v20, 22

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vv v2, v30, v6

  li t2, 0xe14fc7b52a4fb98c
  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vx v24, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vi v14, v10, 0

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vv v22, v10, v28

  li t2, 0x380b41b2b39cec99
  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vx v10, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vi v22, v18, 9

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vv v18, v4, v28

  li t2, 0xa8b59dd214338f6a
  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vx v20, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vi v14, v8, 20

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vv v16, v30, v4

  li t2, 0xa0ac0b205261afbb
  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vx v8, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vi v16, v18, 19

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vv v18, v24, v16

  li t2, 0xbb0eaf4914f319ed
  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vx v10, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vi v4, v16, 20

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vv v16, v22, v24

  li t2, 0x7b1548d50fd8a246
  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vx v16, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vi v18, v4, 20

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vv v8, v14, v26

  li t2, 0x8c7e42e07a084854
  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vx v6, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vi v28, v16, 26

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vv v14, v16, v22

  li t2, 0x73256bcbe3c30019
  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vx v8, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssrl.vi v4, v12, 23

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vv v20, v4, v8

  li t2, 0x6d6a3a3ee6b321e1
  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vx v16, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vi v12, v20, 3

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vv v8, v16, v4

  li t2, 0xd69cac2fa59a2ed8
  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vi v16, v20, 6

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vv v28, v12, v8

  li t2, 0x1baba2c16d858878
  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vi v4, v16, 6

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vv v20, v28, v4

  li t2, 0xd99f8a91c05f81ee
  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vi v4, v12, 25

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vv v20, v8, v28

  li t2, 0xeac7a9dd8b46b529
  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vx v4, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vi v8, v4, 6

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vv v8, v20, v4

  li t2, 0xb8a5ddcbb5fec7cd
  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vx v16, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vi v20, v24, 25

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vv v8, v28, v4

  li t2, 0x3d990228d56cdebe
  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vx v16, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vi v16, v12, 8

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vv v16, v8, v20

  li t2, 0x12478b75d4d42ced
  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vx v20, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vi v16, v20, 24

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vv v16, v20, v8

  li t2, 0x414ca8a834952140
  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vx v16, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vi v16, v12, 24

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vv v12, v16, v28

  li t2, 0xf1cfbec5b44c1928
  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssrl.vi v28, v20, 19

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vv v8, v24, v16

  li t2, 0x1cf9a5398b3e24f6
  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vi v8, v24, 17

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vv v16, v8, v24

  li t2, 0x194a8c7060e5d497
  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vi v24, v8, 21

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vv v24, v16, v8

  li t2, 0x9e0b182f2d9ac85e
  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vi v16, v24, 0

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vv v16, v8, v24

  li t2, 0xe4ec53084cf7bb27
  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vi v16, v8, 24

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vv v8, v16, v24

  li t2, 0xfe12d89bc64bcbce
  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vi v8, v16, 18

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vv v8, v16, v24

  li t2, 0x5af8694a5a8bf68f
  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vi v24, v16, 29

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vv v24, v8, v16

  li t2, 0xc9492394d3b19381
  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vi v16, v8, 15

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vv v8, v16, v24

  li t2, 0x8da26e4114d9ed3d
  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vi v16, v8, 7

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vv v24, v16, v8

  li t2, 0xe5ca3cda07c8b7e6
  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vi v8, v24, 13

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vv v24, v16, v8

  li t2, 0x1ba077c376809aed
  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssrl.vi v16, v8, 17

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vv v4, v1, v8

  li t2, 0x91a2227221608e63
  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vx v31, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vi v22, v16, 16

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vv v9, v7, v29

  li t2, 0xb94c65e81267b402
  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vx v30, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vi v1, v26, 4

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vv v3, v4, v19

  li t2, 0x3992130d9b4dcfdd
  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vx v22, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vi v4, v27, 12

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vv v2, v22, v26

  li t2, 0x717cce2eca6a4da5
  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vx v6, v31, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vi v13, v31, 26

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vv v27, v17, v25

  li t2, 0x8b95f00df2ea267e
  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vx v3, v11, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vi v28, v15, 13

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vv v12, v28, v29

  li t2, 0x0b2a0bc26106d23f
  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vx v28, v26, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vi v1, v9, 14

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vv v9, v27, v2

  li t2, 0x9999994a423d0507
  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vx v18, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vi v15, v4, 18

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vv v25, v13, v24

  li t2, 0x6660282e0ea2396e
  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vx v11, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vi v17, v13, 1

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vv v31, v11, v23

  li t2, 0x1b6ad61fa84be00b
  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vx v26, v19, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vi v18, v7, 30

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vv v21, v4, v19

  li t2, 0x16c81800403ac58b
  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vx v7, v25, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssrl.vi v31, v6, 31

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vv v22, v12, v2

  li t2, 0xfa94a137930b0efc
  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vx v26, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vi v24, v22, 31

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vv v2, v12, v4

  li t2, 0xfdc18dab70487f40
  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vx v30, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vi v2, v10, 21

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vv v30, v26, v16

  li t2, 0x5671db6915a52c63
  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vx v28, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vi v14, v28, 28

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vv v24, v22, v26

  li t2, 0xa80603f8aaa75467
  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vx v22, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vi v20, v24, 4

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vv v6, v14, v24

  li t2, 0xa64185e66a9b96d7
  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vx v18, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vi v28, v8, 26

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vv v8, v14, v22

  li t2, 0xe8fe8fa1dfb387d7
  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vx v2, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vi v30, v14, 14

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vv v30, v22, v16

  li t2, 0x724862f2f3a8fb36
  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vx v28, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vi v4, v12, 6

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vv v4, v24, v12

  li t2, 0xd75d98e7b06046fb
  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vx v28, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vi v12, v20, 5

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vv v16, v10, v28

  li t2, 0xd7dd128cd3537407
  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vx v20, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vi v8, v22, 4

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vv v16, v10, v20

  li t2, 0x40a5c0b5102d0cf8
  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vx v14, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssrl.vi v2, v24, 18

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vv v12, v8, v20

  li t2, 0xec1b7577ed65b7d4
  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vx v8, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vi v28, v20, 31

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vv v24, v16, v12

  li t2, 0x114f03a3a03ce074
  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vx v12, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vi v20, v8, 26

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vv v20, v16, v4

  li t2, 0x9894c3704438dced
  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vx v24, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vi v8, v28, 0

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vv v16, v28, v4

  li t2, 0x7be68490e8df9949
  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vx v4, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vi v28, v16, 18

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vv v28, v16, v24

  li t2, 0x36d53e338f06b73c
  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vx v20, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vi v16, v12, 14

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vv v8, v20, v24

  li t2, 0x072aff57898f5091
  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vx v20, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vi v16, v20, 7

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vv v28, v24, v16

  li t2, 0xcfdffc7e5110e30c
  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vx v12, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vi v4, v8, 11

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vv v20, v4, v12

  li t2, 0xfc3e7b08cd3a9c47
  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vx v20, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vi v12, v28, 1

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vv v12, v16, v4

  li t2, 0xff3b797c8ae97559
  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vx v16, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vi v16, v24, 2

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vv v28, v8, v12

  li t2, 0x9ac21a7039bb3200
  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vx v12, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssrl.vi v16, v24, 24

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vv v16, v24, v8

  li t2, 0xa0e70bffde8a0f50
  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vi v24, v8, 20

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vv v24, v8, v16

  li t2, 0xdd09e5c106bd4d5b
  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vi v24, v8, 14

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vv v8, v24, v16

  li t2, 0xa0279b638c99859d
  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vi v24, v8, 18

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vv v16, v8, v24

  li t2, 0xb3048bbbd19b1bc1
  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vi v8, v16, 7

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vv v16, v24, v8

  li t2, 0xbce823aff350129c
  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vi v16, v24, 10

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vv v16, v8, v24

  li t2, 0x5d446d030849c506
  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vi v8, v16, 10

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vv v24, v16, v8

  li t2, 0x20b1e4111b450e0a
  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vi v24, v8, 29

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vv v16, v8, v24

  li t2, 0x7802a20f648c693d
  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vi v24, v16, 3

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vv v8, v24, v16

  li t2, 0xb4fa03ea5322dce1
  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vi v16, v24, 14

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vv v16, v8, v24

  li t2, 0x2f1dcb6333294774
  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssrl.vi v24, v8, 9

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vv v6, v18, v24

  li t2, 0xae83ffefb185b4da
  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vx v22, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vi v31, v15, 16

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vv v11, v10, v31

  li t2, 0x80b0ca629a856ff6
  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vx v1, v21, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vi v22, v26, 1

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vv v28, v9, v15

  li t2, 0x6d22e691a72c15d0
  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vx v8, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vi v13, v3, 19

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vv v18, v17, v31

  li t2, 0xec7e2f82cbe7d4e8
  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vx v30, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vi v1, v21, 15

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vv v7, v6, v2

  li t2, 0x9b34ea48963adfb9
  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vx v5, v21, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vi v2, v28, 13

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vv v3, v14, v13

  li t2, 0xadd864ca441d5adf
  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vx v16, v2, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vi v22, v14, 10

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vv v20, v17, v29

  li t2, 0x84fa6452ebe06537
  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vx v10, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vi v16, v18, 12

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vv v28, v6, v23

  li t2, 0x75e6b0dc8f072fc9
  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vx v12, v17, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vi v20, v19, 26

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vv v3, v23, v31

  li t2, 0x97976f4f7afd78be
  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vx v11, v3, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vi v25, v29, 23

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vv v22, v28, v9

  li t2, 0xca70c97e3f6ab59f
  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vx v30, v22, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssrl.vi v24, v2, 1

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vv v16, v22, v8

  li t2, 0x95206fc305c8229f
  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vx v2, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vi v14, v24, 27

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vv v24, v20, v26

  li t2, 0x89b7c1df296c0d2f
  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vx v30, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vi v14, v22, 18

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vv v20, v14, v10

  li t2, 0x9e9ee00b4791041e
  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vx v8, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vi v2, v6, 11

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vv v14, v2, v20

  li t2, 0xc3ddb24716f2d2f3
  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vx v6, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vi v28, v12, 20

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vv v22, v4, v14

  li t2, 0xe39030bc474200ce
  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vx v14, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vi v10, v30, 28

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vv v6, v16, v4

  li t2, 0xaf03a53638d1ca74
  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vx v24, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vi v6, v30, 24

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vv v28, v10, v16

  li t2, 0xff0bcde417fc80ca
  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vx v18, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vi v14, v20, 9

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vv v30, v24, v20

  li t2, 0xdf24af2e764b1c15
  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vx v12, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vi v4, v26, 18

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vv v2, v18, v26

  li t2, 0x29f5ad6382332257
  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vx v30, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vi v8, v6, 16

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vv v8, v12, v20

  li t2, 0x4011226a692c9ade
  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vx v30, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssrl.vi v4, v24, 28

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vv v12, v4, v16

  li t2, 0x46b9ba93d401a315
  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vx v12, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vi v12, v4, 16

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vv v8, v4, v28

  li t2, 0x7b3d945e49698a0d
  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vi v12, v16, 14

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vv v24, v8, v16

  li t2, 0x7f0affd41c21133d
  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vx v8, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vi v28, v12, 18

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vv v8, v16, v12

  li t2, 0x9ee007dcba1c9a3a
  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vi v24, v12, 23

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vv v24, v20, v16

  li t2, 0xca125eb473c1f9c0
  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vx v8, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vi v12, v20, 26

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vv v12, v20, v28

  li t2, 0xa8e9710b41656d98
  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vx v20, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vi v16, v28, 13

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vv v24, v12, v8

  li t2, 0x7615e8e047c3956e
  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vx v16, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vi v20, v8, 17

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vv v16, v4, v12

  li t2, 0x9bdaaa7a3f882f40
  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vx v12, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vi v20, v8, 25

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vv v24, v4, v20

  li t2, 0x939e532e2ba7c99d
  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vx v8, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vi v20, v16, 30

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vv v20, v8, v4

  li t2, 0x4932cf8188bc3f71
  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vx v28, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssrl.vi v24, v8, 23

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vv v24, v8, v16

  li t2, 0xa5e9178f7f74b7ef
  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vi v24, v16, 10

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vv v16, v24, v8

  li t2, 0x9914568caa58ac6a
  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vi v16, v8, 27

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vv v8, v24, v16

  li t2, 0x52bad02d1b311543
  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vi v16, v8, 9

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vv v16, v8, v24

  li t2, 0x4562c305a6566c1d
  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vi v24, v16, 20

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vv v8, v16, v24

  li t2, 0xdc0712d95cf70a5d
  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vi v24, v8, 31

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vv v24, v8, v16

  li t2, 0x861903e804acddff
  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vi v8, v16, 24

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vv v24, v8, v16

  li t2, 0xf0552b7562fd872d
  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vi v24, v8, 26

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vv v16, v8, v24

  li t2, 0xbff86a522093abb6
  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vi v24, v16, 17

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vv v16, v8, v24

  li t2, 0x44142d3fedd4113c
  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vi v8, v24, 7

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vv v24, v16, v8

  li t2, 0x512d43fb8d9d21a7
  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssrl.vi v16, v8, 30

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
