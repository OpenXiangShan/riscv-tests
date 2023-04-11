#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v2, v30, v9, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v15, v18, v28, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v13, v23, v29, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v6, v9, v25, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v28, v10, v3, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v10, v28, v12, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v6, v10, v7, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v25, v22, v26, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v28, v9, v19, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v27, v24, v18, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v23, v10, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v27, v20, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v21, v14, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v6, v22, v31

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v21, v15, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v10, v13, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v10, v11, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v12, v2, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v31, v5, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vv v15, v14, v31

  li t2, 0xdffb1d4875dfe9f0
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v18, v12, t2, v0.t

  li t2, 0xe740119fca31b5da
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v11, v22, t2, v0.t

  li t2, 0xa17b60d64aabfbe9
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v7, v16, t2, v0.t

  li t2, 0x8abf973f149b5658
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v29, v8, t2, v0.t

  li t2, 0xe4331fd098c977e2
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v17, v21, t2, v0.t

  li t2, 0xd224ab3a5b33571a
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v25, v31, t2, v0.t

  li t2, 0xd720c97cec716131
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v26, v25, t2, v0.t

  li t2, 0xd579c6e90765b8c1
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v19, v21, t2, v0.t

  li t2, 0xbd6434b5fe7bf468
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v30, v15, t2, v0.t

  li t2, 0x43e58344698fdbd6
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v20, v29, t2, v0.t

  li t2, 0xcd267863969c8cd7
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v23, v30, t2

  li t2, 0xe61dd74f804a7861
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v12, v5, t2

  li t2, 0x26ed7da5a20543b5
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v26, v7, t2

  li t2, 0x80966cde91282890
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v31, v3, t2

  li t2, 0x3b86a4aa5e7c1960
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v5, v21, t2

  li t2, 0x1b9d65bd204b5d9a
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v21, v10, t2

  li t2, 0x7576f210b8d1c45b
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v19, v31, t2

  li t2, 0xcd7a9c15a9d8b973
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v9, v14, t2

  li t2, 0x67aea0bdd6e64aba
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v30, v20, t2

  li t2, 0x3913d77c3cf03181
  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vx v28, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v27, v23, 30, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v27, v6, 21, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v6, v30, 13, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v14, v9, 2, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v24, v10, 24, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v17, v10, 25, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v28, v18, 27, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v22, v28, 27, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v10, v26, 0, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v18, v4, 25, v0.t

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v26, v24, 2

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v25, v19, 30

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v28, v13, 29

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v10, v8, 0

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v30, v28, 29

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v1, v20, 0

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v24, v14, 27

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v6, v8, 12

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v26, v13, 17

  vsetvli t1, t0, e8, m1, ta, ma
  vrgather.vi v7, v3, 1

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v6, v22, v12, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v28, v22, v20, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v12, v8, v2, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v30, v4, v22, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v2, v20, v28, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v30, v28, v10, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v24, v22, v28, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v14, v16, v6, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v26, v8, v18, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v26, v2, v28, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v28, v4, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v28, v2, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v10, v20, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v26, v30, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v10, v24, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v8, v10, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v10, v2, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v14, v2, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v20, v18, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vv v8, v20, v28

  li t2, 0xfa89970d1016eee4
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v2, v10, t2, v0.t

  li t2, 0xac5552a169f83cf3
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v6, v20, t2, v0.t

  li t2, 0xa28015d5b9e2c67f
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v14, v12, t2, v0.t

  li t2, 0x15ff5e7c851c8ef0
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v12, v8, t2, v0.t

  li t2, 0xa566a14e8d4896f5
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v2, v12, t2, v0.t

  li t2, 0x38c1cce2ec2754b7
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v24, v22, t2, v0.t

  li t2, 0xe8766f070e642c9b
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v6, v12, t2, v0.t

  li t2, 0x458d357e2d690843
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v12, v8, t2, v0.t

  li t2, 0x7b481935610078c6
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v4, v12, t2, v0.t

  li t2, 0x4d338148d503949a
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v12, v14, t2, v0.t

  li t2, 0x3a0d43963863b26e
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v4, v2, t2

  li t2, 0x4b0b832cdb7fd795
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v28, v30, t2

  li t2, 0xbfe57a50f74b4cbe
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v22, v6, t2

  li t2, 0x9cf0585fac97d15f
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v2, v10, t2

  li t2, 0xe15539c5e0cc1e47
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v20, v14, t2

  li t2, 0xd7aef6208cbf606b
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v24, v26, t2

  li t2, 0x3e154f70be569fd0
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v18, v28, t2

  li t2, 0xc901a23b69640bec
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v16, v6, t2

  li t2, 0x79f484d49a98b768
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v4, v30, t2

  li t2, 0xfa5d0f2fa9b50ad4
  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vx v30, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v6, v8, 23, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v22, v28, 10, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v18, v16, 24, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v28, v14, 23, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v16, v10, 19, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v16, v24, 12, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v24, v4, 25, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v26, v18, 22, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v22, v16, 31, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v12, v22, 3, v0.t

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v18, v28, 15

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v2, v8, 25

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v22, v28, 17

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v16, v26, 17

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v30, v14, 20

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v14, v24, 31

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v4, v14, 5

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v20, v28, 12

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v30, v8, 17

  vsetvli t1, t0, e8, m2, ta, ma
  vrgather.vi v12, v14, 3

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v8, v4, v16, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v8, v20, v24, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v4, v20, v8, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v8, v20, v16, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v20, v16, v24, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v28, v8, v20, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v8, v12, v16, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v20, v24, v16, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v8, v12, v24, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v4, v8, v20, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v24, v28, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v12, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v4, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v4, v20, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v12, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v8, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v12, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v12, v20, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v12, v24, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vv v20, v8, v16

  li t2, 0xdcc2c451a5c5b5cf
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v28, v20, t2, v0.t

  li t2, 0x39d1ae408d95040b
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v20, v4, t2, v0.t

  li t2, 0x9d091e23da9ef507
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v8, v4, t2, v0.t

  li t2, 0x8a88867da62f7b1d
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v8, v12, t2, v0.t

  li t2, 0x5b11d22728b4dc2d
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v8, v12, t2, v0.t

  li t2, 0xf27a5cfbc7a156d6
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v24, v16, t2, v0.t

  li t2, 0x83c35e548377cbc2
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v8, v16, t2, v0.t

  li t2, 0xf2019a3ffe0bbfe2
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v16, v20, t2, v0.t

  li t2, 0x0826e9c36562c06b
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v24, v16, t2, v0.t

  li t2, 0x242dd02770014207
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v20, v4, t2, v0.t

  li t2, 0x21b0f0a5bcf7b100
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v4, v16, t2

  li t2, 0x1d7bc5ebfd176a18
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v20, v12, t2

  li t2, 0x8dedaef570967039
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v12, v28, t2

  li t2, 0xcb1df283ab3e451c
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v8, v24, t2

  li t2, 0x10a86d0a65e2d464
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v20, v12, t2

  li t2, 0x6f9163f9a7641fda
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v8, v24, t2

  li t2, 0x47aded78713a811d
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v24, v12, t2

  li t2, 0x9a91fbae2d8381dc
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v24, v8, t2

  li t2, 0x1f9fb548e2abac15
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v4, v24, t2

  li t2, 0xa9a45fa66294b760
  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v4, v16, 29, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v20, v28, 30, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v28, v20, 20, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v28, v12, 29, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v4, v28, 24, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v8, v28, 8, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v4, v20, 6, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v24, v28, 17, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v16, v4, 30, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v20, v28, 28, v0.t

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v16, v8, 24

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v28, v8, 16

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v8, v4, 30

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v16, v12, 19

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v24, v8, 27

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v8, v12, 4

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v16, v8, 8

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v20, v12, 1

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v4, v28, 19

  vsetvli t1, t0, e8, m4, ta, ma
  vrgather.vi v20, v28, 1

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v24, v16, v8, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v8, v24, v16, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v24, v8, v16, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v24, v16, v8, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v8, v24, v16, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v16, v24, v8, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v24, v8, v16, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v8, v24, v16, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vv v8, v24, v16

  li t2, 0x722b6cd05f73ba59
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v8, v16, t2, v0.t

  li t2, 0xfadf035d07437dc2
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v24, v8, t2, v0.t

  li t2, 0x6d61d0d6c133dd12
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v24, v8, t2, v0.t

  li t2, 0xb9c23ca94576d674
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v24, v16, t2, v0.t

  li t2, 0xb0ffb998d285c1d6
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v8, v16, t2, v0.t

  li t2, 0x16e798048f3db6cd
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v16, v24, t2, v0.t

  li t2, 0xeafe5bb84f2de3fb
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v16, v8, t2, v0.t

  li t2, 0x113999ca93a367c3
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v8, v24, t2, v0.t

  li t2, 0x94c709ffed8eacab
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v24, v8, t2, v0.t

  li t2, 0x391db936d96a7d75
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v8, v24, t2, v0.t

  li t2, 0x1eef93d8346f5aa8
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v8, v24, t2

  li t2, 0x29b2b6a7ea704143
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v16, v24, t2

  li t2, 0xeab46bbc2a936d60
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v16, v24, t2

  li t2, 0x882c916eb889f103
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v8, v16, t2

  li t2, 0x219efbb7d031e22f
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v8, v24, t2

  li t2, 0x3d6d2e10aa22fe09
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v8, v24, t2

  li t2, 0xae4132df5bc1f9b0
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v8, v24, t2

  li t2, 0x4332968315a87cb9
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v8, v24, t2

  li t2, 0x0f960ce59de2a597
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v24, v16, t2

  li t2, 0xf7d4301baf6ecfa3
  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v16, v24, 7, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v8, v24, 3, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v24, v8, 11, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v24, v16, 15, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v8, v24, 25, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v8, v16, 7, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v8, v16, 22, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v24, v8, 15, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v16, v8, 11, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v24, v8, 22, v0.t

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v16, v24, 13

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v8, v24, 7

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v8, v24, 13

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v16, v24, 24

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v16, v24, 24

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v16, v8, 14

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v16, v24, 8

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v24, v8, 23

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v16, v8, 20

  vsetvli t1, t0, e8, m8, ta, ma
  vrgather.vi v24, v16, 2

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v10, v12, v27, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v10, v19, v5, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v17, v25, v23, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v7, v31, v28, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v18, v29, v7, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v5, v3, v23, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v9, v19, v31, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v27, v24, v31, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v9, v20, v31, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v4, v21, v9, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v10, v13, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v9, v7, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v6, v21, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v1, v5, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v8, v22, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v7, v26, v29

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v5, v6, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v24, v23, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v26, v18, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vv v7, v6, v3

  li t2, 0x5264125f5215b1fa
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v30, v22, t2, v0.t

  li t2, 0x87947fedf33487cd
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v3, v18, t2, v0.t

  li t2, 0x0d67329dd019eeab
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v15, v14, t2, v0.t

  li t2, 0xd629f66797bcce4a
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v28, v26, t2, v0.t

  li t2, 0x4371b434e9ac93e6
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v6, v29, t2, v0.t

  li t2, 0x62e83c183279d3a8
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v24, v11, t2, v0.t

  li t2, 0x7323aaab03413bd7
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v21, v1, t2, v0.t

  li t2, 0xebd796b3dce82b5b
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v5, v7, t2, v0.t

  li t2, 0xd658708429fa3744
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v15, v28, t2, v0.t

  li t2, 0xa0bac0f1ac779488
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v30, v22, t2, v0.t

  li t2, 0x7523ac59d0c8d417
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v1, v17, t2

  li t2, 0xf2b4eb634b215d17
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v20, v30, t2

  li t2, 0xb3bf9e9b84689640
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v20, v11, t2

  li t2, 0x5c059d8544d8a406
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v22, v8, t2

  li t2, 0x6a88b03f3825980b
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v4, v23, t2

  li t2, 0xbf7b55261b87b0bd
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v13, v17, t2

  li t2, 0x34da52e62919cda2
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v8, v20, t2

  li t2, 0x154f36cf2cec1668
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v2, v9, t2

  li t2, 0xf2440e603406efa5
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v27, v6, t2

  li t2, 0xdc908a8ee8a8169a
  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vx v7, v17, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v16, v21, 1, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v7, v20, 13, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v12, v23, 21, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v18, v21, 20, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v5, v27, 18, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v20, v5, 30, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v13, v1, 28, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v22, v26, 15, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v29, v7, 3, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v26, v21, 26, v0.t

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v21, v24, 13

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v24, v17, 21

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v21, v10, 9

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v24, v7, 9

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v1, v23, 20

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v26, v24, 5

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v25, v15, 8

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v20, v9, 6

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v28, v23, 18

  vsetvli t1, t0, e16, m1, ta, ma
  vrgather.vi v6, v12, 8

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v24, v22, v14, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v20, v28, v16, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v18, v28, v8, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v6, v12, v24, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v14, v20, v16, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v28, v26, v2, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v20, v14, v8, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v8, v18, v20, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v6, v8, v4, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v22, v24, v12, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v22, v4, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v2, v28, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v24, v16, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v10, v14, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v22, v30, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v18, v24, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v14, v8, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v28, v6, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v14, v8, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vv v6, v10, v12

  li t2, 0xbc5187aec44e65b5
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v4, v28, t2, v0.t

  li t2, 0x4b703a4f06d47751
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v4, v18, t2, v0.t

  li t2, 0xb8a9143927ac6648
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v20, v14, t2, v0.t

  li t2, 0xbcf6ae8d33d813e4
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v6, v14, t2, v0.t

  li t2, 0xfc1cacfaee960557
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v4, v2, t2, v0.t

  li t2, 0x60b704c8ddeab79a
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v22, v30, t2, v0.t

  li t2, 0xac135b267fbb64bb
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v10, v12, t2, v0.t

  li t2, 0x6aba751d1bcf746d
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v6, v2, t2, v0.t

  li t2, 0x19655984024708f6
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v24, v4, t2, v0.t

  li t2, 0x77c5435582b9e843
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v16, v14, t2, v0.t

  li t2, 0x4efe3c9e16a02cd0
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v2, v4, t2

  li t2, 0x4ae3baf1b796293e
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v26, v24, t2

  li t2, 0x80f0eb737692e4e9
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v8, v12, t2

  li t2, 0xdae57743c5659984
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v8, v10, t2

  li t2, 0xcdfb56834e9d576a
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v6, v20, t2

  li t2, 0x7f857db351d4b8a6
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v4, v14, t2

  li t2, 0xff43c7acdca039f9
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v28, v22, t2

  li t2, 0xd13de0d6d446e8cb
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v14, v30, t2

  li t2, 0x34136bac1c3015ae
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v18, v10, t2

  li t2, 0xd4af0e81db9b96ce
  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vx v12, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v16, v30, 26, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v14, v22, 3, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v16, v28, 22, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v4, v20, 31, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v8, v4, 9, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v8, v22, 16, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v20, v8, 19, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v12, v4, 19, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v4, v10, 26, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v16, v24, 24, v0.t

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v20, v12, 19

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v8, v14, 7

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v28, v2, 13

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v12, v2, 14

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v16, v8, 26

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v6, v18, 24

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v22, v10, 30

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v4, v20, 26

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v26, v28, 2

  vsetvli t1, t0, e16, m2, ta, ma
  vrgather.vi v28, v20, 2

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v16, v24, v4, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v24, v28, v16, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v12, v28, v20, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v24, v28, v20, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v24, v28, v8, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v28, v8, v20, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v28, v8, v16, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v24, v12, v20, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v28, v12, v16, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v4, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v8, v24, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v12, v8, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v12, v20, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v4, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v16, v28, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v28, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v20, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v28, v4, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vv v20, v4, v16

  li t2, 0xfae3fc050a3f4d21
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v16, v28, t2, v0.t

  li t2, 0xe4cf754755c2da0d
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v8, v24, t2, v0.t

  li t2, 0x079337285c42c3be
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v12, v28, t2, v0.t

  li t2, 0xae2093b472effa4e
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v20, v28, t2, v0.t

  li t2, 0x0380184a6ebdc3a4
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v8, v12, t2, v0.t

  li t2, 0x45328f3eb13984ae
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v20, v24, t2, v0.t

  li t2, 0x89932892c8ecab78
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v16, v12, t2, v0.t

  li t2, 0xf09ea322e1f0972a
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v4, v28, t2, v0.t

  li t2, 0x480aa422bfc35cf2
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v24, v12, t2, v0.t

  li t2, 0x09b011e73773b089
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v8, v16, t2, v0.t

  li t2, 0x8522302bd2333d3b
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v12, v24, t2

  li t2, 0x5ec0cb11bd454e56
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v28, v24, t2

  li t2, 0xac4c3d5e10166522
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v20, v12, t2

  li t2, 0xca764c3c8203730b
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v12, v28, t2

  li t2, 0x227c7b0a3fdd7644
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v12, v4, t2

  li t2, 0xe2ffe7b5663f669a
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v8, v20, t2

  li t2, 0x8a0776a01fe9ba91
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v16, v4, t2

  li t2, 0x2bb07d634e47930e
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v8, v4, t2

  li t2, 0x26623eca2f1a8d32
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v8, v28, t2

  li t2, 0xc7881356809968a9
  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v24, v16, 0, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v20, v4, 17, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v12, v16, 20, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v4, v8, 13, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v4, v28, 10, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v28, v24, 3, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v4, v24, 24, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v20, v12, 22, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v24, v28, 16, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v16, v8, 7, v0.t

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v24, v12, 19

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v24, v8, 13

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v16, v8, 30

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v12, v4, 12

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v4, v8, 5

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v24, v20, 28

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v12, v20, 23

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v20, v12, 20

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v8, v16, 24

  vsetvli t1, t0, e16, m4, ta, ma
  vrgather.vi v20, v4, 7

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v24, v16, v8, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v16, v24, v8, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v16, v8, v24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v16, v8, v24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v24, v8, v16, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vv v16, v24, v8

  li t2, 0x79301ac43ed25628
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v24, v16, t2, v0.t

  li t2, 0xf95888383a9a0ad8
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v8, v16, t2, v0.t

  li t2, 0x892224dc64ca9ca8
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v24, v16, t2, v0.t

  li t2, 0xe9d406b351d54eee
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v8, v16, t2, v0.t

  li t2, 0x6b0a43887c6bbbcf
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v24, v8, t2, v0.t

  li t2, 0xb5899be2d449f54a
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v24, v16, t2, v0.t

  li t2, 0x3a56f3bbd9b16f02
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v8, v24, t2, v0.t

  li t2, 0xc0a5ae5a0cbcb1b9
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v8, v24, t2, v0.t

  li t2, 0x4aa1593b7b029cd8
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v8, v16, t2, v0.t

  li t2, 0x6ef2fb58cd263fcf
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v16, v24, t2, v0.t

  li t2, 0x939cd13ed9cb4177
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v24, v16, t2

  li t2, 0x8cb851b971c4758c
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v24, v8, t2

  li t2, 0x0dffdfd894d7c7d9
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v24, v8, t2

  li t2, 0x4dfda18c4bdd8ae9
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v8, v24, t2

  li t2, 0x6120908f7f11de6c
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v24, v8, t2

  li t2, 0x18a294574b96bc9e
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v8, v24, t2

  li t2, 0x5105b0543d89e7c3
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v24, v16, t2

  li t2, 0x072aef327cf014f7
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v16, v24, t2

  li t2, 0xb585285e9c55aa64
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v24, v8, t2

  li t2, 0x5556921fb1fe909f
  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v24, v8, 24, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v16, v24, 26, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v24, v16, 25, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v24, v16, 29, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v8, v16, 9, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v16, v8, 22, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v8, v24, 4, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v16, v24, 18, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v8, v24, 27, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v24, v8, 30, v0.t

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v16, v24, 4

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v24, v16, 10

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v24, v16, 4

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v8, v24, 19

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v8, v16, 26

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v16, v24, 15

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v24, v16, 26

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v16, v8, 8

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v16, v8, 16

  vsetvli t1, t0, e16, m8, ta, ma
  vrgather.vi v8, v24, 21

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v12, v30, v18, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v27, v26, v30, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v3, v15, v1, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v21, v29, v14, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v5, v25, v14, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v12, v25, v2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v27, v29, v12, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v25, v24, v3, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v9, v21, v4, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v8, v9, v27, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v19, v2, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v11, v7, v31

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v19, v13, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v1, v2, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v3, v7, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v9, v17, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v21, v24, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v8, v24, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v19, v5, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vv v29, v23, v31

  li t2, 0x95d394204168173e
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v15, v19, t2, v0.t

  li t2, 0xdcfce41b1c9b93cc
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v5, v1, t2, v0.t

  li t2, 0xcd20ef9acdb0855b
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v18, v30, t2, v0.t

  li t2, 0x3482fd8fb766d178
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v27, v30, t2, v0.t

  li t2, 0x9c5a7814a5e4f3a7
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v11, v9, t2, v0.t

  li t2, 0x1f12e1c6377a2ded
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v6, v2, t2, v0.t

  li t2, 0x07ea5bf591d06f2e
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v5, v22, t2, v0.t

  li t2, 0xf63b9424db646b24
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v19, v9, t2, v0.t

  li t2, 0x3e5e53620c62f9e8
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v8, v11, t2, v0.t

  li t2, 0x2c1df26afdc9230a
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v20, v29, t2, v0.t

  li t2, 0xc92879d34bcb5e56
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v21, v15, t2

  li t2, 0x5a6cf2b0a80ea193
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v25, v21, t2

  li t2, 0x878a4a1b59df7ba8
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v19, v12, t2

  li t2, 0x8a178b329730380f
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v4, v7, t2

  li t2, 0x65a6597535cd7521
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v7, v17, t2

  li t2, 0x65b14bcbf5983c2a
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v1, v17, t2

  li t2, 0xc8189ff304d37f63
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v1, v25, t2

  li t2, 0x857ebce9de80ab3c
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v24, v9, t2

  li t2, 0x6784f8a3a988034c
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v30, v16, t2

  li t2, 0xfcab1d499b532219
  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vx v17, v25, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v17, v22, 13, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v2, v27, 29, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v7, v10, 0, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v22, v5, 5, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v26, v21, 29, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v29, v26, 25, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v4, v26, 18, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v23, v6, 23, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v8, v21, 30, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v25, v29, 14, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v20, v31, 6

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v9, v13, 0

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v6, v13, 30

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v26, v20, 18

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v26, v21, 5

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v2, v4, 1

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v1, v20, 24

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v3, v2, 15

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v1, v24, 28

  vsetvli t1, t0, e32, m1, ta, ma
  vrgather.vi v21, v5, 3

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v14, v26, v28, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v2, v16, v30, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v22, v28, v6, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v26, v4, v6, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v10, v28, v20, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v24, v30, v6, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v30, v20, v2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v16, v10, v6, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v14, v2, v6, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v28, v30, v16, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v26, v4, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v2, v6, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v26, v30, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v30, v24, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v8, v4, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v14, v18, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v20, v24, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v10, v8, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v28, v4, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vv v30, v2, v22

  li t2, 0x45606b3e79ed5cf3
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v18, v8, t2, v0.t

  li t2, 0xf383cc23ae10ea96
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v14, v8, t2, v0.t

  li t2, 0xa3485a7a0fcaf91e
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v22, v12, t2, v0.t

  li t2, 0x1aa0e855ee6b9491
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v24, v18, t2, v0.t

  li t2, 0x534ff4d6d7553155
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v10, v14, t2, v0.t

  li t2, 0xb9a31aeb3c72f750
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v30, v18, t2, v0.t

  li t2, 0xf092c676003e706a
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v6, v18, t2, v0.t

  li t2, 0xb5de375e9b06bc82
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v10, v28, t2, v0.t

  li t2, 0xdf3d2e5ef34c1190
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v12, v28, t2, v0.t

  li t2, 0xf1050e551a7d8939
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v24, v18, t2, v0.t

  li t2, 0x5625c6a5abd42049
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v14, v22, t2

  li t2, 0xc381f06bda378f64
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v26, v14, t2

  li t2, 0x122b85c0882cb92e
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v28, v2, t2

  li t2, 0x9f763c6a4ba07605
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v12, v4, t2

  li t2, 0xebfe0195a92177ae
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v12, v4, t2

  li t2, 0xab824b8901a0b427
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v4, v10, t2

  li t2, 0x14e07b2e5ad7e34b
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v20, v18, t2

  li t2, 0x9bba10ca670169ca
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v30, v12, t2

  li t2, 0x984ab8a027428f7f
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v10, v30, t2

  li t2, 0xef6c963c1d779b05
  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vx v16, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v2, v6, 16, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v16, v30, 6, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v22, v24, 6, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v4, v16, 16, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v8, v30, 17, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v22, v26, 13, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v14, v30, 3, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v4, v8, 6, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v4, v30, 17, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v20, v26, 8, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v28, v24, 14

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v24, v14, 8

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v14, v28, 1

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v18, v10, 3

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v2, v18, 25

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v26, v2, 6

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v12, v22, 27

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v12, v10, 22

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v12, v30, 10

  vsetvli t1, t0, e32, m2, ta, ma
  vrgather.vi v14, v28, 26

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v12, v8, v20, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v8, v28, v12, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v24, v20, v16, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v16, v12, v8, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v24, v28, v8, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v16, v12, v4, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v12, v20, v8, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v12, v16, v28, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v4, v8, v16, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v16, v4, v12, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v20, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v12, v16, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v12, v28, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v20, v4, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v24, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v4, v16, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v20, v8, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v12, v28, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vv v28, v24, v4

  li t2, 0x766790ef87dedf1e
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v8, v4, t2, v0.t

  li t2, 0xfed0ef7df58fec42
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v20, v12, t2, v0.t

  li t2, 0x1ccc2e4c82dd439a
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v4, v12, t2, v0.t

  li t2, 0x507ccdabffda7613
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v20, v24, t2, v0.t

  li t2, 0x310333eddaaa2a3a
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v16, v20, t2, v0.t

  li t2, 0x852be164522b82ac
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v20, v8, t2, v0.t

  li t2, 0xbd3c13d836029724
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v20, v4, t2, v0.t

  li t2, 0x0ead40032f8ad0ab
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v4, v8, t2, v0.t

  li t2, 0x58ef47379abcb8e6
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v12, v4, t2, v0.t

  li t2, 0xa861bee336d07d77
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v24, v16, t2, v0.t

  li t2, 0x827dfd6b60914c53
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v12, v28, t2

  li t2, 0x221d705150f95cb5
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v16, v28, t2

  li t2, 0x3e8f41c13bd0602f
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v4, v20, t2

  li t2, 0xf185b793522469a3
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v28, v8, t2

  li t2, 0x5e39a5fb61fb0649
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v24, v28, t2

  li t2, 0x848f576d3f24a9d2
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v4, v20, t2

  li t2, 0xf4ccb13062fadccd
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v28, v24, t2

  li t2, 0x983adbd33cab4418
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v16, v12, t2

  li t2, 0x18197dc319f1bc01
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v12, v16, t2

  li t2, 0x9c335a13a0404bc2
  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v28, v4, 31, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v16, v4, 18, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v24, v8, 6, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v16, v8, 24, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v12, v24, 25, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v16, v12, 6, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v12, v4, 23, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v12, v4, 24, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v4, v8, 5, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v8, v28, 7, v0.t

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v16, v8, 13

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v28, v16, 5

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v28, v4, 10

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v12, v16, 27

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v24, v8, 25

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v24, v20, 6

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v24, v4, 18

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v4, v8, 17

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v24, v4, 24

  vsetvli t1, t0, e32, m4, ta, ma
  vrgather.vi v24, v12, 12

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v8, v24, v16, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v8, v24, v16, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v24, v16, v8, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v16, v8, v24, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v16, v8, v24, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v8, v24, v16, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v8, v24, v16, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v24, v16, v8, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vv v16, v24, v8

  li t2, 0x8076a9533e84c6fd
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v16, v24, t2, v0.t

  li t2, 0xf270627a53574ce9
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v24, v8, t2, v0.t

  li t2, 0xe9ca9f4f7787b13b
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v8, v24, t2, v0.t

  li t2, 0x438d38b3c1045ca4
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v24, v16, t2, v0.t

  li t2, 0xec01c7d22cfbef50
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v16, v24, t2, v0.t

  li t2, 0xcdbbc80d6d4e44b5
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v16, v24, t2, v0.t

  li t2, 0x3e03a9ebb8d0ca50
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v8, v24, t2, v0.t

  li t2, 0x8407a4030241fb45
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v24, v8, t2, v0.t

  li t2, 0x2ce1b38d883f2009
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v16, v24, t2, v0.t

  li t2, 0x54ee7bda8ceb34f0
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v24, v16, t2, v0.t

  li t2, 0xb8b2a4e0c8e3e421
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v8, v16, t2

  li t2, 0xe5fcede08995f138
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v24, v16, t2

  li t2, 0x68d0647c92c68b1f
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v16, v24, t2

  li t2, 0xf197a4f5f7189d0b
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v24, v16, t2

  li t2, 0xaf2dbc785bc9f448
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v16, v24, t2

  li t2, 0x4a50be60a89af5ae
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v16, v8, t2

  li t2, 0xfb165358c73adb10
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v16, v24, t2

  li t2, 0x3b3e34ce6f1e0cef
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v16, v24, t2

  li t2, 0x8e4a6c54310e2f6b
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v24, v16, t2

  li t2, 0x60228a7ccb869bc2
  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v24, v16, 7, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v16, v8, 29, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v8, v24, 27, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v8, v16, 13, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v8, v24, 29, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v24, v16, 13, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v8, v16, 0, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v24, v8, 30, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v24, v16, 5, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v24, v8, 11, v0.t

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v24, v16, 26

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v8, v16, 5

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v16, v8, 27

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v24, v8, 31

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v24, v16, 31

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v8, v24, 29

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v8, v16, 8

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v16, v24, 1

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v24, v16, 27

  vsetvli t1, t0, e32, m8, ta, ma
  vrgather.vi v24, v16, 8

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v4, v30, v8, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v13, v31, v17, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v27, v17, v26, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v15, v30, v20, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v21, v22, v29, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v3, v28, v30, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v9, v15, v20, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v26, v5, v13, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v20, v3, v21, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v5, v2, v4, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v4, v3, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v28, v7, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v14, v12, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v20, v12, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v1, v13, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v25, v2, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v12, v19, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v25, v7, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v19, v22, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vv v15, v25, v22

  li t2, 0x1fa1f20dd0ff7c20
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v17, v25, t2, v0.t

  li t2, 0xa371a5329146259e
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v14, v5, t2, v0.t

  li t2, 0xfc2ce13ccf53e202
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v9, v10, t2, v0.t

  li t2, 0x17736790709471ac
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v1, v10, t2, v0.t

  li t2, 0xaaf78caa0eff129e
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v30, v9, t2, v0.t

  li t2, 0x977157121c4e9ec6
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v20, v4, t2, v0.t

  li t2, 0x5500523298c48aaa
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v11, v13, t2, v0.t

  li t2, 0x89bc5a08125b5b45
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v27, v26, t2, v0.t

  li t2, 0x3bef07be78c31881
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v8, v23, t2, v0.t

  li t2, 0x64aa433fe53346a3
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v29, v2, t2, v0.t

  li t2, 0xc56a492a158c69fa
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v1, v24, t2

  li t2, 0xed8ac8624f33ab7a
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v5, v2, t2

  li t2, 0xf6fae849e7731249
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v23, v21, t2

  li t2, 0x9a70623d665c26b0
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v30, v3, t2

  li t2, 0x58bb08bd56792094
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v1, v20, t2

  li t2, 0xadeb798f44359801
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v28, v2, t2

  li t2, 0x7d4fb6effca1688c
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v29, v1, t2

  li t2, 0x69db36a558855b48
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v8, v25, t2

  li t2, 0x42757e7bdf59b185
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v31, v17, t2

  li t2, 0x44695a0cacd08a27
  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vx v3, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v27, v25, 12, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v22, v3, 3, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v18, v31, 16, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v30, v13, 2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v9, v30, 9, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v30, v13, 16, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v19, v4, 5, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v19, v23, 22, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v30, v16, 29, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v31, v12, 2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v1, v30, 27

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v29, v8, 26

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v1, v26, 20

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v29, v19, 4

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v24, v2, 13

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v5, v26, 10

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v23, v27, 22

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v1, v19, 29

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v12, v23, 28

  vsetvli t1, t0, e64, m1, ta, ma
  vrgather.vi v29, v9, 15

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v26, v12, v18, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v22, v24, v20, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v18, v28, v20, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v2, v24, v6, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v2, v6, v10, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v30, v12, v20, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v12, v28, v26, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v14, v24, v30, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v4, v16, v12, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v6, v24, v28, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v4, v30, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v24, v30, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v10, v2, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v10, v16, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v10, v22, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v14, v4, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v12, v28, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v2, v24, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v28, v12, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vv v18, v14, v2

  li t2, 0x711eb5d0be9ae7b4
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v24, v14, t2, v0.t

  li t2, 0xecdc2c0751ca85fc
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v28, v22, t2, v0.t

  li t2, 0x9eddb34568817593
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v26, v14, t2, v0.t

  li t2, 0xa261c3a971cdab5e
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v18, v12, t2, v0.t

  li t2, 0xaa70adeb122545e5
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v30, v26, t2, v0.t

  li t2, 0xb208cc016e6ee986
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v28, v26, t2, v0.t

  li t2, 0x7f39112f6a3c23c7
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v24, v26, t2, v0.t

  li t2, 0x4d336867a6f16971
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v24, v26, t2, v0.t

  li t2, 0x0eafda8de32e5fe5
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v14, v24, t2, v0.t

  li t2, 0x3d8199330c32296e
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v6, v26, t2, v0.t

  li t2, 0x36751d66099d4cee
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v16, v6, t2

  li t2, 0xdeea40d06de43400
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v20, v18, t2

  li t2, 0x6c53a51da3c3e960
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v30, v26, t2

  li t2, 0x823823bdd1e66c60
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v4, v14, t2

  li t2, 0x4cd7d7a11470eb37
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v4, v18, t2

  li t2, 0xf6728fd95f57b741
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v22, v26, t2

  li t2, 0xa4836a9040cb0f7c
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v16, v20, t2

  li t2, 0x80f8e5a8f9036baf
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v2, v16, t2

  li t2, 0x1d8d7ea88ce3eab0
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v30, v16, t2

  li t2, 0xc61727919eb86203
  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vx v10, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v28, v20, 31, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v20, v8, 14, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v18, v2, 3, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v26, v2, 22, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v8, v2, 27, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v24, v8, 16, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v6, v2, 5, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v6, v28, 1, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v2, v22, 15, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v10, v24, 1, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v12, v26, 14

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v10, v4, 8

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v8, v24, 4

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v20, v18, 14

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v8, v12, 3

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v14, v24, 29

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v26, v22, 4

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v26, v28, 22

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v14, v8, 25

  vsetvli t1, t0, e64, m2, ta, ma
  vrgather.vi v24, v18, 29

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v20, v24, v4, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v24, v16, v12, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v12, v24, v16, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v28, v16, v8, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v28, v12, v4, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v28, v8, v4, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v24, v28, v12, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v4, v12, v8, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v20, v8, v4, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v16, v8, v24, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v8, v28, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v8, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v8, v4, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v12, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v4, v28, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v20, v4, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v20, v24, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v4, v28, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v28, v20, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vv v24, v8, v20

  li t2, 0x1796ff1511198438
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v12, v8, t2, v0.t

  li t2, 0xb8fb26fd98d00510
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v16, v20, t2, v0.t

  li t2, 0x98df547f2186ff7b
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v4, v12, t2, v0.t

  li t2, 0xf4868ec3b0845c9f
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v8, v28, t2, v0.t

  li t2, 0x1f44005574004862
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v8, v12, t2, v0.t

  li t2, 0x641ed25b9876f8df
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v28, v24, t2, v0.t

  li t2, 0xdb93991ca8b62bc0
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v20, v12, t2, v0.t

  li t2, 0x9f4e421c9eb0853d
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v4, v12, t2, v0.t

  li t2, 0x47ccee25f757a5d9
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v24, v28, t2, v0.t

  li t2, 0x971757c36cc08404
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v24, v16, t2, v0.t

  li t2, 0xa04b522a002d41e4
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v28, v20, t2

  li t2, 0xd7d432a434a92a9e
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v24, v4, t2

  li t2, 0x44c0119c36f44a2b
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v24, v4, t2

  li t2, 0x80e7087d88c341d1
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v20, v12, t2

  li t2, 0x8869659a2124f9f4
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v20, v28, t2

  li t2, 0x9ae8f6e2a499b178
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v12, v28, t2

  li t2, 0x95c549f72932fa0d
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v4, v28, t2

  li t2, 0xf212be505d9c7363
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v4, v20, t2

  li t2, 0xd44f36a4ed8775a6
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v28, v4, t2

  li t2, 0x30a35375def0ee3a
  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vx v8, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v28, v24, 19, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v16, v20, 2, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v12, v24, 22, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v16, v28, 30, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v8, v20, 4, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v16, v28, 29, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v16, v8, 11, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v28, v20, 4, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v16, v24, 26, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v12, v16, 30, v0.t

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v8, v20, 28

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v24, v12, 14

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v24, v4, 22

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v12, v4, 20

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v20, v28, 11

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v20, v12, 15

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v20, v4, 26

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v24, v28, 24

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v16, v24, 9

  vsetvli t1, t0, e64, m4, ta, ma
  vrgather.vi v28, v8, 6

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v16, v24, v8, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v16, v24, v8, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v8, v16, v24, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v24, v8, v16, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v8, v24, v16, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v8, v24, v16, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v16, v24, v8, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v24, v16, v8, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v16, v24, v8, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v24, v16, v8, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vv v16, v8, v24

  li t2, 0xd90473f60f5964ac
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v8, v16, t2, v0.t

  li t2, 0x35bb2e644a5d10a9
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v16, v24, t2, v0.t

  li t2, 0x7fe5dcccab9f709c
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v24, v16, t2, v0.t

  li t2, 0xe352df073fb29b4e
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v24, v8, t2, v0.t

  li t2, 0x0c9807f8c1415fec
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v8, v24, t2, v0.t

  li t2, 0xa1c9ce6e79f1671a
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v16, v8, t2, v0.t

  li t2, 0x049d2b9145b9e158
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v24, v16, t2, v0.t

  li t2, 0xc129820b1c452c1d
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v16, v24, t2, v0.t

  li t2, 0x25b0d09e2bc8be0d
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v24, v8, t2, v0.t

  li t2, 0xa719ee1b7d1898e0
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v16, v8, t2, v0.t

  li t2, 0x9c7e7c01df4fa43e
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v8, v16, t2

  li t2, 0x18ba2db83cd2434b
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v24, v16, t2

  li t2, 0x825f72467b520b60
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v8, v16, t2

  li t2, 0x958fac7f111d6536
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v24, v8, t2

  li t2, 0x355c5e979cb7a1a3
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v8, v16, t2

  li t2, 0xcc8a4aff42b29a72
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v16, v8, t2

  li t2, 0xddeb8e6abef10d80
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v16, v8, t2

  li t2, 0x6983fed71bc39ab7
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v8, v24, t2

  li t2, 0x44864d127db150fa
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v16, v24, t2

  li t2, 0xfc3e9467ea0229e3
  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v8, v24, 28, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v24, v8, 5, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v24, v8, 28, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v24, v16, 31, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v8, v24, 11, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v16, v8, 13, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v24, v8, 5, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v24, v8, 17, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v16, v24, 14, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v24, v16, 13, v0.t

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v16, v8, 13

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v16, v8, 8

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v24, v16, 11

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v24, v8, 13

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v24, v8, 27

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v24, v8, 16

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v8, v24, 4

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v8, v24, 16

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v16, v8, 12

  vsetvli t1, t0, e64, m8, ta, ma
  vrgather.vi v8, v16, 13

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
