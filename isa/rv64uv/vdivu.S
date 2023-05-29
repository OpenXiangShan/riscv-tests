#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v21, v7, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v17, v27, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v8, v2, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v29, v11, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v2, v16, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v26, v22, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v20, v1, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v25, v13, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v17, v12, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vv v14, v10, v21

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v4, v26, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v8, v2, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v26, v4, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v20, v22, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v16, v12, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v22, v4, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v22, v24, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v2, v16, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v10, v26, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vv v26, v12, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v20, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v12, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v20, v8, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v28, v4, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v20, v12, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v16, v12, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v24, v20, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v12, v20, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v4, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vv v4, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v30, v7, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v16, v17, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v28, v11, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v22, v10, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v28, v3, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v27, v13, v9

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v8, v10, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v26, v7, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v17, v19, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vv v6, v8, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v30, v24, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v8, v2, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v24, v8, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v18, v24, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v14, v26, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v10, v2, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v16, v26, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v28, v4, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v22, v26, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vv v14, v4, v10

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v8, v16, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v8, v4, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v12, v28, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v20, v16, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v4, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v4, v16, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v12, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v24, v20, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v8, v28, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vv v28, v16, v4

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vv v8, v24, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v5, v15, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v23, v19, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v22, v11, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v25, v26, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v24, v17, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v16, v26, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v23, v11, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v23, v29, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v1, v2, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vv v23, v3, v9

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v8, v24, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v10, v30, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v8, v14, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v6, v16, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v30, v16, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v12, v26, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v12, v8, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v24, v4, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v30, v12, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vv v12, v6, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v20, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v20, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v24, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v8, v28, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v4, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v16, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v8, v12, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v4, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vv v12, v24, v4

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vv v16, v8, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v1, v27, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v12, v4, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v22, v18, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v2, v29, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v18, v1, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v28, v13, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v3, v4, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v13, v2, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v6, v31, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vv v8, v19, v21

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v18, v30, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v4, v30, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v24, v2, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v14, v10, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v4, v10, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v30, v20, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v16, v26, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v22, v14, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v6, v8, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vv v30, v8, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v28, v4, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v24, v20, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v24, v8, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v16, v24, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v12, v8, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v4, v16, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v4, v8, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v16, v28, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v16, v28, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vv v20, v24, v4

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vv v16, v8, v24

  li t2, 0x6165314093552502
  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v13, v22, t2

  li t2, 0x5dda3dc98518c788
  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v25, v30, t2

  li t2, 0x76d758f1bf9168b1
  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v11, v19, t2

  li t2, 0x7e1e468c5fb423ad
  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v23, v4, t2

  li t2, 0x9f765440c13093ba
  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v18, v17, t2

  li t2, 0x8997e6c866520df7
  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v16, v4, t2

  li t2, 0x05b26d3d4c1a2f54
  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v23, v10, t2

  li t2, 0x59544c0d3a1db820
  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v25, v30, t2

  li t2, 0x9908f05fea373e95
  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v30, v10, t2

  li t2, 0xd7c94fed91115792
  vsetvli t1, t0, e8, m1, ta, ma
  vdivu.vx v21, v30, t2

  li t2, 0xab55652be27d18d3
  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v8, v12, t2

  li t2, 0xf98d3084580c1610
  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v24, v22, t2

  li t2, 0x6e8ed20f07a60e45
  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v24, v10, t2

  li t2, 0x12d7cd23e0ec93e7
  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v22, v14, t2

  li t2, 0x958678e0705e5b54
  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v16, v10, t2

  li t2, 0xf03edf4373aa4ade
  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v26, v22, t2

  li t2, 0xbe05ebd7f9ce172f
  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v18, v28, t2

  li t2, 0x6dc619a64df4cd21
  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v16, v14, t2

  li t2, 0x265780d8c341e4d0
  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v30, v20, t2

  li t2, 0x7faeca92dc737a5b
  vsetvli t1, t0, e8, m2, ta, ma
  vdivu.vx v20, v28, t2

  li t2, 0x2b0d5aa429147f84
  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v16, v28, t2

  li t2, 0x14a43a69bddb54cd
  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v12, v24, t2

  li t2, 0xe1cf6256362bc47d
  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v8, v16, t2

  li t2, 0xa05d075cb4fc9200
  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v16, v12, t2

  li t2, 0x06c60f593900c764
  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v20, v8, t2

  li t2, 0xc95eb561daf97cd4
  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v20, v16, t2

  li t2, 0x34f86b743a48082a
  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v16, v12, t2

  li t2, 0x8715633177283334
  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v12, v24, t2

  li t2, 0x544824cd9976e138
  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v8, v4, t2

  li t2, 0x1b255dd120a48096
  vsetvli t1, t0, e8, m4, ta, ma
  vdivu.vx v4, v12, t2

  li t2, 0x6a02338ae7e96f0a
  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v24, v8, t2

  li t2, 0xc26a9f48ac65a522
  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v24, v16, t2

  li t2, 0xdc64794ae54ba965
  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v16, v8, t2

  li t2, 0xd4b867302c42a0a4
  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v8, v16, t2

  li t2, 0xd0c6d67119df0ff3
  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v8, v16, t2

  li t2, 0x6bf28932221dc89d
  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v24, v16, t2

  li t2, 0x42233a5f8d470bdb
  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v24, v16, t2

  li t2, 0xfb81a041681c38b1
  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v24, v16, t2

  li t2, 0x84e532b0ca6abed4
  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v24, v8, t2

  li t2, 0xf501d67bdc0d59a9
  vsetvli t1, t0, e8, m8, ta, ma
  vdivu.vx v8, v16, t2

  li t2, 0x11a7d10024963dc4
  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v24, v25, t2

  li t2, 0xeff15ac3ffcb501d
  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v13, v27, t2

  li t2, 0xa8d60a6144a87fba
  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v6, v31, t2

  li t2, 0x420c63d015fe68e3
  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v14, v8, t2

  li t2, 0xd54ae7b49fd66e03
  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v15, v18, t2

  li t2, 0xf14058ab0c1aac55
  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v12, v8, t2

  li t2, 0x221afff39e163653
  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v1, v8, t2

  li t2, 0xd405efd27e361fb8
  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v2, v27, t2

  li t2, 0x892bf56db50a9fd5
  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v19, v26, t2

  li t2, 0xa42e2395c0ee2283
  vsetvli t1, t0, e16, m1, ta, ma
  vdivu.vx v12, v1, t2

  li t2, 0x0d2cd0b032b0de8f
  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v30, v2, t2

  li t2, 0xc8f88a1fc67ba2c1
  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v18, v2, t2

  li t2, 0x83086225ef626129
  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v6, v10, t2

  li t2, 0x1bb1eb96a9ddc7e2
  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v16, v6, t2

  li t2, 0x26eab9a6cd47ebfd
  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v2, v8, t2

  li t2, 0xd7c4b41097d2619f
  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v8, v18, t2

  li t2, 0xc3efcdf1d2f90a0e
  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v10, v14, t2

  li t2, 0x0bd057cdc44a1d9d
  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v28, v20, t2

  li t2, 0x43f5335d908b0c39
  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v26, v16, t2

  li t2, 0x0edbe438b3ceb6a6
  vsetvli t1, t0, e16, m2, ta, ma
  vdivu.vx v24, v20, t2

  li t2, 0xa2b0053f19fa667f
  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v16, v20, t2

  li t2, 0x7287f36f05e7452b
  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v20, v8, t2

  li t2, 0xb980668b51897435
  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v24, v20, t2

  li t2, 0xe321880a8683b6ba
  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v20, v4, t2

  li t2, 0x8632f4e944d8a3c4
  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v4, v12, t2

  li t2, 0x515fa9e19403b422
  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v24, v16, t2

  li t2, 0xffe89f533eb93620
  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v20, v16, t2

  li t2, 0xa00a342ccf799e6f
  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v20, v12, t2

  li t2, 0x953118743e8493fd
  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v24, v16, t2

  li t2, 0xada64b9e447e2edd
  vsetvli t1, t0, e16, m4, ta, ma
  vdivu.vx v20, v28, t2

  li t2, 0x226a1e3a9da1efa0
  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v16, v24, t2

  li t2, 0xd9cc7ee11032d931
  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v16, t2

  li t2, 0x2a77a97781d8f0c6
  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v16, v8, t2

  li t2, 0x6a40bd9bb6d1e3bf
  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v16, v8, t2

  li t2, 0x75848d059e6968d5
  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v24, t2

  li t2, 0xbea2a3516eecefb1
  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v16, v8, t2

  li t2, 0x59899a6f4e7ff4de
  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v24, t2

  li t2, 0x876d2b1f964e9402
  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v16, v24, t2

  li t2, 0x83d636e9158fc248
  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v16, t2

  li t2, 0x52e2884558e9bfd5
  vsetvli t1, t0, e16, m8, ta, ma
  vdivu.vx v8, v16, t2

  li t2, 0xce648e1b1f21d518
  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v26, v1, t2

  li t2, 0x12ca5c2acaf2a886
  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v4, v22, t2

  li t2, 0xa4cb4b2b8fd9d8a3
  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v22, v1, t2

  li t2, 0x5eaa740179cfd09c
  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v18, v30, t2

  li t2, 0x2c9706c8ddb2c835
  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v20, v27, t2

  li t2, 0x48c5a1758e96fc6c
  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v11, v10, t2

  li t2, 0xfcf7ce68996d60d2
  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v30, v2, t2

  li t2, 0x44b8d6164fab4a76
  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v12, v20, t2

  li t2, 0xc622780bb31bd702
  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v7, v23, t2

  li t2, 0xe18fb4e4542e74dc
  vsetvli t1, t0, e32, m1, ta, ma
  vdivu.vx v12, v15, t2

  li t2, 0xeb1fc6ac31fe2abb
  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v30, v4, t2

  li t2, 0x4a0c734cdecbd0f6
  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v26, v20, t2

  li t2, 0x92d05b96f3e70685
  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v8, v2, t2

  li t2, 0x55317021997b6e58
  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v26, v14, t2

  li t2, 0xd425db3f8b5e4885
  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v12, v14, t2

  li t2, 0x2b349eeb1127c83b
  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v26, v20, t2

  li t2, 0x0f90bbd38ee428aa
  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v6, v8, t2

  li t2, 0x3702fdcd8a8ff085
  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v12, v22, t2

  li t2, 0x4faa3a5fafa038ea
  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v20, v28, t2

  li t2, 0x794b96a2813b1ce6
  vsetvli t1, t0, e32, m2, ta, ma
  vdivu.vx v16, v18, t2

  li t2, 0x5afa8043e618aca4
  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v4, v12, t2

  li t2, 0x16b1ecb116a298d5
  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v12, v4, t2

  li t2, 0x75f0fa4620062a17
  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v28, v24, t2

  li t2, 0x2ef1d4e9bfc829f3
  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v20, v8, t2

  li t2, 0x5152ab10dd61b7e9
  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v28, v20, t2

  li t2, 0x68eec3afb99a3eaa
  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v20, v24, t2

  li t2, 0x74514c305f26e6aa
  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v24, v20, t2

  li t2, 0xf0e7c39084b48c1a
  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v28, v24, t2

  li t2, 0x306b656e973355dc
  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v16, v28, t2

  li t2, 0xb99beeeb5172f025
  vsetvli t1, t0, e32, m4, ta, ma
  vdivu.vx v12, v8, t2

  li t2, 0x7f5b3a09906b2266
  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v16, v8, t2

  li t2, 0x0285a301cf58601f
  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v16, v8, t2

  li t2, 0x27cef99a211abdce
  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v16, v24, t2

  li t2, 0x53dd72f6634cf5bd
  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v24, v8, t2

  li t2, 0x04359e802188d30c
  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v8, v16, t2

  li t2, 0x71046a08df0520e3
  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v16, v24, t2

  li t2, 0xa98af4203ad47aac
  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v16, v8, t2

  li t2, 0xfa59a590b63c5ade
  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v8, v24, t2

  li t2, 0xa127b75fc628a8fd
  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v8, v24, t2

  li t2, 0xc4466d28565c2fd7
  vsetvli t1, t0, e32, m8, ta, ma
  vdivu.vx v16, v24, t2

  li t2, 0xd7a081ce32d17682
  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v10, v12, t2

  li t2, 0xfa3f3a5316dbd5e5
  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v21, v2, t2

  li t2, 0x3207d93901187355
  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v28, v10, t2

  li t2, 0x36981969a0f2a2a2
  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v28, v24, t2

  li t2, 0x44348adc4df37c40
  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v6, v15, t2

  li t2, 0x81df10d523445f00
  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v3, v26, t2

  li t2, 0x92f26e5f734d6f48
  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v19, v1, t2

  li t2, 0x759456522748c186
  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v6, v14, t2

  li t2, 0xd07bcf0ff0636543
  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v14, v3, t2

  li t2, 0x6577099747846656
  vsetvli t1, t0, e64, m1, ta, ma
  vdivu.vx v23, v26, t2

  li t2, 0x0255cd682a9dd56e
  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v24, v10, t2

  li t2, 0x5b8d9e7709ede76c
  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v6, v22, t2

  li t2, 0x14873c8510840f11
  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v2, v10, t2

  li t2, 0xbf8aa8b4531491b5
  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v20, v4, t2

  li t2, 0x9b544048a80524e7
  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v12, v18, t2

  li t2, 0x69c5d40b80eb0813
  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v10, v26, t2

  li t2, 0xf68f300674c956fd
  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v14, v10, t2

  li t2, 0x847bdf1ab804ff1d
  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v10, v6, t2

  li t2, 0x12807d09c3fb4b50
  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v14, v26, t2

  li t2, 0x7442b00247b63427
  vsetvli t1, t0, e64, m2, ta, ma
  vdivu.vx v10, v14, t2

  li t2, 0x69040746ac17f6e5
  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v8, v20, t2

  li t2, 0xd0d072ff9e05f431
  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v12, v4, t2

  li t2, 0x91c79858db532862
  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v20, v24, t2

  li t2, 0xcb70aff783f6eb41
  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v24, v4, t2

  li t2, 0x8a54c8065ea29943
  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v28, v4, t2

  li t2, 0xb436227fd30ea9d9
  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v24, v16, t2

  li t2, 0x26574abb39a6328c
  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v12, v24, t2

  li t2, 0x3d4f30b853aae180
  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v28, v20, t2

  li t2, 0x55d3a23692aac81d
  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v8, v28, t2

  li t2, 0x11e462d2c415464c
  vsetvli t1, t0, e64, m4, ta, ma
  vdivu.vx v16, v24, t2

  li t2, 0xd42672b99308200c
  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v24, v8, t2

  li t2, 0xfb5be5f280b0a2ba
  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v8, v16, t2

  li t2, 0x5e157d2be8306440
  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v24, t2

  li t2, 0x219a00d3c61217dd
  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v24, t2

  li t2, 0x593fdb5625f789b9
  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v8, t2

  li t2, 0x7d6483d770b65b82
  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v8, t2

  li t2, 0x3d9c6893ec87e600
  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v24, v16, t2

  li t2, 0x04306e6bfec7ec42
  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v24, v16, t2

  li t2, 0xac7d121a8ef523f1
  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v16, v8, t2

  li t2, 0x3f8c089fe7230e17
  vsetvli t1, t0, e64, m8, ta, ma
  vdivu.vx v8, v24, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
