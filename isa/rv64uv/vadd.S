#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v17, v7, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v27, v18, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v22, v20, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v29, v3, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v14, v9, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v7, v24, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v27, v3, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v11, v27, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v26, v16, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vv v12, v7, v11

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vv v2, v22, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vv v8, v18, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vv v30, v18, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vv v18, v24, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vv v16, v22, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vv v2, v30, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vv v24, v18, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vv v24, v12, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vv v12, v26, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vv v24, v20, v22

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vv v24, v8, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vv v8, v20, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vv v12, v8, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vv v28, v20, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vv v12, v20, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vv v4, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vv v24, v4, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vv v8, v28, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vv v8, v20, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vv v12, v8, v4

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vv v24, v16, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v30, v14, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v28, v22, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v19, v26, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v27, v12, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v1, v2, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v23, v15, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v17, v11, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v9, v5, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v26, v15, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vv v2, v21, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vv v30, v28, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vv v26, v4, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vv v22, v10, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vv v24, v18, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vv v30, v28, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vv v24, v14, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vv v24, v26, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vv v2, v8, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vv v8, v24, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vv v22, v14, v10

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vv v4, v8, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vv v12, v28, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vv v4, v24, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vv v28, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vv v28, v20, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vv v28, v4, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vv v20, v28, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vv v12, v4, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vv v24, v4, v12

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vv v8, v16, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v11, v8, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v14, v28, v25

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v26, v12, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v13, v9, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v24, v16, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v24, v22, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v22, v21, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v31, v26, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v9, v15, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vv v25, v14, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vv v24, v28, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vv v26, v2, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vv v20, v30, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vv v4, v16, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vv v16, v30, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vv v6, v16, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vv v26, v14, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vv v2, v18, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vv v2, v24, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vv v10, v14, v2

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vv v24, v4, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vv v12, v20, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vv v8, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vv v4, v12, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vv v4, v20, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vv v16, v28, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vv v4, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vv v16, v20, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vv v28, v24, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vv v16, v24, v28

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vv v8, v16, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v25, v28, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v18, v21, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v5, v1, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v1, v10, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v7, v3, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v4, v19, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v18, v10, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v3, v18, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v10, v21, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vv v11, v2, v15

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v24, v18, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v14, v16, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v16, v24, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v12, v30, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v2, v12, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v22, v16, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v10, v4, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v24, v6, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v2, v28, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vv v14, v26, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v20, v24, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v4, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v20, v16, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v4, v16, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v28, v20, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v8, v24, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v20, v8, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v28, v4, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v16, v20, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vv v12, v28, v20

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vv v16, v8, v24

  li t2, 0x14308300f61eb6d1
  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vx v31, v4, t2

  li t2, 0xc4d21f1105704847
  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vx v24, v10, t2

  li t2, 0x3a200d347673610e
  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vx v11, v9, t2

  li t2, 0xf8775a0f6f07bb15
  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vx v5, v19, t2

  li t2, 0x3723c782fb7619b4
  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vx v5, v1, t2

  li t2, 0xd025c63ea85cd37c
  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vx v27, v23, t2

  li t2, 0x14bb6c1bf6c47659
  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vx v11, v3, t2

  li t2, 0xdfe967a271b78e8a
  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vx v24, v26, t2

  li t2, 0x4f8fb68233e3181f
  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vx v6, v22, t2

  li t2, 0x0d991ae292ed381a
  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vx v26, v6, t2

  li t2, 0xca4df2623a82ddba
  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vx v22, v18, t2

  li t2, 0xc0d103001637a295
  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vx v2, v18, t2

  li t2, 0x9b7beb858c8e6fb3
  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vx v24, v22, t2

  li t2, 0x44cc36d48687e8cb
  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vx v28, v14, t2

  li t2, 0x8e16313b775cb40f
  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vx v22, v10, t2

  li t2, 0x33e4bb3bc0527e14
  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vx v12, v26, t2

  li t2, 0x860bb90a7e8dcab2
  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0x2e965c9519b2b4a6
  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vx v2, v20, t2

  li t2, 0xbc24650a8997ed08
  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vx v28, v10, t2

  li t2, 0x21619d841ecdf064
  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vx v2, v16, t2

  li t2, 0x6b9197410b358af6
  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vx v16, v8, t2

  li t2, 0xde15c207c3dc7325
  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0x2f25c88f88992b90
  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vx v16, v4, t2

  li t2, 0xc665c6433f714a0b
  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vx v24, v4, t2

  li t2, 0x2fba72857c1d1bd5
  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vx v28, v4, t2

  li t2, 0xf5acaae7b2dcef6e
  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vx v16, v12, t2

  li t2, 0x97328a24818e0ad9
  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vx v20, v4, t2

  li t2, 0xb45a1f3438066fe8
  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vx v12, v20, t2

  li t2, 0x216e8476281ccca4
  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vx v16, v4, t2

  li t2, 0x9e9727491280c341
  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vx v20, v8, t2

  li t2, 0x34a912a28cdef632
  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0x99e5f40d5671de56
  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vx v8, v24, t2

  li t2, 0x3f598657a10cd61d
  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vx v24, v16, t2

  li t2, 0xec483be51b9c98be
  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vx v24, v16, t2

  li t2, 0xef901ef0c0f54c9d
  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vx v16, v8, t2

  li t2, 0x9e83fed20fddd874
  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0xb98c7dc2260ff1d4
  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vx v8, v16, t2

  li t2, 0x41160d9106c0435e
  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vx v24, v16, t2

  li t2, 0x36cd31bba29d318e
  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vx v16, v8, t2

  li t2, 0xf3d3092600950a95
  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vx v24, v16, t2

  li t2, 0xb555f97fbd7b76dc
  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vx v1, v20, t2

  li t2, 0x2f5108eca8566603
  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vx v1, v17, t2

  li t2, 0xeff03425eaf537fd
  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vx v13, v12, t2

  li t2, 0xfae403f13a41fafc
  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vx v30, v3, t2

  li t2, 0xb9a6ac7ed180c4ae
  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vx v31, v3, t2

  li t2, 0x979f9a98f1393b68
  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vx v1, v12, t2

  li t2, 0x09f50fa8d8a6b7a1
  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vx v21, v11, t2

  li t2, 0x9f070de99b1099e4
  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vx v5, v31, t2

  li t2, 0x6f3b0dc8f1826bea
  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vx v21, v14, t2

  li t2, 0x15162c8dd621aee2
  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vx v25, v18, t2

  li t2, 0x08bf055edfd141d4
  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vx v10, v12, t2

  li t2, 0x8b9c61f54f99bde1
  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vx v28, v16, t2

  li t2, 0xdfd2377a8ef80b9a
  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vx v16, v2, t2

  li t2, 0x52f78a38203455c3
  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vx v4, v28, t2

  li t2, 0xd82ba5bea3d3dc3b
  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vx v22, v8, t2

  li t2, 0x6a8f37a4a2618274
  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vx v18, v8, t2

  li t2, 0x7a0f2bc188dfaba4
  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vx v30, v10, t2

  li t2, 0x913e40790c112263
  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vx v22, v30, t2

  li t2, 0x5abdff0dcf9939ed
  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vx v12, v18, t2

  li t2, 0x3a0e8bb474513caa
  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vx v8, v20, t2

  li t2, 0x6f06ee8844b4a30c
  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vx v28, v24, t2

  li t2, 0xc939a1512619c38f
  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vx v12, v28, t2

  li t2, 0x79874699e3d30e56
  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vx v8, v20, t2

  li t2, 0x2fafa1bc846ce450
  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vx v20, v8, t2

  li t2, 0x31504028404f7060
  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vx v20, v4, t2

  li t2, 0x69d4bea1539f99b7
  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vx v16, v12, t2

  li t2, 0x30350de7254d7772
  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vx v20, v24, t2

  li t2, 0x73f08c080fd5580f
  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vx v8, v4, t2

  li t2, 0x65386a02cb4e0c2a
  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vx v16, v8, t2

  li t2, 0x77915525fcf59931
  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vx v24, v20, t2

  li t2, 0x273a95711dec95c7
  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vx v8, v24, t2

  li t2, 0x2cfbecc4fc55e347
  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vx v8, v16, t2

  li t2, 0x7111f87a6dd74928
  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0xf9090c0f1c4628eb
  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vx v16, v24, t2

  li t2, 0x571c07f7e60d2634
  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vx v16, v24, t2

  li t2, 0x06d6999f2d5b6b36
  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0x388a0b0d1133a5ce
  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vx v16, v24, t2

  li t2, 0x9c2f2150f70f8f6a
  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0x0334c9486262d7db
  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0xcf57e629d08f443a
  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vx v8, v24, t2

  li t2, 0xb73bf5b950fb88cf
  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vx v12, v2, t2

  li t2, 0xfdae3c125569ea3c
  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vx v7, v16, t2

  li t2, 0x4999600b64ccf8fc
  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vx v22, v11, t2

  li t2, 0x154cc6e9543bdacc
  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vx v26, v30, t2

  li t2, 0x9b6fa28a9da2c6d2
  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vx v12, v19, t2

  li t2, 0x87f0c0ce59702370
  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vx v17, v16, t2

  li t2, 0xb8542550ec6a5030
  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vx v22, v12, t2

  li t2, 0x9517a2552b03ec4f
  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vx v13, v3, t2

  li t2, 0x5ef0003cf471d646
  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vx v24, v5, t2

  li t2, 0xd7159cb424db59df
  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vx v23, v29, t2

  li t2, 0x410fccfac552679e
  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vx v2, v30, t2

  li t2, 0xcad0a3515e9fa3e6
  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vx v14, v6, t2

  li t2, 0x69cb69080a56f8a8
  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vx v30, v26, t2

  li t2, 0xdfdcf39bfbde6024
  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vx v2, v18, t2

  li t2, 0x33aae360702f2831
  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vx v20, v2, t2

  li t2, 0x18c9164b37fbdd16
  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vx v10, v18, t2

  li t2, 0x85596b3fd6fe0f9f
  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vx v4, v8, t2

  li t2, 0xdef73a316373ef0e
  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vx v20, v28, t2

  li t2, 0x2adb2a4f68586b2f
  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vx v22, v16, t2

  li t2, 0x4962311225042a51
  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vx v18, v20, t2

  li t2, 0x7fc0d4f22022b59b
  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vx v8, v16, t2

  li t2, 0xcca3320241d0e9f9
  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vx v28, v4, t2

  li t2, 0x1bf02745b550017a
  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vx v28, v16, t2

  li t2, 0x2c141bde2bee632e
  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vx v4, v24, t2

  li t2, 0xdb611811f8d2c7dc
  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vx v4, v12, t2

  li t2, 0x3ff11af07e8f322e
  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vx v28, v12, t2

  li t2, 0x21488a8f3c43c218
  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0xdb7bd17e01f9515f
  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vx v8, v20, t2

  li t2, 0x77834772d0f5c389
  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vx v20, v8, t2

  li t2, 0x17c5e5daef3b012b
  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vx v16, v24, t2

  li t2, 0x7015b1a4a2edba0e
  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vx v16, v24, t2

  li t2, 0x4c21944c2ea6dc66
  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0x65b6e4ae24b8214c
  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vx v16, v8, t2

  li t2, 0x1df21dc926dab3b3
  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0x432cd73fdbf7bd79
  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vx v8, v24, t2

  li t2, 0xb7f9c0e743abf2c9
  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0xc9c0ead059b8e0d8
  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0xed2c0d068fa4848f
  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vx v24, v16, t2

  li t2, 0x0f33017702dca351
  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0x028770061b071d3e
  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vx v8, v24, t2

  li t2, 0xdc49db32a481f806
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v29, v16, t2

  li t2, 0xa70de7159c1755f3
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v6, v14, t2

  li t2, 0x4432c8568df7bb8b
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v23, v26, t2

  li t2, 0xf2b520d116b54079
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v28, v27, t2

  li t2, 0x1e6aa50482b8eb24
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v4, v18, t2

  li t2, 0xe3e1d9f0cc618ae5
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v27, v24, t2

  li t2, 0x9e1b3d0ce3f22055
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v27, v20, t2

  li t2, 0xa68acae94c2f280d
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v16, v8, t2

  li t2, 0x29fa931693670ac7
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v23, v14, t2

  li t2, 0x9d4670f4dff71311
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v29, v21, t2

  li t2, 0xb3e24365d53d0ba8
  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vx v18, v10, t2

  li t2, 0x14c303d094f1f23a
  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vx v14, v8, t2

  li t2, 0xf4882ce33747a27b
  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vx v8, v22, t2

  li t2, 0xcd5d586c3847ed4a
  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vx v8, v22, t2

  li t2, 0x7bd9d7881b560294
  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vx v30, v10, t2

  li t2, 0x8930a18af1dd13ce
  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vx v24, v16, t2

  li t2, 0x1ce1380123657056
  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vx v24, v12, t2

  li t2, 0x526dd65895767a9e
  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vx v6, v10, t2

  li t2, 0x8c6b32f04d02adc3
  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vx v16, v14, t2

  li t2, 0x9e002d65a45f1d96
  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vx v28, v14, t2

  li t2, 0xfa9c30784356697e
  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vx v8, v28, t2

  li t2, 0x2a5884cade20104d
  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vx v16, v20, t2

  li t2, 0x16584729fd869097
  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vx v16, v8, t2

  li t2, 0xaeefb0b1e7b5abd5
  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0x6709202306e2219e
  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vx v8, v16, t2

  li t2, 0x7ad588beed6bc37d
  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vx v8, v20, t2

  li t2, 0x638f3aa25f039a02
  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vx v24, v28, t2

  li t2, 0xe001527808f218e1
  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vx v28, v4, t2

  li t2, 0x629b57b942216627
  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vx v28, v8, t2

  li t2, 0xaae821d4c3e9ee53
  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vx v8, v28, t2

  li t2, 0xfcc8e4903da97501
  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vx v8, v24, t2

  li t2, 0x5e640797625ea0a9
  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vx v16, v24, t2

  li t2, 0x7f29fc1a3ef1bf6b
  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vx v8, v16, t2

  li t2, 0xc845ebb1a53030f5
  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vx v16, v24, t2

  li t2, 0x478d24a8e5c4e93a
  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vx v24, v16, t2

  li t2, 0x2d06d7016fa4e66b
  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vx v8, v16, t2

  li t2, 0x34b779fa6e43583e
  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vx v8, v24, t2

  li t2, 0xbd7081bef1613ef2
  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vx v8, v16, t2

  li t2, 0x3097b00a443bc6eb
  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vx v24, v8, t2

  li t2, 0xaf9c08babb9329fd
  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vx v24, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v3, v8, 5

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v7, v25, -3

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v31, v25, 7

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v2, v30, -16

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v18, v15, 15

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v30, v12, -8

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v13, v8, -8

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v19, v2, 3

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v21, v8, -2

  vsetvli t1, t0, e8, m1, ta, ma
  vadd.vi v29, v11, -5

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v10, v30, -2

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v28, v30, 6

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v6, v16, -14

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v20, v16, 2

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v6, v28, -13

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v6, v30, -11

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v14, v24, 13

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v16, v2, -3

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v2, v12, 6

  vsetvli t1, t0, e8, m2, ta, ma
  vadd.vi v20, v14, 11

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v8, 4

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v28, 5

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v12, v20, 4

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v28, -5

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v4, -10

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v4, 4

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v16, v8, -1

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v8, v4, 0

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v28, v12, 8

  vsetvli t1, t0, e8, m4, ta, ma
  vadd.vi v20, v4, -8

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, -15

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v24, 8

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v8, -8

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, -13

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v24, v16, 11

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v24, 9

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, -15

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, -14

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v8, v16, -10

  vsetvli t1, t0, e8, m8, ta, ma
  vadd.vi v16, v8, 3

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v6, v17, 4

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v7, v15, -1

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v24, v5, 4

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v13, v15, -16

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v9, v7, -14

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v29, v5, 11

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v15, v28, -1

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v31, v18, -14

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v8, v21, 12

  vsetvli t1, t0, e16, m1, ta, ma
  vadd.vi v12, v28, 10

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v22, v4, -6

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v18, v12, 12

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v20, v16, -10

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v26, v22, 5

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v30, v10, -4

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v14, v2, 12

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v26, v20, 1

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v2, v8, 11

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v26, v12, -2

  vsetvli t1, t0, e16, m2, ta, ma
  vadd.vi v18, v14, 12

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v12, 9

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v4, v16, -13

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v16, v8, -1

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v28, v24, -16

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v12, -16

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v24, -8

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v20, v28, -10

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v28, v8, 13

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v20, 1

  vsetvli t1, t0, e16, m4, ta, ma
  vadd.vi v8, v4, 14

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, 0

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v16, 14

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v8, 10

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v24, 9

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, 6

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v16, 0

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v24, 10

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v16, v8, -5

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v8, v16, 5

  vsetvli t1, t0, e16, m8, ta, ma
  vadd.vi v24, v16, -15

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v6, v20, -16

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v29, v17, 6

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v3, v2, -10

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v22, v21, -7

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v13, v4, 3

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v28, v10, -12

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v17, v12, -6

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v3, v18, 13

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v6, v11, 15

  vsetvli t1, t0, e32, m1, ta, ma
  vadd.vi v6, v8, 2

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v20, v8, -13

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v14, v8, 11

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v26, v20, 12

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v14, v28, -3

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v20, v18, -2

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v8, v30, 11

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v28, v22, 5

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v24, v14, -6

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v26, v16, -3

  vsetvli t1, t0, e32, m2, ta, ma
  vadd.vi v4, v22, 5

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v8, v12, 8

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v24, v12, -2

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v16, v24, 11

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v16, v4, -6

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v16, 10

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v16, v12, -10

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v12, v24, -11

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v28, v20, -12

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v20, v16, -6

  vsetvli t1, t0, e32, m4, ta, ma
  vadd.vi v28, v12, -5

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v24, -10

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, -8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, 7

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, 4

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, -6

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v16, 8

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v8, 12

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v8, v16, 9

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v16, -5

  vsetvli t1, t0, e32, m8, ta, ma
  vadd.vi v24, v16, 1

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v21, v11, -2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v16, v26, -11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v19, v24, -11

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v27, v6, -16

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v2, v26, 14

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v30, v25, 10

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v8, v7, 6

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v18, v22, 7

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v8, v2, 2

  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vi v15, v23, 1

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v2, v16, 0

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v8, v24, 1

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v22, v30, 4

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v10, v16, -3

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v24, v8, -15

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v24, v20, -9

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v28, v12, 0

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v12, v2, 6

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v20, v8, 5

  vsetvli t1, t0, e64, m2, ta, ma
  vadd.vi v22, v4, 12

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v4, v16, -13

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v16, 6

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v4, v16, -13

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v24, 3

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v20, v16, 9

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v4, -2

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v8, v24, 12

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v24, v12, -10

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v16, v20, 11

  vsetvli t1, t0, e64, m4, ta, ma
  vadd.vi v8, v28, 3

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v24, -7

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, -2

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, 13

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, -3

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v16, 1

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, 6

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v16, v8, -3

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, -14

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v8, v24, 4

  vsetvli t1, t0, e64, m8, ta, ma
  vadd.vi v24, v16, 14

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
