#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vv v12, v28, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vv v30, v14, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vv v20, v31, v7

  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vv v28, v4, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vv v23, v6, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vv v27, v12, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vv v25, v19, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vv v27, v24, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vv v31, v2, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vv v24, v13, v3

  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vv v20, v22, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vv v10, v18, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vv v26, v12, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vv v6, v2, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vv v26, v18, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vv v10, v2, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vv v28, v20, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vv v18, v10, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vv v14, v20, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vv v8, v22, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vv v24, v12, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vv v28, v12, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vv v4, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vv v24, v20, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vv v24, v28, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vv v8, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vv v16, v20, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vv v20, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vv v16, v24, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vv v28, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vv v16, v8, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vv v26, v27, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vv v20, v3, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vv v22, v27, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vv v7, v22, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vv v10, v23, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vv v1, v12, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vv v22, v31, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vv v25, v21, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vv v31, v13, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vv v2, v30, v1

  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vv v8, v2, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vv v22, v20, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vv v4, v12, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vv v18, v26, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vv v16, v6, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vv v14, v6, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vv v2, v6, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vv v12, v26, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vv v24, v4, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vv v22, v16, v2

  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vv v28, v16, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vv v16, v24, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vv v24, v28, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vv v24, v16, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vv v4, v12, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vv v8, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vv v12, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vv v16, v20, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vv v8, v16, v28

  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vv v8, v16, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vv v30, v9, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vv v14, v16, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vv v20, v26, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vv v21, v23, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vv v5, v16, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vv v19, v21, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vv v11, v28, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vv v3, v8, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vv v15, v9, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vv v29, v12, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vv v22, v14, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vv v28, v22, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vv v6, v20, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vv v18, v12, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vv v26, v8, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vv v12, v10, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vv v12, v6, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vv v24, v18, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vv v16, v26, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vv v30, v22, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vv v24, v28, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vv v8, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vv v24, v12, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vv v24, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vv v4, v20, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vv v28, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vv v24, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vv v12, v16, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vv v28, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vv v4, v28, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vv v16, v24, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vv v15, v2, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vv v15, v28, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vv v29, v9, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vv v28, v24, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vv v3, v6, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vv v9, v29, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vv v5, v18, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vv v18, v13, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vv v21, v29, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vv v14, v31, v19

  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vv v4, v16, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vv v20, v12, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vv v24, v16, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vv v20, v30, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vv v8, v18, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vv v16, v4, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vv v12, v18, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vv v16, v24, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vv v24, v8, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vv v12, v26, v10

  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vv v8, v4, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vv v4, v20, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vv v24, v20, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vv v12, v8, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vv v4, v16, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vv v16, v12, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vv v28, v20, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vv v8, v20, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vv v16, v20, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vv v24, v16, v4

  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vv v16, v24, v8

  li t2, 0x74c30958a0eae7c4
  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vx v6, v13, t2

  li t2, 0xc951ed1ab65c4a64
  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vx v8, v30, t2

  li t2, 0xa7c7241b2249719a
  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vx v8, v19, t2

  li t2, 0x408173c0f497adce
  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vx v12, v18, t2

  li t2, 0xc4be24e4c35d46f3
  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vx v19, v14, t2

  li t2, 0xb02a155aecf3dd69
  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vx v3, v26, t2

  li t2, 0x43bddaf08fe01f17
  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vx v16, v31, t2

  li t2, 0x70971ef5085bb0cd
  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vx v2, v13, t2

  li t2, 0x0ed5661b7c2c30af
  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vx v10, v26, t2

  li t2, 0x23ef68293742f384
  vsetvli t1, t0, e8, m1, ta, ma
  vminu.vx v7, v19, t2

  li t2, 0x9b2563f78f777d30
  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vx v14, v22, t2

  li t2, 0x9016a28105b96a83
  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vx v28, v24, t2

  li t2, 0xedcd8f7380077b38
  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vx v20, v12, t2

  li t2, 0x0468b47169926ddd
  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vx v6, v10, t2

  li t2, 0x7163591a16183532
  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vx v26, v16, t2

  li t2, 0x7b94786fb5117dec
  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vx v16, v12, t2

  li t2, 0x0dbd1fd77b4536b2
  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vx v8, v16, t2

  li t2, 0xd1d122d2f5abaa95
  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vx v18, v22, t2

  li t2, 0xa590ae0627db38b4
  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vx v8, v22, t2

  li t2, 0xf8d64c2ea6546b9e
  vsetvli t1, t0, e8, m2, ta, ma
  vminu.vx v4, v14, t2

  li t2, 0xf7c0cdb5ddb73f08
  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vx v8, v20, t2

  li t2, 0x6114e2d2316d1674
  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vx v16, v12, t2

  li t2, 0xebbd4d1336043079
  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vx v20, v4, t2

  li t2, 0x25045cc60b738a90
  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vx v20, v24, t2

  li t2, 0xead7ade934c3c7af
  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vx v4, v16, t2

  li t2, 0x7d5787a720484b5d
  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vx v8, v20, t2

  li t2, 0x4688099bf7c7ba1a
  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vx v4, v8, t2

  li t2, 0x1b22426368b7de39
  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vx v20, v24, t2

  li t2, 0x914ea84d507ed876
  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0xd3104ec89e2c42d7
  vsetvli t1, t0, e8, m4, ta, ma
  vminu.vx v8, v16, t2

  li t2, 0x3de3e7876bd909b1
  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vx v8, v16, t2

  li t2, 0xf66ff39d603a2e7c
  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vx v24, v8, t2

  li t2, 0x970b1986dcc1cf5c
  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0x549c415373cc2e36
  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vx v8, v16, t2

  li t2, 0x645d1f0d995acc8c
  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0x309965a50968a200
  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vx v16, v24, t2

  li t2, 0xa09cd090c4daaf0d
  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0x081e1e2d6a28dda4
  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vx v8, v24, t2

  li t2, 0x5353d4bfb86b62f6
  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vx v16, v24, t2

  li t2, 0xe834a1203428645a
  vsetvli t1, t0, e8, m8, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0xd67b57625bf11b28
  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vx v7, v23, t2

  li t2, 0x0fabf9021a0872f3
  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vx v22, v6, t2

  li t2, 0x579423d27d225367
  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vx v26, v29, t2

  li t2, 0xb18c979b4b3b0c1a
  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vx v25, v4, t2

  li t2, 0x3a1d813a7501b7d7
  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vx v12, v19, t2

  li t2, 0x1efcb7dd6c606b02
  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vx v5, v12, t2

  li t2, 0x4d80f1e160ded951
  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vx v10, v18, t2

  li t2, 0xdd13a944f9949407
  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vx v21, v1, t2

  li t2, 0x2c295e9363b874a9
  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vx v9, v28, t2

  li t2, 0xe17c2cf8111ba881
  vsetvli t1, t0, e16, m1, ta, ma
  vminu.vx v8, v28, t2

  li t2, 0x314c876f570ba572
  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vx v30, v28, t2

  li t2, 0xc5e3f16991407c96
  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vx v18, v2, t2

  li t2, 0xfdb3458d25858728
  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vx v12, v8, t2

  li t2, 0xccaac5e02d0281d5
  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vx v26, v22, t2

  li t2, 0x8abf78463590e1d7
  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vx v10, v8, t2

  li t2, 0x2cf2119f2663588e
  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vx v14, v28, t2

  li t2, 0x2253e8e8f9454ec5
  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vx v24, v18, t2

  li t2, 0x743ec632574bd958
  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vx v10, v16, t2

  li t2, 0xa84291ec939f633a
  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vx v20, v16, t2

  li t2, 0x3b96248803d3665d
  vsetvli t1, t0, e16, m2, ta, ma
  vminu.vx v14, v2, t2

  li t2, 0x4b3c78a34b811b91
  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vx v12, v28, t2

  li t2, 0x2a6300af70774882
  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vx v16, v20, t2

  li t2, 0x4f0379c02e4c1384
  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vx v16, v8, t2

  li t2, 0x451aaa6a2ddd8849
  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vx v4, v8, t2

  li t2, 0xe9451826951d1336
  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vx v8, v4, t2

  li t2, 0x31cfef37434c3c8b
  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vx v12, v20, t2

  li t2, 0xce8816ca3aa69032
  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vx v8, v28, t2

  li t2, 0x8f6132c1abcb1ad7
  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vx v24, v20, t2

  li t2, 0x90a70efbdb3e154d
  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vx v20, v12, t2

  li t2, 0xa4dd99afe4390721
  vsetvli t1, t0, e16, m4, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0x58766a2b80a50b75
  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vx v16, v8, t2

  li t2, 0x1ee0f026abe4e355
  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vx v8, v16, t2

  li t2, 0x7b5aa6786106fc66
  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0x0aac3e119fa793c9
  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vx v8, v16, t2

  li t2, 0x5bb25a8aad58c4f8
  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vx v24, v8, t2

  li t2, 0xbadcb03faab43f56
  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vx v16, v8, t2

  li t2, 0x83602045e0bac972
  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vx v8, v24, t2

  li t2, 0x89e0a1438e2115a4
  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vx v16, v24, t2

  li t2, 0xf09960ece7152f69
  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vx v16, v24, t2

  li t2, 0xb5c94f4890d4080d
  vsetvli t1, t0, e16, m8, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0x37dd1916fe58946f
  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vx v28, v18, t2

  li t2, 0x7d6e9bc0b42bd8b8
  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vx v4, v21, t2

  li t2, 0x80e5ebf24379bd8c
  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vx v25, v10, t2

  li t2, 0x981dd4e970adb0ca
  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vx v20, v29, t2

  li t2, 0x177db525e1f4ffb6
  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vx v20, v3, t2

  li t2, 0x71aaca2831cd60ca
  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vx v14, v1, t2

  li t2, 0xbd77716e9878283e
  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vx v2, v15, t2

  li t2, 0x0fbf279316e4ee3b
  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vx v28, v4, t2

  li t2, 0x3ad4849db0f70802
  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vx v6, v25, t2

  li t2, 0xe3d3ff524a0ec93c
  vsetvli t1, t0, e32, m1, ta, ma
  vminu.vx v25, v12, t2

  li t2, 0xc06d8e07bb4ea153
  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vx v26, v4, t2

  li t2, 0x4fe0195f88a976ea
  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vx v14, v12, t2

  li t2, 0xf3ed2f35ea139046
  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vx v22, v16, t2

  li t2, 0x429ba72f70c74c7b
  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vx v8, v16, t2

  li t2, 0xc3cf1a304fb344fe
  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vx v26, v4, t2

  li t2, 0x54d701d6b4e687df
  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vx v12, v20, t2

  li t2, 0x8d57a0767eb9617b
  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vx v28, v10, t2

  li t2, 0x8233a0f0d168d4ed
  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vx v16, v26, t2

  li t2, 0x6bd4daaa9b3bd833
  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vx v18, v30, t2

  li t2, 0x7e1edca8759aa6a6
  vsetvli t1, t0, e32, m2, ta, ma
  vminu.vx v18, v10, t2

  li t2, 0x29212d0b040c40ab
  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vx v12, v28, t2

  li t2, 0xc0cfa51ca21f2183
  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vx v28, v4, t2

  li t2, 0x5eadeb7383ded2dd
  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vx v12, v8, t2

  li t2, 0xe099a6866706bc54
  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vx v24, v4, t2

  li t2, 0x6f27dc82e805ce1f
  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vx v28, v20, t2

  li t2, 0x354174adcf90fdaf
  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vx v20, v24, t2

  li t2, 0xa81c0e5064a5d470
  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vx v20, v16, t2

  li t2, 0x4662ac6fb4918818
  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vx v12, v28, t2

  li t2, 0x4a5fcc6ecdd1c197
  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vx v28, v4, t2

  li t2, 0x9c40018965981979
  vsetvli t1, t0, e32, m4, ta, ma
  vminu.vx v20, v12, t2

  li t2, 0x1c8099c2c2447e34
  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0xdfa006d46f8f1dae
  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0xdf8785f74ff18938
  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0x9f5f2e7d2fb325cd
  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0x1b277b0657a0ba83
  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vx v8, v16, t2

  li t2, 0xb2bfeebdfe686455
  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vx v8, v16, t2

  li t2, 0x3a71211b7c5ad79d
  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vx v24, v8, t2

  li t2, 0xb1227054c64d4222
  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vx v16, v8, t2

  li t2, 0xcd5506ec76d9cd83
  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vx v16, v8, t2

  li t2, 0x25c7a8dc1c66dae0
  vsetvli t1, t0, e32, m8, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0xf766cf8dd046c048
  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vx v23, v2, t2

  li t2, 0xb8c2e8004cc2d4ba
  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vx v10, v27, t2

  li t2, 0xa5ead9aa882f59f6
  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vx v13, v1, t2

  li t2, 0xa6fd63075d4edca8
  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vx v19, v9, t2

  li t2, 0xf6fd79d2e097c5b3
  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vx v28, v27, t2

  li t2, 0xb3dcc877b3bd616d
  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vx v28, v7, t2

  li t2, 0xbfa85e6c585beee5
  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vx v3, v9, t2

  li t2, 0xcb9451f4c537626c
  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vx v23, v12, t2

  li t2, 0x06c7cda56db8b799
  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vx v9, v2, t2

  li t2, 0x2b247475dea5e882
  vsetvli t1, t0, e64, m1, ta, ma
  vminu.vx v28, v12, t2

  li t2, 0xd6ed69074f71ae90
  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vx v10, v28, t2

  li t2, 0xf5716f19f70144cd
  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vx v10, v14, t2

  li t2, 0x3cd65fbf6bbf5af7
  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vx v30, v4, t2

  li t2, 0xda379203dd008c42
  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vx v22, v28, t2

  li t2, 0xf5939e048955a683
  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vx v30, v16, t2

  li t2, 0x07f66c485e488d4f
  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vx v28, v2, t2

  li t2, 0x31d8cba746686412
  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vx v18, v6, t2

  li t2, 0xbdfa991af6b54399
  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vx v10, v30, t2

  li t2, 0x8f16a5c7494b1973
  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vx v18, v24, t2

  li t2, 0xb6b2165e6c71cc70
  vsetvli t1, t0, e64, m2, ta, ma
  vminu.vx v2, v28, t2

  li t2, 0xb7ccd468658c9254
  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vx v12, v4, t2

  li t2, 0x8a2e87e6ad0007c0
  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vx v28, v8, t2

  li t2, 0x04eb52ecfd590bbb
  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vx v28, v4, t2

  li t2, 0x5515e4736df98150
  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vx v20, v4, t2

  li t2, 0xcd5f6fdf4c5cb4ae
  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vx v12, v20, t2

  li t2, 0xa67959a23adbf7f8
  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vx v28, v8, t2

  li t2, 0xae6305ebaab51234
  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vx v24, v28, t2

  li t2, 0xf99650124156f076
  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vx v4, v16, t2

  li t2, 0x4ee106583ae6e748
  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vx v8, v28, t2

  li t2, 0x5b207789410b2714
  vsetvli t1, t0, e64, m4, ta, ma
  vminu.vx v4, v28, t2

  li t2, 0xc272f28b0027f375
  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0xa9cfbf7e039af59c
  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vx v24, v8, t2

  li t2, 0x3c7e89b77f0fb973
  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vx v24, v8, t2

  li t2, 0x327e3f68f8f108f8
  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vx v16, v8, t2

  li t2, 0xdd584d966f4c71c7
  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vx v8, v24, t2

  li t2, 0x3a4dfd2af77f2f31
  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vx v16, v8, t2

  li t2, 0x880cc204f6b8eba5
  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vx v16, v24, t2

  li t2, 0x989feb95ad4fbea2
  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0xe4f88d1526eaa4b1
  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vx v24, v16, t2

  li t2, 0xb14bdda93c77f49d
  vsetvli t1, t0, e64, m8, ta, ma
  vminu.vx v24, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
