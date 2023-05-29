#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v11, v22, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v21, v30, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v3, v15, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v21, v17, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v31, v3, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v5, v18, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v5, v7, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v5, v31, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v7, v19, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vv v15, v19, v31

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v30, v8, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v14, v16, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v16, v28, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v6, v10, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v18, v14, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v4, v24, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v10, v22, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v30, v18, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v6, v30, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vv v12, v22, v2

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v28, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v20, v16, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v20, v4, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v16, v12, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v8, v24, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v4, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v4, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vv v24, v8, v20

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v12, v26, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v1, v21, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v13, v24, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v19, v4, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v10, v8, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v4, v22, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v24, v2, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v22, v24, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v17, v14, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vv v15, v26, v13

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v14, v2, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v12, v28, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v20, v18, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v24, v20, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v26, v10, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v30, v4, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v6, v20, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v24, v10, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vv v20, v12, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v24, v28, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v8, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v24, v16, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v28, v20, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v16, v20, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v8, v4, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v20, v24, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v20, v8, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v12, v20, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vv v12, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vv v8, v16, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v15, v14, v5

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v27, v22, v5

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v29, v15, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v9, v7, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v1, v30, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v7, v24, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v12, v2, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v30, v26, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v8, v6, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vv v5, v18, v13

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v2, v14, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v16, v8, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v4, v26, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v20, v18, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v16, v12, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v16, v14, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v16, v4, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v12, v22, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v2, v6, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vv v26, v20, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v20, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v16, v20, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v12, v28, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v20, v4, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v4, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v24, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v20, v28, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v8, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v12, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vv v24, v4, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vv v8, v24, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v2, v27, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v18, v26, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v10, v9, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v8, v2, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v31, v22, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v11, v8, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v29, v12, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v7, v11, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v13, v2, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vv v29, v23, v17

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v4, v20, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v2, v12, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v20, v6, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v24, v22, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v28, v14, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v30, v14, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v16, v4, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v24, v16, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v2, v4, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vv v2, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v28, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v20, v16, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v24, v16, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v28, v20, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v4, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v28, v12, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v20, v24, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v12, v4, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v4, v20, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vv v28, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vv v24, v8, v16

  li t2, 0x2d26f3d7ddc5280b
  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v25, v5, t2

  li t2, 0x9e5741ab7f64e657
  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v10, v15, t2

  li t2, 0x490be19e8b7db834
  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v24, v14, t2

  li t2, 0x939a80071cc7d3f7
  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v13, v31, t2

  li t2, 0x6e7e6751b693594d
  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v24, v16, t2

  li t2, 0x81beacca2a527d3f
  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v7, v26, t2

  li t2, 0x91e0f8668d7b27d8
  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v27, v13, t2

  li t2, 0x8e5c1101e0e928fa
  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v4, v18, t2

  li t2, 0xbfb93bdecf13e350
  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v17, v11, t2

  li t2, 0xde2e680e1b84bec4
  vsetvli t1, t0, e8, m1, ta, ma
  vremu.vx v16, v1, t2

  li t2, 0x134193f74fe565a9
  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v2, v22, t2

  li t2, 0x44a721dc581f3421
  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v20, v2, t2

  li t2, 0x091bdba440d71586
  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v22, v2, t2

  li t2, 0xe288f6ddd49b2ad2
  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v2, v24, t2

  li t2, 0x072b37fb817defd4
  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v26, v24, t2

  li t2, 0x0d055a5b200fb715
  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v30, v8, t2

  li t2, 0xcc27208990c52cb1
  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v22, v6, t2

  li t2, 0xf865df9bab6ac51e
  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v4, v2, t2

  li t2, 0x68ac40b00e187806
  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v12, v22, t2

  li t2, 0x6fd2f4d184edfaa0
  vsetvli t1, t0, e8, m2, ta, ma
  vremu.vx v10, v24, t2

  li t2, 0xc9c232f9d098139c
  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v28, v20, t2

  li t2, 0x7cc50317c9ba3bfe
  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v12, v20, t2

  li t2, 0x10ff157af98125c0
  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v12, v20, t2

  li t2, 0x48f13e4b1adc3e2d
  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v24, v12, t2

  li t2, 0xad59971425cf45e6
  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v8, v24, t2

  li t2, 0xd1b10dadb13aeb95
  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v8, v16, t2

  li t2, 0xd236acc62aa8e7ce
  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v16, v28, t2

  li t2, 0x70782bf57a6bf102
  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v24, v28, t2

  li t2, 0x0f5520f9da53c977
  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v12, v4, t2

  li t2, 0x98e25e42c024fc33
  vsetvli t1, t0, e8, m4, ta, ma
  vremu.vx v8, v4, t2

  li t2, 0x7f5327783a131952
  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v8, v16, t2

  li t2, 0xd0c063e10bddb0bc
  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v16, v8, t2

  li t2, 0xae28c58ec985867b
  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v16, v8, t2

  li t2, 0x14c2af901a7a290c
  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v8, t2

  li t2, 0x8392f1ba5d3816f5
  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v8, t2

  li t2, 0x26cea556c62a9dc0
  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v8, v16, t2

  li t2, 0x69395f9478ebd792
  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v8, t2

  li t2, 0x6ec6e867c133a929
  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v16, v24, t2

  li t2, 0xe36c1bc4d127a67c
  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v24, v8, t2

  li t2, 0x7b83d94a3d417a15
  vsetvli t1, t0, e8, m8, ta, ma
  vremu.vx v16, v24, t2

  li t2, 0x1ef5717429450334
  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v4, v3, t2

  li t2, 0xfce5a0f2bdd3239c
  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v30, v19, t2

  li t2, 0x7a92bf6cd0bc1d9b
  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v21, v3, t2

  li t2, 0xa40d50ff63d42f32
  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v7, v23, t2

  li t2, 0x8c24500cd928c120
  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v12, v17, t2

  li t2, 0x9db464052c74b244
  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v30, v3, t2

  li t2, 0x6332bdcc87370e0a
  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v11, v21, t2

  li t2, 0x061be474697f92d5
  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v30, v14, t2

  li t2, 0xf8ef7be869133e11
  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v22, v24, t2

  li t2, 0x187f6b9483afd72d
  vsetvli t1, t0, e16, m1, ta, ma
  vremu.vx v3, v17, t2

  li t2, 0x9a2f971770216e79
  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v22, v2, t2

  li t2, 0xce3b5f7a54886839
  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v28, v8, t2

  li t2, 0xf25cdb864ed562df
  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v30, v22, t2

  li t2, 0x685c8f59e0e949d4
  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v10, v28, t2

  li t2, 0xfe347619a8dc367b
  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v20, v6, t2

  li t2, 0x6daf5f1ad354592e
  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v30, v18, t2

  li t2, 0x389c485aae49d9de
  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v6, v8, t2

  li t2, 0xaa100135b6fcfd5d
  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v22, v24, t2

  li t2, 0xe3b897af60b99705
  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v28, v2, t2

  li t2, 0x70eca4b060e1b993
  vsetvli t1, t0, e16, m2, ta, ma
  vremu.vx v6, v12, t2

  li t2, 0x87f3795163a4cbb0
  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v12, v28, t2

  li t2, 0xf1682521ada3ceb8
  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v16, v12, t2

  li t2, 0xb7206b6b11609de8
  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v20, v8, t2

  li t2, 0x35cd22757cadc0c4
  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v12, v4, t2

  li t2, 0xb1f7889f524be7f7
  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v28, v24, t2

  li t2, 0x196299ce01f282ee
  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v28, v4, t2

  li t2, 0xf12de6394fb14760
  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v16, v24, t2

  li t2, 0x6278c4a3c7f3df83
  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v16, v20, t2

  li t2, 0x970afd2923553a4a
  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v28, v8, t2

  li t2, 0x9e0c7fe1997fa4d9
  vsetvli t1, t0, e16, m4, ta, ma
  vremu.vx v8, v20, t2

  li t2, 0x3c9dd05b61d8dbac
  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v24, v16, t2

  li t2, 0x44c26479410cf316
  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v24, v16, t2

  li t2, 0x55cf80b02d5a701a
  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v8, v16, t2

  li t2, 0x75a87ee946ff845f
  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v24, v16, t2

  li t2, 0xb552fe4ecbf60dde
  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v24, v8, t2

  li t2, 0x96b41ad5406a04c7
  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v16, v8, t2

  li t2, 0x7f88f6c67fd70ec9
  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v16, v24, t2

  li t2, 0x8f93ae06d818565c
  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v24, v16, t2

  li t2, 0xaf9dd55354aa626d
  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v24, v8, t2

  li t2, 0x70fabeb9d2152d1a
  vsetvli t1, t0, e16, m8, ta, ma
  vremu.vx v24, v8, t2

  li t2, 0xddebff9c9433868e
  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v15, v28, t2

  li t2, 0x1af133a89686beac
  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v25, v12, t2

  li t2, 0x597462065fc3eda3
  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v1, v31, t2

  li t2, 0x15610bb9e0b59e1d
  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v25, v24, t2

  li t2, 0xdaf98ff87efa43f0
  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v13, v16, t2

  li t2, 0x9def9a8d071ff557
  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v8, v3, t2

  li t2, 0x66721cbe955f5227
  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v25, v30, t2

  li t2, 0x0eee313534798fde
  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v20, v26, t2

  li t2, 0x909aca6ffd5b213b
  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v18, v15, t2

  li t2, 0x75ef0eb0bb7793ed
  vsetvli t1, t0, e32, m1, ta, ma
  vremu.vx v27, v19, t2

  li t2, 0x1853f57d62d67f94
  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v14, v24, t2

  li t2, 0x84b856eca387987d
  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v22, v30, t2

  li t2, 0x104c6eeb2393a1ae
  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v2, v16, t2

  li t2, 0xe512f40efbdde5e0
  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v22, v8, t2

  li t2, 0xa12e698886e1fac4
  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v30, v12, t2

  li t2, 0xe09dd394e19a367d
  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v26, v4, t2

  li t2, 0x7ec6f5920c619bef
  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v2, v30, t2

  li t2, 0x6fb5ccf7739751a8
  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v14, v22, t2

  li t2, 0x304acafd7ba2a65d
  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v22, v8, t2

  li t2, 0x001f93cd18347cc7
  vsetvli t1, t0, e32, m2, ta, ma
  vremu.vx v30, v4, t2

  li t2, 0x4e0fc83a42bae432
  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v4, v24, t2

  li t2, 0x6aa0052c8193d011
  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v24, v4, t2

  li t2, 0x5bee424c5bb1e4b7
  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v16, v28, t2

  li t2, 0x172566d44d53f8a5
  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v4, v16, t2

  li t2, 0x245ffdf1f9d180af
  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v24, v4, t2

  li t2, 0xd8f82b6cf64b964b
  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v24, v28, t2

  li t2, 0xb5fdef6a690a7edc
  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v4, v8, t2

  li t2, 0x761c8fed60c4b8d8
  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v12, v20, t2

  li t2, 0x3d36f90653f6cac6
  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v28, v24, t2

  li t2, 0x60a7394a70e77389
  vsetvli t1, t0, e32, m4, ta, ma
  vremu.vx v20, v24, t2

  li t2, 0x5afb05e7b79828ea
  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v24, v16, t2

  li t2, 0x161d96d0d0ca7d82
  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v16, v24, t2

  li t2, 0x810f37d4549bb4f1
  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v24, t2

  li t2, 0x040a0b66075fb7b3
  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v16, v8, t2

  li t2, 0x6f4656d5d38d1329
  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v16, v8, t2

  li t2, 0x156bea896d9e43c3
  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v16, t2

  li t2, 0x3f124fc6dfd1aa61
  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v16, v8, t2

  li t2, 0x1d92a7777410a2ba
  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v24, t2

  li t2, 0x1240ae9c97d67d89
  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v16, t2

  li t2, 0xeb5c9f1a94b4596b
  vsetvli t1, t0, e32, m8, ta, ma
  vremu.vx v8, v16, t2

  li t2, 0xb79408f829bc5194
  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v4, v24, t2

  li t2, 0xfa805ac438efcd30
  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v16, v24, t2

  li t2, 0xb15296344c178f11
  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v20, v5, t2

  li t2, 0xab868d5cd8249124
  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v8, v27, t2

  li t2, 0x16c2d9fb6d5f89ca
  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v20, v2, t2

  li t2, 0x373c43985305714e
  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v22, v16, t2

  li t2, 0xf1d5e5cb0d220fa5
  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v24, v13, t2

  li t2, 0x419fe7a991bd8f5c
  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v14, v23, t2

  li t2, 0xb85ae5a09c848845
  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v6, v3, t2

  li t2, 0x93071194c06c7960
  vsetvli t1, t0, e64, m1, ta, ma
  vremu.vx v4, v12, t2

  li t2, 0xdb1ac7635a70cb1d
  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v4, v8, t2

  li t2, 0xb4a07a0b3a781cb5
  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v8, v18, t2

  li t2, 0x9ce03128d16c7ce0
  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v28, v12, t2

  li t2, 0x1ccdc78cff434a8b
  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v22, v28, t2

  li t2, 0x966742f210b958db
  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v2, v20, t2

  li t2, 0x2dbd095ec11fa166
  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v4, v12, t2

  li t2, 0x32db4d73b4e56796
  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v22, v24, t2

  li t2, 0x20526e19704d4b91
  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v22, v24, t2

  li t2, 0x2cb95b75303476eb
  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v20, v4, t2

  li t2, 0xbed65d8507961a80
  vsetvli t1, t0, e64, m2, ta, ma
  vremu.vx v22, v18, t2

  li t2, 0xa78dae51b2ceb216
  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v24, v16, t2

  li t2, 0x023da3af8cf1b0cf
  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v4, v24, t2

  li t2, 0x0649a685afecc1b3
  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v12, v4, t2

  li t2, 0x4911e38df2497cea
  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v28, v20, t2

  li t2, 0xff375b7e6d6f66f2
  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v28, v24, t2

  li t2, 0x4d241e699dc42f71
  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v20, v16, t2

  li t2, 0xf1f9e3bc85a83b0e
  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v12, v20, t2

  li t2, 0x81b49cd5e56275e0
  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v20, v24, t2

  li t2, 0x1961aabb88d37516
  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v16, v20, t2

  li t2, 0x29d224fd2ab10436
  vsetvli t1, t0, e64, m4, ta, ma
  vremu.vx v16, v20, t2

  li t2, 0x6552984aa176b930
  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v8, t2

  li t2, 0x2cb3081648a6e02f
  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v24, t2

  li t2, 0x63a99180d11081a6
  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v24, v8, t2

  li t2, 0xcd80850f218099d1
  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v8, v16, t2

  li t2, 0x7c24c5d31db18e82
  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v8, t2

  li t2, 0x0266543cf8e7f40c
  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v8, v16, t2

  li t2, 0x52cd5368aac050d2
  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v8, v16, t2

  li t2, 0x7879ee41f9e5afae
  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v24, v8, t2

  li t2, 0x69097bad8061ad7a
  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v16, v24, t2

  li t2, 0x2b93812586a54c31
  vsetvli t1, t0, e64, m8, ta, ma
  vremu.vx v24, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
