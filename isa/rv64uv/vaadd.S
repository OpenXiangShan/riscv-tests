#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vv v20, v30, v23

  li t2, 0x76eb91cbe44ec7ff
  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vx v25, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vv v17, v22, v4

  li t2, 0xb4f6d68cb74fdb64
  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vx v27, v19, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vv v21, v17, v10

  li t2, 0x8fa458b3e10d8b13
  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vx v28, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vv v30, v2, v20

  li t2, 0x5c91a36f18371144
  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vx v21, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vv v9, v22, v28

  li t2, 0x9e67a8a3227a036e
  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vx v31, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vv v8, v16, v9

  li t2, 0xd274d76b0032962a
  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vx v19, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vv v1, v3, v29

  li t2, 0x1594f81d320e7aa4
  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vx v24, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vv v28, v9, v7

  li t2, 0x002dc5f4fa1ffe5b
  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vx v15, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vv v12, v28, v1

  li t2, 0x0b53b45b495cab6d
  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vx v11, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vv v3, v26, v23

  li t2, 0x56d0884148633713
  vsetvli t1, t0, e8, m1, ta, ma
  vaadd.vx v24, v7, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vv v16, v22, v10

  li t2, 0xb41c0633d7353e22
  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vx v16, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vv v24, v26, v30

  li t2, 0x017c6ce58b944c19
  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vx v30, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vv v6, v2, v16

  li t2, 0x58373e11b1867910
  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vx v12, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vv v14, v2, v30

  li t2, 0x96039f7bf5763242
  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vx v4, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vv v6, v10, v20

  li t2, 0x35b25fd98a2ff052
  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vx v22, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vv v20, v16, v26

  li t2, 0x6b3b2311aefcd5bc
  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vx v28, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vv v2, v14, v8

  li t2, 0x33f403e34054aaca
  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vx v14, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vv v6, v26, v20

  li t2, 0x4d73731c79c35c64
  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vx v12, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vv v8, v12, v24

  li t2, 0xa3b7cd208c43e35d
  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vx v12, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vv v4, v22, v20

  li t2, 0x22ab423d444c6dba
  vsetvli t1, t0, e8, m2, ta, ma
  vaadd.vx v22, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vv v20, v4, v24

  li t2, 0xbce633a17efc555f
  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vv v4, v28, v16

  li t2, 0x0b116aa309dc41c3
  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vx v16, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vv v20, v16, v28

  li t2, 0xbd413d2b434c8903
  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vv v28, v16, v8

  li t2, 0x46b14edc1aa69dae
  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vx v28, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vv v4, v8, v16

  li t2, 0xcca6d923ddd6f50c
  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vv v20, v12, v28

  li t2, 0x04df70ce1c911074
  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vx v4, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vv v12, v24, v16

  li t2, 0x5dd62f8a5881b456
  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vx v16, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vv v12, v24, v4

  li t2, 0xf7a3885772f691a6
  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vx v24, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vv v24, v20, v8

  li t2, 0xde475bfa64abce20
  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vx v12, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vv v8, v4, v28

  li t2, 0x234c66ab3ea278c8
  vsetvli t1, t0, e8, m4, ta, ma
  vaadd.vx v4, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vv v8, v24, v16

  li t2, 0x2e1616a8f2f0267a
  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vv v8, v16, v24

  li t2, 0x43cf57cb8609a832
  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vv v16, v24, v8

  li t2, 0x9429fc5c5534c725
  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vv v24, v16, v8

  li t2, 0x23dfce0abfb0c2dd
  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vv v16, v8, v24

  li t2, 0x4e5bb75c0021632d
  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vv v24, v8, v16

  li t2, 0x876eef34c477ebdd
  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vv v8, v16, v24

  li t2, 0x736f2becb3fb4223
  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vv v8, v24, v16

  li t2, 0x4d51ed52c64e6ee3
  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vv v24, v16, v8

  li t2, 0xb1bfe6aac61cfe61
  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vv v8, v16, v24

  li t2, 0xa8c5612f7b9cc69c
  vsetvli t1, t0, e8, m8, ta, ma
  vaadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vv v16, v10, v15

  li t2, 0xdc718e8fcca9bc1b
  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vx v24, v29, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vv v20, v8, v17

  li t2, 0x221d90cbf56f9975
  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vx v15, v9, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vv v26, v24, v28

  li t2, 0x72e96c115b23f60d
  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vx v18, v5, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vv v13, v15, v1

  li t2, 0xc6336eded72f5def
  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vx v14, v23, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vv v31, v7, v2

  li t2, 0x3cf16b1a8ae14e18
  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vx v8, v26, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vv v29, v5, v31

  li t2, 0xe413b623fda19b4b
  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vx v27, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vv v13, v27, v31

  li t2, 0x12263abe8570b361
  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vx v9, v17, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vv v10, v18, v24

  li t2, 0x326cbb8fb1a62d30
  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vx v14, v17, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vv v6, v26, v31

  li t2, 0x1f964acac8b8826b
  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vx v27, v6, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vv v27, v14, v8

  li t2, 0xfc013e24f4750e12
  vsetvli t1, t0, e16, m1, ta, ma
  vaadd.vx v28, v15, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vv v20, v26, v8

  li t2, 0x7fd2196f865442ab
  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vx v24, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vv v8, v4, v20

  li t2, 0xcf1d7b69c3159116
  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vx v24, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vv v12, v24, v18

  li t2, 0x064576ee13753957
  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vx v20, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vv v16, v2, v12

  li t2, 0x2c0e6f6aeefdcba7
  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vx v14, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vv v26, v4, v22

  li t2, 0x97a8cfc89bd3d4b0
  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vx v28, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vv v10, v12, v24

  li t2, 0x24f176b397778d93
  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vx v4, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vv v4, v2, v30

  li t2, 0x01e9a284eb2a4153
  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vx v20, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vv v18, v2, v8

  li t2, 0x8d6aa9029e8cd983
  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vx v28, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vv v20, v4, v16

  li t2, 0x089539fff156ea80
  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vx v12, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vv v20, v2, v24

  li t2, 0x0eab783c9e137957
  vsetvli t1, t0, e16, m2, ta, ma
  vaadd.vx v18, v2, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vv v4, v12, v28

  li t2, 0xafaab7955c4345d0
  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vx v16, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vv v16, v12, v8

  li t2, 0x5781bb41097ab4b7
  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vx v20, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vv v12, v16, v28

  li t2, 0x7951f405169de1c6
  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vx v8, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vv v8, v20, v4

  li t2, 0x52a2b016005ea371
  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vx v24, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vv v4, v16, v12

  li t2, 0xedd12138da5f6cae
  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vx v4, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vv v24, v4, v8

  li t2, 0xc60973e8d08216a3
  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vx v24, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vv v12, v8, v20

  li t2, 0x4b28d88e15d17007
  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vx v20, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vv v4, v16, v28

  li t2, 0x1d4bdee67e553243
  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vx v16, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vv v16, v24, v12

  li t2, 0x9ffb590c858124b1
  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vx v24, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vv v16, v20, v4

  li t2, 0xcc56eb6c71cf8e4c
  vsetvli t1, t0, e16, m4, ta, ma
  vaadd.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vv v8, v24, v16

  li t2, 0x7b4bc4e68e2205e2
  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vv v8, v24, v16

  li t2, 0x3a243b8ec1679f48
  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vv v8, v16, v24

  li t2, 0xdbd53dec4880cbf4
  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vv v16, v24, v8

  li t2, 0xcba7d89445f9e175
  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vv v8, v16, v24

  li t2, 0x659cc42bc047f96c
  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vv v8, v24, v16

  li t2, 0xe90af45c546e0a2b
  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vv v16, v8, v24

  li t2, 0x579ae3a0ae978b8d
  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vv v24, v16, v8

  li t2, 0xf90af4d142b664b3
  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vv v8, v16, v24

  li t2, 0xe4a71d50226dcfc1
  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vv v16, v8, v24

  li t2, 0x27186933dd71f0ad
  vsetvli t1, t0, e16, m8, ta, ma
  vaadd.vx v8, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vv v30, v2, v14

  li t2, 0xaf0e10b02bc6a28a
  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vx v17, v1, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vv v18, v3, v7

  li t2, 0x09e7bc3ae7a766f9
  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vx v6, v19, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vv v21, v17, v11

  li t2, 0xd120fc3899a58fed
  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vx v30, v26, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vv v30, v23, v19

  li t2, 0x894ba21abf481d94
  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vx v28, v22, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vv v1, v29, v3

  li t2, 0x5f098df311e68e7e
  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vx v11, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vv v5, v8, v6

  li t2, 0x34d34aaf8aacf723
  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vx v8, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vv v6, v31, v20

  li t2, 0x29243b304cd1b69e
  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vx v25, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vv v13, v23, v16

  li t2, 0x1b5e52427124bec4
  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vx v16, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vv v6, v30, v10

  li t2, 0xaa88ebe293a86d20
  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vx v23, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vv v29, v23, v25

  li t2, 0xc14e73dbdc898eb2
  vsetvli t1, t0, e32, m1, ta, ma
  vaadd.vx v15, v9, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vv v16, v14, v4

  li t2, 0x2b4d54f34d7b1148
  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vx v12, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vv v24, v14, v20

  li t2, 0xab9f99f67a5040fb
  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vx v4, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vv v22, v18, v24

  li t2, 0xa177cc2ee67c891f
  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vx v30, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vv v6, v18, v4

  li t2, 0x1cd9ff2914a2db05
  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vx v28, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vv v26, v12, v20

  li t2, 0xac9f3bff53635c8e
  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vx v4, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vv v2, v18, v30

  li t2, 0x05d4cd0e6d00d588
  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vx v14, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vv v18, v14, v16

  li t2, 0x80abaf945063063e
  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vx v4, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vv v14, v8, v4

  li t2, 0x055072227f2cf26e
  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vx v22, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vv v20, v28, v18

  li t2, 0xf521460286de672f
  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vx v14, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vv v16, v30, v6

  li t2, 0xd9768fc979ca2a2b
  vsetvli t1, t0, e32, m2, ta, ma
  vaadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vv v28, v16, v12

  li t2, 0x762f6725daa0b6a7
  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vx v24, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vv v24, v28, v4

  li t2, 0xa0c6305d92581ba5
  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vx v20, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vv v4, v12, v16

  li t2, 0xb6da3bd5ff3d2879
  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vx v16, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vv v20, v8, v12

  li t2, 0xb8251f4f06cfa4d7
  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vx v24, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vv v20, v8, v24

  li t2, 0x29e393766c0793ed
  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vx v16, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vv v12, v28, v20

  li t2, 0xe1739a8ab78c62e6
  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vx v8, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vv v28, v8, v24

  li t2, 0xa21a632fece6f9f0
  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vx v16, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vv v4, v12, v8

  li t2, 0x81771f51d23944ba
  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vx v4, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vv v28, v16, v24

  li t2, 0x830be51be307c19f
  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vx v16, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vv v8, v24, v4

  li t2, 0x430efd709bd43394
  vsetvli t1, t0, e32, m4, ta, ma
  vaadd.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vv v16, v8, v24

  li t2, 0x97f0c8739f07e4fa
  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vv v24, v8, v16

  li t2, 0xe126e14490ef3912
  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vv v24, v16, v8

  li t2, 0xb893ec770964be01
  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vv v16, v8, v24

  li t2, 0xa3a6471ec9c2a72c
  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vv v16, v24, v8

  li t2, 0x077e2c72dba12597
  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vv v24, v8, v16

  li t2, 0xfd4b2fd66113b07b
  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vv v16, v8, v24

  li t2, 0xdaf8173db5251802
  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vv v24, v16, v8

  li t2, 0xe36a4e75d991c09e
  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vv v24, v8, v16

  li t2, 0x9ffda15d7774cb69
  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vv v16, v8, v24

  li t2, 0xd05eedeb6c23d0cd
  vsetvli t1, t0, e32, m8, ta, ma
  vaadd.vx v16, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vv v6, v14, v20

  li t2, 0x39612e529e806a47
  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vx v10, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vv v23, v25, v2

  li t2, 0x26c4b419564a7630
  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vx v19, v6, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vv v29, v23, v16

  li t2, 0xe7560a42a4631423
  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vx v8, v5, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vv v13, v2, v29

  li t2, 0x33e56464840fb9a3
  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vx v27, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vv v9, v8, v18

  li t2, 0xbaa5b5a04fbe2884
  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vx v30, v15, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vv v22, v28, v7

  li t2, 0x0c917ca078d1b9e9
  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vx v26, v4, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vv v18, v21, v13

  li t2, 0xf478659a91e8fb94
  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vx v9, v7, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vv v2, v26, v30

  li t2, 0x7b4d5b3b3002f7a8
  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vx v28, v5, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vv v15, v3, v30

  li t2, 0xed018ad9726a6f26
  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vx v27, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vv v1, v20, v17

  li t2, 0x343db0e5a39f0530
  vsetvli t1, t0, e64, m1, ta, ma
  vaadd.vx v11, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vv v6, v12, v14

  li t2, 0x7219fee9099f2546
  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vx v22, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vv v26, v24, v18

  li t2, 0xb58e18ee488670db
  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vx v6, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vv v8, v26, v22

  li t2, 0x611f895eb95b2b8a
  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vx v10, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vv v6, v26, v12

  li t2, 0x662f43bac53e8553
  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vx v30, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vv v6, v2, v16

  li t2, 0x9ac84feaea79c3d1
  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vx v18, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vv v18, v20, v24

  li t2, 0xc635f31ee70aa0ee
  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vx v18, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vv v6, v22, v28

  li t2, 0x2611e0e8805e41e0
  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vx v18, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vv v8, v16, v30

  li t2, 0x95aa742c9dbb9555
  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vx v26, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vv v16, v2, v30

  li t2, 0xeed8444d47ea7883
  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vx v28, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vv v22, v28, v4

  li t2, 0x429745af83c14bb9
  vsetvli t1, t0, e64, m2, ta, ma
  vaadd.vx v18, v14, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vv v24, v16, v20

  li t2, 0x7f3fcd857267d3f3
  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vx v24, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vv v8, v20, v16

  li t2, 0x0554363dc91afc35
  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vx v20, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vv v4, v28, v12

  li t2, 0xe4e3c424d26a406e
  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vx v16, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vv v20, v12, v16

  li t2, 0xd95345a8a4a4c7f3
  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vx v12, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vv v12, v20, v24

  li t2, 0x99b2fc93db83d3eb
  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vv v28, v20, v16

  li t2, 0x4dd8be9f3c776691
  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vx v24, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vv v4, v28, v20

  li t2, 0x7faf7c7d89253778
  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vv v12, v16, v4

  li t2, 0x5ae0aaefa6c14fd5
  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vx v16, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vv v4, v24, v20

  li t2, 0xd4f7e63d8021520d
  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vx v4, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vv v12, v8, v24

  li t2, 0xf186bdc8c2cdf453
  vsetvli t1, t0, e64, m4, ta, ma
  vaadd.vx v8, v4, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vv v16, v24, v8

  li t2, 0x5f20f7c35974a9d4
  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vv v16, v24, v8

  li t2, 0x837748ccb4d14d1f
  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vv v24, v8, v16

  li t2, 0xe38c015e0c767a23
  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vv v8, v24, v16

  li t2, 0xe077c2e51885f5c6
  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vv v24, v16, v8

  li t2, 0xbedd9ff46b157ffa
  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vv v8, v24, v16

  li t2, 0x57e93a542600fb17
  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vv v24, v8, v16

  li t2, 0xb2b34fccd5642c42
  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vv v8, v24, v16

  li t2, 0xb9f00d725ec748f1
  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vv v24, v16, v8

  li t2, 0x897d1926ca063795
  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vv v16, v24, v8

  li t2, 0x1a17955358762fb4
  vsetvli t1, t0, e64, m8, ta, ma
  vaadd.vx v8, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
