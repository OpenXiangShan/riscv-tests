#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vv v18, v19, v17

  li t2, 0xcc818002fd398f3d
  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vx v27, v1, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vv v26, v14, v29

  li t2, 0xf00b5a44832576c7
  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vx v15, v23, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vv v27, v29, v21

  li t2, 0x1561e8118a09febf
  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vx v3, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vv v14, v11, v3

  li t2, 0x53e31c30e2672344
  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vx v5, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vv v28, v26, v23

  li t2, 0xf5701354e349d6aa
  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vx v26, v15, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vv v18, v23, v17

  li t2, 0xac62c6ccf661e2fb
  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vx v15, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vv v31, v5, v26

  li t2, 0x77a96e01af6d3918
  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vx v15, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vv v23, v3, v7

  li t2, 0x00fc568bb3ab8c13
  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vx v9, v10, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vv v23, v31, v13

  li t2, 0xbfb65f00497442d9
  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vx v3, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vv v25, v27, v9

  li t2, 0xa4962507c34ad781
  vsetvli t1, t0, e8, m1, ta, ma
  vasubu.vx v31, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vv v14, v20, v22

  li t2, 0x645d33f7c1ca616b
  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vx v2, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vv v22, v30, v28

  li t2, 0x2466f46e3ef076c2
  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vx v8, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vv v22, v8, v14

  li t2, 0xed32792bf0878186
  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vx v4, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vv v26, v20, v14

  li t2, 0x3fc36eb1b2b2d576
  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vx v20, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vv v28, v6, v10

  li t2, 0x5f269b43114e3139
  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vx v28, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vv v18, v30, v10

  li t2, 0xd213b15cae46e05c
  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vx v18, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vv v8, v26, v10

  li t2, 0x4b2d0dacac339d16
  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vx v30, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vv v2, v20, v30

  li t2, 0xec38cef6a932e096
  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vv v8, v12, v30

  li t2, 0x8252bae8168647ef
  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vx v2, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vv v22, v4, v12

  li t2, 0x75dfb73e75bb9fb0
  vsetvli t1, t0, e8, m2, ta, ma
  vasubu.vx v18, v30, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vv v8, v28, v16

  li t2, 0xc7668c985d29ab3b
  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vx v20, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vv v8, v24, v20

  li t2, 0x8823fbb29ffea7e8
  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vx v20, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vv v4, v28, v20

  li t2, 0x34e17970fb814fce
  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vx v8, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vv v16, v24, v28

  li t2, 0x6dfa1ae5387ce2b1
  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vx v28, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vv v16, v12, v24

  li t2, 0xec86f2ac4aedaa58
  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vx v20, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vv v28, v24, v12

  li t2, 0x89ec05c7f09e4dec
  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vx v4, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vv v8, v4, v28

  li t2, 0x1e6f9090f67a6c7b
  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vx v28, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vv v28, v24, v12

  li t2, 0xa48f0a3c8f99c09f
  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vv v12, v8, v20

  li t2, 0xf4a37aa2cdfc2a20
  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vx v12, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vv v16, v8, v28

  li t2, 0x26c2d9fea2b79429
  vsetvli t1, t0, e8, m4, ta, ma
  vasubu.vx v12, v20, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vv v8, v24, v16

  li t2, 0xc0000c8a064bd729
  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vv v8, v16, v24

  li t2, 0x4e63ec52a784df14
  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vv v16, v24, v8

  li t2, 0xc0713a3cf30dda83
  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vv v24, v8, v16

  li t2, 0x4f1f254fccfd2d45
  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vv v24, v16, v8

  li t2, 0x2008ea55adac19a9
  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vv v24, v16, v8

  li t2, 0x6e9e0e6a4937983f
  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vv v16, v24, v8

  li t2, 0x08d329f7ae0db382
  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vv v24, v8, v16

  li t2, 0x167b66abd25d1b7a
  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vv v16, v8, v24

  li t2, 0xbc2dab9b6626afe9
  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vv v8, v16, v24

  li t2, 0x03d6a286a6c28781
  vsetvli t1, t0, e8, m8, ta, ma
  vasubu.vx v24, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vv v19, v1, v21

  li t2, 0x41f8faa42f2d0954
  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vx v12, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vv v30, v29, v22

  li t2, 0x5e3fe65f1e7d954b
  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vx v31, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vv v27, v6, v22

  li t2, 0x027f94d1740c5706
  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vx v30, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vv v4, v28, v17

  li t2, 0xcd017e2a914bcc7a
  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vx v9, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vv v25, v22, v24

  li t2, 0xf312b9dd70fcd362
  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vx v1, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vv v17, v20, v12

  li t2, 0x19fe1eb71fddb4da
  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vx v13, v12, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vv v31, v17, v29

  li t2, 0x74964026c94836e9
  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vx v2, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vv v3, v4, v20

  li t2, 0xe86bc2c33d22f327
  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vx v8, v5, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vv v17, v12, v24

  li t2, 0xf1cfb2c398a54000
  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vx v21, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vv v11, v5, v9

  li t2, 0x1ace6b3fa59503d9
  vsetvli t1, t0, e16, m1, ta, ma
  vasubu.vx v31, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vv v14, v12, v30

  li t2, 0x050d098d04651a6c
  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vx v6, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vv v4, v18, v14

  li t2, 0x6194d7775a8e15be
  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vx v10, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vv v2, v8, v20

  li t2, 0x06c96a6465092b67
  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vx v18, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vv v18, v26, v24

  li t2, 0x57f34bb99aa71254
  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vx v12, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vv v8, v10, v24

  li t2, 0xeb6f2cc2f784a29a
  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vx v2, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vv v14, v6, v16

  li t2, 0x76b17fa7eca12a76
  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vx v4, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vv v4, v6, v30

  li t2, 0x8fec86ace3447782
  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vx v10, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vv v10, v16, v28

  li t2, 0xa9aff6d385579e3a
  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vx v2, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vv v4, v10, v24

  li t2, 0x607847233779dec0
  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vx v26, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vv v4, v26, v2

  li t2, 0xe5d395caf6d40238
  vsetvli t1, t0, e16, m2, ta, ma
  vasubu.vx v6, v14, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vv v28, v8, v4

  li t2, 0x7bf6a4321adafb03
  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vx v4, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vv v20, v8, v12

  li t2, 0x95593d1da1da1033
  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vx v8, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vv v4, v8, v20

  li t2, 0x8a671a6090db236a
  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vx v20, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vv v12, v8, v28

  li t2, 0xe130c33c2f20502f
  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vx v20, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vv v28, v24, v16

  li t2, 0xa20077cd95fb87f4
  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vx v28, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vv v12, v8, v4

  li t2, 0x3851e68f7bc45484
  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vv v20, v4, v24

  li t2, 0x1b00a9233e6deff7
  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vx v24, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vv v8, v28, v24

  li t2, 0x641eab3415df8900
  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vv v4, v24, v28

  li t2, 0x2a7d6bf6e4919d97
  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vx v28, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vv v8, v4, v20

  li t2, 0x42debe81e60d68f8
  vsetvli t1, t0, e16, m4, ta, ma
  vasubu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vv v24, v16, v8

  li t2, 0x9d1d107c3b0e4acc
  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vv v16, v24, v8

  li t2, 0xeb16864c170e4bc2
  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vv v24, v16, v8

  li t2, 0x0ce3c5ae1b12e882
  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vv v8, v24, v16

  li t2, 0x963dd52cb128a507
  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vv v16, v8, v24

  li t2, 0x7b0d5ac4492799b9
  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vv v16, v8, v24

  li t2, 0x7528403b5eaeeea7
  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vv v24, v8, v16

  li t2, 0xf6e8cf143eaf0ea0
  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vv v16, v8, v24

  li t2, 0x309c9ee70eb7f210
  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vv v16, v24, v8

  li t2, 0xc088fbe49b875d27
  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vv v16, v24, v8

  li t2, 0xe5a8dc0317502957
  vsetvli t1, t0, e16, m8, ta, ma
  vasubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vv v14, v1, v26

  li t2, 0xa0667e657727b7a6
  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vx v12, v11, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vv v19, v26, v3

  li t2, 0x50b23da585614122
  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vx v12, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vv v8, v7, v10

  li t2, 0x72fb95b4ef63786f
  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vx v25, v2, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vv v12, v5, v17

  li t2, 0xed1f5cbc82d3a724
  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vx v8, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vv v23, v21, v10

  li t2, 0x76e3961e1e87507c
  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vx v3, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vv v28, v24, v23

  li t2, 0x80301582519cf9e8
  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vx v8, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vv v6, v2, v8

  li t2, 0xbbab2b7eed7f8e4a
  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vx v19, v31, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vv v31, v1, v3

  li t2, 0x9c2fd46284532c96
  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vx v29, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vv v3, v11, v14

  li t2, 0x8c6fc55e141eb682
  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vx v5, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vv v10, v23, v20

  li t2, 0x4a0f6a93ed603f49
  vsetvli t1, t0, e32, m1, ta, ma
  vasubu.vx v22, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vv v26, v16, v2

  li t2, 0xa6af24e9f1d3137e
  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vx v10, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vv v10, v14, v20

  li t2, 0xc16bb91b3422196c
  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vx v6, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vv v14, v24, v20

  li t2, 0xdc785c0fa3b9fd90
  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vx v26, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vv v28, v12, v18

  li t2, 0x17e9aceedb215374
  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vx v2, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vv v30, v14, v18

  li t2, 0x64c5e59639b3b543
  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vx v26, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vv v18, v6, v28

  li t2, 0xb3b44d7e2199df68
  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vx v4, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vv v28, v6, v8

  li t2, 0xee3b4eb3f1ff0957
  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vx v4, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vv v6, v28, v30

  li t2, 0x3f589040db01d26a
  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vx v24, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vv v4, v12, v18

  li t2, 0x7df2f278b6b7fe73
  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vx v12, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vv v6, v14, v18

  li t2, 0x14c95c5384c9cb2d
  vsetvli t1, t0, e32, m2, ta, ma
  vasubu.vx v16, v22, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vv v12, v20, v28

  li t2, 0x91bfbd08735b0922
  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vv v28, v8, v20

  li t2, 0xf9d2e8266b00920d
  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vv v20, v12, v4

  li t2, 0xa179167dbbbcbc36
  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vx v4, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vv v12, v16, v8

  li t2, 0xd2daa6e39bafcfd2
  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vx v4, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vv v28, v8, v24

  li t2, 0x1701cdb07ef26a6e
  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vv v4, v8, v12

  li t2, 0x0c56898586119493
  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vx v28, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vv v20, v8, v12

  li t2, 0x5c64a5e866a60922
  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vx v4, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vv v4, v8, v20

  li t2, 0x24f2ac8c9fdac54f
  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vv v12, v8, v4

  li t2, 0xca62ed46046bfdc0
  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vx v4, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vv v24, v20, v8

  li t2, 0xd48f55488c63cfc5
  vsetvli t1, t0, e32, m4, ta, ma
  vasubu.vx v8, v4, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vv v8, v16, v24

  li t2, 0xf43ab1e788274a1f
  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vv v24, v16, v8

  li t2, 0x4992b6dc724a7a88
  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vv v8, v24, v16

  li t2, 0xe04d0e0096e75ec8
  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vv v24, v8, v16

  li t2, 0xaec00aea89892135
  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vv v8, v16, v24

  li t2, 0x7677137c5744c9fd
  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vv v24, v16, v8

  li t2, 0x8e5096d097027b96
  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vv v8, v16, v24

  li t2, 0xb884363956398795
  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vv v8, v24, v16

  li t2, 0xe904b89ee20cb027
  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vv v8, v16, v24

  li t2, 0x013d7e36b2928022
  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vv v24, v16, v8

  li t2, 0x56a3a1c5d5c248b1
  vsetvli t1, t0, e32, m8, ta, ma
  vasubu.vx v8, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vv v7, v16, v24

  li t2, 0x2c3672c497c4ad3a
  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vx v22, v7, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vv v14, v9, v31

  li t2, 0x49cceac0cd54e509
  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vx v12, v15, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vv v16, v11, v25

  li t2, 0x28b42336a14b4d31
  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vx v12, v9, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vv v3, v16, v29

  li t2, 0xb3a3ddeba68471da
  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vx v24, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vv v12, v17, v4

  li t2, 0x84643f20fb962d6d
  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vx v13, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vv v1, v11, v10

  li t2, 0xa6741d9afeebbcf5
  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vx v14, v25, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vv v3, v7, v10

  li t2, 0x534fc90876267991
  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vx v6, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vv v30, v3, v10

  li t2, 0x66d322e29c05d8f6
  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vx v17, v6, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vv v4, v2, v15

  li t2, 0xfff4736cec3ab2db
  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vx v28, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vv v11, v7, v1

  li t2, 0xd0cc6a9a44101697
  vsetvli t1, t0, e64, m1, ta, ma
  vasubu.vx v21, v15, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vv v20, v16, v22

  li t2, 0x115bd9e1eaa39962
  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vx v20, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vv v16, v22, v10

  li t2, 0x5ccb95a348c64ef0
  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vx v16, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vv v4, v26, v8

  li t2, 0x7de4ec03df7f73cd
  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vx v26, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vv v12, v22, v16

  li t2, 0xe3cb7e02d90744d6
  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vx v30, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vv v6, v18, v12

  li t2, 0xe144c4a4170935f4
  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vx v2, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vv v16, v22, v2

  li t2, 0xbb14350bd24fce6c
  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vx v12, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vv v16, v4, v10

  li t2, 0x846ad95b6db3e277
  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vx v24, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vv v12, v8, v4

  li t2, 0x851aca820760154c
  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vx v18, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vv v28, v30, v4

  li t2, 0xc6a56a337a62fbfd
  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vx v18, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vv v22, v26, v10

  li t2, 0x63b1d3fd85bceb25
  vsetvli t1, t0, e64, m2, ta, ma
  vasubu.vx v4, v14, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vv v16, v20, v24

  li t2, 0x136caf4e192ab5f0
  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vx v20, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vv v8, v28, v4

  li t2, 0x0ae64faf46f4c26a
  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vx v8, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vv v24, v20, v4

  li t2, 0xda1b4c8216e75cf8
  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vx v16, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vv v20, v24, v16

  li t2, 0x00f99a0f5155e27c
  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vv v24, v8, v12

  li t2, 0x960dabbbaf8103e3
  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vv v24, v20, v4

  li t2, 0x75d9896fdbc3c056
  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vx v24, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vv v4, v20, v8

  li t2, 0x453abd0ec5dff6dc
  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vx v28, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vv v12, v16, v4

  li t2, 0xc8fe39063cadbde3
  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vx v28, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vv v16, v28, v20

  li t2, 0xfa0e05df916d43db
  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vx v28, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vv v28, v24, v8

  li t2, 0x518a78e802b0b743
  vsetvli t1, t0, e64, m4, ta, ma
  vasubu.vx v24, v12, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vv v24, v8, v16

  li t2, 0x4ef1f89755e1205e
  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vv v8, v24, v16

  li t2, 0x078609dbfaf7347e
  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vv v24, v8, v16

  li t2, 0x7e784343805faf12
  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vv v8, v16, v24

  li t2, 0x6fb2a73e40a6bf25
  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vv v24, v8, v16

  li t2, 0x967e5aa51e406bec
  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vv v24, v16, v8

  li t2, 0xeb8cc523bb5bcd97
  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vv v16, v24, v8

  li t2, 0xa63d449cf683f1ed
  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vv v8, v24, v16

  li t2, 0x28b003baee766ee8
  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vv v16, v24, v8

  li t2, 0x1b3b2fe8a222be92
  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vv v24, v16, v8

  li t2, 0xa1a2e41575ece514
  vsetvli t1, t0, e64, m8, ta, ma
  vasubu.vx v8, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
