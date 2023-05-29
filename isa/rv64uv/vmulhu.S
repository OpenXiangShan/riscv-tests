#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vv v12, v29, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vv v20, v4, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vv v31, v10, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vv v28, v17, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vv v8, v7, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vv v19, v21, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vv v10, v2, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vv v8, v23, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vv v10, v7, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vv v7, v21, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vv v8, v26, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vv v14, v8, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vv v18, v24, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vv v30, v8, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vv v20, v24, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vv v20, v6, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vv v14, v20, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vv v14, v20, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vv v14, v16, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vv v28, v14, v22

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vv v8, v28, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vv v28, v16, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vv v4, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vv v4, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vv v12, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vv v28, v8, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vv v4, v20, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vv v12, v20, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vv v4, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vv v8, v16, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vv v18, v1, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vv v16, v23, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vv v20, v29, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vv v28, v15, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vv v21, v23, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vv v22, v3, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vv v15, v23, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vv v12, v28, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vv v30, v24, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vv v23, v21, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vv v20, v6, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vv v14, v30, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vv v8, v10, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vv v12, v6, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vv v10, v18, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vv v20, v16, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vv v6, v16, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vv v30, v12, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vv v6, v12, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vv v14, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vv v12, v4, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vv v12, v8, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vv v24, v12, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vv v20, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vv v24, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vv v16, v28, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vv v24, v28, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vv v16, v20, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vv v4, v20, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vv v12, v20, v4

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vv v16, v8, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vv v23, v26, v5

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vv v17, v7, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vv v22, v26, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vv v21, v13, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vv v18, v28, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vv v26, v23, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vv v3, v23, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vv v9, v26, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vv v13, v24, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vv v20, v15, v29

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vv v10, v4, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vv v12, v26, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vv v20, v24, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vv v12, v2, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vv v4, v24, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vv v4, v22, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vv v18, v14, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vv v16, v12, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vv v4, v6, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vv v28, v18, v6

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vv v24, v20, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vv v4, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vv v28, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vv v16, v24, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vv v8, v28, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vv v4, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vv v4, v20, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vv v28, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vv v28, v12, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vv v24, v12, v20

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vv v24, v8, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vv v29, v7, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vv v26, v21, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vv v29, v22, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vv v17, v25, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vv v25, v18, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vv v2, v17, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vv v18, v3, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vv v13, v1, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vv v17, v24, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vv v15, v5, v17

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vv v18, v4, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vv v8, v18, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vv v8, v18, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vv v12, v2, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vv v4, v24, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vv v16, v24, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vv v20, v30, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vv v4, v8, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vv v28, v30, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vv v14, v10, v18

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vv v28, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vv v20, v24, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vv v12, v28, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vv v16, v8, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vv v28, v12, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vv v8, v24, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vv v4, v20, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vv v8, v4, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vv v4, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vv v8, v4, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vv v8, v16, v24

  li t2, 0x4c65d93ffb8423bf
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v30, v19, t2

  li t2, 0x1c97c120139d610b
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v14, v20, t2

  li t2, 0x1e17e60b798500ad
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v13, v14, t2

  li t2, 0xf20d04788804cb53
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v3, v25, t2

  li t2, 0x0b0115937811c824
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v1, v16, t2

  li t2, 0x33cca3babbdb9556
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v21, v29, t2

  li t2, 0xf3dec238032ce1fa
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v13, v1, t2

  li t2, 0xdf6e071d3604f154
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v12, v28, t2

  li t2, 0xd9781fa3732e4f69
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v27, v29, t2

  li t2, 0x485c26a4e8f7557f
  vsetvli t1, t0, e8, m1, ta, ma
  vmulhu.vx v8, v4, t2

  li t2, 0xac89a709aa1cec96
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v14, v8, t2

  li t2, 0x9200d5343eb2f370
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v20, v10, t2

  li t2, 0xefccb4d11d8e9fb9
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v18, v12, t2

  li t2, 0x7cd844b82b1150c8
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v24, v14, t2

  li t2, 0x90bb6a7db1acdb9c
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v22, v30, t2

  li t2, 0x73dc39f7ca722a3d
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v4, v28, t2

  li t2, 0xc5c754f938af5104
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v4, v16, t2

  li t2, 0xb1cae790eda04e3a
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v12, v30, t2

  li t2, 0xbff861098b67ca83
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v14, v12, t2

  li t2, 0xb894fe1669e961f2
  vsetvli t1, t0, e8, m2, ta, ma
  vmulhu.vx v14, v30, t2

  li t2, 0xe059d4fef028567e
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v8, v16, t2

  li t2, 0x53614040693b8e06
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v20, v28, t2

  li t2, 0x70192cb09353d9aa
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v24, v28, t2

  li t2, 0xf7ca83368ef28f24
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v24, v8, t2

  li t2, 0x79a424de3aa32bd1
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v28, v8, t2

  li t2, 0x8103abdf2293b5ba
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v24, v4, t2

  li t2, 0x6fbc4633b9196b09
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v8, v20, t2

  li t2, 0x0f2f85a204cf55b4
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v20, v16, t2

  li t2, 0xc5f705fce7809cd0
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v4, v12, t2

  li t2, 0xdb2ab349aee342a3
  vsetvli t1, t0, e8, m4, ta, ma
  vmulhu.vx v24, v8, t2

  li t2, 0xc21786eef871e0a2
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v8, v16, t2

  li t2, 0xc28285dafb491f87
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v8, v24, t2

  li t2, 0x498c8dea22fd7c6f
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v16, v24, t2

  li t2, 0xa873f6363e65aac7
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v8, v16, t2

  li t2, 0xf5c4e17e1c1e0173
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v16, v24, t2

  li t2, 0x7b7f6670b38bf478
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v24, v16, t2

  li t2, 0x5c5a91fea0f84e2f
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v24, v8, t2

  li t2, 0xf1b08bc192e924d1
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v8, v16, t2

  li t2, 0xea8332b1146bfdf5
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v16, v24, t2

  li t2, 0x78874db1c47c7576
  vsetvli t1, t0, e8, m8, ta, ma
  vmulhu.vx v8, v16, t2

  li t2, 0x30baac5cda93091e
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v1, v9, t2

  li t2, 0x63a8fbfb20d0c6dc
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v2, v1, t2

  li t2, 0x028dbde80be1b0f6
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v7, v26, t2

  li t2, 0xf6b2d0424bead020
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v25, v18, t2

  li t2, 0xa1fc1212f255ca41
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v20, v25, t2

  li t2, 0x88f6a1773596dbd7
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v30, v17, t2

  li t2, 0xdcb01af41da6a53f
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v4, v21, t2

  li t2, 0xc48c72e4c61d7732
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v19, v18, t2

  li t2, 0xec785b410e254fe3
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v19, v7, t2

  li t2, 0x43af898ca835ae39
  vsetvli t1, t0, e16, m1, ta, ma
  vmulhu.vx v31, v12, t2

  li t2, 0xb9895b7d01c44d45
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v24, v6, t2

  li t2, 0xbf43d472bdfc506d
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v28, v8, t2

  li t2, 0x1c8191e6f522ed68
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v16, v8, t2

  li t2, 0x5f8f9517cc1207df
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v2, v6, t2

  li t2, 0x5ffeb0d152780be6
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v10, v28, t2

  li t2, 0x66008bc1e1db51dc
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v20, v6, t2

  li t2, 0x4db650119276a66d
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v20, v30, t2

  li t2, 0xc20f38b64805be67
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v14, v22, t2

  li t2, 0x7f4632abd1787b97
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v26, v30, t2

  li t2, 0x489609f002e49d5d
  vsetvli t1, t0, e16, m2, ta, ma
  vmulhu.vx v10, v30, t2

  li t2, 0x1eac613423637485
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v20, v16, t2

  li t2, 0xee2e61e73c395a7e
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v24, v20, t2

  li t2, 0x80c02a5daca60bf2
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v12, v4, t2

  li t2, 0x5713dfc93192a47d
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v12, v8, t2

  li t2, 0x27a815cab2dc85a2
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v24, v20, t2

  li t2, 0x6c18d521f63dd20c
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v28, v8, t2

  li t2, 0xe724054cbd37f8e4
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v20, v16, t2

  li t2, 0xf0ad0410ed104b4a
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v8, v28, t2

  li t2, 0x32939f62e1513d0e
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v12, v20, t2

  li t2, 0x8fa8dba343a13ae5
  vsetvli t1, t0, e16, m4, ta, ma
  vmulhu.vx v8, v16, t2

  li t2, 0xee48047834aaf641
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v8, v16, t2

  li t2, 0x0b4f489c211d32eb
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v8, v24, t2

  li t2, 0xf2e4f60e59539833
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v24, v8, t2

  li t2, 0xaee252675be906e7
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v8, v24, t2

  li t2, 0x4953f81e32ac4cba
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v16, v8, t2

  li t2, 0xf936bdc35a2fb54b
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v16, v24, t2

  li t2, 0x89634377875f07bc
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v24, v16, t2

  li t2, 0x12fbe8c1059875d7
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v16, v24, t2

  li t2, 0x2be5b98b207759f0
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v8, v24, t2

  li t2, 0xde4b5497d0440f79
  vsetvli t1, t0, e16, m8, ta, ma
  vmulhu.vx v8, v16, t2

  li t2, 0x4396f3979ec9c6ae
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v1, v20, t2

  li t2, 0xce3d1e11d1047670
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v25, v28, t2

  li t2, 0xe693285656158eb1
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v26, v24, t2

  li t2, 0x6048d346cb4aba21
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v29, v1, t2

  li t2, 0x720177947fa6b6bd
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v18, v26, t2

  li t2, 0x34d5a2f1b5b52eec
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v29, v2, t2

  li t2, 0x0a5aef3e4d552b03
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v30, v10, t2

  li t2, 0x11d0ca1466c37a9f
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v12, v6, t2

  li t2, 0x4d93fb5ef589195c
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v29, v1, t2

  li t2, 0x9c1894f8d9a68e7a
  vsetvli t1, t0, e32, m1, ta, ma
  vmulhu.vx v27, v29, t2

  li t2, 0xe86f87cd9b43bf65
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v10, v6, t2

  li t2, 0x7a54228269c6b522
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v4, v20, t2

  li t2, 0xde819ee89cd32be8
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v26, v30, t2

  li t2, 0x32174f6feb4e2a87
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v10, v8, t2

  li t2, 0x6bd78db9f37d1f23
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v18, v24, t2

  li t2, 0xee4158d3c5d21f6a
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v10, v8, t2

  li t2, 0x66ac3ee5d98e2c5d
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v6, v4, t2

  li t2, 0x2105129c03e15166
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v22, v8, t2

  li t2, 0xade89b93861c7636
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v4, v14, t2

  li t2, 0x308423384b605bda
  vsetvli t1, t0, e32, m2, ta, ma
  vmulhu.vx v10, v12, t2

  li t2, 0x30c469fd449bfa8e
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v12, v4, t2

  li t2, 0x8912393857f36a8f
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v28, v8, t2

  li t2, 0xb7af4cc457859d77
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v12, v8, t2

  li t2, 0xf820f49baa408123
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v20, v4, t2

  li t2, 0xc337df81e37f5e2c
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v16, v8, t2

  li t2, 0x7e303acef88398c3
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v12, v20, t2

  li t2, 0xb361d2b637e2c6f5
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v8, v20, t2

  li t2, 0xcffcb0140398063e
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v12, v16, t2

  li t2, 0x630daf6f0ebd58f6
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v20, v8, t2

  li t2, 0x021c2b672219dbd9
  vsetvli t1, t0, e32, m4, ta, ma
  vmulhu.vx v24, v28, t2

  li t2, 0xac853cd5a0aa72fb
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v24, v16, t2

  li t2, 0x72346526ace061eb
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v16, v8, t2

  li t2, 0x060ebf303be6e48f
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v24, v16, t2

  li t2, 0x9b2574da8ee13d4b
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v8, v16, t2

  li t2, 0x9d70c898f3f237b3
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v16, v8, t2

  li t2, 0x169d673e3c178480
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v24, v8, t2

  li t2, 0x21df55642aecf13c
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v16, v24, t2

  li t2, 0x3b4be4cd6517fc71
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v24, v16, t2

  li t2, 0x73024b57888c12e6
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v16, v24, t2

  li t2, 0xe5ff39b01ddc6f9e
  vsetvli t1, t0, e32, m8, ta, ma
  vmulhu.vx v8, v16, t2

  li t2, 0x13cbb630a826cf8d
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v21, v13, t2

  li t2, 0xed9a88e6ad549dde
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v7, v24, t2

  li t2, 0x50e44f78d2ea00b9
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v28, v14, t2

  li t2, 0xbf878c26d771764f
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v27, v8, t2

  li t2, 0x43d8855b970ce7be
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v27, v14, t2

  li t2, 0x855dbd85a1950afc
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v28, v1, t2

  li t2, 0xea86d0500b2d0d90
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v17, v21, t2

  li t2, 0x1e5b56f045ddc095
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v11, v10, t2

  li t2, 0x292731c5468c1c36
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v10, v22, t2

  li t2, 0xe97d40b8a667e96c
  vsetvli t1, t0, e64, m1, ta, ma
  vmulhu.vx v4, v9, t2

  li t2, 0x5025c802888bc048
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v22, v18, t2

  li t2, 0x4140a64ff772669d
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v28, v4, t2

  li t2, 0xab03773993c670da
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v26, v22, t2

  li t2, 0x671bfe0b00256f16
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v14, v24, t2

  li t2, 0xbcb7348451bbb99d
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v2, v18, t2

  li t2, 0x276425316cfc3538
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v28, v14, t2

  li t2, 0xf8de713c87a7ab9e
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v22, v16, t2

  li t2, 0x97b94d9055a9b8bf
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v2, v18, t2

  li t2, 0xc7765936ba53d0bb
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v18, v10, t2

  li t2, 0xd2289d27c4fce83f
  vsetvli t1, t0, e64, m2, ta, ma
  vmulhu.vx v12, v10, t2

  li t2, 0x9c659795b7b827f6
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v12, v20, t2

  li t2, 0xd54706c4a7d31992
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v28, v24, t2

  li t2, 0xf7aac7ba960ad21a
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v8, v12, t2

  li t2, 0x1c1c16b35fb5d8ea
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v8, v4, t2

  li t2, 0x473673e8718b45aa
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v20, v12, t2

  li t2, 0x2f199cfb98e63da3
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v16, v28, t2

  li t2, 0xea1f98494587d7e5
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v4, v8, t2

  li t2, 0xe6aac732448f4175
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v8, v20, t2

  li t2, 0x68a6141948a1066c
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v4, v16, t2

  li t2, 0x5c8e3e0d5a93ea53
  vsetvli t1, t0, e64, m4, ta, ma
  vmulhu.vx v12, v8, t2

  li t2, 0x64ddd563810b8ca8
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v16, v8, t2

  li t2, 0x3805fb4de7e0a786
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v8, v24, t2

  li t2, 0xac4225d876259d32
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v8, v16, t2

  li t2, 0xb85e2953a337a73e
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v8, v16, t2

  li t2, 0x8277d3157d2b90da
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v16, v24, t2

  li t2, 0xf8d7cee5a7e4787d
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v24, v8, t2

  li t2, 0x3783f5bcecc02b0c
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v24, v8, t2

  li t2, 0x3e31e4c7882b5829
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v16, v8, t2

  li t2, 0x9674c719acf3d40f
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v8, v16, t2

  li t2, 0x8a4bc1c0f305d0b2
  vsetvli t1, t0, e64, m8, ta, ma
  vmulhu.vx v8, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
