#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vv v26, v3, v28

  li t2, 0xf283be34b9f1233b
  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vx v2, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vi v24, v17, -9

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vv v28, v5, v15

  li t2, 0x6bc0f6f0e4a2bb6e
  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vx v13, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vi v17, v20, -2

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vv v5, v22, v28

  li t2, 0xa8e6ee3ca9b19de7
  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vx v28, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vi v14, v22, -3

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vv v29, v9, v25

  li t2, 0x9ab1900f5575bf90
  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vx v31, v27, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vi v10, v7, -6

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vv v18, v4, v19

  li t2, 0x23e310a338076698
  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vx v30, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vi v27, v22, -9

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vv v2, v26, v29

  li t2, 0xe0b7734bbcdce34c
  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vx v13, v30, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vi v2, v27, -2

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vv v30, v27, v11

  li t2, 0xff4fa405ff1043b6
  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vx v14, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vi v24, v28, 12

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vv v28, v15, v23

  li t2, 0x5ec010b134462ee7
  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vx v10, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vi v26, v18, -13

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vv v8, v27, v11

  li t2, 0xe7eab74e8b029818
  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vx v12, v1, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vi v26, v8, -8

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vv v28, v9, v22

  li t2, 0x973c6dd7dddceba9
  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vx v6, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsadd.vi v25, v28, -15

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vv v4, v2, v30

  li t2, 0x1543b0b027eafa9e
  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vx v22, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vi v22, v24, 15

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vv v20, v8, v28

  li t2, 0x54c75f7625662a43
  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vx v20, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vi v6, v16, -9

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vv v24, v6, v16

  li t2, 0x4acf388313ce15d5
  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vx v30, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vi v14, v6, -4

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vv v10, v14, v12

  li t2, 0x4696c6e9dc316e4a
  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vx v16, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vi v30, v28, -13

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vv v8, v10, v2

  li t2, 0xbdbaba3d857f62ff
  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vx v18, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vi v30, v14, -5

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vv v12, v8, v28

  li t2, 0x30d60a237987825b
  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vx v18, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vi v4, v24, -10

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vv v4, v14, v6

  li t2, 0xe935047993117a30
  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vx v26, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vi v28, v16, -8

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vv v12, v4, v18

  li t2, 0x03be5b1434cd4319
  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vx v14, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vi v30, v4, -6

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vv v4, v14, v26

  li t2, 0xd43f5f86f82dc7d4
  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vx v10, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vi v16, v30, -4

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vv v28, v10, v16

  li t2, 0xad616285ad16f447
  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vx v16, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsadd.vi v12, v22, -1

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vv v4, v16, v12

  li t2, 0xa3a2eb7c683545a4
  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vx v4, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vi v12, v16, -2

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vv v20, v4, v16

  li t2, 0x2328152b5eadeff3
  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vx v24, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vi v24, v28, -8

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vv v24, v16, v12

  li t2, 0x0a2e4aedc032c835
  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vi v28, v4, 15

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vv v16, v8, v20

  li t2, 0xcec35bf6e013ffd7
  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vx v20, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vi v8, v4, -3

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vv v8, v24, v16

  li t2, 0xf9289488e0d5ccc6
  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vx v24, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vi v4, v8, 7

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vv v24, v12, v28

  li t2, 0x2562bf36355b09c4
  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vx v20, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vi v16, v24, -2

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vv v16, v28, v20

  li t2, 0xb9a58ed909fa8e16
  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vx v16, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vi v28, v12, -2

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vv v20, v4, v12

  li t2, 0xbfa8f510e326c9a1
  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vx v16, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vi v24, v16, -4

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vv v4, v12, v16

  li t2, 0xf01e0debb75515d0
  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vi v16, v20, -14

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vv v8, v12, v16

  li t2, 0x16be8d325cf2bae1
  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsadd.vi v4, v20, 8

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vv v16, v24, v8

  li t2, 0xba1b3c68a1e32940
  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vi v8, v24, -1

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vv v24, v8, v16

  li t2, 0x50da7aea023c3620
  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vi v24, v16, 12

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vv v8, v24, v16

  li t2, 0x0c2f2969a3b3d439
  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vi v16, v24, -7

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vv v8, v16, v24

  li t2, 0x3f70290173e5ef56
  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vi v24, v8, -5

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vv v16, v24, v8

  li t2, 0x0b9fd39b7be59d62
  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vi v24, v16, 10

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vv v8, v16, v24

  li t2, 0x35282b6a8ab18461
  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vi v16, v8, 4

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vv v8, v16, v24

  li t2, 0x749726c6bb31f626
  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vi v8, v16, -10

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vv v16, v24, v8

  li t2, 0x58a30092833da97b
  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vi v16, v24, -14

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vv v8, v16, v24

  li t2, 0x7d8337f4d85b1191
  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vi v24, v16, -5

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vv v24, v8, v16

  li t2, 0xf5b8cda359534d44
  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsadd.vi v8, v24, 0

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vv v25, v23, v10

  li t2, 0xa8da72a5a103f302
  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vx v4, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vi v9, v4, -3

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vv v23, v1, v12

  li t2, 0x27b73af885275715
  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vx v30, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vi v28, v4, -9

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vv v1, v27, v15

  li t2, 0x6a00618eeee4230d
  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vx v18, v26, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vi v22, v14, -13

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vv v2, v3, v26

  li t2, 0xa4cdb6b66d32e0aa
  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vx v26, v5, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vi v13, v27, -12

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vv v12, v6, v4

  li t2, 0x3365c66f334d6a83
  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vx v30, v12, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vi v19, v27, 4

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vv v7, v14, v11

  li t2, 0xe59eee51d5521ec0
  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vx v6, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vi v9, v23, -1

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vv v20, v6, v16

  li t2, 0xce9bab3d3bbface6
  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vx v13, v17, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vi v3, v11, -12

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vv v5, v11, v28

  li t2, 0xa021e55805a2d54b
  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vx v17, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vi v20, v10, 1

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vv v8, v5, v17

  li t2, 0x41455dfe506aee34
  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vx v10, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vi v29, v7, 15

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vv v27, v10, v30

  li t2, 0x7234fcd9b14fdc86
  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vx v10, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsadd.vi v22, v11, 2

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vv v24, v6, v16

  li t2, 0x789da905c68432e6
  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vx v30, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vi v30, v28, -11

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vv v4, v6, v10

  li t2, 0xcb1639608bc7fd87
  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vx v14, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vi v22, v24, -5

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vv v14, v22, v30

  li t2, 0xd53198ddce7a7be5
  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vx v16, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vi v8, v10, 2

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vv v20, v26, v4

  li t2, 0x30bf33a4f7d4c41e
  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vx v30, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vi v2, v4, -4

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vv v12, v30, v16

  li t2, 0x7ede3fe9bf222505
  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vx v26, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vi v4, v12, 1

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vv v28, v16, v26

  li t2, 0x776e5fe41c0f9590
  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vx v10, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vi v20, v2, 13

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vv v28, v10, v6

  li t2, 0x85506b07ac9ed66a
  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vx v2, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vi v6, v26, -7

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vv v20, v24, v16

  li t2, 0xbd31827f29d46943
  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vx v30, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vi v16, v26, -8

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vv v14, v30, v28

  li t2, 0xddd72b4c7c648ac5
  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vx v18, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vi v16, v22, 6

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vv v16, v24, v26

  li t2, 0x8b3b6a4a666c4006
  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vx v20, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsadd.vi v16, v24, -7

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vv v28, v16, v12

  li t2, 0xd169f98111c15f7b
  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vx v12, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vi v28, v20, 13

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vv v24, v12, v8

  li t2, 0x82786a4ec4703df8
  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vx v20, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vi v12, v4, 4

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vv v20, v12, v8

  li t2, 0xd7b47c63bb1daae8
  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vi v4, v24, -16

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vv v20, v16, v4

  li t2, 0x591ac11eecdac132
  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vx v4, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vi v12, v28, -13

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vv v16, v20, v28

  li t2, 0x7e4f4348e4cc97f0
  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vi v4, v28, 8

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vv v4, v16, v24

  li t2, 0xedb2d69a3f3fb2bb
  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vx v16, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vi v28, v8, -4

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vv v12, v8, v20

  li t2, 0x4644ad2919e10816
  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vx v8, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vi v8, v16, -10

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vv v28, v4, v16

  li t2, 0xef11ed6f4e659945
  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vi v4, v12, 1

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vv v16, v20, v24

  li t2, 0xd93ffa7685127082
  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vx v20, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vi v20, v4, -8

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vv v12, v24, v28

  li t2, 0xe67188cf5843cb21
  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vx v20, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsadd.vi v20, v12, 6

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vv v8, v16, v24

  li t2, 0x9c9c394e64ac4d5c
  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vi v8, v16, -9

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vv v16, v8, v24

  li t2, 0xc7bfc32db779d883
  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vi v16, v8, -14

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vv v8, v24, v16

  li t2, 0x3d09b63339458c03
  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vi v24, v16, 5

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vv v24, v16, v8

  li t2, 0xfe2f7a2fe4f1529f
  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vi v24, v16, 4

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vv v16, v8, v24

  li t2, 0xd5ed03c37fc4fe5b
  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vi v24, v8, 12

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vv v8, v24, v16

  li t2, 0x02644866020e0e43
  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vi v8, v24, -16

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vv v8, v24, v16

  li t2, 0x4200c595434ec253
  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vi v24, v16, -14

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vv v24, v8, v16

  li t2, 0xb0c56780146a98d4
  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vi v16, v8, 11

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vv v24, v16, v8

  li t2, 0xeb24321307bd514c
  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vi v24, v16, 14

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vv v8, v16, v24

  li t2, 0xadf1fff105a088f0
  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsadd.vi v16, v24, 5

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vv v28, v29, v12

  li t2, 0x08a17dd76ca76046
  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vx v3, v11, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vi v19, v26, -14

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vv v7, v6, v17

  li t2, 0x0d5252cb0af6cc9f
  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vx v23, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vi v16, v17, -11

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vv v29, v22, v19

  li t2, 0xc324e67a3a3c87ab
  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vx v20, v3, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vi v28, v30, -11

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vv v24, v17, v31

  li t2, 0x7710e849582d1237
  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vx v19, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vi v10, v6, 15

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vv v21, v16, v8

  li t2, 0x7e96f33d6fe8bacd
  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vx v24, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vi v13, v17, -6

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vv v16, v3, v10

  li t2, 0xc368ee7dda438c61
  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vx v7, v23, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vi v1, v15, 2

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vv v29, v1, v27

  li t2, 0xc1b754a41da5a88c
  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vx v21, v3, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vi v7, v1, 9

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vv v15, v7, v24

  li t2, 0x464c7624a38f4ac8
  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vx v4, v29, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vi v29, v10, 2

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vv v8, v27, v21

  li t2, 0x85e6f7551dad2d2e
  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vx v3, v23, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vi v1, v21, -8

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vv v13, v10, v7

  li t2, 0x98d1726dbdf5353e
  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vx v22, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsadd.vi v3, v27, 1

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vv v22, v14, v26

  li t2, 0xdddda8e9241a64ed
  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vx v10, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vi v30, v6, 13

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vv v12, v24, v4

  li t2, 0x0fa2b0c0ad0a4e59
  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vx v12, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vi v24, v2, -12

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vv v28, v12, v10

  li t2, 0xabbb29cfa73a0d48
  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vx v22, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vi v10, v16, -13

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vv v26, v10, v2

  li t2, 0xf1325efd3fd8d0fa
  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vx v6, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vi v4, v18, -6

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vv v24, v10, v16

  li t2, 0xb48a49765a015ca3
  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vx v6, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vi v20, v26, -16

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vv v6, v22, v8

  li t2, 0xc6cfe4bd77cb7b0c
  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vx v24, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vi v10, v14, -9

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vv v16, v20, v18

  li t2, 0x945bdac106ad7ef2
  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vx v12, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vi v14, v18, 7

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vv v28, v22, v6

  li t2, 0x87ebdd3c9acb9e08
  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vx v6, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vi v30, v24, -6

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vv v8, v24, v16

  li t2, 0x66961dbc885e3fbe
  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vx v30, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vi v22, v20, 1

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vv v16, v26, v8

  li t2, 0x6bc84f2999d24a14
  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vx v16, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsadd.vi v4, v30, -11

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vv v28, v12, v24

  li t2, 0x7c164455f627b522
  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vx v12, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vi v12, v28, -9

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vv v12, v4, v20

  li t2, 0x51431a5beef5ad70
  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vx v20, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vi v12, v8, -13

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vv v20, v4, v28

  li t2, 0x1fb3524e0abb6e10
  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vi v8, v16, 14

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vv v24, v28, v8

  li t2, 0xe506ef375f6621b6
  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vx v16, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vi v16, v20, -16

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vv v24, v12, v28

  li t2, 0xf24f1079bedfe5be
  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vx v8, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vi v12, v8, 13

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vv v8, v4, v20

  li t2, 0x025a6354ebf78970
  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vx v28, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vi v16, v4, -11

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vv v20, v16, v4

  li t2, 0x1718cd112a92fb69
  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vx v16, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vi v24, v28, 10

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vv v28, v12, v24

  li t2, 0xfc9e8a9dfecb3998
  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vx v12, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vi v28, v20, 2

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vv v20, v24, v28

  li t2, 0xbff95e2b9e97799e
  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vx v4, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vi v4, v12, -12

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vv v20, v4, v16

  li t2, 0xdb72f7a2927e7df6
  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vx v28, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsadd.vi v20, v4, 8

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vv v8, v16, v24

  li t2, 0x09e156bdab45d278
  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vi v16, v8, -15

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vv v8, v24, v16

  li t2, 0x13bef7cf086887c0
  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vi v24, v16, -13

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vv v16, v8, v24

  li t2, 0x6ab07520f7ded825
  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vi v16, v24, -11

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vv v16, v24, v8

  li t2, 0x2c4a81b0d607bcf3
  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vi v24, v16, -2

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vv v16, v8, v24

  li t2, 0xfaa95c49a4d974cb
  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vi v8, v24, 6

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vv v8, v16, v24

  li t2, 0xdcf785a959b19baa
  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vi v8, v16, 0

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vv v8, v16, v24

  li t2, 0x67878814a25a91e9
  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vi v8, v24, -1

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vv v8, v24, v16

  li t2, 0xecb5328ee1114e94
  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vi v8, v24, -6

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vv v8, v16, v24

  li t2, 0x6a1ea5612fb6bdab
  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vi v16, v8, 8

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vv v16, v24, v8

  li t2, 0xe4947fc9a90f59da
  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsadd.vi v24, v16, -16

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vv v7, v16, v11

  li t2, 0x8d3486f717b8b27e
  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vx v2, v22, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vi v4, v19, -14

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vv v10, v6, v18

  li t2, 0x4f6521514d1b9b30
  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vx v6, v9, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vi v8, v21, 14

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vv v27, v3, v5

  li t2, 0xdf5f06584090fe7f
  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vx v8, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vi v24, v28, 1

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vv v4, v18, v22

  li t2, 0xd25eea4c3a5f430f
  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vx v5, v10, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vi v15, v6, -3

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vv v15, v12, v5

  li t2, 0x78a7b39cce574763
  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vx v4, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vi v3, v21, -3

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vv v21, v22, v17

  li t2, 0x45077f60346bf601
  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vx v23, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vi v19, v6, 12

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vv v14, v23, v24

  li t2, 0x718543f05b38711f
  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vx v7, v4, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vi v21, v16, -10

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vv v18, v29, v24

  li t2, 0xe47d5adb38cf9a82
  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vx v7, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vi v26, v18, 6

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vv v30, v9, v8

  li t2, 0xac6897ce55514b9c
  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vx v20, v21, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vi v9, v3, 0

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vv v21, v14, v13

  li t2, 0x46370bccfa86d8ac
  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vx v4, v2, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsadd.vi v19, v16, 13

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vv v14, v28, v30

  li t2, 0x26ccd5e262abf69c
  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vx v28, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vi v12, v24, 4

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vv v30, v26, v14

  li t2, 0xe9e2c918ef924f81
  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vx v26, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vi v24, v18, -8

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vv v14, v28, v26

  li t2, 0xc66a438d9b755e8f
  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vx v6, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vi v2, v18, -15

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vv v10, v12, v28

  li t2, 0xbd8d1594f9f8656a
  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vx v2, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vi v30, v2, 2

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vv v18, v16, v6

  li t2, 0xfbda056337ba1e9f
  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vx v14, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vi v16, v26, -10

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vv v2, v10, v26

  li t2, 0x74cd34837c4e5b08
  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vx v28, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vi v20, v18, 11

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vv v28, v30, v12

  li t2, 0x925f27874259f874
  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vx v8, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vi v26, v14, 3

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vv v20, v18, v6

  li t2, 0x504c73d8919fc777
  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vx v16, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vi v14, v12, 8

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vv v10, v4, v12

  li t2, 0x607f161752db035c
  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vx v18, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vi v12, v2, 3

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vv v22, v30, v14

  li t2, 0xfcf56527cfd081f2
  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vx v22, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsadd.vi v16, v4, 4

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vv v28, v8, v16

  li t2, 0x21cfe53192545775
  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vx v24, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vi v4, v16, 13

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vv v16, v28, v8

  li t2, 0x8158e2abd28b3621
  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vx v4, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vi v16, v20, 1

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vv v20, v24, v16

  li t2, 0xa5438b16954bac79
  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vi v24, v16, -14

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vv v12, v4, v20

  li t2, 0x4cc5a277c9649fe6
  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vi v12, v4, 12

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vv v4, v28, v12

  li t2, 0x4f6c8c28cb470eed
  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vx v4, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vi v4, v12, -8

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vv v4, v16, v12

  li t2, 0xb3f45b5578dcd7ac
  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vx v16, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vi v12, v4, 5

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vv v20, v24, v8

  li t2, 0x60ab623fd85793d8
  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vx v16, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vi v4, v20, -8

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vv v24, v12, v4

  li t2, 0x492cd6f8ff965c2a
  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vi v24, v20, -4

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vv v20, v16, v4

  li t2, 0x2dd564f19321fd8c
  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vx v16, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vi v12, v28, -4

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vv v12, v8, v16

  li t2, 0x83ae3a4a60d9c5a3
  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vx v4, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsadd.vi v24, v20, -7

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vv v8, v24, v16

  li t2, 0x190322d09858180e
  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vi v8, v16, -6

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vv v16, v8, v24

  li t2, 0xd78268b8532d0bba
  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vi v8, v16, -6

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vv v16, v24, v8

  li t2, 0xe570ff9fde95285f
  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vi v16, v24, -15

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vv v8, v24, v16

  li t2, 0x55010b43a3a879f3
  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vi v16, v8, -3

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vv v16, v8, v24

  li t2, 0x3a013c6182bdd0d0
  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vi v16, v24, -12

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vv v24, v8, v16

  li t2, 0x1d98d3ba78b93e8f
  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vi v8, v16, 1

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vv v16, v8, v24

  li t2, 0xd351b1fcbfd588d9
  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vi v24, v16, -9

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vv v8, v24, v16

  li t2, 0xaa6aa5a90d53b0b4
  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vi v16, v24, 6

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vv v16, v24, v8

  li t2, 0xb973932bb4b0f700
  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vi v24, v16, -10

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vv v8, v24, v16

  li t2, 0x4b075ce38fecb1d7
  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsadd.vi v24, v16, -14

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
