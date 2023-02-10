#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vv v17, v13, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vv v15, v12, v21

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vv v29, v23, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vv v7, v17, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vv v26, v16, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vv v9, v4, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vv v8, v11, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vv v2, v9, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vv v8, v5, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vv v1, v5, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vv v26, v24, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vv v14, v10, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vv v28, v18, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vv v4, v12, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vv v12, v24, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vv v18, v22, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vv v22, v4, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vv v14, v16, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vv v4, v22, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vv v28, v22, v14

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vv v12, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vv v12, v4, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vv v16, v12, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vv v20, v8, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vv v28, v20, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vv v20, v4, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vv v28, v4, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vv v28, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vv v12, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vv v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vv v8, v24, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vv v4, v12, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vv v23, v6, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vv v20, v2, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vv v29, v9, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vv v21, v9, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vv v3, v27, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vv v2, v17, v29

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vv v4, v15, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vv v20, v21, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vv v29, v7, v15

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vv v10, v16, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vv v2, v10, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vv v14, v22, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vv v18, v6, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vv v24, v28, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vv v2, v14, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vv v30, v18, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vv v16, v30, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vv v10, v26, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vv v30, v28, v14

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vv v20, v12, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vv v4, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vv v4, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vv v28, v20, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vv v8, v20, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vv v12, v28, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vv v4, v20, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vv v12, v4, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vv v16, v12, v28

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vv v16, v8, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vv v18, v28, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vv v10, v7, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vv v1, v23, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vv v21, v18, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vv v5, v21, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vv v19, v18, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vv v31, v16, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vv v21, v9, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vv v31, v13, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vv v6, v4, v13

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vv v24, v12, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vv v30, v22, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vv v26, v30, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vv v28, v26, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vv v14, v22, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vv v20, v30, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vv v26, v20, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vv v4, v26, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vv v2, v26, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vv v28, v16, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vv v16, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vv v24, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vv v4, v24, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vv v20, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vv v12, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vv v16, v12, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vv v12, v16, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vv v4, v24, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vv v28, v24, v4

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vv v8, v16, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vv v10, v11, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vv v1, v11, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vv v26, v30, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vv v22, v2, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vv v8, v20, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vv v28, v16, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vv v1, v2, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vv v6, v19, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vv v6, v8, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vv v9, v10, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vv v12, v24, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vv v14, v4, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vv v2, v20, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vv v30, v20, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vv v4, v6, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vv v8, v6, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vv v18, v26, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vv v20, v14, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vv v14, v28, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vv v8, v2, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vv v28, v4, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vv v12, v8, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vv v8, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vv v12, v24, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vv v12, v4, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vv v28, v16, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vv v20, v4, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vv v20, v16, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vv v4, v12, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vv v4, v20, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vv v24, v16, v8

  li t2, 0x17e40d8c7c44ff5c
  vsetvli t1, t0, e8, m1, ta, ma
  vand.vx v19, v15, t2

  li t2, 0x9c4519b7fa4ac363
  vsetvli t1, t0, e8, m1, ta, ma
  vand.vx v31, v6, t2

  li t2, 0x143a1a486b30c1b3
  vsetvli t1, t0, e8, m1, ta, ma
  vand.vx v16, v2, t2

  li t2, 0xc296e9069504bb5d
  vsetvli t1, t0, e8, m1, ta, ma
  vand.vx v3, v26, t2

  li t2, 0x77fa17c92974aa06
  vsetvli t1, t0, e8, m1, ta, ma
  vand.vx v16, v5, t2

  li t2, 0x8917d7c860a66046
  vsetvli t1, t0, e8, m1, ta, ma
  vand.vx v15, v17, t2

  li t2, 0x482214ac2d5f2bc4
  vsetvli t1, t0, e8, m1, ta, ma
  vand.vx v31, v23, t2

  li t2, 0xaba835a37e1521a7
  vsetvli t1, t0, e8, m1, ta, ma
  vand.vx v10, v13, t2

  li t2, 0x70fb737710299b93
  vsetvli t1, t0, e8, m1, ta, ma
  vand.vx v20, v18, t2

  li t2, 0xf170928501834a6d
  vsetvli t1, t0, e8, m1, ta, ma
  vand.vx v27, v24, t2

  li t2, 0xe3ee66f8fc8f930c
  vsetvli t1, t0, e8, m2, ta, ma
  vand.vx v30, v6, t2

  li t2, 0xf2da17e9f132cd6e
  vsetvli t1, t0, e8, m2, ta, ma
  vand.vx v30, v4, t2

  li t2, 0x3dba2ebb1fcb2276
  vsetvli t1, t0, e8, m2, ta, ma
  vand.vx v16, v30, t2

  li t2, 0xbf717d123c3a2026
  vsetvli t1, t0, e8, m2, ta, ma
  vand.vx v28, v2, t2

  li t2, 0x1fcb9e0f5e59112c
  vsetvli t1, t0, e8, m2, ta, ma
  vand.vx v2, v20, t2

  li t2, 0x660e9def541987f8
  vsetvli t1, t0, e8, m2, ta, ma
  vand.vx v30, v8, t2

  li t2, 0xbd9fc9390cd0a4ce
  vsetvli t1, t0, e8, m2, ta, ma
  vand.vx v14, v10, t2

  li t2, 0xadfcdc7ade73055f
  vsetvli t1, t0, e8, m2, ta, ma
  vand.vx v8, v20, t2

  li t2, 0x7468e56d5b36e12c
  vsetvli t1, t0, e8, m2, ta, ma
  vand.vx v2, v16, t2

  li t2, 0xd46bdc21379fd7e8
  vsetvli t1, t0, e8, m2, ta, ma
  vand.vx v28, v2, t2

  li t2, 0x9bba65db62cce714
  vsetvli t1, t0, e8, m4, ta, ma
  vand.vx v20, v8, t2

  li t2, 0xdf6a56698656ad5d
  vsetvli t1, t0, e8, m4, ta, ma
  vand.vx v24, v16, t2

  li t2, 0x52ed52a7c2adebb2
  vsetvli t1, t0, e8, m4, ta, ma
  vand.vx v20, v4, t2

  li t2, 0x7edba64531e70202
  vsetvli t1, t0, e8, m4, ta, ma
  vand.vx v16, v20, t2

  li t2, 0xd63cc11c116bbf6e
  vsetvli t1, t0, e8, m4, ta, ma
  vand.vx v16, v12, t2

  li t2, 0xc17fa81040bc6389
  vsetvli t1, t0, e8, m4, ta, ma
  vand.vx v16, v4, t2

  li t2, 0xbe7fe1eb2af71eb2
  vsetvli t1, t0, e8, m4, ta, ma
  vand.vx v20, v24, t2

  li t2, 0xf047b969cf69f0e0
  vsetvli t1, t0, e8, m4, ta, ma
  vand.vx v16, v20, t2

  li t2, 0x67ebe262bd34884e
  vsetvli t1, t0, e8, m4, ta, ma
  vand.vx v20, v4, t2

  li t2, 0x500751381004ecff
  vsetvli t1, t0, e8, m4, ta, ma
  vand.vx v4, v8, t2

  li t2, 0x99dfbf38450170ec
  vsetvli t1, t0, e8, m8, ta, ma
  vand.vx v24, v8, t2

  li t2, 0xccacf24ff6ef019c
  vsetvli t1, t0, e8, m8, ta, ma
  vand.vx v24, v8, t2

  li t2, 0x61f0652a0068368f
  vsetvli t1, t0, e8, m8, ta, ma
  vand.vx v24, v16, t2

  li t2, 0xfd55bc3c31e2ff8f
  vsetvli t1, t0, e8, m8, ta, ma
  vand.vx v8, v24, t2

  li t2, 0xb0dc37b40cf1b7fe
  vsetvli t1, t0, e8, m8, ta, ma
  vand.vx v8, v24, t2

  li t2, 0x048ceb1cb04a4e74
  vsetvli t1, t0, e8, m8, ta, ma
  vand.vx v8, v24, t2

  li t2, 0x16e6047a153ff31a
  vsetvli t1, t0, e8, m8, ta, ma
  vand.vx v8, v24, t2

  li t2, 0xd2bcd2e45385fff9
  vsetvli t1, t0, e8, m8, ta, ma
  vand.vx v16, v8, t2

  li t2, 0x31c7230259987903
  vsetvli t1, t0, e8, m8, ta, ma
  vand.vx v8, v16, t2

  li t2, 0x152f083cdc3ba569
  vsetvli t1, t0, e8, m8, ta, ma
  vand.vx v16, v8, t2

  li t2, 0x7d41a14325cfd06a
  vsetvli t1, t0, e16, m1, ta, ma
  vand.vx v29, v16, t2

  li t2, 0x020fd2c0423a3cb0
  vsetvli t1, t0, e16, m1, ta, ma
  vand.vx v1, v17, t2

  li t2, 0xf68e82399d9e2c34
  vsetvli t1, t0, e16, m1, ta, ma
  vand.vx v25, v14, t2

  li t2, 0x3c4d86c484ca431a
  vsetvli t1, t0, e16, m1, ta, ma
  vand.vx v22, v23, t2

  li t2, 0x6624234281dd21c6
  vsetvli t1, t0, e16, m1, ta, ma
  vand.vx v17, v15, t2

  li t2, 0xdd156ffd7cc68a42
  vsetvli t1, t0, e16, m1, ta, ma
  vand.vx v31, v24, t2

  li t2, 0x0354817584b2b201
  vsetvli t1, t0, e16, m1, ta, ma
  vand.vx v5, v14, t2

  li t2, 0x62f923e4d7abb29a
  vsetvli t1, t0, e16, m1, ta, ma
  vand.vx v5, v8, t2

  li t2, 0x20d11a98bfb6ee88
  vsetvli t1, t0, e16, m1, ta, ma
  vand.vx v20, v15, t2

  li t2, 0x724e7fe8e1159d26
  vsetvli t1, t0, e16, m1, ta, ma
  vand.vx v26, v16, t2

  li t2, 0x89d7a6df3bdeb588
  vsetvli t1, t0, e16, m2, ta, ma
  vand.vx v26, v8, t2

  li t2, 0x3e4f1db6b63405c3
  vsetvli t1, t0, e16, m2, ta, ma
  vand.vx v28, v12, t2

  li t2, 0xdb50eaee3e97b7e1
  vsetvli t1, t0, e16, m2, ta, ma
  vand.vx v20, v4, t2

  li t2, 0x0a7d4138947c54ea
  vsetvli t1, t0, e16, m2, ta, ma
  vand.vx v12, v16, t2

  li t2, 0xd260278634137c3f
  vsetvli t1, t0, e16, m2, ta, ma
  vand.vx v18, v14, t2

  li t2, 0x8540d0fa13b4f519
  vsetvli t1, t0, e16, m2, ta, ma
  vand.vx v6, v28, t2

  li t2, 0x3fcd011ccb56c9c3
  vsetvli t1, t0, e16, m2, ta, ma
  vand.vx v24, v10, t2

  li t2, 0xe45008bfb90cdaf0
  vsetvli t1, t0, e16, m2, ta, ma
  vand.vx v24, v30, t2

  li t2, 0xff3f5c90c5fb2a0b
  vsetvli t1, t0, e16, m2, ta, ma
  vand.vx v28, v30, t2

  li t2, 0x16ce3723fdb08cbd
  vsetvli t1, t0, e16, m2, ta, ma
  vand.vx v28, v30, t2

  li t2, 0xa4466812d3a4cf10
  vsetvli t1, t0, e16, m4, ta, ma
  vand.vx v24, v4, t2

  li t2, 0x6918ac9ac2cbe966
  vsetvli t1, t0, e16, m4, ta, ma
  vand.vx v4, v20, t2

  li t2, 0x196ff5a63f704f0a
  vsetvli t1, t0, e16, m4, ta, ma
  vand.vx v16, v8, t2

  li t2, 0xf9039c99e1f7051e
  vsetvli t1, t0, e16, m4, ta, ma
  vand.vx v16, v20, t2

  li t2, 0x85fd0f3eeb77f75f
  vsetvli t1, t0, e16, m4, ta, ma
  vand.vx v8, v20, t2

  li t2, 0xf6809d1077101e24
  vsetvli t1, t0, e16, m4, ta, ma
  vand.vx v12, v20, t2

  li t2, 0x768516feee6f2766
  vsetvli t1, t0, e16, m4, ta, ma
  vand.vx v28, v24, t2

  li t2, 0x138363b925c4d841
  vsetvli t1, t0, e16, m4, ta, ma
  vand.vx v16, v4, t2

  li t2, 0x48c7b96811164a76
  vsetvli t1, t0, e16, m4, ta, ma
  vand.vx v4, v16, t2

  li t2, 0xff1604bdf956f712
  vsetvli t1, t0, e16, m4, ta, ma
  vand.vx v20, v28, t2

  li t2, 0xa8cbed8ce7060217
  vsetvli t1, t0, e16, m8, ta, ma
  vand.vx v8, v24, t2

  li t2, 0x43468c765dd30b44
  vsetvli t1, t0, e16, m8, ta, ma
  vand.vx v16, v8, t2

  li t2, 0xf454e37f32cde1ca
  vsetvli t1, t0, e16, m8, ta, ma
  vand.vx v16, v8, t2

  li t2, 0x68e7f80471c1fb3e
  vsetvli t1, t0, e16, m8, ta, ma
  vand.vx v8, v24, t2

  li t2, 0x4e79f47c8a505da1
  vsetvli t1, t0, e16, m8, ta, ma
  vand.vx v8, v24, t2

  li t2, 0x16b2f99bd27470db
  vsetvli t1, t0, e16, m8, ta, ma
  vand.vx v24, v8, t2

  li t2, 0x37e32e2b7034b739
  vsetvli t1, t0, e16, m8, ta, ma
  vand.vx v8, v24, t2

  li t2, 0x2dd9e0993db8055a
  vsetvli t1, t0, e16, m8, ta, ma
  vand.vx v24, v16, t2

  li t2, 0x010b5fe6247ac940
  vsetvli t1, t0, e16, m8, ta, ma
  vand.vx v24, v16, t2

  li t2, 0x131018c8c158dff0
  vsetvli t1, t0, e16, m8, ta, ma
  vand.vx v8, v24, t2

  li t2, 0x09f10abac2855f17
  vsetvli t1, t0, e32, m1, ta, ma
  vand.vx v10, v2, t2

  li t2, 0x4e5b6d236bec0b48
  vsetvli t1, t0, e32, m1, ta, ma
  vand.vx v4, v30, t2

  li t2, 0xc76051fc0fdd0bfe
  vsetvli t1, t0, e32, m1, ta, ma
  vand.vx v26, v22, t2

  li t2, 0x881ce00981feda86
  vsetvli t1, t0, e32, m1, ta, ma
  vand.vx v13, v2, t2

  li t2, 0x9f3706015955a799
  vsetvli t1, t0, e32, m1, ta, ma
  vand.vx v23, v16, t2

  li t2, 0x17db63baf2aab3d0
  vsetvli t1, t0, e32, m1, ta, ma
  vand.vx v27, v9, t2

  li t2, 0x35e2ac68a55e9445
  vsetvli t1, t0, e32, m1, ta, ma
  vand.vx v5, v19, t2

  li t2, 0x101eb2be15677ebd
  vsetvli t1, t0, e32, m1, ta, ma
  vand.vx v31, v1, t2

  li t2, 0xcba2a8a6d3c866f4
  vsetvli t1, t0, e32, m1, ta, ma
  vand.vx v22, v30, t2

  li t2, 0xacffea9711c61fe4
  vsetvli t1, t0, e32, m1, ta, ma
  vand.vx v1, v23, t2

  li t2, 0x50d801f30b1a2d50
  vsetvli t1, t0, e32, m2, ta, ma
  vand.vx v4, v8, t2

  li t2, 0xa9d28d4e4cebe6d2
  vsetvli t1, t0, e32, m2, ta, ma
  vand.vx v2, v8, t2

  li t2, 0xcb6bf444c2e34a68
  vsetvli t1, t0, e32, m2, ta, ma
  vand.vx v14, v26, t2

  li t2, 0x63f6e05d6fac9bab
  vsetvli t1, t0, e32, m2, ta, ma
  vand.vx v16, v14, t2

  li t2, 0x3eb8fea71f826cf6
  vsetvli t1, t0, e32, m2, ta, ma
  vand.vx v20, v12, t2

  li t2, 0xd00d61f799afc544
  vsetvli t1, t0, e32, m2, ta, ma
  vand.vx v2, v18, t2

  li t2, 0xbadaa74ce66fd58b
  vsetvli t1, t0, e32, m2, ta, ma
  vand.vx v22, v18, t2

  li t2, 0x52576c500159f5f6
  vsetvli t1, t0, e32, m2, ta, ma
  vand.vx v18, v16, t2

  li t2, 0x591f1bb6d4e16389
  vsetvli t1, t0, e32, m2, ta, ma
  vand.vx v4, v30, t2

  li t2, 0x1a2db4f8e888f5be
  vsetvli t1, t0, e32, m2, ta, ma
  vand.vx v18, v6, t2

  li t2, 0x2594c6950e1b1e7f
  vsetvli t1, t0, e32, m4, ta, ma
  vand.vx v16, v12, t2

  li t2, 0x1ac0ff6298b6334b
  vsetvli t1, t0, e32, m4, ta, ma
  vand.vx v24, v28, t2

  li t2, 0xd6b1bf2d0990ec45
  vsetvli t1, t0, e32, m4, ta, ma
  vand.vx v12, v16, t2

  li t2, 0xd41bf2abcb953646
  vsetvli t1, t0, e32, m4, ta, ma
  vand.vx v24, v16, t2

  li t2, 0x9801881f9c5818c9
  vsetvli t1, t0, e32, m4, ta, ma
  vand.vx v16, v28, t2

  li t2, 0x9108100b9a5311b1
  vsetvli t1, t0, e32, m4, ta, ma
  vand.vx v24, v16, t2

  li t2, 0x540596add0a807c4
  vsetvli t1, t0, e32, m4, ta, ma
  vand.vx v16, v12, t2

  li t2, 0xcd252a7ce9c0924b
  vsetvli t1, t0, e32, m4, ta, ma
  vand.vx v4, v12, t2

  li t2, 0x4e8d89f4557dcb89
  vsetvli t1, t0, e32, m4, ta, ma
  vand.vx v28, v4, t2

  li t2, 0x91f7ddd3038d91ad
  vsetvli t1, t0, e32, m4, ta, ma
  vand.vx v28, v4, t2

  li t2, 0xa5e9fe6c0fcb03d8
  vsetvli t1, t0, e32, m8, ta, ma
  vand.vx v24, v8, t2

  li t2, 0x5f7a89154ff7d059
  vsetvli t1, t0, e32, m8, ta, ma
  vand.vx v16, v24, t2

  li t2, 0x61571a04bc38e33e
  vsetvli t1, t0, e32, m8, ta, ma
  vand.vx v8, v24, t2

  li t2, 0xf7074b0890d28bba
  vsetvli t1, t0, e32, m8, ta, ma
  vand.vx v8, v16, t2

  li t2, 0x0ae676436bc39eda
  vsetvli t1, t0, e32, m8, ta, ma
  vand.vx v24, v16, t2

  li t2, 0xcbe431ae8ac76ee5
  vsetvli t1, t0, e32, m8, ta, ma
  vand.vx v16, v24, t2

  li t2, 0x94ca5e225a526795
  vsetvli t1, t0, e32, m8, ta, ma
  vand.vx v16, v24, t2

  li t2, 0x362652d573260f74
  vsetvli t1, t0, e32, m8, ta, ma
  vand.vx v16, v24, t2

  li t2, 0x6f426d3994d20de4
  vsetvli t1, t0, e32, m8, ta, ma
  vand.vx v8, v16, t2

  li t2, 0xa765f6d168901fba
  vsetvli t1, t0, e32, m8, ta, ma
  vand.vx v24, v8, t2

  li t2, 0xd54f4f7ad264af74
  vsetvli t1, t0, e64, m1, ta, ma
  vand.vx v1, v29, t2

  li t2, 0x68872b0393a07850
  vsetvli t1, t0, e64, m1, ta, ma
  vand.vx v18, v26, t2

  li t2, 0xbd65977e6aec536d
  vsetvli t1, t0, e64, m1, ta, ma
  vand.vx v17, v12, t2

  li t2, 0x7de0917031d277b6
  vsetvli t1, t0, e64, m1, ta, ma
  vand.vx v28, v8, t2

  li t2, 0x60a7ff3be64e4615
  vsetvli t1, t0, e64, m1, ta, ma
  vand.vx v14, v19, t2

  li t2, 0xe2f78805a5f4cfc7
  vsetvli t1, t0, e64, m1, ta, ma
  vand.vx v24, v15, t2

  li t2, 0x78ae8f1710ad7c80
  vsetvli t1, t0, e64, m1, ta, ma
  vand.vx v1, v21, t2

  li t2, 0xb56387057841d278
  vsetvli t1, t0, e64, m1, ta, ma
  vand.vx v25, v31, t2

  li t2, 0x4f828c76a9750a0a
  vsetvli t1, t0, e64, m1, ta, ma
  vand.vx v22, v7, t2

  li t2, 0xd8a38075ce947e59
  vsetvli t1, t0, e64, m1, ta, ma
  vand.vx v25, v27, t2

  li t2, 0xc8366e650343789f
  vsetvli t1, t0, e64, m2, ta, ma
  vand.vx v20, v24, t2

  li t2, 0xc2004e774c22919c
  vsetvli t1, t0, e64, m2, ta, ma
  vand.vx v18, v20, t2

  li t2, 0x8ef0a8808c43e975
  vsetvli t1, t0, e64, m2, ta, ma
  vand.vx v24, v8, t2

  li t2, 0xa52f83558013865e
  vsetvli t1, t0, e64, m2, ta, ma
  vand.vx v22, v28, t2

  li t2, 0x983ea03f84683b4b
  vsetvli t1, t0, e64, m2, ta, ma
  vand.vx v20, v14, t2

  li t2, 0xbb4ddb37bb33f1c9
  vsetvli t1, t0, e64, m2, ta, ma
  vand.vx v22, v20, t2

  li t2, 0xab9891ba410700a6
  vsetvli t1, t0, e64, m2, ta, ma
  vand.vx v14, v26, t2

  li t2, 0xa64fcd942be814c0
  vsetvli t1, t0, e64, m2, ta, ma
  vand.vx v22, v30, t2

  li t2, 0x016c758b2cdca916
  vsetvli t1, t0, e64, m2, ta, ma
  vand.vx v22, v24, t2

  li t2, 0x55d23f6aacd50ab3
  vsetvli t1, t0, e64, m2, ta, ma
  vand.vx v30, v8, t2

  li t2, 0x787cb76c0bb53127
  vsetvli t1, t0, e64, m4, ta, ma
  vand.vx v28, v12, t2

  li t2, 0x63f79ffcf3a062e1
  vsetvli t1, t0, e64, m4, ta, ma
  vand.vx v16, v12, t2

  li t2, 0xe447175268d7044a
  vsetvli t1, t0, e64, m4, ta, ma
  vand.vx v28, v4, t2

  li t2, 0x961dfca42c99f160
  vsetvli t1, t0, e64, m4, ta, ma
  vand.vx v16, v4, t2

  li t2, 0xdebeba7d2976d3a0
  vsetvli t1, t0, e64, m4, ta, ma
  vand.vx v24, v4, t2

  li t2, 0x56f4bc3f519041c8
  vsetvli t1, t0, e64, m4, ta, ma
  vand.vx v12, v16, t2

  li t2, 0xa5d04383a18bff0f
  vsetvli t1, t0, e64, m4, ta, ma
  vand.vx v24, v8, t2

  li t2, 0x1dbcb17f76924dbf
  vsetvli t1, t0, e64, m4, ta, ma
  vand.vx v28, v24, t2

  li t2, 0xea085758d51d8fce
  vsetvli t1, t0, e64, m4, ta, ma
  vand.vx v20, v16, t2

  li t2, 0xce7c70bd959cf15e
  vsetvli t1, t0, e64, m4, ta, ma
  vand.vx v28, v24, t2

  li t2, 0x7a12403127040bfe
  vsetvli t1, t0, e64, m8, ta, ma
  vand.vx v24, v8, t2

  li t2, 0x6c19c1107be3e769
  vsetvli t1, t0, e64, m8, ta, ma
  vand.vx v24, v8, t2

  li t2, 0x9a527cdea30b21ad
  vsetvli t1, t0, e64, m8, ta, ma
  vand.vx v8, v16, t2

  li t2, 0xb96131f3138b8348
  vsetvli t1, t0, e64, m8, ta, ma
  vand.vx v8, v16, t2

  li t2, 0x07bc29963af01d44
  vsetvli t1, t0, e64, m8, ta, ma
  vand.vx v8, v16, t2

  li t2, 0xf319001a2ff1da06
  vsetvli t1, t0, e64, m8, ta, ma
  vand.vx v24, v8, t2

  li t2, 0x93aefd750d4f1b91
  vsetvli t1, t0, e64, m8, ta, ma
  vand.vx v24, v8, t2

  li t2, 0xc3148af32f416b86
  vsetvli t1, t0, e64, m8, ta, ma
  vand.vx v8, v16, t2

  li t2, 0x92c316364da77a93
  vsetvli t1, t0, e64, m8, ta, ma
  vand.vx v8, v24, t2

  li t2, 0x03853b98a5756730
  vsetvli t1, t0, e64, m8, ta, ma
  vand.vx v8, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vi v29, v2, -3

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vi v23, v3, -4

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vi v23, v12, -14

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vi v23, v10, 15

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vi v6, v25, -6

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vi v1, v20, -7

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vi v10, v14, 9

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vi v2, v10, 8

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vi v4, v20, -8

  vsetvli t1, t0, e8, m1, ta, ma
  vand.vi v28, v11, -10

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vi v8, v22, 11

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vi v20, v10, 8

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vi v2, v26, -2

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vi v22, v26, -7

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vi v22, v16, 11

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vi v10, v2, -3

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vi v10, v24, -12

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vi v2, v26, 0

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vi v2, v30, -3

  vsetvli t1, t0, e8, m2, ta, ma
  vand.vi v10, v14, -11

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vi v20, v8, 2

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vi v24, v4, 7

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vi v12, v20, 6

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vi v8, v4, -13

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vi v16, v4, 0

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vi v28, v4, 11

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vi v20, v12, 13

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vi v20, v4, 1

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vi v28, v8, 10

  vsetvli t1, t0, e8, m4, ta, ma
  vand.vi v8, v24, 4

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vi v8, v24, -12

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vi v8, v24, 2

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vi v8, v16, -10

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vi v8, v24, 10

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vi v16, v24, 1

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vi v8, v24, 11

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vi v16, v8, 15

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vi v8, v24, 12

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vi v16, v8, -7

  vsetvli t1, t0, e8, m8, ta, ma
  vand.vi v24, v8, 10

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vi v8, v2, 12

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vi v11, v27, -5

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vi v13, v15, -5

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vi v2, v20, -15

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vi v22, v20, -4

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vi v27, v24, -9

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vi v23, v2, -16

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vi v23, v27, -5

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vi v11, v23, -2

  vsetvli t1, t0, e16, m1, ta, ma
  vand.vi v24, v2, 3

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vi v26, v18, 11

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vi v6, v2, 13

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vi v14, v28, -2

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vi v10, v16, -2

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vi v6, v2, -10

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vi v24, v8, -11

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vi v2, v12, 14

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vi v16, v28, 4

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vi v24, v10, -9

  vsetvli t1, t0, e16, m2, ta, ma
  vand.vi v14, v8, 13

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vi v4, v8, 10

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vi v20, v12, -15

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vi v12, v20, -12

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vi v12, v8, 10

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vi v4, v24, -11

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vi v4, v28, -11

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vi v12, v24, -8

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vi v8, v20, -10

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vi v20, v4, -6

  vsetvli t1, t0, e16, m4, ta, ma
  vand.vi v24, v20, 0

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vi v24, v16, -11

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vi v24, v8, -13

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vi v16, v8, -10

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vi v16, v24, 0

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vi v8, v16, -1

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vi v16, v24, -14

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vi v8, v16, 15

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vi v24, v8, -10

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vi v16, v8, -13

  vsetvli t1, t0, e16, m8, ta, ma
  vand.vi v16, v8, -7

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vi v12, v23, -14

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vi v2, v23, 8

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vi v31, v22, 12

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vi v27, v14, 2

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vi v29, v6, 9

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vi v6, v26, -5

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vi v21, v24, -9

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vi v15, v7, 8

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vi v19, v1, -2

  vsetvli t1, t0, e32, m1, ta, ma
  vand.vi v8, v13, -12

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vi v4, v24, 5

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vi v26, v16, -16

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vi v26, v12, 6

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vi v12, v20, 13

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vi v12, v22, 6

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vi v18, v16, 7

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vi v2, v4, 12

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vi v20, v2, -7

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vi v18, v20, 6

  vsetvli t1, t0, e32, m2, ta, ma
  vand.vi v28, v8, 8

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vi v8, v24, -3

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vi v20, v16, -10

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vi v24, v20, 8

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vi v28, v8, 6

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vi v20, v12, 4

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vi v4, v24, 7

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vi v28, v4, 4

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vi v12, v24, -3

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vi v8, v4, -2

  vsetvli t1, t0, e32, m4, ta, ma
  vand.vi v20, v8, 15

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vi v8, v24, -12

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vi v8, v24, 12

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vi v16, v8, -3

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vi v24, v8, -13

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vi v16, v24, 1

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vi v8, v24, 6

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vi v8, v16, 2

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vi v16, v8, 8

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vi v16, v8, 8

  vsetvli t1, t0, e32, m8, ta, ma
  vand.vi v24, v8, -7

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vi v2, v15, -12

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vi v3, v1, -3

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vi v7, v20, -12

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vi v20, v30, 15

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vi v6, v15, -7

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vi v11, v4, -1

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vi v14, v30, 9

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vi v27, v26, 12

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vi v2, v11, -9

  vsetvli t1, t0, e64, m1, ta, ma
  vand.vi v27, v16, -6

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vi v18, v30, 1

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vi v6, v14, -7

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vi v22, v4, 12

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vi v26, v6, -5

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vi v4, v8, 14

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vi v6, v28, -14

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vi v24, v10, 12

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vi v30, v16, 8

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vi v18, v6, -5

  vsetvli t1, t0, e64, m2, ta, ma
  vand.vi v20, v8, -13

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vi v12, v24, 13

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vi v28, v16, 6

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vi v12, v28, -16

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vi v4, v16, -14

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vi v28, v16, 15

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vi v8, v28, -4

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vi v12, v16, -3

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vi v20, v24, 15

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vi v12, v20, 5

  vsetvli t1, t0, e64, m4, ta, ma
  vand.vi v16, v20, -15

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vi v24, v16, 9

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vi v16, v24, 15

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vi v8, v16, -9

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vi v24, v16, -6

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vi v8, v16, 4

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vi v8, v16, -12

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vi v8, v16, 11

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vi v8, v24, -12

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vi v8, v16, -9

  vsetvli t1, t0, e64, m8, ta, ma
  vand.vi v16, v24, 4

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
