#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vv v18, v14, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vv v1, v21, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vv v6, v15, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vv v28, v1, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vv v31, v12, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vv v9, v28, v31

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vv v24, v31, v21

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vv v9, v8, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vv v21, v7, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vv v2, v24, v11

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vv v12, v18, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vv v22, v28, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vv v6, v16, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vv v16, v2, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vv v20, v30, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vv v4, v24, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vv v2, v4, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vv v22, v20, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vv v28, v22, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vv v20, v6, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vv v4, v24, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vv v12, v8, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vv v8, v4, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vv v20, v16, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vv v28, v12, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vv v20, v8, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vv v4, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vv v4, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vv v16, v12, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vv v24, v4, v12

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vv v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vv v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vv v16, v8, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vv v3, v14, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vv v27, v29, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vv v23, v7, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vv v8, v12, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vv v17, v25, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vv v15, v3, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vv v29, v19, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vv v26, v10, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vv v8, v22, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vv v20, v5, v13

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vv v2, v28, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vv v20, v28, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vv v4, v16, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vv v2, v14, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vv v4, v30, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vv v6, v20, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vv v28, v22, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vv v12, v2, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vv v10, v12, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vv v6, v20, v26

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vv v28, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vv v24, v16, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vv v8, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vv v8, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vv v28, v16, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vv v28, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vv v16, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vv v12, v20, v28

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vv v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vv v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vv v16, v24, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vv v12, v29, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vv v2, v29, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vv v25, v22, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vv v25, v2, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vv v27, v19, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vv v28, v29, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vv v12, v20, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vv v26, v18, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vv v20, v16, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vv v9, v26, v21

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vv v16, v22, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vv v12, v6, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vv v6, v24, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vv v6, v8, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vv v14, v12, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vv v20, v14, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vv v20, v24, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vv v6, v16, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vv v12, v26, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vv v18, v6, v10

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vv v28, v20, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vv v20, v4, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vv v20, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vv v16, v8, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vv v24, v16, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vv v20, v28, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vv v4, v8, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vv v20, v28, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vv v16, v4, v28

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vv v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vv v16, v8, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vv v29, v23, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vv v18, v13, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vv v4, v8, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vv v23, v20, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vv v17, v11, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vv v20, v22, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vv v8, v7, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vv v16, v23, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vv v13, v28, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vv v17, v29, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vv v20, v10, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vv v18, v2, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vv v12, v24, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vv v16, v24, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vv v8, v4, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vv v22, v26, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vv v30, v22, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vv v30, v28, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vv v10, v18, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vv v16, v26, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vv v12, v16, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vv v16, v8, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vv v4, v24, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vv v8, v12, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vv v28, v8, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vv v16, v12, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vv v4, v20, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vv v16, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vv v12, v20, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vv v12, v20, v28

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vv v16, v8, v24

  li t2, 0x50cd398a735abe40
  vsetvli t1, t0, e8, m1, ta, ma
  vor.vx v11, v30, t2

  li t2, 0x405f36c07c4995f1
  vsetvli t1, t0, e8, m1, ta, ma
  vor.vx v3, v11, t2

  li t2, 0x40c33a0c594bdda2
  vsetvli t1, t0, e8, m1, ta, ma
  vor.vx v29, v24, t2

  li t2, 0x00cd940459651059
  vsetvli t1, t0, e8, m1, ta, ma
  vor.vx v21, v30, t2

  li t2, 0xa9c2dd8362e85614
  vsetvli t1, t0, e8, m1, ta, ma
  vor.vx v14, v12, t2

  li t2, 0xa4f8d50d60dc287f
  vsetvli t1, t0, e8, m1, ta, ma
  vor.vx v31, v17, t2

  li t2, 0x3ba8a95130b94c04
  vsetvli t1, t0, e8, m1, ta, ma
  vor.vx v9, v13, t2

  li t2, 0xe64d2e4947da1853
  vsetvli t1, t0, e8, m1, ta, ma
  vor.vx v20, v4, t2

  li t2, 0x97dc18d5307a5d9f
  vsetvli t1, t0, e8, m1, ta, ma
  vor.vx v10, v30, t2

  li t2, 0x945fe5717062efa8
  vsetvli t1, t0, e8, m1, ta, ma
  vor.vx v6, v15, t2

  li t2, 0x37e2cd1b89d170a1
  vsetvli t1, t0, e8, m2, ta, ma
  vor.vx v26, v22, t2

  li t2, 0x9952f4213a91c5ab
  vsetvli t1, t0, e8, m2, ta, ma
  vor.vx v10, v26, t2

  li t2, 0xab7e47dfb5be3526
  vsetvli t1, t0, e8, m2, ta, ma
  vor.vx v10, v18, t2

  li t2, 0x551864c141070d1f
  vsetvli t1, t0, e8, m2, ta, ma
  vor.vx v16, v26, t2

  li t2, 0xc546f00b56e013a8
  vsetvli t1, t0, e8, m2, ta, ma
  vor.vx v6, v26, t2

  li t2, 0x059c16dbc79ebc48
  vsetvli t1, t0, e8, m2, ta, ma
  vor.vx v28, v16, t2

  li t2, 0xaad89d04dc7839a7
  vsetvli t1, t0, e8, m2, ta, ma
  vor.vx v18, v2, t2

  li t2, 0x08d2eba4481c449a
  vsetvli t1, t0, e8, m2, ta, ma
  vor.vx v16, v8, t2

  li t2, 0x2aafa02c3ecfd315
  vsetvli t1, t0, e8, m2, ta, ma
  vor.vx v24, v4, t2

  li t2, 0x0e1592324304f69e
  vsetvli t1, t0, e8, m2, ta, ma
  vor.vx v30, v14, t2

  li t2, 0x07f0aaa6542309fc
  vsetvli t1, t0, e8, m4, ta, ma
  vor.vx v20, v28, t2

  li t2, 0xa9bc8ac4395ae6cd
  vsetvli t1, t0, e8, m4, ta, ma
  vor.vx v12, v24, t2

  li t2, 0x59fcca0a22186db0
  vsetvli t1, t0, e8, m4, ta, ma
  vor.vx v12, v28, t2

  li t2, 0x76c10ab7575808c8
  vsetvli t1, t0, e8, m4, ta, ma
  vor.vx v12, v20, t2

  li t2, 0x9422e0613aff8111
  vsetvli t1, t0, e8, m4, ta, ma
  vor.vx v8, v28, t2

  li t2, 0x4ba45585593453f9
  vsetvli t1, t0, e8, m4, ta, ma
  vor.vx v28, v24, t2

  li t2, 0x3cee5f1398d721aa
  vsetvli t1, t0, e8, m4, ta, ma
  vor.vx v28, v8, t2

  li t2, 0x35f32995af810185
  vsetvli t1, t0, e8, m4, ta, ma
  vor.vx v20, v24, t2

  li t2, 0x9a1e06be09a3b8b1
  vsetvli t1, t0, e8, m4, ta, ma
  vor.vx v16, v4, t2

  li t2, 0x3509dabb2c94c66a
  vsetvli t1, t0, e8, m4, ta, ma
  vor.vx v20, v8, t2

  li t2, 0x827021d493ad1628
  vsetvli t1, t0, e8, m8, ta, ma
  vor.vx v16, v24, t2

  li t2, 0x5804d844d3c4191a
  vsetvli t1, t0, e8, m8, ta, ma
  vor.vx v8, v16, t2

  li t2, 0x6ae7fc0f9738dcd2
  vsetvli t1, t0, e8, m8, ta, ma
  vor.vx v24, v16, t2

  li t2, 0x2559e9c25da79ded
  vsetvli t1, t0, e8, m8, ta, ma
  vor.vx v16, v24, t2

  li t2, 0x232e3a76c4c2f533
  vsetvli t1, t0, e8, m8, ta, ma
  vor.vx v16, v8, t2

  li t2, 0x9892ff3d076d1416
  vsetvli t1, t0, e8, m8, ta, ma
  vor.vx v8, v16, t2

  li t2, 0xa3267edce6ae971e
  vsetvli t1, t0, e8, m8, ta, ma
  vor.vx v24, v8, t2

  li t2, 0xfef3886462bd9e80
  vsetvli t1, t0, e8, m8, ta, ma
  vor.vx v8, v24, t2

  li t2, 0xe6d39c6134b7eec2
  vsetvli t1, t0, e8, m8, ta, ma
  vor.vx v16, v8, t2

  li t2, 0x91f9e022401358e4
  vsetvli t1, t0, e8, m8, ta, ma
  vor.vx v16, v8, t2

  li t2, 0xb4db0495357a2c58
  vsetvli t1, t0, e16, m1, ta, ma
  vor.vx v5, v31, t2

  li t2, 0x2336804379078278
  vsetvli t1, t0, e16, m1, ta, ma
  vor.vx v27, v11, t2

  li t2, 0xb2c0ab9c82506644
  vsetvli t1, t0, e16, m1, ta, ma
  vor.vx v15, v26, t2

  li t2, 0x4a7da6f750268b9f
  vsetvli t1, t0, e16, m1, ta, ma
  vor.vx v3, v14, t2

  li t2, 0x860b3c220cfdeef3
  vsetvli t1, t0, e16, m1, ta, ma
  vor.vx v27, v28, t2

  li t2, 0xd44e89d0a0e23106
  vsetvli t1, t0, e16, m1, ta, ma
  vor.vx v1, v22, t2

  li t2, 0x495cc635ce7800dd
  vsetvli t1, t0, e16, m1, ta, ma
  vor.vx v23, v11, t2

  li t2, 0x2b5d063f2a941574
  vsetvli t1, t0, e16, m1, ta, ma
  vor.vx v10, v13, t2

  li t2, 0x68edaaf9583dea69
  vsetvli t1, t0, e16, m1, ta, ma
  vor.vx v30, v3, t2

  li t2, 0x445cc8c60df3908b
  vsetvli t1, t0, e16, m1, ta, ma
  vor.vx v26, v3, t2

  li t2, 0xb7c3d49d6043490b
  vsetvli t1, t0, e16, m2, ta, ma
  vor.vx v26, v4, t2

  li t2, 0x37a5b8022d9d6916
  vsetvli t1, t0, e16, m2, ta, ma
  vor.vx v16, v8, t2

  li t2, 0x8a6862059ae72585
  vsetvli t1, t0, e16, m2, ta, ma
  vor.vx v10, v26, t2

  li t2, 0x1781ace3140a12ac
  vsetvli t1, t0, e16, m2, ta, ma
  vor.vx v12, v16, t2

  li t2, 0x688a33e2c53b08e3
  vsetvli t1, t0, e16, m2, ta, ma
  vor.vx v22, v14, t2

  li t2, 0xf7f2a2f26484cf9c
  vsetvli t1, t0, e16, m2, ta, ma
  vor.vx v4, v20, t2

  li t2, 0x089d5855f98893b9
  vsetvli t1, t0, e16, m2, ta, ma
  vor.vx v20, v8, t2

  li t2, 0xdb030cb319b6e128
  vsetvli t1, t0, e16, m2, ta, ma
  vor.vx v20, v22, t2

  li t2, 0x8f85b763f85e421f
  vsetvli t1, t0, e16, m2, ta, ma
  vor.vx v8, v24, t2

  li t2, 0xe4f4824aebed14db
  vsetvli t1, t0, e16, m2, ta, ma
  vor.vx v30, v4, t2

  li t2, 0x4820e8e7e4089329
  vsetvli t1, t0, e16, m4, ta, ma
  vor.vx v4, v16, t2

  li t2, 0x7a12fd051fdeb168
  vsetvli t1, t0, e16, m4, ta, ma
  vor.vx v16, v28, t2

  li t2, 0xa6cbdd724ffd8569
  vsetvli t1, t0, e16, m4, ta, ma
  vor.vx v8, v4, t2

  li t2, 0x69927e653eadd540
  vsetvli t1, t0, e16, m4, ta, ma
  vor.vx v4, v28, t2

  li t2, 0x9d4bc4f75731a3e9
  vsetvli t1, t0, e16, m4, ta, ma
  vor.vx v28, v20, t2

  li t2, 0x84ace3d7313ff2e4
  vsetvli t1, t0, e16, m4, ta, ma
  vor.vx v4, v28, t2

  li t2, 0x31fd6066bb4edace
  vsetvli t1, t0, e16, m4, ta, ma
  vor.vx v16, v8, t2

  li t2, 0x8c1ebfcfaca97f00
  vsetvli t1, t0, e16, m4, ta, ma
  vor.vx v8, v24, t2

  li t2, 0x6297bce039051afa
  vsetvli t1, t0, e16, m4, ta, ma
  vor.vx v8, v12, t2

  li t2, 0x0bd8d2eaa0036e55
  vsetvli t1, t0, e16, m4, ta, ma
  vor.vx v20, v16, t2

  li t2, 0x7e693280b9d0691f
  vsetvli t1, t0, e16, m8, ta, ma
  vor.vx v16, v8, t2

  li t2, 0xc0705f4a226a7bab
  vsetvli t1, t0, e16, m8, ta, ma
  vor.vx v24, v8, t2

  li t2, 0x4c54369fb39657b2
  vsetvli t1, t0, e16, m8, ta, ma
  vor.vx v8, v16, t2

  li t2, 0xe40c5270c4ebf843
  vsetvli t1, t0, e16, m8, ta, ma
  vor.vx v24, v16, t2

  li t2, 0x6651cb3b96d7d800
  vsetvli t1, t0, e16, m8, ta, ma
  vor.vx v24, v8, t2

  li t2, 0x4eb75fa0f95ee023
  vsetvli t1, t0, e16, m8, ta, ma
  vor.vx v24, v16, t2

  li t2, 0x1923224521c44035
  vsetvli t1, t0, e16, m8, ta, ma
  vor.vx v16, v24, t2

  li t2, 0x2a3d69af3d853ca5
  vsetvli t1, t0, e16, m8, ta, ma
  vor.vx v24, v16, t2

  li t2, 0x7620363053248ba7
  vsetvli t1, t0, e16, m8, ta, ma
  vor.vx v8, v24, t2

  li t2, 0x19f676c8bbd36eb3
  vsetvli t1, t0, e16, m8, ta, ma
  vor.vx v8, v16, t2

  li t2, 0x83e0ae2e72f50c19
  vsetvli t1, t0, e32, m1, ta, ma
  vor.vx v18, v23, t2

  li t2, 0x546cdcb9bc98a153
  vsetvli t1, t0, e32, m1, ta, ma
  vor.vx v26, v11, t2

  li t2, 0xd509ab18ae0ff740
  vsetvli t1, t0, e32, m1, ta, ma
  vor.vx v26, v2, t2

  li t2, 0xd6e1da05b76951ee
  vsetvli t1, t0, e32, m1, ta, ma
  vor.vx v4, v9, t2

  li t2, 0x50e245c727daf844
  vsetvli t1, t0, e32, m1, ta, ma
  vor.vx v30, v6, t2

  li t2, 0xe043bc154648d205
  vsetvli t1, t0, e32, m1, ta, ma
  vor.vx v25, v7, t2

  li t2, 0x99e5b753842bc7b2
  vsetvli t1, t0, e32, m1, ta, ma
  vor.vx v17, v16, t2

  li t2, 0x027d72f13c9f176d
  vsetvli t1, t0, e32, m1, ta, ma
  vor.vx v20, v24, t2

  li t2, 0x36fff5b2df135995
  vsetvli t1, t0, e32, m1, ta, ma
  vor.vx v27, v31, t2

  li t2, 0xa37cb4ec7315afd8
  vsetvli t1, t0, e32, m1, ta, ma
  vor.vx v6, v18, t2

  li t2, 0x7f37175bae4b2398
  vsetvli t1, t0, e32, m2, ta, ma
  vor.vx v16, v24, t2

  li t2, 0x59755e13513628db
  vsetvli t1, t0, e32, m2, ta, ma
  vor.vx v26, v30, t2

  li t2, 0xe2364b6f7a8c5bd2
  vsetvli t1, t0, e32, m2, ta, ma
  vor.vx v30, v24, t2

  li t2, 0xb49d99aaf4fd10c6
  vsetvli t1, t0, e32, m2, ta, ma
  vor.vx v26, v12, t2

  li t2, 0x1711cbaaf941db7a
  vsetvli t1, t0, e32, m2, ta, ma
  vor.vx v18, v20, t2

  li t2, 0xfc3408e6552f7a6f
  vsetvli t1, t0, e32, m2, ta, ma
  vor.vx v22, v10, t2

  li t2, 0x272542b8f2ea2f15
  vsetvli t1, t0, e32, m2, ta, ma
  vor.vx v2, v26, t2

  li t2, 0xfd40e84ad7385060
  vsetvli t1, t0, e32, m2, ta, ma
  vor.vx v20, v30, t2

  li t2, 0x06444b2f8603a2a0
  vsetvli t1, t0, e32, m2, ta, ma
  vor.vx v24, v4, t2

  li t2, 0x3d41fa3ee2516e09
  vsetvli t1, t0, e32, m2, ta, ma
  vor.vx v30, v10, t2

  li t2, 0x2008ec52a957ea78
  vsetvli t1, t0, e32, m4, ta, ma
  vor.vx v28, v4, t2

  li t2, 0xd0732a12cd8eab62
  vsetvli t1, t0, e32, m4, ta, ma
  vor.vx v28, v24, t2

  li t2, 0x698625b892c05688
  vsetvli t1, t0, e32, m4, ta, ma
  vor.vx v24, v16, t2

  li t2, 0x61089d180d4a7c69
  vsetvli t1, t0, e32, m4, ta, ma
  vor.vx v4, v16, t2

  li t2, 0xbd764e09af9bf952
  vsetvli t1, t0, e32, m4, ta, ma
  vor.vx v28, v24, t2

  li t2, 0xd99b8ffae04de997
  vsetvli t1, t0, e32, m4, ta, ma
  vor.vx v8, v24, t2

  li t2, 0xe921cbbf34ceba32
  vsetvli t1, t0, e32, m4, ta, ma
  vor.vx v12, v8, t2

  li t2, 0x752ba8f4007794b8
  vsetvli t1, t0, e32, m4, ta, ma
  vor.vx v20, v12, t2

  li t2, 0x4a6b17869d388ca9
  vsetvli t1, t0, e32, m4, ta, ma
  vor.vx v20, v4, t2

  li t2, 0x45b010e2a89eacb3
  vsetvli t1, t0, e32, m4, ta, ma
  vor.vx v4, v28, t2

  li t2, 0x72927e33bff001e2
  vsetvli t1, t0, e32, m8, ta, ma
  vor.vx v24, v16, t2

  li t2, 0xcc89e4415d98e765
  vsetvli t1, t0, e32, m8, ta, ma
  vor.vx v8, v24, t2

  li t2, 0xfbfb3f6f11125d74
  vsetvli t1, t0, e32, m8, ta, ma
  vor.vx v16, v24, t2

  li t2, 0x843282232f9cb6a6
  vsetvli t1, t0, e32, m8, ta, ma
  vor.vx v16, v8, t2

  li t2, 0x14fa0461699f18f2
  vsetvli t1, t0, e32, m8, ta, ma
  vor.vx v24, v16, t2

  li t2, 0xd49367f6326877d5
  vsetvli t1, t0, e32, m8, ta, ma
  vor.vx v24, v16, t2

  li t2, 0xf5a658c170f2e405
  vsetvli t1, t0, e32, m8, ta, ma
  vor.vx v24, v16, t2

  li t2, 0xa094bc3c6d0a0bfc
  vsetvli t1, t0, e32, m8, ta, ma
  vor.vx v24, v16, t2

  li t2, 0x520ea1319ce5ca48
  vsetvli t1, t0, e32, m8, ta, ma
  vor.vx v16, v8, t2

  li t2, 0x8eb9f9fda09e03a9
  vsetvli t1, t0, e32, m8, ta, ma
  vor.vx v24, v8, t2

  li t2, 0x7737332263a5fc84
  vsetvli t1, t0, e64, m1, ta, ma
  vor.vx v17, v1, t2

  li t2, 0x3b5376f67f304ec0
  vsetvli t1, t0, e64, m1, ta, ma
  vor.vx v26, v28, t2

  li t2, 0xa5f16258ec384f98
  vsetvli t1, t0, e64, m1, ta, ma
  vor.vx v26, v12, t2

  li t2, 0xacbcd7edd8fd9616
  vsetvli t1, t0, e64, m1, ta, ma
  vor.vx v4, v26, t2

  li t2, 0x93206700f6073f27
  vsetvli t1, t0, e64, m1, ta, ma
  vor.vx v14, v17, t2

  li t2, 0xb47e0555b12ac288
  vsetvli t1, t0, e64, m1, ta, ma
  vor.vx v31, v14, t2

  li t2, 0x85dedd416556a369
  vsetvli t1, t0, e64, m1, ta, ma
  vor.vx v4, v27, t2

  li t2, 0x6cf8640557581310
  vsetvli t1, t0, e64, m1, ta, ma
  vor.vx v20, v31, t2

  li t2, 0x7797945bc3836dba
  vsetvli t1, t0, e64, m1, ta, ma
  vor.vx v4, v10, t2

  li t2, 0xd90999ad9b85fece
  vsetvli t1, t0, e64, m1, ta, ma
  vor.vx v5, v15, t2

  li t2, 0xb3260621a9733cc7
  vsetvli t1, t0, e64, m2, ta, ma
  vor.vx v6, v24, t2

  li t2, 0x1a5c594cc5daa0d7
  vsetvli t1, t0, e64, m2, ta, ma
  vor.vx v28, v18, t2

  li t2, 0x582a6a8660d3005b
  vsetvli t1, t0, e64, m2, ta, ma
  vor.vx v18, v2, t2

  li t2, 0x1ce366ea52933e21
  vsetvli t1, t0, e64, m2, ta, ma
  vor.vx v4, v30, t2

  li t2, 0x242ebbf3e71eacf3
  vsetvli t1, t0, e64, m2, ta, ma
  vor.vx v28, v18, t2

  li t2, 0x8ae1663f5065e7a7
  vsetvli t1, t0, e64, m2, ta, ma
  vor.vx v6, v18, t2

  li t2, 0x76803604be5ef83c
  vsetvli t1, t0, e64, m2, ta, ma
  vor.vx v30, v22, t2

  li t2, 0x48efb1f2c199a052
  vsetvli t1, t0, e64, m2, ta, ma
  vor.vx v30, v26, t2

  li t2, 0x49f2c5faefbc9ead
  vsetvli t1, t0, e64, m2, ta, ma
  vor.vx v30, v10, t2

  li t2, 0x938811d73268e0d7
  vsetvli t1, t0, e64, m2, ta, ma
  vor.vx v26, v14, t2

  li t2, 0xd51f2dbdc76f81bd
  vsetvli t1, t0, e64, m4, ta, ma
  vor.vx v20, v28, t2

  li t2, 0xf2c8d69a6a60c57e
  vsetvli t1, t0, e64, m4, ta, ma
  vor.vx v16, v28, t2

  li t2, 0x21f5d9f6a044f3fb
  vsetvli t1, t0, e64, m4, ta, ma
  vor.vx v20, v24, t2

  li t2, 0x84f87bee4ac2c067
  vsetvli t1, t0, e64, m4, ta, ma
  vor.vx v28, v4, t2

  li t2, 0xdd0aba6a313719e5
  vsetvli t1, t0, e64, m4, ta, ma
  vor.vx v12, v4, t2

  li t2, 0x4773fa7b83741e30
  vsetvli t1, t0, e64, m4, ta, ma
  vor.vx v16, v20, t2

  li t2, 0x9afe0814998741b4
  vsetvli t1, t0, e64, m4, ta, ma
  vor.vx v12, v16, t2

  li t2, 0x197a65064cfc2990
  vsetvli t1, t0, e64, m4, ta, ma
  vor.vx v12, v16, t2

  li t2, 0xc65d0029fbff9533
  vsetvli t1, t0, e64, m4, ta, ma
  vor.vx v28, v16, t2

  li t2, 0x89e199df1757ea39
  vsetvli t1, t0, e64, m4, ta, ma
  vor.vx v4, v20, t2

  li t2, 0xa206e9d85e9fde5a
  vsetvli t1, t0, e64, m8, ta, ma
  vor.vx v16, v24, t2

  li t2, 0xb7ebf1fdc6a950ce
  vsetvli t1, t0, e64, m8, ta, ma
  vor.vx v24, v16, t2

  li t2, 0x8d8097ea35014fe4
  vsetvli t1, t0, e64, m8, ta, ma
  vor.vx v16, v8, t2

  li t2, 0x24189ce0a54e14ba
  vsetvli t1, t0, e64, m8, ta, ma
  vor.vx v8, v16, t2

  li t2, 0xfabc2da9434c608d
  vsetvli t1, t0, e64, m8, ta, ma
  vor.vx v16, v8, t2

  li t2, 0xdfaab125075e5599
  vsetvli t1, t0, e64, m8, ta, ma
  vor.vx v8, v16, t2

  li t2, 0x87c309e89438f396
  vsetvli t1, t0, e64, m8, ta, ma
  vor.vx v8, v24, t2

  li t2, 0xc650a89b63c04aa3
  vsetvli t1, t0, e64, m8, ta, ma
  vor.vx v24, v8, t2

  li t2, 0xc54c37d1b081d05a
  vsetvli t1, t0, e64, m8, ta, ma
  vor.vx v16, v8, t2

  li t2, 0xffbe87e30d31846c
  vsetvli t1, t0, e64, m8, ta, ma
  vor.vx v16, v24, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vi v30, v21, -6

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vi v5, v2, -12

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vi v27, v14, -6

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vi v25, v13, -9

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vi v6, v13, 15

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vi v30, v8, 3

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vi v7, v30, -3

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vi v7, v8, -13

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vi v19, v4, 7

  vsetvli t1, t0, e8, m1, ta, ma
  vor.vi v14, v19, -3

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vi v28, v20, -11

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vi v8, v4, -11

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vi v6, v24, 5

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vi v16, v20, 6

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vi v6, v2, -10

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vi v26, v16, 6

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vi v16, v12, -11

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vi v10, v22, -5

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vi v6, v24, 0

  vsetvli t1, t0, e8, m2, ta, ma
  vor.vi v6, v4, -4

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vi v28, v12, 4

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vi v16, v4, 8

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vi v4, v28, 10

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vi v20, v4, -4

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vi v28, v24, 3

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vi v24, v20, 11

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vi v8, v20, -1

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vi v8, v12, 13

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vi v8, v12, -15

  vsetvli t1, t0, e8, m4, ta, ma
  vor.vi v8, v28, 10

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vi v8, v24, 4

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vi v24, v16, -1

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vi v24, v16, 14

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vi v16, v24, -10

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vi v8, v24, 9

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vi v16, v8, -8

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vi v16, v24, -9

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vi v8, v24, -10

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vi v24, v16, 10

  vsetvli t1, t0, e8, m8, ta, ma
  vor.vi v8, v24, 5

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vi v11, v1, -4

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vi v3, v13, 8

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vi v28, v26, -6

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vi v28, v17, -11

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vi v2, v16, 1

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vi v8, v18, 7

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vi v10, v5, -4

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vi v24, v16, 15

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vi v10, v7, -5

  vsetvli t1, t0, e16, m1, ta, ma
  vor.vi v24, v5, -3

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vi v8, v30, -12

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vi v14, v4, 6

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vi v26, v16, 3

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vi v10, v26, -8

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vi v24, v2, 6

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vi v6, v2, 3

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vi v16, v20, -11

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vi v28, v22, -14

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vi v10, v18, 5

  vsetvli t1, t0, e16, m2, ta, ma
  vor.vi v10, v8, 11

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vi v28, v4, -14

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vi v28, v8, 11

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vi v12, v8, 8

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vi v12, v28, 10

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vi v12, v24, 1

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vi v12, v28, -11

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vi v28, v4, 4

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vi v28, v12, -3

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vi v20, v16, 1

  vsetvli t1, t0, e16, m4, ta, ma
  vor.vi v16, v20, -3

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vi v16, v8, 8

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vi v24, v16, 0

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vi v24, v8, 2

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vi v8, v16, 2

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vi v24, v16, -2

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vi v8, v24, 4

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vi v24, v16, 11

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vi v24, v8, 8

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vi v8, v16, 9

  vsetvli t1, t0, e16, m8, ta, ma
  vor.vi v24, v8, 15

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vi v14, v1, -11

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vi v29, v25, -4

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vi v29, v6, -16

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vi v12, v19, -16

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vi v1, v31, 9

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vi v16, v9, 2

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vi v14, v25, 10

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vi v18, v8, -1

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vi v21, v8, -10

  vsetvli t1, t0, e32, m1, ta, ma
  vor.vi v16, v28, -10

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vi v20, v22, -14

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vi v14, v24, -16

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vi v2, v18, -6

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vi v16, v4, -1

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vi v18, v28, 1

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vi v28, v22, -2

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vi v22, v28, -9

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vi v16, v18, 1

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vi v18, v6, -12

  vsetvli t1, t0, e32, m2, ta, ma
  vor.vi v16, v24, -4

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vi v8, v24, -8

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vi v24, v20, -10

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vi v28, v16, -12

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vi v24, v20, -12

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vi v4, v16, -13

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vi v16, v12, -7

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vi v8, v28, 10

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vi v20, v24, 3

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vi v8, v20, -12

  vsetvli t1, t0, e32, m4, ta, ma
  vor.vi v20, v28, 2

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vi v24, v8, -9

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vi v16, v8, 11

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vi v8, v16, -2

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vi v8, v16, 0

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vi v24, v16, -12

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vi v24, v8, -11

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vi v8, v24, -8

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vi v24, v8, -14

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vi v8, v24, 5

  vsetvli t1, t0, e32, m8, ta, ma
  vor.vi v8, v16, 7

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vi v7, v6, -5

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vi v18, v15, -9

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vi v9, v31, 4

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vi v3, v13, 3

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vi v24, v23, -15

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vi v15, v27, 11

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vi v30, v5, -6

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vi v1, v18, 1

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vi v4, v21, 13

  vsetvli t1, t0, e64, m1, ta, ma
  vor.vi v22, v3, 10

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vi v22, v18, -6

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vi v20, v16, -10

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vi v4, v22, 7

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vi v6, v2, 9

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vi v24, v20, -10

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vi v30, v16, 5

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vi v2, v10, 6

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vi v24, v18, 11

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vi v12, v16, -6

  vsetvli t1, t0, e64, m2, ta, ma
  vor.vi v4, v10, -6

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vi v28, v20, 1

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vi v12, v20, -7

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vi v4, v24, 10

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vi v28, v12, -2

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vi v24, v16, 3

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vi v4, v12, 0

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vi v12, v24, -12

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vi v24, v20, -15

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vi v28, v20, 6

  vsetvli t1, t0, e64, m4, ta, ma
  vor.vi v16, v28, 13

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vi v16, v8, 15

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vi v24, v8, 11

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vi v8, v16, -11

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vi v8, v16, 13

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vi v24, v8, 11

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vi v24, v8, -9

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vi v8, v16, -14

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vi v8, v24, -15

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vi v8, v16, 8

  vsetvli t1, t0, e64, m8, ta, ma
  vor.vi v8, v16, -3

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
