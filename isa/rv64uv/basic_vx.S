#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  li t2, 0x2de3b0898caa161a
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v14, v1, t2

  li t2, 0xe0d45b82054f271f
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v24, v13, t2

  li t2, 0x4e5cbb3ab80e991a
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v1, v19, t2

  li t2, 0xf80ffb82c4640cc1
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v20, v15, t2

  li t2, 0x134c06af649724a8
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v6, v15, t2

  li t2, 0x4176dcce03c7808b
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v26, v7, t2

  li t2, 0x751abb64970737ad
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v25, v15, t2

  li t2, 0x28bacc01a00056bd
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v17, v19, t2

  li t2, 0x87bc18caadec8ebe
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v23, v17, t2

  li t2, 0x08d716ca1e4d56e4
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v16, v15, t2

  li t2, 0x9f8dcaebcdc1768e
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v25, v28, t2

  li t2, 0xf4ae3383086da2fc
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v8, v12, t2

  li t2, 0x49fcf5e3fcaf94cc
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v27, v25, t2

  li t2, 0x5c4431fc0e9d4241
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v12, v11, t2

  li t2, 0xf1613791a6678104
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v21, v2, t2

  li t2, 0xa40cf5283fd2c269
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v15, v13, t2

  li t2, 0xd55407ce5e7c2772
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v4, v26, t2

  li t2, 0x2d8eb0f9c7f0ea91
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v25, v22, t2

  li t2, 0x5a58e54950369272
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v6, v7, t2

  li t2, 0xb215b7e71d2b4b0a
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v26, v3, t2

  li t2, 0xd832379e65c25c1c
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v18, v25, t2

  li t2, 0xedbbc2e0798da32e
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v5, v31, t2

  li t2, 0x347bbb73779aafe8
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v24, v22, t2

  li t2, 0x985d1e110c90a2f2
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v31, v30, t2

  li t2, 0x39374da7979ef7d6
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v1, v12, t2

  li t2, 0x6adfaebbba35c4d9
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v14, v19, t2

  li t2, 0x7c41e025992718f6
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v24, v5, t2

  li t2, 0xa0df551f2217326f
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v9, v26, t2

  li t2, 0xd8587a7e1e459696
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v10, v11, t2

  li t2, 0x70987d0078108602
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v4, v26, t2

  li t2, 0xa1604f98a6588dd7
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v22, v1, t2

  li t2, 0xb597755c7899f449
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v20, v28, t2

  li t2, 0xbf3bd530b3977e14
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v11, v5, t2

  li t2, 0xd29ce6c0688bf504
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v5, v27, t2

  li t2, 0x390ad21e4992b5be
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v24, v25, t2

  li t2, 0xe1e6d6841bd1eed0
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v13, v28, t2

  li t2, 0xf48effc05787a517
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v2, v14, t2

  li t2, 0xd4a1166ad2b7d77b
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v8, v25, t2

  li t2, 0x44a3063986880db0
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v18, v16, t2

  li t2, 0xdd483da969d40812
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v1, v8, t2

  li t2, 0x0243b3844c59131b
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v7, v8, t2

  li t2, 0xde15dd492751d988
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v13, v6, t2

  li t2, 0xfe9889832c4758e0
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v10, v28, t2

  li t2, 0xa99f935cc51cf472
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v5, v19, t2

  li t2, 0x9de5f6b739e774ed
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v25, v23, t2

  li t2, 0xb1be3ac1469f4931
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v2, v21, t2

  li t2, 0x416d6e051c63ebfd
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v6, v23, t2

  li t2, 0x881d3dfc0672f4d0
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v2, v20, t2

  li t2, 0x8bfb964ffde1311c
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v13, v19, t2

  li t2, 0x4dd2d7a73794f7c9
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v31, v6, t2

  li t2, 0x60bbcf4dc6c5bf5d
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v6, v23, t2

  li t2, 0x6d5e4bc6ef6ca701
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v16, v4, t2

  li t2, 0xa46d644d9e8e0690
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v31, v2, t2

  li t2, 0xe383eb3d6e8c221d
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v8, v6, t2

  li t2, 0x7db026497ca3faaf
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v22, v25, t2

  li t2, 0x410c24a2b7637520
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v30, v12, t2

  li t2, 0x4b4f63da409a266b
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v17, v28, t2

  li t2, 0x100eb3b1b153cc19
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v17, v21, t2

  li t2, 0xd80b7f9764527619
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v17, v10, t2

  li t2, 0xcc216061dcc05015
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v11, v23, t2

  li t2, 0xe2849275680c6283
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v14, v11, t2

  li t2, 0x9d2778bd3a6258d5
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v13, v28, t2

  li t2, 0xbf5d2df51a330fae
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v29, v5, t2

  li t2, 0x0c442dbb7f0b2099
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v7, v12, t2

  li t2, 0x24fce23ad199c99b
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v7, v15, t2

  li t2, 0x8a15dc15ff6a1fef
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v29, v27, t2

  li t2, 0x2bf82a142ddd093e
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v21, v15, t2

  li t2, 0x8f0ba27359f64caf
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v15, v6, t2

  li t2, 0x6a003d250d306940
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v29, v23, t2

  li t2, 0xc5d11172e61b9705
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v8, v28, t2

  li t2, 0x20820eac2f831c07
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v10, v17, t2

  li t2, 0x5ce5a8ee963fc8bf
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v2, v9, t2

  li t2, 0xeacbb49069d99a9f
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v2, v8, t2

  li t2, 0x42bae31d8614fe9c
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v14, v25, t2

  li t2, 0x658ee95a24ce7f74
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v27, v12, t2

  li t2, 0x0ef6d6f78e24310d
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v25, v26, t2

  li t2, 0x2a66502dbb0d2c8f
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v9, v29, t2

  li t2, 0xffff09d3b6f3baf0
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v17, v14, t2

  li t2, 0x219105ad11b92175
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v26, v2, t2

  li t2, 0xa2f1b2492a4b689c
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v7, v4, t2

  li t2, 0xacab12bcf7fa0fbd
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v16, v18, t2

  li t2, 0x24c1baabd9394ea4
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v12, v4, t2

  li t2, 0xac26af85f65abef0
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v26, v27, t2

  li t2, 0xd68dce3fb0ced8a2
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v3, v19, t2

  li t2, 0x7adf54da1c4ba43a
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v27, v31, t2

  li t2, 0x36c83b0c95afc9fc
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v14, v5, t2

  li t2, 0x1b3f8dc88a97cd44
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v1, v16, t2

  li t2, 0x26a1f7930b9b4a10
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v9, v2, t2

  li t2, 0x44e0120e84ae3e5f
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v31, v10, t2

  li t2, 0x74c9b1334bd53a5a
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v14, v15, t2

  li t2, 0x0b98ec2784c69f63
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v11, v15, t2

  li t2, 0xcb5147170476c760
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v19, v20, t2

  li t2, 0x1363e22e086d5241
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v14, v21, t2

  li t2, 0x0c98686cb7aa8da1
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v13, v26, t2

  li t2, 0xc561144a04a53778
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v6, v28, t2

  li t2, 0x1b0cee3af949629b
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v20, v29, t2

  li t2, 0x7d7e9a392d29786d
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v28, v5, t2

  li t2, 0x52da8382047ae8eb
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v30, v22, t2

  li t2, 0xa68751c0de4a3d9f
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v3, v27, t2

  li t2, 0xeba440b1e9ad00b2
  vsetvli t1, t0, e64, m1, ta, ma
  vadd.vx v1, v6, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
