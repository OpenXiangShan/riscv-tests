#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  li t2, 0xe5c6d33dce917f04
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v4, t2, v14

  li t2, 0xd8845809f3d90504
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v26, t2, v14

  li t2, 0xdc2d5ae85455e38b
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v14, t2, v30

  li t2, 0xe1d321f97fcb15f3
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v24, t2, v28

  li t2, 0x1a57249b8c0ea7d6
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v20, t2, v18

  li t2, 0xcc96e53009d78933
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v28, t2, v16

  li t2, 0xf4c8615ee230540a
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v22, t2, v30

  li t2, 0x9be25cb9b108af0a
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v20, t2, v12

  li t2, 0x093a0a57325b4c4b
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v28, t2, v20

  li t2, 0x43fe3011a3e3c650
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v18, t2, v16

  li t2, 0xa5623b93bf58cd6f
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v6, t2, v2

  li t2, 0xe8fe34543fdc87d0
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v12, t2, v16

  li t2, 0x0087fbc0ab73f05a
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v26, t2, v14

  li t2, 0x9df843f284539885
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v24, t2, v10

  li t2, 0xab22a426ce0ca113
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v12, t2, v28

  li t2, 0x93db14c4cf72b13f
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v8, t2, v2

  li t2, 0xb958afeae5fdab91
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v18, t2, v28

  li t2, 0xa869aec36b033283
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v10, t2, v6

  li t2, 0x42bd1994faad91c7
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v2, t2, v8

  li t2, 0x691b136f6e82a744
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v24, t2, v28

  li t2, 0x4694e9d812429364
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v20, t2, v14

  li t2, 0x9bf5c3c3e3802f7f
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v28, t2, v10

  li t2, 0x8851d9a4d0aa25af
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v10, t2, v18

  li t2, 0x585c2988b103d9f0
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v10, t2, v12

  li t2, 0x183b3d6637647512
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x21afade94b37d711
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v20, t2, v24

  li t2, 0xd5b7d8eb6ca0135a
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v18, t2, v14

  li t2, 0x3be5bfcf44ac74c9
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v10, t2, v18

  li t2, 0x5015b8904673e4d1
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v26, t2, v24

  li t2, 0x710cc8e0c654fcf4
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v22, t2, v2

  li t2, 0xc9439f02efa20d45
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v10, t2, v30

  li t2, 0x5cfaeb5a0a494cc4
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v10, t2, v16

  li t2, 0x0ee375b4d92c6814
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v18, t2, v16

  li t2, 0x4f25a376f83a6147
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v4, t2, v14

  li t2, 0x2f172837dcc6ef47
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v30, t2, v18

  li t2, 0x364537597f481120
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v20, t2, v4

  li t2, 0xdba00a5b58f83b9b
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0xa49c4f4ba313af3d
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x1d56b7d1b3a32175
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v26, t2, v6

  li t2, 0x039c9050f86fdad4
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xecc6df9cce70c1f9
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v8, t2, v18

  li t2, 0x524ec784dd068bbe
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v2, t2, v6

  li t2, 0xa2e4b81e06b29248
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v20, t2, v18

  li t2, 0x71dd0f6a2b7c22b5
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v22, t2, v28

  li t2, 0xf1199ec59c7b10d0
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v18, t2, v22

  li t2, 0x69d319cd5709fc3c
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v14, t2, v8

  li t2, 0xc48b12f73309faf7
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v12, t2, v20

  li t2, 0x99a01ca26c13a874
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v28, t2, v6

  li t2, 0x03c2ef96ae462124
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v26, t2, v10

  li t2, 0x1f9f947059724c13
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v28, t2, v22

  li t2, 0x295899b8ff276beb
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v24, t2, v14

  li t2, 0xf85e31f937c50dfe
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v8, t2, v28

  li t2, 0x27c01af0fa0cf14e
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v22, t2, v6

  li t2, 0x248f87298296db69
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xdf2fec5c9911f33a
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v12, t2, v16

  li t2, 0xb2dccd19cadade3d
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v16, t2, v22

  li t2, 0x56f4133d29395fec
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v8, t2, v18

  li t2, 0xe98815ac5edc4c72
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v10, t2, v24

  li t2, 0xd2085826aa7cd938
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v16, t2, v28

  li t2, 0xf17ea24601c80e4d
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v6, t2, v30

  li t2, 0xd5b6f68eb52d7f67
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v26, t2, v8

  li t2, 0xbaffed2c49bface2
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v24, t2, v2

  li t2, 0x6054d0340a118728
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v4, t2, v12

  li t2, 0x0bec9b01db14d9ce
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v8, t2, v4

  li t2, 0x2122241f470f4678
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v30, t2, v22

  li t2, 0xda21db9211951aee
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v14, t2, v8

  li t2, 0xfd0828eb730efc66
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v18, t2, v22

  li t2, 0xfa1d35870e38214a
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0xd751bcb91c35aae4
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v30, t2, v6

  li t2, 0xb31e7097e9c5b3d5
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v4, t2, v18

  li t2, 0xeaf016012a632cc4
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v12, t2, v14

  li t2, 0x8097d35533a790b5
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v8, t2, v12

  li t2, 0x48352a148d995f98
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v28, t2, v20

  li t2, 0xcb41053da7a6a416
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v20, t2, v14

  li t2, 0xc2f1a18549fbe033
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v18, t2, v30

  li t2, 0x678e3f1e925eebbd
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v8, t2, v18

  li t2, 0xabc5d58d3276a175
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v26, t2, v22

  li t2, 0xa9bf577748b50212
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v30, t2, v10

  li t2, 0x586e0d0fb80bfcb8
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v6, t2, v10

  li t2, 0xf0390a382e0d7f27
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v22, t2, v14

  li t2, 0x29c3bbfbb63bd4e1
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v28, t2, v20

  li t2, 0xdc2a77e1743b0d93
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v14, t2, v28

  li t2, 0x5af4f57980b96bed
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v28, t2, v12

  li t2, 0xee94a17513e80926
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v8, t2, v18

  li t2, 0xc1c21aadda108797
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v22, t2, v26

  li t2, 0x61075687f6cfefb6
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v12, t2, v6

  li t2, 0x3be8ff4519108e9f
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v2, t2, v6

  li t2, 0x6cdb9953ca0ab459
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v14, t2, v10

  li t2, 0xea877f1f7ccbc5af
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v12, t2, v20

  li t2, 0xcf47d2527c0da327
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v2, t2, v10

  li t2, 0xee6776725ad34a72
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v16, t2, v6

  li t2, 0x6dcad7fb7003b0fd
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v20, t2, v28

  li t2, 0x6f413673d132c3d4
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v24, t2, v6

  li t2, 0x39362302c252cffe
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v26, t2, v4

  li t2, 0x374adf75f80f767b
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v12, t2, v10

  li t2, 0x01069b2291a2121b
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x3dd6061a4563072a
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v20, t2, v4

  li t2, 0xb494326e302b44f3
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v22, t2, v12

  li t2, 0x3ba42c0b79e817ed
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v24, t2, v6

  li t2, 0x276992ae817ac105
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccus.vx v22, t2, v24

  li t2, 0x461d5c8da60279de
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v4, t2, v12

  li t2, 0xc7448abf426e5111
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x93dc3b2eb358d309
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v8, t2, v28

  li t2, 0xe11ba9e3c257672d
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v4, t2, v16

  li t2, 0x94c9dd5f31cec7a7
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v16

  li t2, 0xae15c204880e6439
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v8

  li t2, 0x545819bdfa84a747
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v8

  li t2, 0xc1cddb626f59b86e
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x109f594c7501a7d4
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v28, t2, v16

  li t2, 0xf3f1f9e4d5915077
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xd42364b80101591d
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xc1cd2dab8ca290d1
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v24

  li t2, 0x2701ab55b3de497a
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v8

  li t2, 0xcb5c10939b712308
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v8

  li t2, 0xdb42936df28f2f1b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v20

  li t2, 0xf8962aa802d0d096
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v20

  li t2, 0x8c2de91c740cddad
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xf26e52d281306a4a
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x2a4e6c3e99287ad2
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x8d079415870e3bd3
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v4

  li t2, 0xe79040470603667e
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v8, t2, v12

  li t2, 0x2c80d396d587f429
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xed501dee87525579
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v12

  li t2, 0xd8086556d399ba47
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v4, t2, v28

  li t2, 0xe59b8446b324a3cd
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v12

  li t2, 0x68b1aeb0e6080f8b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v16

  li t2, 0xe1167c2d93ffdbb4
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v24

  li t2, 0x47d9e61711cb64e7
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v28, t2, v16

  li t2, 0xa400f968efbc852b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v20

  li t2, 0x714e55de79a49ac0
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v28

  li t2, 0x95f238770736e593
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v4, t2, v20

  li t2, 0x052e17670bd6053c
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v24

  li t2, 0x246fb58a6b451153
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v28, t2, v16

  li t2, 0x1ff57d58192a3fa2
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v8, t2, v4

  li t2, 0xd9dcb9357f46ce58
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v8

  li t2, 0x8b49a3cb85402d19
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0x537729caf8f0e81d
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v8, t2, v28

  li t2, 0x79f008cb078e43ab
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v4

  li t2, 0xbdeb5f16cc209917
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v4

  li t2, 0x75e212f6cc084240
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v28

  li t2, 0x58495b4c76dac4a3
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v28

  li t2, 0x16d5731a110a429f
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v28

  li t2, 0xd3007d6b7d8eb792
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v24

  li t2, 0x9630be7f177b4236
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v12

  li t2, 0xb242085edafbac1e
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v24

  li t2, 0x19ddc503fb8d37f8
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v8, t2, v28

  li t2, 0xc12416ca3a421d04
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xd22c5d434a2f6962
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v28, t2, v8

  li t2, 0xc556614d29370f19
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v20

  li t2, 0xc1adeb2ddc0d0df5
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v20

  li t2, 0x65073f64a32ec467
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v16, t2, v12

  li t2, 0xce8a7457bc9b9cda
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v16

  li t2, 0x3f4e3578e448dd29
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v16

  li t2, 0x9351d99598a762e6
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xe4a39e930d757913
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v4, t2, v20

  li t2, 0xf39560a7f52b869b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v28, t2, v20

  li t2, 0x2c689bc346fd05df
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v28, t2, v8

  li t2, 0x7d99a1fadd843c59
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v8, t2, v20

  li t2, 0x8224abd8ff96ada8
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v24

  li t2, 0x6269618fe0b8fe48
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v28, t2, v12

  li t2, 0xc9ffac2645aca9bc
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v12

  li t2, 0x99c8930d52f2e152
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v4, t2, v20

  li t2, 0xb88d6d96b4b2f772
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0xfdbb04cadf42061d
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x3a9a9021979fbc60
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v4, t2, v24

  li t2, 0x8ff0090fd578c534
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v8

  li t2, 0x03446e2597c843cb
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v16, t2, v20

  li t2, 0x64387f220ba1059b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v28, t2, v20

  li t2, 0x37ca3cb346775e7f
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x8a6cfc77589b9ecb
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v28, t2, v24

  li t2, 0x0f70fcd3fee4981c
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v8

  li t2, 0x2cf2e648f7c2d66b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v4, t2, v28

  li t2, 0xd86ad94860fdf441
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v28, t2, v16

  li t2, 0xe332a1dd29688fb6
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v4

  li t2, 0x2d832faeea053330
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v4, t2, v20

  li t2, 0xe0e65ddca96b55ce
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v16, t2, v20

  li t2, 0x5b4ad9f36cd6d098
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v8

  li t2, 0x706c19bb7bbb7e4c
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v20

  li t2, 0x370348d87b5cedc4
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v8

  li t2, 0x51fa5b088d9f054c
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v16, t2, v12

  li t2, 0x723e437053d93a51
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v4

  li t2, 0xfb1ca01a67b905c8
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v8

  li t2, 0xac74d9d81398b73a
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v8

  li t2, 0x553aabdc7b4667a7
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0xba1506e2e4cd8376
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v4

  li t2, 0xccb9cf71160b9668
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v24

  li t2, 0x58fa4db2a7244336
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v20, t2, v16

  li t2, 0xb2ca929ae9c80c41
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v28

  li t2, 0x03765db7e592dac5
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v28, t2, v20

  li t2, 0xe3dcd8973744216e
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x91d94549a340dd0d
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v24, t2, v20

  li t2, 0xd3e2e052ea48977b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v4, t2, v28

  li t2, 0x63eef418f64f7310
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v12, t2, v28

  li t2, 0xd93400cdd5327316
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v4, t2, v8

  li t2, 0x5305c88169c2e097
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v4, t2, v28

  li t2, 0xd4dd555e774827ad
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x0ae356883635af11
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v28, t2, v20

  li t2, 0x6fa0f3aac0324833
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v28, t2, v12

  li t2, 0x30398f6dcf6561b5
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v16, t2, v4

  li t2, 0xda0e5ad73c673dc4
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccus.vx v4, t2, v20

  li t2, 0xe5729c80781b7efe
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x02c9db68a57ecd39
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x43537a1cbdafa018
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x0ff618c8dd8c16e1
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xc4b56387c6c4c4a7
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x94f994082f5ae843
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xeb89cb6fea5aa127
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xd7e956d581fb7820
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xd6312880c8e10e25
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xd045a9ba5808e8b6
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x29fdcb6c7e39e506
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x3d9384d23eaa7d85
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x07a73d173506d332
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xedb7cc6c7d45abac
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x17d08b6d28ac099b
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x2b990361386536ea
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x76fe1a77ae80bb99
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x9d8f479c2bbccd6c
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x7f1d4d66d923e43f
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x337900839f6e918a
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xcb021364fc6e468c
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xbb7e3f64e2c0f086
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x5c93cd9d8b52ef3a
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x41b5e93583176527
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x421d519e1ab411f6
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x6b7f9da35a2d6a66
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x81028c34b3f854e8
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x8e4471945058b81a
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xa02c3a5a8515d226
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x8c1b0c0dfaef8f01
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x166c6270fc670d11
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x15532529d796d3ed
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x833b3064e15a2624
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x759ce1e1ee85ea72
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xc3489a183d4b0b4c
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x39b246f977e19898
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x268e11b67fc80b69
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xd6b310451feed347
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x3ed47a9e0bf2f53e
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xa68af1d225967268
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0xf8c83bff4da03302
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x30c4059c8b0d3701
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x487bb2745f0850f8
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xe17690a2bc8f0835
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x084b596517ef98f6
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x8fe1a2388f79d1cf
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xf8a1d8452904ac39
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x2027bd31746726ed
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0xec83f871a3e58b9f
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xfe695f65d1db7219
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xfc166f9200ae642d
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x1562fbdf78f3b1c1
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x4eba2824b7ec7b7b
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xf9928d7f2b757b26
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0xb397c9b608b812e5
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x524fa64f79809075
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x19d2b01a7c49301b
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x7ad0c4eb1293fcb4
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x4c9e5d9a8ba25892
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x43730b1f7f5024fa
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x24da5fd806efefb4
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x70d56ad7f88d02fc
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x2c5505a95cdcb79d
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x675f8b862920d1a5
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x686f1b6b60c94179
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xd251b3744d62403e
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x60957080f5f015d9
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x5ad594e10c773462
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x571db8b3ecd5877e
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xc5cff0138cb937c0
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x9c5b16ef2cc4bc17
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xcca68c0f1610bfa0
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x68e5406016a69e2d
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x4cb61fcfc2b05e08
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xea913437134eaefa
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x03d406bdfc0cec65
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xf2554eaa4fbdcd51
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0xc4a15e1365bada75
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xd925bac74b93cf4c
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x4c26af0509bc6301
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xc4874fd377ac893f
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xcc5085bac1926037
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x79dfcf16ee61f8a3
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x7772ef9629c14a7a
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x06ca30b2b4fea74b
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x4e312bf6026fee8c
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x5e63cab168c45e0e
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xc258c3a8d80916e6
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xcf7c9a7916dbff9f
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x04112ee5cd3ba4e7
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x7e1878bbc91c0965
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xb027a999c93e4fe3
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xffbc7512f9a37673
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x3ed6813e20d47c8c
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xba6fb987dec4a491
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xbda10ed2b691883a
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x6949762eff2f7f38
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x0faf5f0a1395aa56
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xfd3ad984d796d5ee
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x7662b0b67fa29d26
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xa1ca6468cb46d89b
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v4, t2, v28

  li t2, 0x97a15a94f9cc7682
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v12, t2, v22

  li t2, 0xb48bbfcd4bbaf848
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v4, t2, v12

  li t2, 0x9fb5fad289536101
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xcffaa69a99462e44
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v2, t2, v18

  li t2, 0xe4309544fe3ef9fc
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v2, t2, v24

  li t2, 0x6910d2b9bc6b9bd8
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v26, t2, v6

  li t2, 0x2c7f137ea66f2778
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v2, t2, v26

  li t2, 0x12ca5b9c246ca533
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v14, t2, v24

  li t2, 0xc781140cd8a37b6f
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v8, t2, v18

  li t2, 0xd2046118a9faeee5
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v16, t2, v10

  li t2, 0xf09837e940f60851
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v6, t2, v8

  li t2, 0x43e8b051114d455f
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v2, t2, v4

  li t2, 0x1350030dad0292bd
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v2, t2, v12

  li t2, 0x9b3a381759eefba5
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v10, t2, v28

  li t2, 0x750011227d1c2f16
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v30, t2, v18

  li t2, 0xf2d5c38103d6a7ac
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v6, t2, v10

  li t2, 0x46ea135db042fd6c
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v30, t2, v26

  li t2, 0x1df9e64897dbdd79
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v20, t2, v6

  li t2, 0x1b96bbfe848302dd
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v28, t2, v10

  li t2, 0x31e4615577ac995f
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v26, t2, v8

  li t2, 0xe00255b859688abb
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v18, t2, v28

  li t2, 0xd910a86db17f0a1d
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v18, t2, v6

  li t2, 0x6a61e1dec0b9e7d7
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v30, t2, v24

  li t2, 0xef5da357802ec9bc
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v18, t2, v10

  li t2, 0x5b24f5b1f4dabc2b
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v12, t2, v26

  li t2, 0x6999beaf83756002
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v12, t2, v10

  li t2, 0x6b367764e0f69674
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v16, t2, v22

  li t2, 0xd198a15de8f1f00b
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v18, t2, v26

  li t2, 0x61993c98a7bfb453
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v6, t2, v14

  li t2, 0xb699d9e18d0e5825
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v26, t2, v16

  li t2, 0x0c201104df7e12b9
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v30, t2, v12

  li t2, 0x14f4757bc1345763
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v6, t2, v18

  li t2, 0x2fc9530240faa2f0
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v24, t2, v6

  li t2, 0x74dbe15d6d337b3e
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v14, t2, v30

  li t2, 0xebeb0aeb7eb83ccc
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v26, t2, v16

  li t2, 0x25d2192458a759dd
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v30, t2, v12

  li t2, 0x8ddfc55e05e68de8
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v22, t2, v6

  li t2, 0x385b75213933cbe7
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v24, t2, v28

  li t2, 0xd370fbe7aea0d514
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v22, t2, v16

  li t2, 0xbbd3d893e41a45c3
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v8, t2, v14

  li t2, 0x178bf77e633f7b12
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v12, t2, v6

  li t2, 0x72a060e8d50ef0e5
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v14, t2, v18

  li t2, 0x2dd9786e981e2e93
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v10, t2, v12

  li t2, 0x1a5e3f6bd781b511
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v24, t2, v18

  li t2, 0xfb8706816f23f050
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v8, t2, v18

  li t2, 0xd0a481d38260c490
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v6, t2, v30

  li t2, 0x2344e470e0a15e1f
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v18, t2, v6

  li t2, 0x8ebed9fe1dec8eba
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v26, t2, v12

  li t2, 0xeeec12d6b9017358
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v4, t2, v8

  li t2, 0x9c8c8a5c03e31417
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v4, t2, v8

  li t2, 0xed223ff8e1eac32a
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v22, t2, v4

  li t2, 0xe5455b7e53030797
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v10, t2, v30

  li t2, 0x8a842934e0867f91
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v28, t2, v22

  li t2, 0x8fa51e89f7afd19e
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v6, t2, v24

  li t2, 0x68ff50349571077f
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v30, t2, v16

  li t2, 0x86bd6c48b2140ded
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v20, t2, v6

  li t2, 0xa0432eb9ccee6a21
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v6, t2, v20

  li t2, 0x982a3b3e1dcc0fd0
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v12, t2, v8

  li t2, 0xa5b6e9f9288873da
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v4, t2, v18

  li t2, 0x02d74e9ec3d96cda
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v14, t2, v8

  li t2, 0x20aad06d925ccf63
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v30, t2, v2

  li t2, 0x11751859f57e4b49
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v26, t2, v22

  li t2, 0xd1b49c5863520652
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v24, t2, v20

  li t2, 0xc5dd8bbc69620f84
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v8, t2, v14

  li t2, 0x864cea1b971d4adb
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v4, t2, v16

  li t2, 0xbedfc26084269978
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v22, t2, v6

  li t2, 0xca3b148a1245037b
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v28, t2, v26

  li t2, 0x789a5449ce65e251
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v12, t2, v26

  li t2, 0x2b019b96455d2cb8
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v10, t2, v18

  li t2, 0x01c731ed9065aceb
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v8, t2, v20

  li t2, 0xf413ad879b640100
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v14, t2, v28

  li t2, 0xbf25c1ebea24c6c0
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v2, t2, v10

  li t2, 0x27ebff9f7b66a515
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xa17f198d78267074
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v10, t2, v28

  li t2, 0x04d5aebd498be73d
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v20, t2, v26

  li t2, 0x090e5f30e67d9622
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v4, t2, v18

  li t2, 0x3d5de0c2a0568d4a
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v4, t2, v28

  li t2, 0xe3a44defa443cfc0
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v10, t2, v4

  li t2, 0xe839eb97f2a5d52b
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v8, t2, v28

  li t2, 0xa07ad56f43aebeff
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v24, t2, v20

  li t2, 0xe72180f31e7834d2
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v2, t2, v4

  li t2, 0x7df078d3015f4043
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v2, t2, v4

  li t2, 0xc736bd6362682779
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v10, t2, v26

  li t2, 0xf00a4d07a48861d3
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v30, t2, v14

  li t2, 0xacaa21dc0908d9bf
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v2, t2, v18

  li t2, 0x45fad84a403d6318
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v10, t2, v12

  li t2, 0xbab578462d79ad14
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v28, t2, v26

  li t2, 0x031096af9bd5f5e8
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v8, t2, v4

  li t2, 0x451f49cfe7aa4754
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v4, t2, v24

  li t2, 0x1d97edd17d36a4a5
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v20, t2, v12

  li t2, 0x28fc0f28abf14d69
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v6, t2, v4

  li t2, 0x7e2819f0458c3faf
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v22, t2, v2

  li t2, 0x7cab92a863efafe2
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v28, t2, v24

  li t2, 0xce5e6fe1ff6aa2bf
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v28, t2, v26

  li t2, 0x68f081a2a3fe5bc1
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v8, t2, v2

  li t2, 0x609a9ca5e4bc5140
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v30, t2, v6

  li t2, 0x33aff2fcbb4f37a0
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v12, t2, v28

  li t2, 0xe0ebef7829ed4c34
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v30, t2, v16

  li t2, 0x891225b27e606ed8
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccus.vx v6, t2, v22

  li t2, 0x94fc27aee5dca905
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x9339e09ad7202098
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v24

  li t2, 0x7d4faabe4a5066dc
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0x3abab6a76e1ce3fd
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v20, t2, v8

  li t2, 0xcc27577cc3c5a9a6
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0xddcb3f8b62b6fa7b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v20, t2, v12

  li t2, 0x056a0d56a660e95e
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v20, t2, v28

  li t2, 0x13213ef3bd6264ea
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v12

  li t2, 0x3f2ee69c4073b307
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xcf0f9ef2eb6a829c
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v28

  li t2, 0x131f9c9951f1bb63
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x4466f862eba4a14f
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v16, t2, v4

  li t2, 0xacf7b1714f4d6bca
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v28

  li t2, 0x46a71280b5fa5c9a
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xc06f03a78e174300
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v4

  li t2, 0x926b5a44fdbcd5b1
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v20, t2, v24

  li t2, 0x6c17be7d1ac28729
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v12, t2, v16

  li t2, 0x1046e42a977d6f8f
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v12

  li t2, 0xe69c29dfb85c976d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v8

  li t2, 0x21eb9cc830c9abbc
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v16

  li t2, 0x8dbf779971650d1a
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v28, t2, v12

  li t2, 0xf12daa31ef2c31f9
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v20

  li t2, 0x81f5182bb80490c2
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v20, t2, v16

  li t2, 0xe309e5fe0dfa43c1
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x383fcd94dd0fc999
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v16, t2, v12

  li t2, 0xcbf3de6073257d4d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v20, t2, v4

  li t2, 0xd29d4fcce29d0738
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v16, t2, v4

  li t2, 0x1d68b7ec61e0bc41
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v12, t2, v24

  li t2, 0x1c2737b89401e9d6
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v12, t2, v24

  li t2, 0xd3859cb93affe5e8
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v20

  li t2, 0x1ffe5c382a15a7a4
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v28, t2, v4

  li t2, 0x5b5e6fc2d869d2c7
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xd378206bbd3bb292
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v20, t2, v28

  li t2, 0xab09d0a8220eff32
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v12, t2, v24

  li t2, 0x612abf14f9ce49ba
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v4

  li t2, 0xb0b9958ab8a7502b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v12, t2, v4

  li t2, 0x65e984c85949ae8c
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v24

  li t2, 0xb7cf09b62045c434
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v4

  li t2, 0x8d862ff0141ff5dc
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v28

  li t2, 0xee00ddb9d96e4d97
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x471c23732c763938
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x1c1d54a9e1acf376
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v12

  li t2, 0x9571534d0b8d7568
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v12, t2, v20

  li t2, 0xea419b69734658a6
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v16, t2, v12

  li t2, 0x7a7a6b7dc6f886d5
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x7588763498d041eb
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v20

  li t2, 0xbb63af417565554d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v28

  li t2, 0xd646117cfaa59d08
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v28

  li t2, 0xd8a3c0586447dee4
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0x1491e28ba0c5c070
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0xf511198b48e4c7f6
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v20, t2, v16

  li t2, 0xca37b81663b1b80f
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v16, t2, v12

  li t2, 0x547e1347b46dff62
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x39431c7f8ce616f3
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v20

  li t2, 0xdce6646bbf7f0670
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v12, t2, v16

  li t2, 0xe663b1c888018cca
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v28

  li t2, 0x0e2533d67f95d12d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v12

  li t2, 0x07caf95d66c6b006
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0x95eb6d8727db87c6
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v28

  li t2, 0x7dfda8d86310e15b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v28

  li t2, 0xac0253fa0715bf41
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x170d2b6fe5ae80dc
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v28, t2, v16

  li t2, 0x12ab9502d15175ed
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v28, t2, v24

  li t2, 0x17396a6550b0868d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xf8dbec393235d142
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v20

  li t2, 0x9ab77c45342ff5f1
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v16, t2, v28

  li t2, 0x69f3aeab30187b25
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v12

  li t2, 0xba3bfbe5f2120fc1
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v4

  li t2, 0xd81cd3cda6d905c4
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v28

  li t2, 0x6ed30d474ac4ae83
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v28

  li t2, 0x740a270d018d7f8e
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0xc54ff86427e50cd7
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v28, t2, v8

  li t2, 0xd93b423219df58e9
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v28

  li t2, 0x09ce0cbc3980dd90
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x71f0e0d1f5a86ab7
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v20, t2, v24

  li t2, 0x76e9a6623b98dc9d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0xd96a54493182f951
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v20, t2, v16

  li t2, 0x04350b2ed0726498
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xc56ca8e99cdd9553
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v12, t2, v16

  li t2, 0x9956e007541c381d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v20, t2, v12

  li t2, 0x1eb9ca29f73bc21a
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v12

  li t2, 0x76802c0211360dbf
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v16, t2, v28

  li t2, 0x748ff9f699ed4eb5
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v12

  li t2, 0x185f39ed68d59ea3
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xb968059881b5d283
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v12

  li t2, 0xb7b848868262b605
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v8

  li t2, 0x1403133d8bd505ee
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v8

  li t2, 0xd8ca7ca13503faa1
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v4

  li t2, 0x4dfb5add451db8b2
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v20

  li t2, 0xd88d0416fd39135d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v20, t2, v8

  li t2, 0x52d83b6c7214e483
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v20

  li t2, 0xab589543f170a8c2
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x2857980757018ce0
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v28

  li t2, 0x0eaa412c7211d924
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xc2643a8daa29e724
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v20, t2, v12

  li t2, 0x3e76c7203ad4da44
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v16, t2, v4

  li t2, 0x1f1f1815763699f3
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v4, t2, v16

  li t2, 0x91e3b184f7446a99
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v28, t2, v4

  li t2, 0xe0a2a589e4e9d2d3
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v12, t2, v4

  li t2, 0x7bb00be73191a94c
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccus.vx v20, t2, v24

  li t2, 0x7048ab3f3b884888
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xafe4f3057c2e2a0e
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x36a38f640b18ab61
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xc48d02e4d4e9d368
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x83b3a6c8574a9eb2
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x293f34ea6743a2f1
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x0e304832bb914a8c
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x3035ec83825e2496
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xc66bb75a67b339e2
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x49f841bc8de34086
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xe2cb6ec37b92c2f8
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x5da1e957e14a4b92
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x0b06fb3007c3cf99
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x6a8b07e8fd4e5417
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0xc9cb9dbf9f8f3083
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x479fe8e1833cf9e4
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x4772ca1f321146df
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x1ab8997c4295c1d3
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xcba15e1321fd0017
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x032cdf09aeea1ef7
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xea31995550d8eaaa
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x4a4fa7b32b6ee3ce
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xf36ace2c0da9cb94
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xd4ab752acdaf0d78
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xe871a0e67afdea31
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x8a48744ca08eab1f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x2ebadb5e10db2a21
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xc0390e95062bafed
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xc7d8a2f19a245025
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x84831097691679e7
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x895e2f8f45045863
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xd77eb7b318639eb7
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x948deeb8c4b56936
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x5aaa483f4e4475ff
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xa5bda67f0b54ef6d
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x212227c88bd82489
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x0e345756871c26d2
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x73c9d27294248fa7
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x00b82125d17cf55f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x4be5487841ba499b
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x6023560ec823af7c
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xc13ef0399f3830c6
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x4726173d39458c42
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x4eac90e8a03ed6d3
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x33671ea6aee32e3a
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xef6c8f1b815efd67
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x4e9f629ff775a82b
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x7eb0d1be55d0d24f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xebf52e6ee0b66a32
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0xc2c6d683ff32c431
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xceca29a297764993
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x5d0b0a80c45b4c75
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x6c709e1268065df1
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x00cb4d629f3edc99
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xf2dc3bbb47bbeb56
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xbbbd799b9c786f24
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x92f8f21c6d50b205
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x9691939eb8751463
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0xce1435ffd05d28fa
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xb8dbad3e0317b6b0
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xf155f43b8988480f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x52334bcbb708d7a1
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x0e6791aba58a5131
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x546aaaa372234567
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xe9c34f01ec60c45f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xbae2ab5292229e15
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xf02f7efb5be88b0a
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xe1dd97b0b66ffe63
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xbb7e48d2003f036b
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xb04690a76b646d64
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x7e1cb64003c0a999
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xe3a926fdd198ecf1
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x6943731c8c2a4e85
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x3facd37f8e37d7d1
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x06363c3904178121
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xaa54ccd25b010a91
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0xeec50f05b66d338d
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x2906966b7bb3abe1
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x9ed8f69e0139bf0c
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x0169e73d6bb6e0c8
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x8d77af464d5dd808
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xe6932e4a20d73145
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x79b8b24647244840
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xfc90f990cbeabd1f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x0eab9a7674362a6b
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x713619820b3a711d
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x081a085376ef9104
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x5cc3a60ebe574d17
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x4b27a93944b55d7a
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xf6772535618eb130
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xc57ece6e654bbbbb
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x27da35227ec4cd1a
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x6a3a9f026d62dcab
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x00f50c8f9ad7a127
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xb62bab0904754ebf
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x5f67d017bcbe1b16
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x3c92c3e51f45fd11
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x2b499562a3f9c18e
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x1cdd8c85ccd36f6e
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x04bb46923318a0f0
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x17799271dc12be6e
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v18, t2, v2

  li t2, 0x9ff7820d4cc2e5c4
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v6, t2, v18

  li t2, 0x3cb67700a7eff392
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v28, t2, v26

  li t2, 0x82037115a4da137d
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v6, t2, v20

  li t2, 0x7d9592fb96d9bb7f
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v10, t2, v24

  li t2, 0xb2cb7831c61bf1bd
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v26, t2, v12

  li t2, 0x85944742adbe7855
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v4, t2, v2

  li t2, 0xc740c91d30198250
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v26, t2, v6

  li t2, 0x6c4e82bdc73b3400
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v8, t2, v20

  li t2, 0x619e71622599623c
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v12, t2, v30

  li t2, 0x85d152c2e06037f0
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v8, t2, v26

  li t2, 0x9794e28757b634aa
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v12, t2, v6

  li t2, 0x32f4fadc8fda3ec5
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v26, t2, v30

  li t2, 0xf05a62b50b617f23
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v12, t2, v26

  li t2, 0xed4339de098cc315
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v8, t2, v10

  li t2, 0x8749499c637dbc85
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v18, t2, v24

  li t2, 0x0d26e495fa90695e
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v14, t2, v28

  li t2, 0xc2dd8220ccc74d18
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v12, t2, v6

  li t2, 0xd7edc2b5378ad5ff
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v24, t2, v30

  li t2, 0x23ef0c232eeb6437
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v16, t2, v10

  li t2, 0x10260d34a724c1d5
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v22, t2, v8

  li t2, 0xb3de6789590bb9a6
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v26, t2, v16

  li t2, 0xdd4c0bbc4c24a557
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v20, t2, v22

  li t2, 0x757719cd27295373
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0x54f552c7702cccff
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v4, t2, v28

  li t2, 0xf1cf8df12881a3c1
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v16, t2, v2

  li t2, 0x429f07341dc1fc46
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v6, t2, v30

  li t2, 0x45de3c8be8281c40
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v14, t2, v30

  li t2, 0xdf97e820d3f76ecc
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v10, t2, v30

  li t2, 0x880bd51ffe1a3ff6
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v30, t2, v4

  li t2, 0xb96145af99ba4705
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v20, t2, v8

  li t2, 0xa990eaaf6310d5a2
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v14, t2, v8

  li t2, 0x3b7ae1deced76a0c
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v22, t2, v4

  li t2, 0xc2d70cce14f400a1
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v28, t2, v14

  li t2, 0xf7d05f9912e2dc5f
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v6, t2, v20

  li t2, 0x3ab16032ee58d400
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v28, t2, v4

  li t2, 0x334a656e76db7665
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v30, t2, v28

  li t2, 0x5e229ea98fe7bc6a
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v30, t2, v12

  li t2, 0x4fc342ba3fbfdb85
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v12, t2, v26

  li t2, 0x50c193d6bc1102b7
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v2, t2, v6

  li t2, 0x07f6edc98b053e9c
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v20, t2, v16

  li t2, 0x29e5f1c5309ee0b3
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v30, t2, v6

  li t2, 0x2c8a61df45fbec80
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v20, t2, v30

  li t2, 0x5eee24dffd18f337
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v10, t2, v20

  li t2, 0xe750b2457dce5c7a
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v22, t2, v18

  li t2, 0xbaa9bb35183ddb5e
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v26, t2, v10

  li t2, 0x46f075a4172db39a
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v22, t2, v18

  li t2, 0x50c31fea2739966c
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v24, t2, v6

  li t2, 0x759f17e2a24d6681
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v12, t2, v10

  li t2, 0x04463a86e561f9d4
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v30, t2, v16

  li t2, 0xe9c6fdbe28046404
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v26, t2, v14

  li t2, 0x620172665b3afd0d
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v12, t2, v14

  li t2, 0x46576f5426eb1d72
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xd90bfd4b76b21fdf
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v16, t2, v10

  li t2, 0x9fd32daba17ff354
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v22, t2, v8

  li t2, 0xb30c740703128d80
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v14, t2, v6

  li t2, 0x402adef4592e9d5d
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v8, t2, v30

  li t2, 0x39cdb1962bdf9f14
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v30, t2, v4

  li t2, 0xd6f0abeae7ab110c
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0xb09984bd98c8ee72
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v26, t2, v22

  li t2, 0xd202286bafe48f78
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v2, t2, v4

  li t2, 0xff55c0773a4f7031
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v22, t2, v10

  li t2, 0x7475f7a67c3a2687
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v26, t2, v10

  li t2, 0xff95c874c5c56f41
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v2, t2, v16

  li t2, 0x8a3fe2cc10c57a73
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v6, t2, v2

  li t2, 0xa008cd136c8f4353
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v22, t2, v14

  li t2, 0xb1fd52042c446e0f
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v24, t2, v18

  li t2, 0x5f752f6ec23230c0
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v18, t2, v30

  li t2, 0x1181d4d2414f4ea3
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v12, t2, v28

  li t2, 0x863afe981837ec5a
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v6, t2, v28

  li t2, 0x3462edbb7afd7593
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v6, t2, v26

  li t2, 0x39c71d6e0e3c5189
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v24, t2, v10

  li t2, 0x076ccf91e9f8307d
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v4, t2, v18

  li t2, 0x6f198fed8985215f
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v10, t2, v14

  li t2, 0x3fa7bc9e09b5219b
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v18, t2, v26

  li t2, 0xd9b8767428d00254
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v30, t2, v22

  li t2, 0xfbaff64ff0d3dff3
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v22, t2, v30

  li t2, 0x734a8167ea8277a2
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v20, t2, v14

  li t2, 0x77c44519348c41cd
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v24, t2, v10

  li t2, 0x0c349583937ff3c7
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v30, t2, v22

  li t2, 0xc25ac98ad22fdbd6
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v30, t2, v14

  li t2, 0x093a43df2b360b68
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v30, t2, v20

  li t2, 0x4af179b3501fba6d
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v10, t2, v6

  li t2, 0x8bf9e6f9313ad92b
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v26, t2, v18

  li t2, 0x26e953b2f6ec1027
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v26, t2, v20

  li t2, 0x81f910a9448b0d00
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v30, t2, v16

  li t2, 0xdad1dbda709545ce
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v8, t2, v2

  li t2, 0x47692c15bcd6d3e6
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v4, t2, v26

  li t2, 0x1e4eb8048a6178e5
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x7de37bccfb05fe5d
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v30, t2, v14

  li t2, 0x7e3c69fb11793e0c
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v28, t2, v30

  li t2, 0xd3deeb10f295d26c
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v22, t2, v8

  li t2, 0xe07432b4d34ba2c5
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v6, t2, v12

  li t2, 0x176ae9dd64431e46
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v26, t2, v12

  li t2, 0xfdfacf441399b6b0
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v6, t2, v22

  li t2, 0x8f56563f777bbd9f
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v6, t2, v12

  li t2, 0x418045d02ec6c3a5
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v30, t2, v14

  li t2, 0xe40b0b8935b54548
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v22, t2, v18

  li t2, 0xc34bfb0b2a8d95b6
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v6, t2, v14

  li t2, 0xace2a4629981540f
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccus.vx v14, t2, v18

  li t2, 0xca6bfff9ca0fffa1
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xe15290e823e2b985
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v24

  li t2, 0xb68527ef1d20cec0
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0xa81f57cd84070507
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v4

  li t2, 0x0d0ab6b27a4da47c
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xa7cf5b31ca31bbc4
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v20, t2, v28

  li t2, 0x64decbde0dc148d0
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v24, t2, v20

  li t2, 0x296cf26ed211fe1b
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v20, t2, v16

  li t2, 0x1855987841794671
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v28

  li t2, 0x9d23bae348849441
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v20, t2, v12

  li t2, 0xdf3e98f4afbe22e8
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v4, t2, v24

  li t2, 0xe91c05534d0b82aa
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v28, t2, v20

  li t2, 0x6b1562dae4c8a921
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v4, t2, v8

  li t2, 0xf023288bbb72e740
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v8, t2, v12

  li t2, 0x34f741a5e2cbfec2
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v24, t2, v20

  li t2, 0xb85e8f76bbb4f7a9
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v20, t2, v12

  li t2, 0xb6206d9e5babf022
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v20

  li t2, 0x24867572be3d682d
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v28

  li t2, 0x9653188553245888
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v20, t2, v8

  li t2, 0x38be1985de51e7e7
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v20, t2, v24

  li t2, 0x1c103225ab01d831
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v16

  li t2, 0xb64d6519e3b710bf
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v16

  li t2, 0xa7b6dcdbc7449846
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v20

  li t2, 0x6809e9311b7caf30
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v8, t2, v28

  li t2, 0x794d4ac7ff513571
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v24, t2, v4

  li t2, 0x0273cc895ff8457a
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v4, t2, v28

  li t2, 0x9732b238c620d142
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v24, t2, v28

  li t2, 0xe7ccdbd8905b4bba
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0x174c7d2849733c57
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x9a7699e0afbed60e
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0xe97532022976d652
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v4, t2, v8

  li t2, 0xe351fb96753f5482
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v4, t2, v20

  li t2, 0xfce549e097b7875b
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v16

  li t2, 0xcc6a79687c86726e
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v8, t2, v12

  li t2, 0x63f33fa16db5e980
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v20

  li t2, 0x65219b47e96f1b7c
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v8

  li t2, 0xba2390b2d26e578d
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v8

  li t2, 0xd4c82320f929ac3e
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v12

  li t2, 0x4f7d2da6eab4138c
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v28, t2, v4

  li t2, 0x479f096a4fc6a26e
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xfd44b75a21a8ce0a
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v4, t2, v8

  li t2, 0x8bd983b0461eb1f9
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v20, t2, v24

  li t2, 0xf508a9a8f96f3bb5
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v28, t2, v12

  li t2, 0xbf55b1b8b3c193d5
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v28

  li t2, 0x322816919cacad9a
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v4, t2, v8

  li t2, 0xb11668c3200be862
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v24

  li t2, 0x04a0cbfd311c2d04
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v28, t2, v24

  li t2, 0x2e6efcc16e33d9f6
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v4, t2, v16

  li t2, 0x4a14d9bada8047f8
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v28, t2, v8

  li t2, 0x42d71914f05d0113
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v16

  li t2, 0x9b25254614c36e16
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v4

  li t2, 0x195db44a78ee0b92
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v28, t2, v20

  li t2, 0x95f612669b96c648
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v4, t2, v12

  li t2, 0x668cc92bd24e9281
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xfcc706551e1a7f98
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v8

  li t2, 0xc4bf3d3311f86524
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v20, t2, v12

  li t2, 0x1b933536589d66ea
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xb87fca08d23b3f25
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v28, t2, v24

  li t2, 0x1f650cf6394c1ddc
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x38752b1b9cec5476
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v24, t2, v20

  li t2, 0x6400930e8e07724a
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0xd75c376a7a9b4285
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v8, t2, v28

  li t2, 0x6ba467e4e9dcad65
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v8, t2, v20

  li t2, 0xe5c347e291f6571a
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v20, t2, v12

  li t2, 0x5bde4b77f31418a3
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v20, t2, v8

  li t2, 0x0856838604a54e33
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v24, t2, v20

  li t2, 0xb31c79b0211a2009
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xbca81d112c3fc81f
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v28, t2, v12

  li t2, 0x62fa2ca734ddc7ed
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v12

  li t2, 0xbc75f04f790cdc40
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v28, t2, v4

  li t2, 0x4e18bcbf2360de33
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v8, t2, v20

  li t2, 0xe3181b14b0b7e464
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v28

  li t2, 0x58d14d50d503e7ec
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v28, t2, v16

  li t2, 0x68ae86dc913a39cb
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v4

  li t2, 0x0d6e85dfac16aa37
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v28

  li t2, 0x943bb15099adc46d
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v24, t2, v4

  li t2, 0x1f0a63242762f1d8
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v24, t2, v12

  li t2, 0x4d3a634d02a33cba
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v20, t2, v16

  li t2, 0x31eb8404b4c57b87
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v20

  li t2, 0x197fcb9af17140b1
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xa6f0d64cd7ccd270
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v20

  li t2, 0x4bfd179c18517bbf
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v24

  li t2, 0x547ddeebcc704331
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v4, t2, v24

  li t2, 0xa204abca203af1c3
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v4, t2, v16

  li t2, 0xd7030415f786aca3
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v24

  li t2, 0x44b708e045ed45a7
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v4, t2, v16

  li t2, 0x44b8e15f7c9eb14b
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v8, t2, v4

  li t2, 0xc98d25fdce366078
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xc90b1faa2fc496ef
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v8, t2, v28

  li t2, 0x506eec680496e181
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v20, t2, v24

  li t2, 0x75f4b433f8d7704d
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v28, t2, v16

  li t2, 0x04d5abff842d3f26
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v4, t2, v20

  li t2, 0x26df748e8acd6a7d
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v8, t2, v12

  li t2, 0xa2e70f1253446b1b
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v20, t2, v16

  li t2, 0x059521a09dc1d81e
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v24, t2, v28

  li t2, 0x28710be2cfd4a4d4
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v20, t2, v24

  li t2, 0x6e6a221aa3eb17e5
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v12, t2, v28

  li t2, 0x632c4cbfae4075af
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v4, t2, v20

  li t2, 0x6faeebe796101084
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v8, t2, v20

  li t2, 0xc200152c46eb6ef9
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccus.vx v16, t2, v20

  li t2, 0xa8b780a290aac656
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x6564fd10b7daa895
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x1c04013e05306aa3
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xcc9bc1b038028a59
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x0c81ddb3fe5e7963
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x807e446ef3483ef9
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x02f45d35ec9e4e49
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x4ff9c3e98806e557
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xf5b027bd0b3bb609
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x54a32af266fc5505
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x4ff17c9db7dfb910
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x1da14afd3ae1a41f
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xb7cc546509e6b25d
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x51b8e707fdc2563e
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x87f8b8b1803482e5
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x1be4e0209d1873fa
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x4ccc0f2fa4454e15
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x406d49cd7f125fa9
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xc580786c93c58fb7
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x26955b0ab1528f17
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x7e3924416f5a8cff
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xd2d10d4fb9d31983
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xf5b7630580c636dd
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xcf584fd3031a0cc6
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x31373dd09fee806f
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x46a16392f5418776
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x5977539b40012144
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x5ce65869cb9ab9ea
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x45e75a67c163ce4c
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x63bcf25790308a1c
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x4499fb7300c6fd79
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x4cd34b6b7b7f0144
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x47714797cd08ab88
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x3921dc99466a52f9
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x827eecd19eb3157f
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x3f870d5539715192
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x1d112036a6a7360b
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x21850b4a01fe0ef7
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x36f72c20d76b09a2
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x3a9c81fba3516ebf
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xc7da68b24a31781d
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x8da24e9d205f69bf
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x5049acf13f8097d5
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x837dd707923668f3
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x0578b48a38f4da15
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x09cfe9b78d80a517
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x02d74a040bd329e4
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x8360be1e31bdd6d3
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xf02b5c1255c1cb32
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x411eda52cce571eb
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xa93c270c10181b92
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x9be730b10477f6bb
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x1473e7b657c77917
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x09c02b9d51809001
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x67f47f3707bc2970
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x55857c63c45d0570
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0xc5590ef2ea520c18
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0xd86b98276fe63712
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xe244f9f173b1fd22
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x78cf21c9d131a2f9
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0xadd02835ee93ff40
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0xa810c2528c7176e1
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x13e7ffdfde9ee85c
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x62b3cf45fa132440
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xffe6b9d02bf59c08
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x48645c2ecc572dc6
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xc0e86ad3170792c9
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x205be86bb50d1f21
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xabc6c0154e734a37
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xda15f9407b1c786b
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0xc6faea946181ffa6
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xaaa0af1afb00f902
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x6a8b26c211f49ba3
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x205657b37e62ec75
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x48fbd8dc75573b10
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x2de5b1854ebade30
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x4bbea285608b9415
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x8b7ad53d2353a490
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xd2c6a14643f8e7f3
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x0e040ffbc0640c6a
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x0f6bef89158d6ffb
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x0af20535f4c4d7a1
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x5b0c8f4baac44bcd
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x710cd85d299b6470
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xb20f7f9d93da627d
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x5000ed060ad47a32
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x73587144bd185c1f
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0x1fb6ed72e18ff725
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x9baa57c128a05211
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  li t2, 0xe9e7d560fc26a8ef
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v16

  li t2, 0x91fea9290d1dc12e
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x331f4d4918a81df1
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v8, t2, v24

  li t2, 0x8fa4c7b2fa405ac0
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x38ad59f74acf3483
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v16

  li t2, 0x98b14a126fce6423
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x1b1238a77bac8f8d
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x3dc7afc80d86002c
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0x1e663f7e881542fe
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v24

  li t2, 0xb7486a3aa74303f1
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v16, t2, v8

  li t2, 0x96725f3599e8dca9
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccus.vx v24, t2, v8

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
