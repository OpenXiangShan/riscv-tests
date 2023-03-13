#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v15, v17, v13

  li t2, 0xbfef4813f9b610fd
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v9, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v29, v17, v20

  li t2, 0x8294d93cd862b60b
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v31, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v19, v1, v15

  li t2, 0x6383483bfeff970e
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v1, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v2, v15, v14

  li t2, 0xd04feb06b2701e63
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v25, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v20, v9, v17

  li t2, 0x4db33d72290467f0
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v29, v15, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v10, v7, v20

  li t2, 0x1f9d7168d1a5a152
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v27, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v16, v27, v4

  li t2, 0xac0e989f2b16b2e5
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v17, v15, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v3, v23, v16

  li t2, 0xb086d642f91c817b
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v3, v19, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v1, v21, v16

  li t2, 0x1fc6955d738cd0d1
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v4, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v28, v1, v3

  li t2, 0xfc54089282840200
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v1, v14, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v5, v8, v15

  li t2, 0x842c6b3a5067ecc7
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v15, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v30, v26, v15

  li t2, 0xafa7bfdbd7128b33
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v31, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v29, v6, v17

  li t2, 0x8ee514b60b6a8dd9
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v28, v2, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v29, v24, v31

  li t2, 0xe4681fba9e2b1fba
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v11, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v19, v9, v14

  li t2, 0x3e872f259a54f016
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v5, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v10, v23, v9

  li t2, 0xf9aec649f5869a7a
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v25, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v18, v3, v8

  li t2, 0x929851aa2f95bb74
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v26, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v8, v30, v17

  li t2, 0xe567e7895517bfdb
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v9, v30, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v2, v21, v3

  li t2, 0x9eb9cf367316b594
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v11, v5, v10

  li t2, 0x0d6ab993c95db7e2
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v13, v1, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v1, v20, v6

  li t2, 0x22b9fdd3245091f9
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v17, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v24, v27, v28

  li t2, 0x30c2b23e70926ed9
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v7, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v1, v29, v2

  li t2, 0x0f72c1e32ba204cf
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v15, v2, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v20, v17, v11

  li t2, 0x4d05ff4bd4eb5915
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v5, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v23, v28, v26

  li t2, 0x002c9c2838f07593
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v3, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v16, v30, v25

  li t2, 0xd1f0ddfe85ee2d46
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v26, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v25, v17, v1

  li t2, 0x8a7ecd467b521c4a
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v12, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v9, v10, v30

  li t2, 0x9755e05e9e396b50
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v15, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v8, v26, v21

  li t2, 0x81e19d0908ba2884
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v7, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v12, v6, v10

  li t2, 0x868302fc6da0f539
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v16, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v17, v31, v19

  li t2, 0x5fd41710e090a172
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v25, v30, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v13, v29, v18

  li t2, 0xfa743b8c7f067f5e
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v27, v23, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v24, v29, v7

  li t2, 0x98f55cf7551d512a
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v5, v14, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v14, v18, v7

  li t2, 0xa1a244f9f3b8ea39
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v21, v19, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v30, v12, v4

  li t2, 0x720a0cc90ff3c1b7
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v12, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v5, v16, v24

  li t2, 0x6f2eecd098c3a30d
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v27, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v12, v13, v30

  li t2, 0xc0cc2e71cfec9201
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v9, v10, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v18, v29, v26

  li t2, 0xaf9d2e454c7e9dc8
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v2, v26, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v10, v14, v4

  li t2, 0xc22975b19dff4fae
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v17, v26, v24

  li t2, 0x420b1d6bd34e56c3
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v18, v13, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v24, v16, v26

  li t2, 0xcaff64273e06c789
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v28, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v14, v2, v18

  li t2, 0x600ca020c64cec4c
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v14, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v3, v21, v5

  li t2, 0x42e0b48471fb260e
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v25, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v17, v22, v21

  li t2, 0x7fdafc6df9779ef8
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v25, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v31, v27, v1

  li t2, 0x69746e6d8422f16e
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v27, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v30, v13, v23

  li t2, 0x7d3f811cfdb7252f
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v3, v7, v29

  li t2, 0x60062d91783a5967
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v7, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v18, v15, v6

  li t2, 0x1864c5603ad70f70
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v29, v2, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v18, v4, v30

  li t2, 0x408c5f308a6538ed
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v13, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v12, v6, v27

  li t2, 0x4d092a5e9fbcb0c2
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v28, v19, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v5, v2, v23

  li t2, 0xc62e44e0b1e0463d
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v26, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v25, v24, v13

  li t2, 0xdc9b273106474da0
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v29, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v11, v29, v13

  li t2, 0xed8017fe2139c39e
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v21, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v15, v24, v28

  li t2, 0xd8aa075ceb3ecdad
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v2, v30, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v5, v26, v19

  li t2, 0xabc3a5bcd6b3a792
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v23, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v1, v28, v5

  li t2, 0xf68bd23be4422b01
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v19, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v23, v25, v28

  li t2, 0x33785078e6f0b5e0
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v19, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v28, v15, v11

  li t2, 0x7f41b1f7e2e6a2fb
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v29, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v13, v16, v14

  li t2, 0xe2f8955c9c1b5582
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v8, v26, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v17, v29, v1

  li t2, 0x00d7540af2e2f705
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v11, v15, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v2, v6, v11

  li t2, 0x06552c9b25a6a1f5
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v13, v14, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v25, v2, v6

  li t2, 0x705136dcd5194faf
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v3, v30, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v15, v21, v17

  li t2, 0xa4c4b199799afe7e
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v11, v3, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v13, v7, v9

  li t2, 0xdf4da77d5581db99
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v6, v1, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v5, v8, v16

  li t2, 0x3262a7d5c3e75872
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v13, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v6, v17, v22

  li t2, 0x4cdb76587e0f9783
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v22, v26, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v23, v2, v18

  li t2, 0x33e291aaa07c6d3a
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v24, v23, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v11, v14, v2

  li t2, 0xd4171396e8a48b9c
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v31, v17, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v13, v24, v15

  li t2, 0x6a8e984cb2d004ed
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v4, v17, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v21, v25, v9

  li t2, 0xd84086488c322265
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v21, v2, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v7, v21, v2

  li t2, 0x9247505df49700e2
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v26, v3, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v19, v11, v6

  li t2, 0x6af019445e449a5f
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v26, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v22, v26, v31

  li t2, 0x3d622dbdb0bfa8ee
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v21, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v24, v25, v17

  li t2, 0xb1e284973c95baf7
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v3, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v30, v14, v2

  li t2, 0x8904e057c1a78e9b
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v26, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v23, v14, v26

  li t2, 0x345eb5aae8327af9
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v31, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v30, v12, v28

  li t2, 0x8755ad6388aa65ef
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v28, v3, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v6, v19, v27

  li t2, 0x814f08243d594f80
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v16, v23, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v9, v5, v25

  li t2, 0xa3714b75f884c8cd
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v12, v1, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v30, v16, v17

  li t2, 0x6f366c60bfc4f4b9
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v21, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v25, v23, v16

  li t2, 0x9649917ad88bf8d6
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v28, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v7, v9, v10

  li t2, 0xa2626308900a0408
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v9, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v12, v21, v26

  li t2, 0x1acde36122344ad9
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v9, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v24, v1, v12

  li t2, 0xcd6b249e3fc0162d
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v6, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v4, v19, v31

  li t2, 0xfee242ac27a827d6
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v19, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v18, v30, v22

  li t2, 0xc2962b3b6ac4b320
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v14, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v3, v18, v31

  li t2, 0xd3b0d0866a4ffcbb
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v18, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v21, v30, v16

  li t2, 0x04682eb5a8e73998
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v27, v12, v3

  li t2, 0xc1e5ef3c156fbcad
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v17, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v22, v17, v31

  li t2, 0xe6c6336d481db4af
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v26, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v17, v11, v1

  li t2, 0xe6859d66320ccda5
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v4, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v19, v13, v16

  li t2, 0x4ca6afa60d3fe5f9
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v15, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v16, v24, v13

  li t2, 0xe9aa939ade5ebb5f
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v12, v30, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v2, v11, v6

  li t2, 0x533eadf79112838d
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v27, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v19, v11, v7

  li t2, 0xb6ed405b0fb5546f
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v1, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v27, v17, v26

  li t2, 0xea65470eb8a6e8f8
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v26, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v7, v29, v17

  li t2, 0x02c21072aff93686
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v19, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v2, v24, v3

  li t2, 0x961814d20801e7fa
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v16, v19, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v29, v5, v12

  li t2, 0x5f8377d173c3da7d
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v10, v26, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vv v4, v23, v6

  li t2, 0x73081ea4af6f36d9
  vsetvli t1, t0, e8, m1, ta, ma
  vsub.vx v16, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v24, v14, v20

  li t2, 0x0a78cf9e07f9608f
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v4, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v2, v26, v12

  li t2, 0x24202e7bbd7e50fc
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v18, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v14, v16, v20

  li t2, 0xa5dd6f41724e2f47
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v2, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v10, v18, v30

  li t2, 0xa41a9f4e801083a0
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v2, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v2, v26, v12

  li t2, 0xe67417c703b7f09a
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v30, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v4, v8, v16

  li t2, 0x53fbbbafab183abc
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v2, v14, v26

  li t2, 0xb28a62f1585948a2
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v26, v30, v20

  li t2, 0x7f5d4067dcb27fc4
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v14, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v24, v12, v14

  li t2, 0x4d04503204e777ce
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v22, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v12, v28, v6

  li t2, 0x2ef133d36e428a16
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v6, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v8, v26, v12

  li t2, 0x680e61ab2f215c48
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v4, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v2, v28, v6

  li t2, 0xa5828ce5b4cfaffb
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v28, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v12, v20, v16

  li t2, 0xd7934e801caaddc3
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v20, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v22, v16, v14

  li t2, 0x8630a4b98db9e42a
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v24, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v24, v28, v2

  li t2, 0x8a5ea2c7fb6a23a5
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v18, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v16, v18, v28

  li t2, 0x4cd7c828da92f2af
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v26, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v2, v16, v30

  li t2, 0x2f7667f0a78c6717
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v26, v12, v4

  li t2, 0x2b5fc9387d135141
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v22, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v26, v2, v6

  li t2, 0x8978896de8906a99
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v12, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v2, v30, v26

  li t2, 0x55f1d953276354ce
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v22, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v24, v8, v10

  li t2, 0xbb8eb0ce52ff3620
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v4, v2, v26

  li t2, 0xb60fa5c9c56563f1
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v22, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v2, v24, v28

  li t2, 0xc8430211d9e4de5e
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v4, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v16, v24, v14

  li t2, 0x1487ddc3697a3af4
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v20, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v8, v20, v4

  li t2, 0x6c97082122cf5519
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v12, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v4, v30, v10

  li t2, 0x644d25ce3dc14486
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v12, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v8, v4, v20

  li t2, 0x98d522d5b210499b
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v26, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v24, v30, v18

  li t2, 0xcd858041d3e01e95
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v18, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v26, v6, v4

  li t2, 0xa78ef70bb6bb47b8
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v6, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v24, v4, v14

  li t2, 0x7ccc2b83d001f64c
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v12, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v16, v14, v28

  li t2, 0x7134f82ce27ca66e
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v8, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v24, v2, v6

  li t2, 0xfe773aba8c7a71a1
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v6, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v12, v4, v26

  li t2, 0x4d4f16da0c967916
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v22, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v14, v22, v2

  li t2, 0xbe1f95420a4c00da
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v28, v10, v16

  li t2, 0xb30f95aec0089cac
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v18, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v24, v8, v10

  li t2, 0x066a442a7c18272b
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v14, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v6, v26, v10

  li t2, 0x09a1c08128f2f28e
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v22, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v20, v4, v2

  li t2, 0xace9bf1ed4a42900
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v12, v4, v18

  li t2, 0x99d3c5f6255c32bb
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v2, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v10, v20, v24

  li t2, 0x5aaa074d2d641be4
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v18, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v6, v4, v8

  li t2, 0x9cc857047cbba6f6
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v12, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v28, v10, v26

  li t2, 0x279c829d79abd636
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v20, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v16, v18, v14

  li t2, 0x2760eebd94f8b6ce
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v22, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v2, v28, v20

  li t2, 0x2dd154d01c026631
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v28, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v2, v4, v22

  li t2, 0xa678eb515485daf0
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v20, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v12, v20, v4

  li t2, 0x0915685182f09e05
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v26, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v4, v20, v14

  li t2, 0x0b06716735807b48
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v18, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v30, v12, v16

  li t2, 0xdc25f52291ff11e8
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v26, v16, v20

  li t2, 0x90f17cb9f345460c
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v20, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v22, v4, v28

  li t2, 0xb92601549cb52877
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v6, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v4, v14, v22

  li t2, 0x75bfc8b0c02be272
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v30, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v10, v22, v16

  li t2, 0xbc564b3a6e23c8c4
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v4, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v14, v26, v24

  li t2, 0x3301caf19c035d8d
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v20, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v12, v20, v16

  li t2, 0x97cbab9215544838
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v10, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v6, v30, v2

  li t2, 0x5783b13c0aa53fa7
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v22, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v22, v30, v2

  li t2, 0x853fc88c57a459b6
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v22, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v22, v10, v14

  li t2, 0x591d3bf3b789ea74
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v12, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v2, v12, v18

  li t2, 0xe5b2b4c69d9f47ca
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v26, v24, v12

  li t2, 0xfbf5c68f07139b23
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v30, v6, v4

  li t2, 0x35a853b7e80145e2
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v6, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v26, v30, v22

  li t2, 0x68241117ce54b0fe
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v14, v6, v2

  li t2, 0xc7ae65c625f8e209
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v30, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v18, v20, v22

  li t2, 0xf2a6b7d5a632ef0a
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v18, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v2, v22, v6

  li t2, 0xf435bbcfe44e535e
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v14, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v24, v8, v4

  li t2, 0xc898a6ac5f98d4a6
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v14, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v24, v6, v20

  li t2, 0xb2854130bfdce3c0
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v16, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v20, v28, v14

  li t2, 0x6d5f77815a2a3c7c
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v8, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v22, v4, v10

  li t2, 0x8ba1dea52e5655bd
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v16, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v6, v22, v20

  li t2, 0xc3b795a193722e86
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v14, v6, v18

  li t2, 0xee366ce2cc1881e0
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v2, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v14, v2, v16

  li t2, 0x210444ccebb0c06d
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v18, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v30, v12, v4

  li t2, 0x987d2c5bc0b8b677
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v20, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v22, v12, v28

  li t2, 0xfa196eb95fbdab5d
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v22, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v12, v16, v26

  li t2, 0xd40cd5d7990b4a60
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v10, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v2, v22, v20

  li t2, 0x243f08011e843a44
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v16, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v22, v14, v8

  li t2, 0x590373e313c93f24
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v4, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v4, v24, v22

  li t2, 0xf14ad3292dd2ba08
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v4, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v30, v4, v8

  li t2, 0xb0ea696ab0111052
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v16, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v26, v12, v30

  li t2, 0xf4c50f6545bb359a
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v24, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v28, v2, v18

  li t2, 0x383651a0331eee90
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v14, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v2, v12, v30

  li t2, 0x47992885d979a5c0
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v14, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v24, v10, v2

  li t2, 0xef4384ebb426e53a
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v6, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v28, v4, v16

  li t2, 0x306c5421244496db
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v14, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v22, v28, v14

  li t2, 0x4b81e2d726ef60bf
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v14, v20, v16

  li t2, 0xf1afd693b6871157
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v30, v6, v8

  li t2, 0x98474a11a22bcfa5
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v24, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v8, v22, v14

  li t2, 0x0a840b8d74dc3ffe
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v24, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v20, v6, v10

  li t2, 0x3be87a9471101f65
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v12, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v20, v30, v26

  li t2, 0x2f15341f17577c07
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v12, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v8, v14, v30

  li t2, 0xa4f5328e2e8eaa91
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v24, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v26, v4, v8

  li t2, 0xf52fd0d10d00c140
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v14, v6, v16

  li t2, 0xdefd31480340572c
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v8, v6, v12

  li t2, 0xc7223cca1afc3140
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v2, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v14, v20, v4

  li t2, 0x62aab02f21201a2e
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v14, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v24, v28, v12

  li t2, 0xb6c6d83d7e05c365
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v30, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v8, v26, v6

  li t2, 0xee0ddb7a888c09ba
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v20, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v30, v24, v18

  li t2, 0x0e60dc3ccde36802
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v18, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v8, v24, v6

  li t2, 0x9435d0284ff8afe8
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v20, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v24, v6, v2

  li t2, 0xf203ab1cc6cfbb45
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v4, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vv v4, v18, v10

  li t2, 0xdebfb6079d9a34f5
  vsetvli t1, t0, e8, m2, ta, ma
  vsub.vx v16, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v16, v8

  li t2, 0x9327a349a7327250
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v24, v8

  li t2, 0xbc1eea58d6ba226e
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v12, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v16, v20

  li t2, 0xb94b14e1c4350052
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v28, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v20, v12, v16

  li t2, 0x1505f847db5d2703
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v8, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v16, v8

  li t2, 0xbfc49aab4f0b53d7
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v12, v16, v20

  li t2, 0xda0a790562be60dc
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v12, v4, v8

  li t2, 0x2d02ee2a55f5bcdd
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v28, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v12, v8, v16

  li t2, 0x7d4c7d22b3e12715
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v20, v8

  li t2, 0x09327971f03dce92
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v12, v8, v4

  li t2, 0xf598d92a0fd9b50c
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v24, v20, v12

  li t2, 0x3dfca885cece60f8
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v24, v12, v20

  li t2, 0x1e8acb0e3eacbf29
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v16, v20

  li t2, 0x768b5cd2dab99556
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v20, v8, v24

  li t2, 0xbd802f768282b32e
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v28, v12

  li t2, 0xfabcf000098c0732
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v20, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v24, v28, v12

  li t2, 0xb84f7ef3c3084ae0
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v28, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v8, v12

  li t2, 0x6e05ef7b6539fa9b
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v24, v4, v12

  li t2, 0x217e226850ca899d
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v28, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v8, v16

  li t2, 0x51eea001c7a63389
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v12, v16, v20

  li t2, 0xf3dfb29c4faf7b90
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v8, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v12, v20

  li t2, 0x69aa5de7019fbf2f
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v12, v20, v8

  li t2, 0x3e35f27a0acd2112
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xd73eeac25e048af0
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v12, v24

  li t2, 0xe0e4a318f88196b6
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v12, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v12, v20, v4

  li t2, 0x87e9d6cee0245d1b
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v8, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v8, v24

  li t2, 0x1d41dbb7ac830962
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v16, v28, v4

  li t2, 0x7e065791e39fff05
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v20, v8, v16

  li t2, 0xc73791c9705ea587
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v28, v20

  li t2, 0x287bb4c0565fa099
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v20, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v4, v20

  li t2, 0x67890612b6ae2a88
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v8, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v12, v4, v20

  li t2, 0x0b34dddebc5716cc
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v12, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v24, v12

  li t2, 0x1ed90c24fce9eda9
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v4, v20

  li t2, 0xdea2df6fd5bb9edd
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v24, v28, v20

  li t2, 0x118bd1a8ee28fd6b
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v20, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v12, v16

  li t2, 0x21d54eb0d3773a51
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v20, v8, v16

  li t2, 0xad4712b6a75134c2
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v16, v20, v8

  li t2, 0x8da92c5d2eef951f
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v20, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v16, v4

  li t2, 0x7454a17e515736e2
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v12, v16, v8

  li t2, 0x47bb041ab6c7a750
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v12, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v8, v24

  li t2, 0xae34b16efbbd2195
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v8, v24

  li t2, 0xa1b45216e11ba376
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v12, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v16, v8, v20

  li t2, 0x4609a352c44ba638
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v28, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xb79eb271d1920253
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xa57a78dbd8258d14
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v12, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v16, v12, v20

  li t2, 0x997751289633efc7
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v8, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v24, v12

  li t2, 0xaf60c2e993136ad2
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v24, v16

  li t2, 0x42b4a798aa56f96a
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v20, v8, v4

  li t2, 0x7d162423701999df
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v20, v4, v28

  li t2, 0x69f8eb212c42064b
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v12, v20

  li t2, 0x8b7680eb9a109ccf
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v8, v16

  li t2, 0x71cf509d2ac3f880
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v16, v8

  li t2, 0x7f2ebe08f02c7941
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v28, v4

  li t2, 0xadd77fa490745578
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v28, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v16, v8, v28

  li t2, 0xe4fae2ce3acc9582
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v8, v20

  li t2, 0x6ae85bab65d1b97b
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v12, v28, v24

  li t2, 0x4cb5ce8a4c0ac089
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v12, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v24, v28, v4

  li t2, 0xa829b1ae526f8e0c
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v4, v12

  li t2, 0xa75265e0e2733926
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v28, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v24, v28

  li t2, 0x670f1ec6c490a67a
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v12, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v24, v20

  li t2, 0x60b4e4b8d76c3286
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v12, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v20, v24, v16

  li t2, 0x261212cb1e86f0e3
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v8, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xe84531512f3c323e
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v20, v12, v28

  li t2, 0x95058ce0f3bb7b43
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v28, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v24, v28, v8

  li t2, 0x366245e841e49a14
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v24, v16, v12

  li t2, 0xa7f18e7fe4a56fc5
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v12, v8, v16

  li t2, 0x14758f74329d1f93
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x4fa0b956ff7fd797
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v16, v8

  li t2, 0x82863b1d28ddcd1a
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v28, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v20, v16

  li t2, 0x9cb6702e6b01a869
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v12, v8

  li t2, 0x5742b61219530f2c
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v28, v24

  li t2, 0x7eeb2a7d0c419446
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v4, v16

  li t2, 0x0a8ac111553f0a58
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v28, v12

  li t2, 0xea1b959064848542
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v28, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v16, v24

  li t2, 0xa86e27217c852b38
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v28, v20

  li t2, 0x18aa5e2c2ac2d563
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v24, v8

  li t2, 0x12391c1b87260022
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v8, v24

  li t2, 0x088925e39e2700cb
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x1815bc79c68ef190
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v20, v12, v28

  li t2, 0x03d62b9bf2403d5f
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v12, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v20, v8, v4

  li t2, 0xb4e7a4cd2623304e
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v24, v12, v8

  li t2, 0xe6f7e8c953c2e3c1
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x90490d4d4a957ace
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v20, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v20, v8

  li t2, 0x02b3b11b2b8fb524
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v20, v28

  li t2, 0xb1e37ffaadc67e99
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v16, v24, v12

  li t2, 0xea7910f008835ebd
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v20, v8, v4

  li t2, 0x86ba737a5b58d55f
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v20, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v8, v4, v24

  li t2, 0x6b4fd15994ad9e53
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v20, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v16, v20

  li t2, 0x8a87d23abc72c56d
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v24, v28, v12

  li t2, 0x9321e95b6a6eda86
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v12, v28, v4

  li t2, 0xbdc0418e3a44f9ff
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v20, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v16, v24

  li t2, 0xb213fbd81f62c868
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v12, v8, v16

  li t2, 0x3c951b0f8e8b3153
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v4, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v28, v16, v8

  li t2, 0x78fb381d7af18405
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v8, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v4, v20, v8

  li t2, 0xa832a762b31a84f1
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v24, v28, v8

  li t2, 0x07df03bbe751738c
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v12, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v20, v8, v16

  li t2, 0x6951fec2e3b490fa
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v16, v8, v28

  li t2, 0x58621d898c1a0905
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v20, v4, v8

  li t2, 0x3485c18758fd36a1
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v16, v24, v4

  li t2, 0xd5995664a16161e2
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vv v16, v4, v8

  li t2, 0x1f8320aaea5aac26
  vsetvli t1, t0, e8, m4, ta, ma
  vsub.vx v24, v4, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x39e53163003a9bcf
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x5df70fe981e37ab3
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xc0a5b5a0de751f12
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xc1daba565f759034
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xc9b36eef471cba75
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x7ebeabb53f57cc08
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xd3fda24a74726c4c
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xaec8b9c90cacebcd
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xcdd515c35a8eed22
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x79b23e0aaf31548b
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x7c8407f927075c20
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xd66270c6046eeba0
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xa2453f4a45cafa29
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x7ca59fc21de22df2
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x2d89c60d8aaafc84
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x86cc0d8434833505
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x082d01a0e75e43f4
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x303eac8dfc2582e2
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x5c7e245ca77a3d6d
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xce9cf77259f7c49a
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xe8a6c274f785823e
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xd2058de4166d15ce
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xd12b257de17d93b0
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xb684086e2d44d646
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xae7ab68debfc1424
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xb9f7687858a46f97
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xcf7cc43bf36eb0e8
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x8f6a14d029d09684
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xaf7cc5370aed08d5
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x1bc55574d4e74e98
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x9c08962bd4af7724
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xe6fa5f7fb448992b
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xff6272d554d856d6
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x54da2cec4b31b3d4
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xb5464f0bc850deee
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xef16e2c3563234fa
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xb01f0a637f336d9c
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x383d0cb89a8c634f
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x92ef29f060c0245c
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x68f7cba5eb2f4bcb
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x8a6a4e6cc12ba0fa
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x3d9e36f8d1068c7c
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x850647d86d7cdfe3
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x6036e82506709ff7
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x4510126a6618e60f
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xdbf476cfcf39d395
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x486f8a488b8d0213
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x5766e8e9fdb9b897
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x6ea5a0bec872b947
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x8c2fcc2e2434e818
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x3e419d6ac3aeea58
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x590766b2e86db506
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x410de973ced9feac
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xc352681af32f0daa
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xddd70124d44545fa
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x19e5863addce8503
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x4382209708853912
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x53622abc8c47c5a6
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x6e38b9bc79fca671
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xafe15fcb0554564c
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x5560df4158d4755c
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x55f10088419f7c6d
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xe834c6a8353e807f
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x0a8817d81325625d
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x6c93fe16200ed065
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x3dc8e92083232a1b
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x1abcf2741842b9e5
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xf39c35b0a92ca36f
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x8b8bc16a0f40f401
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x28bf1fb46a587143
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x73d3c22f576ac9bb
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x4e8aaa5cb5af3b58
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x08e29f1664608413
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xb1ba722368c987c5
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x9405aa8e5b5ff02e
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x92e20bb4a2b6a287
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x1b8283c728b5ca44
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x05375c9ba8991964
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x5d8eca0fddd7e506
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xfb28019ce19830b8
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xcc9cf55d44e38262
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x67ca05f9d86b606f
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x4b601414f0568fdd
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x0690498a895d2dc2
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xdc2cb72948f75a88
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xd76c6b16702ba9c9
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x512b96f1b99651b2
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x99dc9906162fdccc
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xe4c2c8054736ff18
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x9b753b69024817e4
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xb84a0dc1b1189933
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xd191fa4103060776
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x0aae023f23b68788
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x255f37049f10c129
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xaa5f98b5b6c96821
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x7a5d0f9a97fd658b
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x4341e094c80cabb1
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x6e02f5553aa492c6
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x2464c82cd6199721
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xb20d2a21fc89dc99
  vsetvli t1, t0, e8, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v13, v3, v19

  li t2, 0x661901a7e3792969
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v25, v30, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v14, v4, v20

  li t2, 0x4258ad3821cdc01a
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v26, v7, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v4, v24, v7

  li t2, 0xdc6324e2396d5714
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v20, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v8, v5, v10

  li t2, 0x2e5f5174b1d354a5
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v22, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v26, v27, v7

  li t2, 0x3ff7d1d09b1f5fe4
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v10, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v8, v22, v2

  li t2, 0x15dd699e742f40f3
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v18, v23, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v30, v27, v31

  li t2, 0x06ae50ae661436d0
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v4, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v12, v31, v2

  li t2, 0x09eaec1b1c2dff28
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v28, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v4, v12, v31

  li t2, 0x2d2b1817f6d17ef0
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v2, v30, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v6, v25, v15

  li t2, 0xcc206c1b7f6f3f1b
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v28, v18, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v21, v20, v3

  li t2, 0x3afab3bc71f8d660
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v30, v5, v7

  li t2, 0xf7d612fed14bd948
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v28, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v28, v8, v9

  li t2, 0x07d2957f24c65dc3
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v29, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v28, v9, v2

  li t2, 0xd1e63bc98c4c04ec
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v26, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v19, v21, v30

  li t2, 0xc935d580a535dada
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v1, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v9, v2, v8

  li t2, 0xfb92d4410b587f4c
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v1, v5, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v4, v2, v30

  li t2, 0x608ddc0a18390ebe
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v13, v5, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v16, v13, v9

  li t2, 0x6c608cd3debc6d46
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v23, v9, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v3, v2, v27

  li t2, 0x90dbcc9b877cd41d
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v21, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v18, v11, v16

  li t2, 0xcda614687fa7115d
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v2, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v1, v22, v9

  li t2, 0xa5d0e59384fbf726
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v8, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v7, v29, v1

  li t2, 0xe9234329fed7faa8
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v17, v9, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v12, v30, v10

  li t2, 0xf058a1e62dcd920f
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v31, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v21, v2, v27

  li t2, 0x302ad430a15a74d6
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v21, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v27, v14, v28

  li t2, 0xc072596d49b5da6a
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v19, v9, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v10, v19, v7

  li t2, 0x2b4aca2ac2ed6fbd
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v22, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v18, v1, v13

  li t2, 0x966dfacd0dcf33d3
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v28, v14, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v27, v31, v15

  li t2, 0x2d2089e7fdc6f65e
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v3, v18, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v22, v23, v18

  li t2, 0xa8e0025e9b726b45
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v30, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v15, v26, v30

  li t2, 0x96bcc8ea1af6ffb4
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v27, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v7, v11, v27

  li t2, 0x7d07b2efcf76051a
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v27, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v15, v1, v22

  li t2, 0x02050e35a2cda0b0
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v22, v10, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v26, v2, v9

  li t2, 0x69e27ff50ff17e0d
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v25, v13, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v26, v19, v1

  li t2, 0x0dca79c13a251fda
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v4, v30, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v29, v24, v11

  li t2, 0x38690ec5997780d1
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v28, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v8, v6, v9

  li t2, 0xcade34a01b9190f4
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v11, v7, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v10, v21, v25

  li t2, 0x2ba7680e29e86f07
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v21, v17, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v2, v30, v13

  li t2, 0x280241b354909fbb
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v8, v30, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v4, v22, v7

  li t2, 0x39bc345d5c6970cf
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v24, v9, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v16, v4, v29

  li t2, 0xe269ec4e0e36c32b
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v13, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v25, v14, v29

  li t2, 0x65bb32403097ab12
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v29, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v28, v30, v23

  li t2, 0x99331af70a81cfbc
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v14, v31, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v22, v23, v2

  li t2, 0x93579966ca01a3cf
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v16, v1, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v18, v5, v10

  li t2, 0xdef04b200e470607
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v28, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v10, v30, v25

  li t2, 0xed787d66b786dac1
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v5, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v26, v3, v12

  li t2, 0x77a07f52a7b1d7d8
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v26, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v9, v10, v22

  li t2, 0x4aa0be8f42733cfe
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v8, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v20, v8, v1

  li t2, 0x9b2ed80a46739522
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v6, v14, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v20, v5, v26

  li t2, 0x0003c078f287abac
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v24, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v28, v19, v12

  li t2, 0x9b7cbae5fc938bfc
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v17, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v27, v31, v14

  li t2, 0x89a08eeedc9031f9
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v14, v18, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v29, v13, v11

  li t2, 0x1df49afdc6816fe1
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v6, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v21, v29, v26

  li t2, 0x03655243a8755edf
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v5, v26, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v29, v2, v16

  li t2, 0xa8e00d4c0d07289d
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v8, v10, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v19, v4, v28

  li t2, 0x8b36169ca2cbb3d6
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v2, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v18, v22, v8

  li t2, 0xa837d7c830a8df04
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v22, v3, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v21, v29, v26

  li t2, 0xb8bf21dd407ce9bb
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v28, v6, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v23, v4, v24

  li t2, 0x91c20f9951baa22b
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v16, v27, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v22, v23, v14

  li t2, 0x4b46543ecdd5f126
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v16, v14, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v27, v5, v1

  li t2, 0x6ef8c12f6b77ccd1
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v19, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v19, v3, v17

  li t2, 0xa76d9d43642410c5
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v22, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v21, v3, v18

  li t2, 0x72b583dfb4f927c0
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v27, v9, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v30, v23, v2

  li t2, 0xffabc5f3802fd294
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v16, v18, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v1, v29, v31

  li t2, 0x6fb9eb9b79a5dac9
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v24, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v28, v21, v7

  li t2, 0x7765383e406b18ff
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v24, v30, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v7, v22, v25

  li t2, 0x53a390f3ce7b0877
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v10, v3, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v11, v31, v19

  li t2, 0x1773bd33c246199e
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v24, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v30, v31, v13

  li t2, 0x3f573fc101ae339b
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v26, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v2, v22, v24

  li t2, 0x5516303091306376
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v31, v26, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v30, v20, v27

  li t2, 0xad7b3f3498b30e19
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v2, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v16, v1, v26

  li t2, 0x5ee577c1bc3ecb84
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v23, v29, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v29, v25, v3

  li t2, 0x8b73e8a44a4bf0e1
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v17, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v11, v6, v3

  li t2, 0xbfcb160d96a312d5
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v31, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v3, v24, v28

  li t2, 0x55c7206be68785fd
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v19, v29, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v16, v1, v31

  li t2, 0x149de1f59b7832ed
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v12, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v2, v4, v19

  li t2, 0x19ab45f0276ed77d
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v14, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v4, v16, v6

  li t2, 0xc06c7872d97fea20
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v5, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v25, v12, v24

  li t2, 0x7c669dd27bc78008
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v30, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v7, v18, v5

  li t2, 0xb8263dc4dd71a5bb
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v7, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v13, v17, v2

  li t2, 0x426624da7c827a0a
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v25, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v7, v3, v5

  li t2, 0x26d8a950ab51e2dd
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v15, v30, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v3, v31, v30

  li t2, 0xb2cf41a68de7f4bb
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v8, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v21, v6, v11

  li t2, 0x0c1aadae8f718910
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v4, v13, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v10, v27, v4

  li t2, 0x8e8cc656f836eb1a
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v15, v13, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v17, v5, v10

  li t2, 0xd1fad87984cf5a42
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v2, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v6, v28, v19

  li t2, 0xb0e61eb8e08657d5
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v30, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v31, v14, v24

  li t2, 0x648264565016792d
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v17, v10, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v21, v8, v24

  li t2, 0x4c56b2974d60f619
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v1, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v27, v5, v10

  li t2, 0xe40281f60af660a9
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v4, v30, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v5, v20, v8

  li t2, 0xb53988bdb1f3be4c
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v30, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v11, v18, v9

  li t2, 0x4f5f77194132cbc9
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v31, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v11, v29, v20

  li t2, 0xe3514834a50b94c9
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v13, v14, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v24, v27, v6

  li t2, 0xce4fd2296a4f21f9
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v27, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v14, v8, v27

  li t2, 0xbdbdb78f36286201
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v1, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v24, v6, v8

  li t2, 0x19ad074227df621e
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v7, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v18, v27, v30

  li t2, 0xde9378b7c025850b
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v11, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v28, v4, v10

  li t2, 0x8b8f99ed008f7235
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v31, v6, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v6, v18, v28

  li t2, 0xa3c3a85ac5eabb1c
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v6, v1, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v6, v22, v21

  li t2, 0x38c2b504de9bc2ab
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v9, v14, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vv v10, v30, v29

  li t2, 0x6aa8fcc745bccf8c
  vsetvli t1, t0, e16, m1, ta, ma
  vsub.vx v11, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v12, v14, v8

  li t2, 0xa69baf2819df5a52
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v18, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v20, v14, v6

  li t2, 0xeb86e423a592d9c2
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v10, v16, v4

  li t2, 0x126ed5436c04d023
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v28, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v22, v12, v6

  li t2, 0x5fa25a05bf133791
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v6, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v8, v18, v2

  li t2, 0xa167ee97763032d7
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v8, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v10, v22, v4

  li t2, 0xc6c242a794732804
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v10, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v22, v16, v2

  li t2, 0xe75fffd9caa06d6e
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v30, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v4, v22, v26

  li t2, 0x3385aa3fbb669dd8
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v2, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v30, v28, v2

  li t2, 0x20b3028dba13b1f0
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v12, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v18, v8, v26

  li t2, 0x06da28a1d25590ef
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v20, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v24, v4, v28

  li t2, 0x82040532e21d96f1
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v10, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v10, v22, v12

  li t2, 0xa37981792883c36f
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v30, v12, v28

  li t2, 0x6f1e49f633f85f32
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v24, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v14, v12, v30

  li t2, 0x55b7ea517bdcf296
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v22, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v6, v2, v28

  li t2, 0x2c7949920b1e1c3d
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v6, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v22, v4, v8

  li t2, 0x39acc14db5cfd88b
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v6, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v10, v20, v28

  li t2, 0x7f124ac8d250f462
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v14, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v18, v4, v14

  li t2, 0xaafb845ffc271df5
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v6, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v4, v30, v12

  li t2, 0x57a8165cb4eb2cf6
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v26, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v16, v6, v18

  li t2, 0x2261d3736ad5fdfc
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v18, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v30, v12, v24

  li t2, 0xb7c11fa718cb7e73
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v14, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v24, v4, v6

  li t2, 0x87b1aaeddaceed75
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v12, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v18, v12, v30

  li t2, 0xe4643159902a9152
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v14, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v10, v18, v30

  li t2, 0x9cd8989304da78ff
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v26, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v6, v4, v8

  li t2, 0xf85bbe50cd9826d9
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v2, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v24, v30, v12

  li t2, 0x5cdac4f4fe4a837d
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v8, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v22, v26, v16

  li t2, 0x4b84d405689e9f56
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v30, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v4, v22, v20

  li t2, 0x65573f878ae23fbd
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v6, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v24, v14, v28

  li t2, 0x7001f96fd30b66da
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v16, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v8, v16, v4

  li t2, 0xd7d7b05f97441b33
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v18, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v2, v12, v30

  li t2, 0x6a1579cdf3311e75
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v22, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v4, v28, v22

  li t2, 0x3fbc493b2548e5c3
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v28, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v4, v8, v22

  li t2, 0xd73c7b60dae127c8
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v26, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v10, v6, v14

  li t2, 0x91182457655d4b39
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v12, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v16, v18, v8

  li t2, 0xabaf4dc206e808c4
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v30, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v22, v16, v30

  li t2, 0x42a3ce44e587c964
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v16, v26, v2

  li t2, 0x416335c03b837c2c
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v4, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v12, v26, v20

  li t2, 0xcbbd0ef8b32050bb
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v6, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v20, v26, v16

  li t2, 0x23cbfb1aa4878a59
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v14, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v20, v14, v24

  li t2, 0x75e53bbafdd3f657
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v12, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v6, v22, v26

  li t2, 0x1892bca0df530206
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v14, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v16, v6, v30

  li t2, 0xa6fda6007d7d2fdb
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v8, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v26, v12, v2

  li t2, 0xc9dc0e1debd5667f
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v24, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v24, v2, v16

  li t2, 0x79578b849abf70aa
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v16, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v14, v20, v2

  li t2, 0xd7157243d57b1804
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v12, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v18, v24, v14

  li t2, 0x7951ab4b9dd05048
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v20, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v14, v4, v22

  li t2, 0x3c19bc2b928e082b
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v20, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v30, v24, v14

  li t2, 0x91011068591e5493
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v6, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v20, v10, v2

  li t2, 0xcdd97cb0e3aa9f85
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v26, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v18, v24, v28

  li t2, 0x8f02ece7fea0a7ba
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v2, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v26, v24, v2

  li t2, 0xb44bf14c8bf1e71c
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v2, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v10, v6, v24

  li t2, 0xfefe7e01b6c48397
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v24, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v8, v22, v14

  li t2, 0x3fedb0b0f508a861
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v30, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v4, v18, v6

  li t2, 0x1c7b4aaa50f23275
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v22, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v2, v8, v10

  li t2, 0xd7e72f2903e21b7e
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v22, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v16, v4, v18

  li t2, 0x83434fea7868cfe3
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v24, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v18, v8, v16

  li t2, 0x54ad30519f1b6c5d
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v4, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v16, v18, v8

  li t2, 0xb80b0d21f4c11fa1
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v12, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v2, v28, v10

  li t2, 0xc386b54ee38219ed
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v22, v24, v14

  li t2, 0xd529233831112ee9
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v20, v10, v24

  li t2, 0x918eac787deb903f
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v30, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v20, v12, v10

  li t2, 0x1e7a7932a9379433
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v22, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v30, v20, v8

  li t2, 0x7ac61f37ba34541d
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v18, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v12, v18, v14

  li t2, 0x76bdde2f30341732
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v12, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v20, v4, v10

  li t2, 0x07d49ba7655d1bdd
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v16, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v22, v2, v8

  li t2, 0x918d8d0845033d7b
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v14, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v12, v24, v14

  li t2, 0x046b5387e8c8321e
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v26, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v30, v16, v4

  li t2, 0xfc78251c7f61bcfe
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v18, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v24, v6, v4

  li t2, 0xb8545ccf4475886b
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v16, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v30, v6, v8

  li t2, 0xa065190fd506fcea
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v20, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v16, v20, v24

  li t2, 0xf1e485b8ff871ba7
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v22, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v16, v2, v26

  li t2, 0x620cf38f75d4d94a
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v28, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v24, v28, v2

  li t2, 0x0506368e641dea23
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v20, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v18, v6, v22

  li t2, 0x51b5958cc9b6e2bd
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v4, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v20, v30, v22

  li t2, 0xdf7bea5dc984c569
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v18, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v2, v30, v8

  li t2, 0xe9dd69cad8da2ce3
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v28, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v10, v24, v20

  li t2, 0x060e9ea0196c97a6
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v6, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v10, v22, v18

  li t2, 0x7b947d34e25145d4
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v22, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v24, v22, v18

  li t2, 0x3497172b9bcfc0f4
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v8, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v10, v20, v2

  li t2, 0x360afab1880fd003
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v22, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v20, v18, v12

  li t2, 0xd9796fc80e90d832
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v24, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v26, v6, v24

  li t2, 0x18778a7dba45f207
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v26, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v10, v24, v28

  li t2, 0xd9a769f0118f1d4b
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v10, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v28, v30, v26

  li t2, 0xe968377374a7f06c
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v28, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v30, v10, v20

  li t2, 0x7b7c87c2ad4a3531
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v16, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v30, v20, v26

  li t2, 0x6bdb1ef01a90707a
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v22, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v4, v26, v22

  li t2, 0xaafea8108bffc26c
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v26, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v30, v28, v2

  li t2, 0xabb72d98e87b9cf8
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v20, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v4, v12, v6

  li t2, 0xae9235a56805ee7e
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v16, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v8, v12, v18

  li t2, 0xe26098655efcc58c
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v30, v20, v18

  li t2, 0x8765684b5c085196
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v14, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v22, v14, v12

  li t2, 0xed1b6200337ec1f0
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v12, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v30, v26, v4

  li t2, 0x03753b99c1711f0f
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v30, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v28, v10, v18

  li t2, 0x3238de02a143e6c9
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v16, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v4, v26, v20

  li t2, 0x7c400b407b199b76
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v26, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v16, v10, v18

  li t2, 0x3fb6da9d3756260e
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v4, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v30, v28, v8

  li t2, 0x4c240eecae8f39ca
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v24, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v22, v2, v18

  li t2, 0x621b98a992b52fc9
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v6, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v8, v14, v26

  li t2, 0x3bce3124ffaad2c0
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v22, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vv v10, v4, v2

  li t2, 0xcab5820626b342b3
  vsetvli t1, t0, e16, m2, ta, ma
  vsub.vx v30, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v4, v24, v20

  li t2, 0xd5b5db0bfb4146e6
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v12, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v28, v4

  li t2, 0xa8e7d4355fbd62ff
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v8, v4, v12

  li t2, 0x21c9ab888644fda0
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v8, v16

  li t2, 0x833602671e63787e
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v8, v24, v12

  li t2, 0xd3d69739e0bc50eb
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v28, v8

  li t2, 0xe63d71f71d2aab3c
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v8, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v12, v24

  li t2, 0x98fafd25d411efa9
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v16, v8

  li t2, 0x8c6a264c592900ce
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v28, v4

  li t2, 0x7ee64537119e585e
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v4, v28

  li t2, 0x40212a2ca4e1ac62
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v4, v20

  li t2, 0xe221ca99479186da
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v28, v4

  li t2, 0x0278670b506e26fe
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v12, v4, v8

  li t2, 0x2f828e13285f6549
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v4, v20, v28

  li t2, 0x43cdd48c322b5d93
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v12, v28

  li t2, 0x001943d5d5272842
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v12, v4, v20

  li t2, 0x4587392313bf9b0c
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v24, v28

  li t2, 0xf46330b02f690be2
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v28, v8

  li t2, 0x7304fc7826514e65
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v8, v20, v24

  li t2, 0x2ed32cec98a220a3
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v20, v12

  li t2, 0xb9a91d07157b4288
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v24, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v24, v16

  li t2, 0xc2cd2eaa524012b3
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v16, v12

  li t2, 0x64d023cce63f03a7
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v24, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v12, v28, v24

  li t2, 0xaa4431976479d275
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v28, v4

  li t2, 0x66cfcfd213f510b2
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v16, v8

  li t2, 0x06ce7a0ab218e109
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v8, v12

  li t2, 0x2ad67384286ad3cb
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v28, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v12, v24, v8

  li t2, 0x4243c52781a8a1f5
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v4, v12, v20

  li t2, 0x2eabc77115bf72bc
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v28, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v24, v12

  li t2, 0xb59e5c910e4effd8
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v28, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v8, v4

  li t2, 0xdccc3465f7f8c064
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v28, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v28, v8, v12

  li t2, 0x16b9f83716128098
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v12, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v28, v16, v24

  li t2, 0x7a3a2c3e702d899a
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v28, v4, v16

  li t2, 0x2a9ef15abf7ae8da
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v8, v20, v4

  li t2, 0xfa784f4e2db177e4
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v24, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v4, v16, v28

  li t2, 0x01bb6f61c7a69cae
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v4, v12, v16

  li t2, 0xd63ff63ef9e0f434
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v24, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v4, v20

  li t2, 0xf688df17f7a8d3e4
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v28, v4

  li t2, 0x0b67918a12a43bff
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v8, v4, v28

  li t2, 0x711e05300772b0ff
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v20, v8

  li t2, 0x84815cc5488db9be
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v12, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v16, v28

  li t2, 0x7d190ff52f177666
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v24, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v24, v12

  li t2, 0x37d23f63bc1b3216
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v8, v20

  li t2, 0x2576a1cd1e4fd543
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v8, v28, v4

  li t2, 0xa42f550dddf61a44
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v8, v12, v28

  li t2, 0x1c85d8796e48941a
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v4, v28, v8

  li t2, 0x8947aa69ee5efb96
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v28, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v20, v4

  li t2, 0x3a64b96207dc582a
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v12, v28

  li t2, 0x1cf14d2850a45c14
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v8, v12

  li t2, 0x333c188fcca7ace6
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v8, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x8f09d536df7209fc
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v28, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v4, v20

  li t2, 0x1d10353ee91b1ab8
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v12, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v8, v4, v24

  li t2, 0x7596f7aab3cd9153
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v12, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v4, v16, v8

  li t2, 0xd97839af4df0af96
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x2a4c4c144191e97b
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v12, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v8, v28

  li t2, 0xe0c85a5e3d7324f9
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v8, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v12, v28, v8

  li t2, 0xcf1b5260c4617584
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v28, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v28, v16

  li t2, 0x4d3627b3177a22c8
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v28, v8, v24

  li t2, 0xaad0671b1e77c2fb
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v12, v20, v16

  li t2, 0x348fb24ad641f696
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v28, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x7687ec0beecc1fd0
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v12, v4, v28

  li t2, 0x34342bd6b5372a21
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v12, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v28, v8

  li t2, 0x1bf36d37ca4f8964
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v12, v16

  li t2, 0xce33ef290e4767f1
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v8, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v12, v4, v20

  li t2, 0xcb051bfe187b54b0
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v28, v16, v8

  li t2, 0xbffa48b186766cd4
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v4, v12, v28

  li t2, 0x3d5ad09d6da0a57d
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v4, v8, v16

  li t2, 0x24a9459675e607d7
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v16, v20

  li t2, 0x171177dc1e0ab45f
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v12, v4, v8

  li t2, 0x4d58a51f68cb75eb
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v28, v8, v12

  li t2, 0x6a6f9a1e8bfb5e53
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v16, v20

  li t2, 0x7db6300ae2e79869
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v12, v8, v28

  li t2, 0x54d2ea5bf8cbee57
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v28, v12

  li t2, 0xb202f84a28ddcf2e
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v28, v20

  li t2, 0x66d4835dc5c56d79
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v8, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v12, v16, v24

  li t2, 0x359ec1f16d9a974c
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v12, v4

  li t2, 0xa0d28fa209a45c3f
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v12, v24, v8

  li t2, 0x7eada4d6b91452d6
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v28, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x9a3d9d632cfb5262
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v20, v16, v28

  li t2, 0xa8ed4c697fde87fc
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x3fc9b5203fee108f
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v12, v20

  li t2, 0x9ed9e04c8e6a12d0
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v8, v12, v16

  li t2, 0x47d3cd07c1e09689
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v28, v4, v12

  li t2, 0x4719da4beb91439b
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v8, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v12, v8

  li t2, 0x2a0534a389e615e8
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v28, v20, v12

  li t2, 0xabda7361a1b802d8
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v12, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v4, v8, v12

  li t2, 0x5f9dffd443bc7849
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v8, v24, v20

  li t2, 0xd41adcdd1f37aa30
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v28, v16, v12

  li t2, 0x14d293135086932d
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v16, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v28, v20, v8

  li t2, 0xa38bfe98c8b311ca
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v24, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v4, v12, v16

  li t2, 0xa1e90e777b1f6b59
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v28, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v4, v24, v20

  li t2, 0x71d6c48cfc88ae8b
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v12, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v28, v12, v16

  li t2, 0x4a3ede15eb60c669
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v4, v16, v24

  li t2, 0x09be36b1f3c736d3
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v28, v8

  li t2, 0x335d7952ccd00920
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v24, v16, v28

  li t2, 0x1ee7d4a4d62a83b9
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v28, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v8, v28, v12

  li t2, 0xbb51ad49ee1a45f1
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v12, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v12, v4, v8

  li t2, 0x3b8efa0d25fba180
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v8, v12

  li t2, 0x7b674f22f4e23e08
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v16, v28, v8

  li t2, 0xc905e349436b4a55
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v4, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vv v4, v28, v12

  li t2, 0x2958e302efd80dce
  vsetvli t1, t0, e16, m4, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xf394de9122ab1299
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xf8bf70efab04ab48
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x71154a05e14fcbf0
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x1333df749ac68bb6
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x210e2a1dcbd57bcd
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x0741bcc359a7ffa4
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xd66fe3bf4f39320d
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xbff937ba43d7b0a4
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x9509542e2016ce38
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xd62ca308cb8dca9e
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xfcf58a9d84752127
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x945674786fbded82
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xb5ca8b83cf1440ad
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x8993b3b9d76371e7
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x03db53896e0e6082
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x20d7797311a02b0e
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xa2fc81fcbf9172c9
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x9429f256a9d3677d
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x8683a81f30f728be
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xe7e3aa18f59cd0e5
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xd1cd599b6f817217
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x17fa546f7367843d
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xcd5e55af382150c6
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xebf346d1e1bd2a99
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xa1b12405464452b2
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x7ad0f96fb0992619
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x6a1fb7c8546329ff
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x48c0140e015eaffb
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x61a68f0b73e4a84c
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x7980b907048e8382
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x646e75452b27d7e8
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x080bc8f5a90d9f23
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x9dde389bf4b0d868
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x892fe4c6d95bb4ec
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x001f47d990c88306
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x3edaf3835a18b925
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x96bce7a416a177c9
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x8610d96f6b106a12
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x8c5833b9a39d06d6
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xae43307992c8eb12
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xb888e00dedd773a2
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x25ca126c59c7fc0e
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x5f3da331e4243103
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xc578323a593c06ae
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x3463c62e89c22f9f
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x5a629b90ea47db1b
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x8a97e8156e4ebf2f
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xe663e65c413468e5
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xa250337783fe9063
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xec81836fbb7e4ced
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xdc050f83d7e54342
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xd173a866ed58f262
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x838da3343b85cb43
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xe407c216ebbf56bf
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xe334054c4be4c845
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x95cd074599583883
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xcc061eef3a3226c7
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x4001fc1a41a6c030
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x96a7f0a34e4f3ba6
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x2c775521616dc0fa
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x8b18da1fadab7bcd
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xbd20709313e2f3c7
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xb076f14ec25b287e
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x63ddc4067620909b
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xfee81d60d7f1eb15
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xb4f4c897e095f58b
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xf126f3db3049546e
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x9bc2a6ca9dd4653b
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x6e1b9d58533c75bd
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x7a6b20ffaedb674d
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x497e74cd805d5261
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xbeb7735e245385a1
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x2f41cef5e55aff82
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x5977288cb679ffaa
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xea5dd689e2973067
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x1d36ddeb297b58be
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xb48939717c6f0fe8
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x0be7157015c800a5
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xe55b433f0961e9b0
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x550c4c1725558176
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xb149810bd1fe7e79
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x6154ad676fbb5bdb
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x1d2dcead5953783f
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xa7e609f2977e01f4
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x6f7d9e788d1bfc48
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x4e3bdf14808b1539
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xce9a57fdd9e736fc
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xbbe0239c5e7a8d59
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xfc303688d9961b97
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x1244ccd7f056cbb7
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xbcc2ddb2caa15e33
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x77facb727425f702
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x8f690031245ba1ee
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x05d7aeccc6682258
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x78e6bcd50e56e62f
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xbd5ed88166882c14
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x8bc76828213db285
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xd85d424731414505
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x569d79c8b9003982
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xeba2fd96e0c1aadd
  vsetvli t1, t0, e16, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v17, v28, v22

  li t2, 0x409fa7e50a3398c2
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v9, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v3, v29, v19

  li t2, 0x0467400886e63390
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v9, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v19, v27, v6

  li t2, 0xa19c7fbcbf8e73ff
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v24, v1, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v2, v16, v22

  li t2, 0xcecbfd9e07ba9142
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v14, v31, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v11, v3, v9

  li t2, 0xdc2369ce26b8a182
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v28, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v7, v22, v18

  li t2, 0x822a22419592ea27
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v2, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v2, v24, v21

  li t2, 0x4c3f2149b492d25a
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v18, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v17, v16, v1

  li t2, 0x32a49ee594c80b08
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v30, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v16, v28, v31

  li t2, 0x9541a741e7392fd5
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v13, v11, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v12, v8, v22

  li t2, 0x8ea82b7ae4e4ab34
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v31, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v16, v3, v29

  li t2, 0xaccf0021c97084a7
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v29, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v30, v22, v16

  li t2, 0xc15945761a2dbb2f
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v14, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v9, v20, v14

  li t2, 0xbb3b34e91204c780
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v19, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v7, v20, v14

  li t2, 0x4335f1b6c63697e7
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v4, v29, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v29, v7, v11

  li t2, 0x5be88dadafc15da5
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v31, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v11, v12, v10

  li t2, 0xd41c3cd1b783cc33
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v24, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v13, v31, v10

  li t2, 0xf7c12007f4ba4eec
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v6, v27, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v14, v10, v25

  li t2, 0xe0cd225eed69ebf7
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v9, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v31, v30, v10

  li t2, 0x3a7db0075ef800d7
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v30, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v2, v30, v19

  li t2, 0x38516942ea3551d1
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v9, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v26, v6, v18

  li t2, 0x29d97c6193333dd3
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v7, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v16, v21, v5

  li t2, 0xcf4061b148864d79
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v29, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v11, v27, v24

  li t2, 0xb0ac7de6b42bd3e8
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v8, v3, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v7, v24, v12

  li t2, 0xf1204e448985db2d
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v28, v31, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v22, v18, v13

  li t2, 0xfbc1966196da7d6f
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v20, v23, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v12, v15, v5

  li t2, 0xc765d45e734015f3
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v25, v26, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v14, v15, v23

  li t2, 0xa26a1cfab50856b9
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v13, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v25, v14, v2

  li t2, 0x6ce846a77b7d5fc4
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v6, v2, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v20, v30, v5

  li t2, 0x67cc16047a713425
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v18, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v5, v25, v19

  li t2, 0xbaf7805655fbc7e8
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v6, v28, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v30, v5, v21

  li t2, 0xc02a8ab79e1f3653
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v21, v3, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v30, v10, v21

  li t2, 0xa815f996d4714a22
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v30, v26, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v5, v2, v16

  li t2, 0x4cd2958da5a27020
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v27, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v10, v28, v15

  li t2, 0xd5bd0c1a901d8183
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v9, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v14, v25, v31

  li t2, 0x19dd8a782bd44955
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v31, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v2, v15, v25

  li t2, 0xf2cbff458117c97b
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v22, v26, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v23, v30, v13

  li t2, 0xebb4251fe8454be4
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v10, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v31, v12, v7

  li t2, 0x0c101f33e24a8971
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v31, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v3, v14, v6

  li t2, 0xc385cd8c842da519
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v2, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v20, v21, v23

  li t2, 0x33928791f5610e57
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v21, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v19, v27, v11

  li t2, 0xb4b15067c192f3c5
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v1, v3, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v25, v30, v4

  li t2, 0x6e71342cc869814a
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v16, v28, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v11, v29, v10

  li t2, 0x71d06295f72ac096
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v30, v22, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v19, v22, v26

  li t2, 0x5bf79e97a4b5eb70
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v21, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v7, v14, v22

  li t2, 0x0015612eef69ce59
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v28, v1, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v31, v20, v3

  li t2, 0x6e3041640c31170f
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v17, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v21, v7, v31

  li t2, 0x8f8eff51a87b28b4
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v5, v23, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v19, v12, v24

  li t2, 0x8eb5be6cf7ee1fb2
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v24, v19, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v25, v7, v22

  li t2, 0xbd9f8af70e6ab296
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v3, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v26, v2, v23

  li t2, 0xc978bbb7580b0f0e
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v11, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v7, v12, v18

  li t2, 0xbf9bbc7a683d68b6
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v5, v27, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v8, v30, v28

  li t2, 0xeecbe6abdc5c1a24
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v26, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v1, v19, v10

  li t2, 0xe6da358800eecf27
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v2, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v4, v9, v19

  li t2, 0xace9161a66c82623
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v11, v3, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v10, v21, v1

  li t2, 0x9ad8b3e2dd6de4bd
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v8, v25, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v8, v16, v28

  li t2, 0x54733665ad1bf900
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v28, v29, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v1, v21, v2

  li t2, 0x92753c53fc2b69e9
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v21, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v22, v2, v17

  li t2, 0x794cfdb4b792f9bc
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v6, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v19, v30, v21

  li t2, 0xe2faa4143338bc91
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v27, v23, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v29, v11, v24

  li t2, 0x2bc69883a6e63bcd
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v6, v17, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v7, v24, v26

  li t2, 0xcbc4c191cfc8e686
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v8, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v2, v6, v25

  li t2, 0x36e19a0a02f352ed
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v23, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v29, v17, v30

  li t2, 0x6dd82e04f4e0ac44
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v29, v26, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v24, v27, v9

  li t2, 0xc13eb0918af6ba86
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v26, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v1, v22, v15

  li t2, 0x1f407fea21e52478
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v20, v28, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v7, v22, v14

  li t2, 0x00f9e7b6d0268ae6
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v29, v28, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v14, v1, v7

  li t2, 0x7be08524bd8935ad
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v20, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v11, v12, v31

  li t2, 0x2713bd70fc024c1a
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v1, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v20, v9, v15

  li t2, 0x40e08d805e71e297
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v22, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v15, v26, v20

  li t2, 0x3d6094cf482d3ea7
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v13, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v31, v27, v21

  li t2, 0xde58a093e4f963f8
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v16, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v1, v16, v12

  li t2, 0xb12f4167e8908dc4
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v24, v22, v6

  li t2, 0xdae2a77879a3426f
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v18, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v26, v23, v21

  li t2, 0x20afe32bd88dee8a
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v29, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v18, v1, v28

  li t2, 0xb36f409e3ef4574d
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v11, v31, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v17, v4, v29

  li t2, 0x186c2ea7c22698d8
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v21, v2, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v24, v15, v16

  li t2, 0xf34b8e9ef4f0faaa
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v11, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v7, v14, v4

  li t2, 0x79945f2c6b96ca16
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v2, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v29, v19, v22

  li t2, 0x3e704d2731810a8f
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v31, v2, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v12, v18, v2

  li t2, 0x4a203c533e0176a9
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v27, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v7, v15, v25

  li t2, 0x1f29356eef24d0f4
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v30, v1, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v26, v5, v18

  li t2, 0xcb5fe8220ee27d61
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v18, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v8, v21, v29

  li t2, 0x728a83888613dcf4
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v10, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v21, v30, v2

  li t2, 0x7b62f0165d69e5e4
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v29, v2, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v16, v4, v9

  li t2, 0x73bd44913d6b8848
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v27, v26, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v18, v23, v22

  li t2, 0x498a61b1870478ab
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v28, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v4, v11, v12

  li t2, 0x97769385f25b6e92
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v7, v30, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v2, v30, v18

  li t2, 0x6ea0ecfacb676212
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v11, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v8, v12, v18

  li t2, 0xfb763c2d19c33735
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v11, v15, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v12, v22, v1

  li t2, 0x14594aee9b686ad4
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v10, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v29, v19, v24

  li t2, 0x27ccfcacebe2e27c
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v3, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v20, v22, v21

  li t2, 0x59c08f091cb0c2ff
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v23, v14, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v4, v29, v3

  li t2, 0x0c6079eaa3385c46
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v2, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v22, v24, v23

  li t2, 0x3e48ea76999b1f4c
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v20, v29, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v12, v15, v14

  li t2, 0x62ffe1ecf54ecaf5
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v21, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v2, v22, v16

  li t2, 0x7eca91b9e0309748
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v31, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v9, v24, v15

  li t2, 0x39f161a1cb79cf3a
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v22, v3, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v11, v4, v24

  li t2, 0xd524fe7302d9aecf
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v12, v28, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v9, v26, v29

  li t2, 0x3ec149f7c4f86887
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v18, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vv v2, v16, v29

  li t2, 0x19351ca295a63382
  vsetvli t1, t0, e32, m1, ta, ma
  vsub.vx v29, v3, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v30, v16, v8

  li t2, 0x646548ea4cca39bb
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v20, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v2, v22, v14

  li t2, 0x0cd3158e9a44995c
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v6, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v14, v26, v4

  li t2, 0xa8ea7075dc1396d8
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v8, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v4, v6, v18

  li t2, 0xe0f5004a204b7374
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v14, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v4, v26, v24

  li t2, 0xa5fbf7a29482627e
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v8, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v16, v24, v22

  li t2, 0x87401a7f7f3640ec
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v12, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v22, v12, v10

  li t2, 0x9cad4d9ec87eb0b5
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v20, v18, v28

  li t2, 0x150228a274f09e95
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v12, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v22, v6, v12

  li t2, 0x7ea9effabccb697d
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v12, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v28, v20, v26

  li t2, 0x571af7875f037656
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v6, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v4, v8, v12

  li t2, 0xa9e97dc11c1d17aa
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v30, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v2, v18, v20

  li t2, 0xe59a91eb2d434b86
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v18, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v8, v24, v2

  li t2, 0xacb4a4065f4f8447
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v30, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v4, v14, v10

  li t2, 0x1973747abf90c30b
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v4, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v24, v8, v28

  li t2, 0x86e2e14bec45312d
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v26, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v8, v26, v12

  li t2, 0xff38b4c289e1acea
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v22, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v18, v24, v22

  li t2, 0x19212f48fc20ae26
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v26, v8, v24

  li t2, 0xdfe657dcc6faae33
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v4, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v28, v2, v16

  li t2, 0x584cb05d7f9bd01c
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v30, v28, v22

  li t2, 0xe5f3066b49411fee
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v2, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v10, v14, v24

  li t2, 0xde7f5e0d13a1ff90
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v8, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v26, v12, v28

  li t2, 0xe9c052b2b644604e
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v22, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v2, v24, v16

  li t2, 0xdc74229ccb477522
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v2, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v20, v2, v14

  li t2, 0x416d4659491e51ca
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v12, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v14, v30, v20

  li t2, 0xde888d36a6b3637f
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v8, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v8, v28, v10

  li t2, 0x704a444a8d341217
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v22, v8, v16

  li t2, 0xcf68982e61b6835b
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v14, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v26, v28, v4

  li t2, 0xacb21fa4d76602a9
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v2, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v10, v6, v20

  li t2, 0x711082b3839fe8dc
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v30, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v12, v30, v26

  li t2, 0xa97f4ed05566e3e4
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v12, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v2, v26, v16

  li t2, 0xc194d04fef7327fa
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v8, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v14, v12, v20

  li t2, 0x5da0316e31f1af85
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v10, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v10, v6, v12

  li t2, 0xd704407d2ba57c8f
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v2, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v2, v10, v8

  li t2, 0x307b4cf20b70789a
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v18, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v30, v12, v6

  li t2, 0x956ee57c92cb203f
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v24, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v22, v8, v14

  li t2, 0x5a416d1e052c5cca
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v30, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v26, v6, v24

  li t2, 0xbc5d2429219f2a4d
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v6, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v4, v24, v12

  li t2, 0xcf9abc85cc3690f7
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v22, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v22, v28, v16

  li t2, 0xf62747d2e3d2b873
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v30, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v28, v24, v10

  li t2, 0x2ca53ef51e509a42
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v16, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v6, v14, v20

  li t2, 0x3c1e525e4f6a63e1
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v6, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v8, v18, v30

  li t2, 0x5c42d7123aaf979c
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v2, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v4, v28, v6

  li t2, 0x5d5b2c0536975454
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v8, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v30, v12, v14

  li t2, 0x654ac038b1b6926a
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v14, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v6, v26, v4

  li t2, 0x55e7efe587712ac7
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v22, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v28, v6, v8

  li t2, 0x7290d702811c3ece
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v30, v14, v24

  li t2, 0x77ef8743de7a9d4c
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v2, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v18, v24, v26

  li t2, 0x27df693de83a820c
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v20, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v8, v10, v28

  li t2, 0xfd4e8d46aac245d4
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v4, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v20, v16, v18

  li t2, 0x5ee512406f4be17a
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v2, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v2, v20, v30

  li t2, 0x9e655cef4bc351f6
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v26, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v26, v16, v28

  li t2, 0xd7549d0dd12f3e71
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v10, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v4, v18, v30

  li t2, 0x53fa76cf2a4185a2
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v2, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v4, v16, v2

  li t2, 0xee93e198b2bd1449
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v14, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v28, v26, v14

  li t2, 0xbf4464dedf946e38
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v22, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v30, v16, v10

  li t2, 0x0deb5b222868957f
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v18, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v2, v28, v6

  li t2, 0xee0600fee8c99652
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v16, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v2, v26, v24

  li t2, 0x4996be6cbfd45ebf
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v16, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v22, v4, v14

  li t2, 0x0b119bddfa5b51ed
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v6, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v30, v24, v20

  li t2, 0x7f6b7fa44a97b025
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v22, v6, v28

  li t2, 0xc46bcb72a7a907c4
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v10, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v28, v10, v14

  li t2, 0x733be67ad8de7eae
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v26, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v10, v2, v28

  li t2, 0x1ad6e30bd32829ce
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v6, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v28, v8, v16

  li t2, 0xc36b0b28d87dd446
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v18, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v10, v6, v20

  li t2, 0x064ea906e7bef5ec
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v8, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v2, v28, v18

  li t2, 0x28a5b1952ffaff22
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v4, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v30, v12, v20

  li t2, 0xf9ddef5f5c596a04
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v18, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v8, v24, v2

  li t2, 0xa0258447532b4b56
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v24, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v24, v10, v28

  li t2, 0x771a1629e6d58a5b
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v18, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v22, v26, v20

  li t2, 0x548794a120f0b89f
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v2, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v22, v8, v18

  li t2, 0x87db3b89f742c67d
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v10, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v26, v12, v14

  li t2, 0x27c140a596687a1f
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v10, v24, v16

  li t2, 0x0dda3defef5e6383
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v8, v4, v30

  li t2, 0xd5d357fecf57b31d
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v6, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v20, v4, v14

  li t2, 0x463217a4a5818557
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v20, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v12, v28, v14

  li t2, 0xb6073d21ca4e9fe5
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v4, v6, v24

  li t2, 0x9c9d63c6471950bc
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v20, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v14, v12, v22

  li t2, 0xfd62563d0e2483a0
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v10, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v8, v2, v12

  li t2, 0xc0db7c662cfbbcd5
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v26, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v16, v26, v30

  li t2, 0xe62df4722360ca1d
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v28, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v18, v6, v28

  li t2, 0x6b400b662dbe4424
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v4, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v28, v20, v10

  li t2, 0x0cad3dc89a32a882
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v2, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v14, v26, v2

  li t2, 0x3fbbb359632ddfcd
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v14, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v12, v28, v26

  li t2, 0x78fa91ef5ed6b21b
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v30, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v18, v24, v26

  li t2, 0x581c1478d2fb2cb9
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v8, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v30, v18, v24

  li t2, 0x0453e35fce2b3da4
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v24, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v26, v16, v14

  li t2, 0x10a3f5e5cb97e4a7
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v30, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v26, v16, v22

  li t2, 0xf915d7ebf8a8503d
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v20, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v4, v6, v22

  li t2, 0x73911b7fcf097492
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v26, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v26, v10, v8

  li t2, 0xf0bcdb20e8c7ef41
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v28, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v30, v22, v20

  li t2, 0x6421e8f41abdf11d
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v2, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v16, v4, v28

  li t2, 0x1c78d5b154866930
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v14, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v18, v6, v22

  li t2, 0xb2794d40035097a4
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v30, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v18, v30, v10

  li t2, 0x92916716e18a5452
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v16, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v18, v12, v8

  li t2, 0x9f036075d73df623
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v24, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v30, v24, v10

  li t2, 0x9b706783c6d63a95
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v28, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v14, v30, v24

  li t2, 0xab1c4bd80a8f8917
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v6, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v20, v18, v6

  li t2, 0x4aa31b726f5c6b7e
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v6, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v12, v4, v2

  li t2, 0x713c22a76d355855
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v8, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vv v12, v16, v22

  li t2, 0xbff6629eb5206c5e
  vsetvli t1, t0, e32, m2, ta, ma
  vsub.vx v30, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v28, v8

  li t2, 0x1dd2b59b69d29edf
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v20, v28, v4

  li t2, 0xc003e91791d93a1e
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v20, v16

  li t2, 0x8809ed206bad8095
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v16, v12, v24

  li t2, 0x201b116b622f658e
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v12, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v24, v4, v20

  li t2, 0xc731769a8da26baf
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v12, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v4, v8

  li t2, 0xfc03a23d4dfc8bb2
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v4, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v20, v28

  li t2, 0x55f1599fe4102a8f
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v20, v24, v4

  li t2, 0x7da70a081a789f7c
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v28, v8, v24

  li t2, 0xa53e2e7dde852c38
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v4, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v24, v16

  li t2, 0x6954f2e1b0de9e89
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v12, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v28, v4, v20

  li t2, 0xccebbd4b2467b9e7
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v12, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v4, v24

  li t2, 0x851c364f5b63340f
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v20, v24

  li t2, 0x8609678c735c710b
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v20, v12, v16

  li t2, 0xe139001d45accbf4
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v20, v28

  li t2, 0xa5dad1da65c0c9e4
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v4, v12

  li t2, 0x612ad4db8e33b186
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v20, v16

  li t2, 0xcad14c5bcf827438
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v20, v28

  li t2, 0xc37a34e02b4feb8c
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v4, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v28, v4

  li t2, 0xbe279e3f5b93796f
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v24, v4, v12

  li t2, 0x8b2aabab66f3da9a
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v20, v28

  li t2, 0xf8b868f6a8910856
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v24, v4

  li t2, 0x872bc27d014465da
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v16, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v28, v12

  li t2, 0xa608a81fe30fbcda
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v24, v12, v8

  li t2, 0xc760e71f549504d0
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v28, v16, v8

  li t2, 0x195fa74f557c698c
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v24, v4, v16

  li t2, 0x2fd3ae43f2e69e00
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v24, v28, v12

  li t2, 0xe418a2b46661c06f
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v20, v24, v8

  li t2, 0xa6559b1caaf927e7
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v28, v20, v8

  li t2, 0x9000b832a524982a
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v4, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v20, v12, v24

  li t2, 0x5c78d1028ecc89ad
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v24, v20, v28

  li t2, 0xb25064ef542fa877
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v24, v4

  li t2, 0x1d1dee123361ba73
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v4, v12

  li t2, 0x48e237594375f31f
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v12, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v16, v20

  li t2, 0xd4825d9b7cca6972
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v20, v8, v16

  li t2, 0xb89db734ae38ce38
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v16, v24, v28

  li t2, 0xea2e00dc89507b9e
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v24, v20

  li t2, 0xda49e4e6f82adbe6
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v12, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v16, v4, v28

  li t2, 0x4151259f26cdd642
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v28, v16

  li t2, 0x8cb5867d69aaa0b7
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v16, v8, v20

  li t2, 0xb867ab9b4c8c0bb0
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v16, v12

  li t2, 0x11ef2e0c15f0c54d
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x470ddd1d1076800f
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v16, v28, v24

  li t2, 0x43cb379f49e19d50
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v20, v28

  li t2, 0x6737e4cd4937991a
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v20, v24

  li t2, 0xd4e8cbb1adf9aa87
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v8, v24

  li t2, 0x3fc9ccf82b0b8170
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x8ac0b3451a9806b2
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v16, v12, v28

  li t2, 0xa13896f0833c5863
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v20, v16

  li t2, 0x3321d39ecf175962
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v24, v12, v20

  li t2, 0x4c9360ea30e9d1a4
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v20, v28

  li t2, 0xa5e056c4b495d3ee
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v16, v20, v28

  li t2, 0x3e0d57ba549e250f
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v20, v4, v8

  li t2, 0xc46616139a55b06b
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v8, v16

  li t2, 0xef1017fdb752a403
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v20, v16

  li t2, 0xec525820b5c394dc
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v24, v20, v8

  li t2, 0x9a0fbface266aa09
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v24, v8

  li t2, 0x6dd2dd72547d2c4f
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v16, v20, v4

  li t2, 0x35294f55d687cdc3
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v16, v24

  li t2, 0x1066e0f6485db446
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v28, v16, v24

  li t2, 0x8ff5a297a01b4214
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v28, v16, v20

  li t2, 0xa23caa3c8a77589d
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v20, v28

  li t2, 0x7d92896ef917b90c
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v4, v8

  li t2, 0x786d341b232c222b
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v16, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v16, v20, v8

  li t2, 0x8f538b7f8410bd5a
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v20, v24, v8

  li t2, 0xc35554f131447b1b
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v20, v8

  li t2, 0x3c97385388865fd7
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v24, v16, v20

  li t2, 0xb583c1b908d395ab
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v20, v12, v16

  li t2, 0xdb08a421bc559c01
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v12, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v28, v20

  li t2, 0x2828f184b8386635
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v28, v24, v8

  li t2, 0xd834f33b5b7a2de9
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v20, v12, v8

  li t2, 0x42823f22fa50aedc
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v8, v16

  li t2, 0x848b9847cce21c38
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v20, v16, v24

  li t2, 0x56131e5dc5f6454c
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v12, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v20, v4, v16

  li t2, 0x003852a6c4510fb6
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v16, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v20, v28, v12

  li t2, 0x4140e2ac408e2def
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v12, v24

  li t2, 0x2ea9a34137cad92d
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v20, v28, v12

  li t2, 0x635eda7fa9341c8d
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v4, v28

  li t2, 0x2bc4d31f971effd9
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v24, v20

  li t2, 0xdaa919f766f442a6
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v28, v12, v4

  li t2, 0xe805df2139e09647
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v28, v24

  li t2, 0x31a9e29b71b9182d
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v24, v8, v20

  li t2, 0x21e3bd88109af7e9
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v24, v8

  li t2, 0xec490db6d580d5a9
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v20, v8

  li t2, 0x8bc5bb5c349fee87
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v28, v20, v4

  li t2, 0x826ba19f8dbe5597
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v4, v28

  li t2, 0x2f6e8adf0e5bbb7f
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v16, v8

  li t2, 0x3f1c3528784c4b1e
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v24, v20

  li t2, 0x9c28736f5f5c2927
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v28, v24

  li t2, 0x38880bfd2634a5e5
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v28, v8, v12

  li t2, 0x0104c36b505318ca
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v4, v28

  li t2, 0x8d6b840ff6bddddc
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v8, v28, v4

  li t2, 0xbd2f671cfa93a874
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v28, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v24, v28, v4

  li t2, 0x5663aafb257e28c3
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v24, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v20, v24

  li t2, 0x8203d035a47fa5cb
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v8, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v16, v8, v28

  li t2, 0xddcf3339ed2396b2
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v16, v8, v20

  li t2, 0xd3a435f01bb1172a
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v12, v16, v24

  li t2, 0xb8afbe38e901b0b2
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v4, v16, v12

  li t2, 0x5eb3500d9fda1b9c
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v20, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v16, v24, v28

  li t2, 0x2ce102cc36d73ef5
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vv v28, v8, v20

  li t2, 0x7c0debcfbb92cd48
  vsetvli t1, t0, e32, m4, ta, ma
  vsub.vx v4, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xdaf4b4bff5b39485
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x1de694450710525e
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x7a31eb5da7d2098d
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xdd45117fcb8f9386
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x8ee95b2b015cbce0
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xcc2fdf1af3565bb0
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x63cdc6f7e5c73945
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x2f2ae2719395d385
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x974a03c6d0b8c527
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xc4f92821a658cc0d
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xfdde412c1cb7bb04
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x58b475ae4ecf797b
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x4247d4413e0c07ba
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x8a6a97cc8b408278
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xab5fa08bb9825b33
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x98b65f39ad0a5132
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x8e3b9c4ea854ad0c
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xe563891313e938a3
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x07ffb130bae9141e
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xce49d92ba80c50ab
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x09b4b2f746ed9c54
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xa5edeaf6a9af8fdc
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xe7347cecf4a44475
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xc634ee6d3b1e886e
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xfe7903244bb1f451
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x303c21bacce43a0d
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x19132252b205e30d
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xd9acb32739eaadb4
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x8d42e2ddb02e5e1f
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x29159dbc44a4ddad
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x25a5bffad40c4e8c
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xd3632161ccedcb6b
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x5f6f23681d054a2a
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xe89250defc27bc81
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x0309d1a8f89ee382
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x8b16e8b6716b8c61
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x21654bbf722dcc09
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x1368613e39aa3a8e
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xbc0951836c38c174
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x77ff9b745430db3b
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x080394347a4b3a1b
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xfa29ad8cad5525ab
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xe1ce492bf558e7fa
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xf5afe527b3b3b95b
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xc4ee33b4ae6abb02
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xb6f315330c5f8644
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xc777efad00eeedad
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x53db5f2849867d03
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x0a77554e3719207b
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xdb866b8d18f3a2d6
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x0ac4dd2f7e5be672
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xfe65838c6d57d5af
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xd5f1a273515cb557
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x8548c848daeb9fc2
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x73ea96e39d87f9ca
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x27e4da50492cbea1
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x325590e937a0276c
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xce9afaf1f23bb8de
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x09dc6a5090499e51
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x2bb6160ab4250f76
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x60ab89f5ba892b5f
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x6c1fb8eb45e6179a
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xeacb89990b49a3d7
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x31996886a0b05f6c
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xdead3be5f9ce4d51
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xf13486bd1c8fad34
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x88d3230ca4872269
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x9f28e22ed8b2802b
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xe63abdc32321357a
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xef66d18806b1c9fc
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x5887d219c4494861
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x1e14b0aeb7b52932
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x8d6a43d02456e295
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x935261948d67e7f1
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xd783cb5739a48c41
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x345bec2f217fe6bc
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xeb3e43c7b09aec2a
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xa576835914bc9374
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x2314ee20a9bd2aaf
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x80118de9b60c33e1
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x75d36d5738b7624f
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xca960bee1ff3151b
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x3280cd32164f0de7
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x767224d8bf85e852
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x35fd650aead6a55a
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xa2450f809bb0f733
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x5554c48bedc9d80d
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xd03184ef92e35021
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x3eda4625da176a14
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x9349a8b8dbd80e0f
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x4b39f02ed97b528f
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xcc45e07998e642c4
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x7a96072573990de6
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xc928239597642a3a
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x5c368b31e863a6f2
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xedf9561fdcbe5fe0
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x1c7ca46dbfbf23d9
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x44750f2ea43404f1
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x29000b41aaadfc47
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x5c011c9cd5988aaf
  vsetvli t1, t0, e32, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v13, v24, v12

  li t2, 0xca31db4516fea6c3
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v18, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v1, v27, v6

  li t2, 0x1e5e388025408aaf
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v4, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v8, v5, v17

  li t2, 0x6acb0206d7c35311
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v31, v29, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v24, v12, v22

  li t2, 0xc6276ce252975290
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v24, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v1, v9, v17

  li t2, 0x68aef17edea023cc
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v24, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v20, v7, v31

  li t2, 0xa5bf095734072c74
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v25, v21, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v4, v5, v3

  li t2, 0xabf859311d782c44
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v21, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v26, v30, v5

  li t2, 0x7aae4055bf7f74bc
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v10, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v28, v24, v14

  li t2, 0x6149941b82fe4a78
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v5, v14, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v2, v10, v17

  li t2, 0xdb4edd1298edc311
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v20, v13, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v27, v4, v19

  li t2, 0xe06855b5615f9d25
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v26, v25, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v19, v5, v20

  li t2, 0xd3fb25872c1f6002
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v8, v5, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v15, v14, v11

  li t2, 0x909df44401a95968
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v24, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v16, v1, v10

  li t2, 0x2ed4e5d90447df9c
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v20, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v11, v22, v31

  li t2, 0x16af581e04a1c32f
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v12, v13, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v15, v22, v19

  li t2, 0xc9bde598ef4e2b51
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v28, v12, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v18, v2, v13

  li t2, 0x8478856b46b57e65
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v10, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v3, v29, v2

  li t2, 0x311c252855819df3
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v6, v5, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v27, v29, v10

  li t2, 0x4463cb84a7afb7fe
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v23, v12, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v18, v7, v6

  li t2, 0x860e1c3de504aabb
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v5, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v19, v21, v26

  li t2, 0x231f173bc365fe22
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v19, v6, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v28, v26, v9

  li t2, 0x941d652dbbc7e9f7
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v23, v3, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v23, v26, v9

  li t2, 0x5b1ded1065b7b0a5
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v22, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v11, v9, v31

  li t2, 0x2b105f66fc05528e
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v9, v4, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v3, v4, v19

  li t2, 0xc3e26d8d374eaa1b
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v31, v23, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v25, v6, v18

  li t2, 0x7c0b9df8501c1eb0
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v26, v14, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v1, v16, v9

  li t2, 0xf46e4583e874c354
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v30, v2, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v28, v31, v20

  li t2, 0x89af7b129431dbea
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v5, v4, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v25, v12, v30

  li t2, 0xf16d5b82c077fe34
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v26, v28, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v20, v25, v19

  li t2, 0xf8117744a5288e6e
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v4, v9, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v2, v30, v19

  li t2, 0x269d519d398da243
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v20, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v2, v30, v18

  li t2, 0xb976c4f40cc8d2e5
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v26, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v8, v11, v3

  li t2, 0xb48df530ca6c9f8c
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v25, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v25, v29, v30

  li t2, 0x7748c9d32795cf92
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v14, v25, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v23, v8, v15

  li t2, 0x6c2ee35396cc0a92
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v18, v9, v25

  li t2, 0xdcab2a559954d919
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v22, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v26, v30, v13

  li t2, 0xd0417a5c4201016c
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v16, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v9, v3, v12

  li t2, 0xb619d161cc470eec
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v21, v28, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v23, v6, v7

  li t2, 0x31cde64ce8b053ad
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v19, v5, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v18, v26, v10

  li t2, 0xf5b302405d9238e9
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v21, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v9, v12, v13

  li t2, 0x536fec486df6279d
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v3, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v14, v6, v25

  li t2, 0x1846661a238cba3e
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v1, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v29, v23, v25

  li t2, 0x661d61b2a569b96b
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v9, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v5, v29, v19

  li t2, 0x759f547475f82db6
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v30, v7, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v26, v18, v28

  li t2, 0xba2a650614a37eb4
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v17, v26, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v11, v1, v14

  li t2, 0x61b6895ebdfd107e
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v8, v29, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v9, v25, v2

  li t2, 0xfae8cd00064f16a2
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v1, v7, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v14, v2, v10

  li t2, 0x8e038cad1ff3e2df
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v28, v7, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v23, v17, v12

  li t2, 0xf5477c668bdbbaae
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v8, v15, v18

  li t2, 0x82c726dbb98de4eb
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v31, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v6, v8, v15

  li t2, 0x1902c0f3e107b97f
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v15, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v20, v2, v21

  li t2, 0xa5bdce5fae8bd31d
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v20, v1, v31

  li t2, 0x6a4206114a7a4376
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v10, v15, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v30, v21, v8

  li t2, 0x75ec46a913b820b0
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v16, v15, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v29, v25, v24

  li t2, 0x02d54048ca573f32
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v1, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v29, v19, v6

  li t2, 0x73fa2f9adc6bbf5b
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v19, v23, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v21, v8, v26

  li t2, 0x70bd8085196459d0
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v18, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v27, v12, v25

  li t2, 0x5325aaa020e647ec
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v9, v5, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v31, v11, v25

  li t2, 0x883d14cd97f7c7c4
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v24, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v15, v9, v17

  li t2, 0xeab19f9eb8881883
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v27, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v1, v11, v14

  li t2, 0x273281c3c09077d1
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v28, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v16, v14, v26

  li t2, 0x0f60fe7e92d3c072
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v13, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v19, v11, v12

  li t2, 0xf05394ddea2f89f3
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v11, v29, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v4, v12, v16

  li t2, 0x14b5a1a6fe7bc13b
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v31, v13, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v29, v21, v22

  li t2, 0xf4d1733a8dabbc44
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v28, v9, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v17, v30, v19

  li t2, 0x84fb1ed6fda7e444
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v27, v11, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v27, v9, v25

  li t2, 0x79eac236ecf4d733
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v23, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v2, v21, v11

  li t2, 0xf8751fa0cfc1215c
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v7, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v23, v2, v24

  li t2, 0xd22baba66241d610
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v30, v29, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v7, v12, v19

  li t2, 0x7d9d548cb52672dd
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v12, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v2, v31, v8

  li t2, 0xbe3130ab02380bb1
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v3, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v13, v16, v29

  li t2, 0x5064bfd2117e20b9
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v2, v3, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v10, v14, v12

  li t2, 0x7450936458037619
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v1, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v20, v3, v31

  li t2, 0xc205761413377feb
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v19, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v1, v29, v25

  li t2, 0x66e272c182c307d1
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v2, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v29, v12, v18

  li t2, 0xdf79ee0b818a65dc
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v31, v26, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v16, v31, v7

  li t2, 0x86f432b59b0ecd13
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v19, v4, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v4, v27, v18

  li t2, 0xd9efd4b8fc9caaf3
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v1, v3, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v1, v24, v2

  li t2, 0x6e62d090c8245c21
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v20, v7, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v20, v7, v4

  li t2, 0xa0bcc7e8fcde8c5d
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v12, v15, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v21, v15, v12

  li t2, 0x56aff77228e71bff
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v5, v2, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v9, v4, v27

  li t2, 0x6440a7dbe5416e89
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v14, v17, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v15, v8, v24

  li t2, 0xd99c17ba244e2511
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v19, v17, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v12, v23, v1

  li t2, 0x3277d9b5b5415c05
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v25, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v24, v10, v18

  li t2, 0xdd9e8788c9c13969
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v5, v6, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v4, v15, v11

  li t2, 0x732417c2d8617a5f
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v31, v9, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v22, v14, v17

  li t2, 0x00b7589088b29cb8
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v9, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v19, v7, v1

  li t2, 0xf15b1d1faae8e9b1
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v1, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v12, v30, v31

  li t2, 0x13285367cbd0a420
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v3, v10, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v3, v15, v18

  li t2, 0x421d1ffee1bf5ec5
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v16, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v6, v3, v11

  li t2, 0x9e640de30bfb8778
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v3, v4, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v11, v28, v17

  li t2, 0xcfc030217a93fbac
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v22, v29, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v1, v6, v24

  li t2, 0x1423672cd0674029
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v17, v28, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v12, v6, v17

  li t2, 0x7eadf94f34c760e5
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v16, v23, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v12, v27, v8

  li t2, 0x4857bc833185a51d
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v5, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v2, v12, v21

  li t2, 0xbaaa634ed2e9008a
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v14, v17, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v30, v18, v12

  li t2, 0x133788e7a3bdba9a
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v31, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v15, v16, v31

  li t2, 0xe00b1f8cb8d0d3da
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v7, v12, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v14, v23, v28

  li t2, 0xe0541c9e78c43737
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v28, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vv v30, v25, v13

  li t2, 0x45225e773caee093
  vsetvli t1, t0, e64, m1, ta, ma
  vsub.vx v14, v25, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v8, v10, v26

  li t2, 0x331f852284bf7b39
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v8, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v20, v14, v24

  li t2, 0xaac778db8805fea7
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v18, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v2, v20, v4

  li t2, 0x971ec6873990e690
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v18, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v24, v4, v10

  li t2, 0x62f5bf141d2a7bb7
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v28, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v8, v4, v6

  li t2, 0xdf265a9e89533a45
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v12, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v12, v8, v16

  li t2, 0x62819e83eae7176f
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v24, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v20, v2, v12

  li t2, 0xc6ea02c4a60fe5cc
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v30, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v14, v2, v22

  li t2, 0x45df11318502dce3
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v18, v2, v14

  li t2, 0x997b3110cbcefc79
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v14, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v14, v24, v6

  li t2, 0x5967584b6d939829
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v6, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v10, v24, v16

  li t2, 0xc46fa29d0fd7269a
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v12, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v22, v6, v8

  li t2, 0x522aeafe9438f1b9
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v18, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v12, v8, v14

  li t2, 0x2871a8017ad421d4
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v30, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v4, v8, v24

  li t2, 0xebeb973750e1b84a
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v28, v18, v20

  li t2, 0x4c517e742f9978ce
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v28, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v28, v22, v12

  li t2, 0x5f87ae247e1b7e42
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v26, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v24, v20, v28

  li t2, 0xee057ef578766fef
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v30, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v2, v12, v10

  li t2, 0x6069745bd790164c
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v28, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v8, v14, v18

  li t2, 0xc2b6f830a2f2ead2
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v24, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v28, v24, v2

  li t2, 0xe1ca489634431281
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v28, v4, v18

  li t2, 0x36d5ccd3d5793766
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v6, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v12, v2, v16

  li t2, 0x5f9fb4ca05b5edc1
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v18, v30, v22

  li t2, 0xc1799bf9861697aa
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v28, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v18, v30, v26

  li t2, 0x633167e106cf6b0c
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v12, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v26, v28, v16

  li t2, 0xad34b7788c2fcb67
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v22, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v12, v8, v4

  li t2, 0x5b0d5153124f8fcd
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v30, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v10, v2, v6

  li t2, 0x43b6013038beadd2
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v26, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v10, v30, v18

  li t2, 0x8c01f1dc47308b3e
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v30, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v28, v14, v16

  li t2, 0x5f65a14c77b961a7
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v30, v22, v8

  li t2, 0xf574ab5b7c6b8657
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v30, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v16, v6, v14

  li t2, 0x14cede938c40458e
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v2, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v22, v16, v28

  li t2, 0x954eb88ad74bbe58
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v10, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v4, v16, v20

  li t2, 0x130c2e154269b69d
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v2, v30, v14

  li t2, 0x51692c050b310df3
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v2, v18, v20

  li t2, 0x9b0bf471fcec0879
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v2, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v26, v18, v10

  li t2, 0x23ed77a83c9c8622
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v6, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v4, v20, v18

  li t2, 0x623befaaa975f8d5
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v30, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v24, v10, v4

  li t2, 0xa68d7bb30a134604
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v18, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v6, v30, v16

  li t2, 0xfb509235f9dc1536
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v12, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v8, v14, v12

  li t2, 0x5d7e1da07b6b294e
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v20, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v26, v2, v28

  li t2, 0x39393b996d3ca8da
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v16, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v20, v10, v4

  li t2, 0x9d8b4917470e3ed2
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v14, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v10, v18, v8

  li t2, 0x09896b12dc9bf4c4
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v22, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v20, v30, v18

  li t2, 0x2bf84c5c2b6491cd
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v8, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v18, v20, v2

  li t2, 0x891a71506b9fd455
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v24, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v2, v6, v12

  li t2, 0xbe2db2197023418a
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v14, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v2, v30, v28

  li t2, 0x33098fe8c9a582a4
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v20, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v6, v28, v24

  li t2, 0x59da53c1cc2ec9cc
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v8, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v18, v16, v28

  li t2, 0x83e9147f24443f31
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v30, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v18, v22, v26

  li t2, 0xbf274974ef7055bb
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v30, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v16, v4, v20

  li t2, 0xb4925ce669fa508f
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v30, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v6, v4, v12

  li t2, 0x67b6bb74ea098d3a
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v28, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v10, v26, v16

  li t2, 0x189eeed9baf0e9fd
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v2, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v2, v26, v6

  li t2, 0x6d33eddecfa511b9
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v24, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v28, v4, v22

  li t2, 0x07cc081733424679
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v18, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v14, v24, v12

  li t2, 0x1bf58a20ff20c2e8
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v18, v14, v4

  li t2, 0xc159ceb7f7c88469
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v20, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v6, v28, v24

  li t2, 0x87459160409c1e1c
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v28, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v10, v6, v12

  li t2, 0x8dcd1a8f836ccad0
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v20, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v26, v12, v10

  li t2, 0x68a6a7eead6230e4
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v28, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v16, v8, v28

  li t2, 0xdac1ffceb6f27f2c
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v22, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v10, v4, v8

  li t2, 0xa5c6315849d8cf79
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v22, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v18, v4, v26

  li t2, 0xd2bd595cd70889f8
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v14, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v26, v30, v2

  li t2, 0x08422c90a2bc7787
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v8, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v30, v14, v24

  li t2, 0xeea518af4545c88b
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v8, v10, v14

  li t2, 0x2ff700629841406c
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v26, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v28, v8, v12

  li t2, 0x8aac74fa9cb0c27e
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v4, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v24, v30, v16

  li t2, 0x31b49a87cdd00dc2
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v22, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v30, v22, v4

  li t2, 0xb63477beef79da44
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v30, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v30, v10, v20

  li t2, 0xe7ca0535caff7120
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v26, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v18, v30, v28

  li t2, 0xbe9d5aba161f8f88
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v8, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v16, v4, v2

  li t2, 0x1e11abfe10b8ed06
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v10, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v24, v6, v2

  li t2, 0x999d7bad0f00aeab
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v16, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v4, v14, v12

  li t2, 0xf330b3f08384a5b7
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v10, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v10, v22, v2

  li t2, 0xcad8013e83e7de44
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v22, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v16, v22, v8

  li t2, 0xdc2bf2b8b46fa6a9
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v8, v16, v22

  li t2, 0xd0f1ea9f16dc7c42
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v4, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v24, v10, v26

  li t2, 0xbb4c6a0974e264e5
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v14, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v16, v30, v6

  li t2, 0x00c41504b1c775c2
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v8, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v12, v18, v8

  li t2, 0x16296057b417ac15
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v24, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v4, v2, v18

  li t2, 0x6b71ae8ffe05fd8d
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v6, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v4, v24, v16

  li t2, 0xacfd27de5519c3a4
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v24, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v30, v22, v10

  li t2, 0x8d85c0a3326bd1e1
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v12, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v2, v18, v16

  li t2, 0x0e710d30e8f3d49f
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v24, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v18, v22, v2

  li t2, 0x52baae718851c897
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v20, v16, v12

  li t2, 0x7a2b440841fd9ec8
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v14, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v2, v6, v12

  li t2, 0xe73f570271241825
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v30, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v24, v26, v22

  li t2, 0xfeb50662711c4f20
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v10, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v10, v28, v26

  li t2, 0x899e64a357c90653
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v4, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v8, v16, v30

  li t2, 0x0ee60451caf1448d
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v16, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v20, v30, v22

  li t2, 0x7412b232c96fd6b5
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v10, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v2, v14, v22

  li t2, 0x8858b85ce57af2ca
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v26, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v22, v20, v28

  li t2, 0x71c6362685ca7e69
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v22, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v10, v20, v18

  li t2, 0x99fa7c572e99e530
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v26, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v2, v26, v12

  li t2, 0x97e867f5ad7662a5
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v14, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v4, v26, v2

  li t2, 0x396eafe0383ecaf0
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v18, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v16, v28, v14

  li t2, 0x515f87406696a174
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v10, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v26, v30, v12

  li t2, 0xc8fe3862b509ee47
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v24, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v30, v16, v2

  li t2, 0x92ec9e4bfacecc97
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v2, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vv v24, v14, v28

  li t2, 0xdaa03742a5906145
  vsetvli t1, t0, e64, m2, ta, ma
  vsub.vx v24, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v24, v8, v28

  li t2, 0x8bc41e9433f06283
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v20, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v4, v24

  li t2, 0x0cb1b45a808135bf
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v16, v12

  li t2, 0xea5645fe1b2f0631
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v20, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v24, v4, v28

  li t2, 0x70e391bb98af2afd
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v8, v16, v12

  li t2, 0x1eb1e8c09e68601e
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v8, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v8, v4, v16

  li t2, 0xaa98873cac7066fa
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v12, v8, v24

  li t2, 0xf8397a88dc0f33a8
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v28, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v8, v16

  li t2, 0x323a414f8b2dc65b
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v16, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v12, v24, v16

  li t2, 0x5c51b7b49e5848b6
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v28, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v28, v24

  li t2, 0xe148d6d4fa51c40f
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v8, v12, v16

  li t2, 0x828c309ebf64d846
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v24, v4, v28

  li t2, 0x7ac3547e9456d221
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v28, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v8, v4

  li t2, 0x849cf9294fb96c04
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v12, v28, v4

  li t2, 0x15d87a445665c321
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v16, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v24, v16, v28

  li t2, 0xf505b33d97bde4b6
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v16, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v28, v24

  li t2, 0x82d76050ca34bcf9
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v8, v20, v24

  li t2, 0x787855d8b8f4e3c6
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v16, v20

  li t2, 0x1ba198c1ec2e7919
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v16, v20

  li t2, 0x781f9b0f3c4aae5e
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v24, v28, v12

  li t2, 0x965d9f0904469730
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v20, v12

  li t2, 0x50b63a0a3dc52fb3
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v8, v12, v20

  li t2, 0xb9013f32bf3da682
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v16, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v16, v28

  li t2, 0xe58b923fcbde5786
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v12, v16, v28

  li t2, 0x550c4b6a46496536
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v12, v4

  li t2, 0xf122af73ab238d57
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v12, v16, v20

  li t2, 0x405fa99c9d3d9963
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v16, v28, v8

  li t2, 0xd054e646f5398c3c
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v12, v16

  li t2, 0x88436daaaaba9f24
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v8, v12, v24

  li t2, 0xd1fc9f724b12bf01
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v12, v4

  li t2, 0xfc0c0dde7e0e81fc
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v28, v16

  li t2, 0x695e7a85d4ed3a07
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v12, v20

  li t2, 0x95dd3102b26167c1
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v16, v4

  li t2, 0x0b73d9f901def94c
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v24, v16, v12

  li t2, 0xd03d703afa7e1db7
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v28, v4

  li t2, 0x3cb222d7a8540e5a
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v28, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v8, v20

  li t2, 0x0969f2260d1c0809
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v16, v8

  li t2, 0x939414d7d3479bfe
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v24, v4, v16

  li t2, 0xe68695ae834b3ba8
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v24, v4, v28

  li t2, 0x4c78016efa3c40a4
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v24, v16

  li t2, 0xfc109f05a517358f
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v24, v8

  li t2, 0x4679a7fd3eef4ef2
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v28, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v12, v28

  li t2, 0xbf3949c8e8509123
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v16, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v4, v24

  li t2, 0xcf99fe256ca8339d
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v8, v28

  li t2, 0xb4c45c7cb4bc447d
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v20, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v12, v28, v4

  li t2, 0x93d9d7926cf37c4f
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v8, v20

  li t2, 0xa07427c700cecb60
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v8, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v24, v12, v4

  li t2, 0x41c26296e73820a0
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v20, v12

  li t2, 0x9924f2f489ef5fc8
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v8, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v24, v16, v4

  li t2, 0xc98c0882625282bf
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v8, v16

  li t2, 0x1d50bf1c4166eb51
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v24, v20, v28

  li t2, 0xb0cd9fcb25ae97dc
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v8, v24, v28

  li t2, 0x994f28c5e3930613
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v20, v8

  li t2, 0xb9a4a7efa3e82d21
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v24, v28, v12

  li t2, 0x5896ff909f81d8bd
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v8, v4

  li t2, 0x2f127e780da3003f
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v8, v24

  li t2, 0x6cb975ec187ab81c
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v8, v4, v28

  li t2, 0xdd2b2b63dc7da47e
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v4, v24

  li t2, 0x2ae2b8b9eec1d822
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v8, v16, v4

  li t2, 0xcd4c1520810befae
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v20, v24

  li t2, 0xab809509960ef679
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v28, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v12, v28, v20

  li t2, 0xf8eec9235009dec9
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v4, v12

  li t2, 0x6932a31e077987e4
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v20, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v12, v24

  li t2, 0x5957aee05f95c85a
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v4, v12

  li t2, 0xc7e25b62170070c1
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v12, v8, v4

  li t2, 0xff72d024d0f58a3c
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v8, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v24, v8, v4

  li t2, 0x894aaa6c463f9042
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v20, v16

  li t2, 0xb2b62bd2f78719ef
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v16, v24, v4

  li t2, 0xa4c69cf2855a3b02
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v16, v4, v8

  li t2, 0x8da46a23da00f1c6
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v28, v20

  li t2, 0xf790e3dec6283dbf
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v16, v28, v20

  li t2, 0x0739bbbe74d6c136
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v28, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v4, v20

  li t2, 0x9619fe43710c3387
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v28, v12

  li t2, 0x4eb12b8920ae70ad
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v8, v28

  li t2, 0xd51cb3807a8f6983
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v8, v16

  li t2, 0xe82a7f03e152b0db
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v16, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v20, v12

  li t2, 0xecec9dfecab9b3b8
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v20, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v24, v20

  li t2, 0x3d50e2803d289919
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v16, v28, v8

  li t2, 0xe73fe8b355831756
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v20, v24

  li t2, 0x555ab21bc31b1e3b
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v16, v12

  li t2, 0x4db33714b70cb7b5
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v20, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v12, v28

  li t2, 0xf37266ecfbee4b1a
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v12, v28, v8

  li t2, 0x4822ff5475a73cca
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x43c2d331c670ec88
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v20, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v24, v28

  li t2, 0x50ac88406286f6e1
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v20, v28

  li t2, 0x33042ef83c5c7532
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v16, v12

  li t2, 0x66810aa689ea655e
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v20, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v12, v16, v8

  li t2, 0x14702e47285fb961
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v12, v20

  li t2, 0xf9cf3fd4da05cbdf
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v20, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v16, v24

  li t2, 0xf17aad9c5ae419fa
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v8, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v12, v4, v16

  li t2, 0x5e74d6bb999c1d18
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v8, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v24, v8

  li t2, 0xe8027c35933db3cb
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v12, v4

  li t2, 0x26e231d0b981ab2d
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v16, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v24, v20

  li t2, 0xa1485094fcbd592a
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v4, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v20, v16, v24

  li t2, 0x9847669c9b38c63d
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v28, v16, v24

  li t2, 0xedba10d5a6158aa4
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v4, v12, v28

  li t2, 0x9d64c6b43fe1f572
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v20, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v12, v20, v24

  li t2, 0xa43339d8e66083ee
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v8, v20, v16

  li t2, 0xbd1be078ec632a2f
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v28, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v12, v4, v8

  li t2, 0xe34cbf079233a5c1
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vv v16, v8, v20

  li t2, 0x106505009fb0b31d
  vsetvli t1, t0, e64, m4, ta, ma
  vsub.vx v12, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x4e91a5b8e3593105
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xeaa24494c80cbdd1
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x11f4304fcef16213
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x5e395c6821704e78
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x54d7097921a22127
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x0f2c5ad4e5df80e8
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xba5f115dbf47ac49
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x1abcc7f07469a485
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x2f89adaca6378752
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xed28721c092c3037
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x9685be826beab696
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x366216b6eeba4175
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x1aa8a84dd3f43309
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x993c1fe2335fccec
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x0347a79814ef416d
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x085430eece446a76
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x5692a7bf7e70eceb
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x586b74b666cc156d
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x1498aef48a1472e9
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xe70d146193bb2637
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x95e92abed62ab93e
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x7c135b9ff8fc41ac
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x169981eb4c4774b8
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xda50adede4f48205
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x9c0b79e69b3a261f
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x694492b1c294ea7c
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xd662d0d0273c2563
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xcc6d17e9b799f3c3
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xd0f252d4ae05b6ee
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x5c556fc80974fdac
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x7c8721413bb88d95
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x2326219a7f0ba967
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xdd8a7a51719cb91f
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x9955137940ecd15b
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x3fce43c940000f26
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x93baeffe02349ace
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xc932282e4f62655e
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x1bcce4b361748540
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x66221825898a0307
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x8713740a14e01efe
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x12e079cdd9695cc9
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xf7c8869d0345cf1c
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x23fdc7946efd9cc4
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x40c780002e0650dc
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x08ea4bc424dcb7b3
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x347021a031deefa0
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xd7e24b630d5bfd32
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x511277c17e2adf20
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x250ea0ffafe15f7a
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x32ec00518ff54781
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x58df1421165d2a73
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x9e6a2ada732e91f4
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x13592746bed0e0c0
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x7bc38352ab3095f8
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xf6cdc99c22de4533
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x9f752aad4deb1321
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x11d4b7aa5014c48b
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xf784effdfc7e95d4
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xb1f961bfd9d5cad8
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x1c6d172b0c7593a4
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xd671af52fe486256
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x75e5cd4e00b470e6
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x3a4a188fd04c4fc2
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x513d63b2fe706f77
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x69be5694f897cb61
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xd70145388f524487
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x666d932d048fe7de
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xde2b6d126a7ed658
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x7eb6e9618c1835ef
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x0d855f1b2caf2ea0
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x14c13c4ad78da70e
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x48034e42c2c6f83c
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x23455015422be983
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xce1b52f882fdb37c
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x166d518a3cd615d9
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x2f4592b303e63bf7
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xabae22c950e8ed56
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xb6d8eda7ca60c11e
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xe245fbd8c646a27e
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xf2fdf00b5d942246
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0x6d1bba7c4359716c
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0xa15bf0161d812a4a
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xe1ddb2bbfd87e541
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0x5848d14247172a94
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xfa743bebb1fa61f4
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xb37356ea023e1867
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0xf7de5cf58f76364a
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xdb92f78d44f81660
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0xed714e6fd1194f3b
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x28aab1b08081874d
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0xa7296b554df65823
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v16, v8

  li t2, 0x44f30f3f697ac02f
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v24, v8, v16

  li t2, 0x2b3ba7d8143b3ead
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v24, v8

  li t2, 0xdcfe59322db30932
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v16, v8, v24

  li t2, 0xb04118e030b4f0e2
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x969609ddbcdd45c5
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v16, v24

  li t2, 0x9131bcdcef0fd6e6
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x0747a3f8c1557d1f
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x347dafc4e342991a
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vv v8, v24, v16

  li t2, 0x50af92e31757c016
  vsetvli t1, t0, e64, m8, ta, ma
  vsub.vx v8, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
