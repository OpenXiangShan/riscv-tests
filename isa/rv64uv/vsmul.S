#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vv v9, v29, v2

  li t2, 0x4eac920361c53aeb
  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vx v2, v3, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vv v20, v13, v14

  li t2, 0x28905e4305594cf7
  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vx v26, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vv v2, v4, v1

  li t2, 0x8bec5e02376280ab
  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vx v5, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vv v18, v19, v3

  li t2, 0x9ea5c7a2f7bb3135
  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vx v14, v15, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vv v15, v8, v5

  li t2, 0xfb2585cbedde395b
  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vx v7, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vv v24, v16, v28

  li t2, 0x04561819a2e3d4e9
  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vx v1, v24, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vv v28, v29, v31

  li t2, 0xa4820ca181dda3d6
  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vx v18, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vv v29, v8, v9

  li t2, 0xf8e2169bb2cae305
  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vx v30, v14, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vv v24, v7, v15

  li t2, 0xd873e8f6921ac2a8
  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vx v2, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vv v3, v27, v29

  li t2, 0xf743fe579f7c906f
  vsetvli t1, t0, e8, m1, ta, ma
  vsmul.vx v24, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vv v24, v26, v8

  li t2, 0x442255c125ef87c0
  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vx v12, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vv v30, v6, v14

  li t2, 0x308a4d3ef9222980
  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vx v28, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vv v8, v4, v12

  li t2, 0xfc4c6ce495a829a0
  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vx v28, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vv v14, v20, v4

  li t2, 0x075635e6dc00ab15
  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vx v20, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vv v16, v30, v10

  li t2, 0x0d2d559aa149f4a1
  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vx v18, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vv v10, v6, v2

  li t2, 0xf4a58fb921073f29
  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vx v12, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vv v14, v10, v24

  li t2, 0xd25981e8e2621904
  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vx v30, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vv v30, v2, v4

  li t2, 0x7748227669863086
  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vx v24, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vv v24, v10, v2

  li t2, 0xa740134a0503c938
  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vx v28, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vv v18, v2, v8

  li t2, 0x498adb084fb1d51b
  vsetvli t1, t0, e8, m2, ta, ma
  vsmul.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vv v16, v28, v8

  li t2, 0xd31135f8f65ac507
  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vx v24, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vv v12, v16, v4

  li t2, 0x5129820e2c5c90b6
  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vx v20, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vv v4, v28, v12

  li t2, 0x6e645ec9fb01beae
  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vx v12, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vv v12, v28, v24

  li t2, 0x4a3be8dbce70112a
  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vx v24, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vv v16, v24, v4

  li t2, 0xf5a749954bece40a
  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vx v24, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vv v28, v24, v12

  li t2, 0x8600e78522b94141
  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vx v8, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vv v16, v4, v28

  li t2, 0xfadcf2adf1958c3f
  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vx v4, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vv v20, v8, v24

  li t2, 0xe12d072c8170d956
  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vx v20, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vv v20, v8, v28

  li t2, 0xef99ab26721b7059
  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vx v16, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vv v20, v28, v16

  li t2, 0xdf323adbe7e9cbfc
  vsetvli t1, t0, e8, m4, ta, ma
  vsmul.vx v28, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vv v8, v16, v24

  li t2, 0xe87fe4ef3c64dced
  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vv v24, v8, v16

  li t2, 0xc1e01093a5dc553b
  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vv v24, v16, v8

  li t2, 0xc06ee94420290747
  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vv v16, v8, v24

  li t2, 0x5710dea0b471fad6
  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vv v24, v16, v8

  li t2, 0x8e10c790bedb8f05
  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vv v16, v24, v8

  li t2, 0x5e1609fdd41abe90
  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vv v8, v16, v24

  li t2, 0xd0ed516660f3c4b4
  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vv v24, v16, v8

  li t2, 0x3356051da2ae3b32
  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vv v8, v16, v24

  li t2, 0x9f64e5e71e6a76fb
  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vv v16, v8, v24

  li t2, 0x7c516e7cc7d5a3b3
  vsetvli t1, t0, e8, m8, ta, ma
  vsmul.vx v16, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vv v2, v18, v30

  li t2, 0xf62a739cc9726e11
  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vx v22, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vv v1, v16, v3

  li t2, 0x72d3b357a714acbe
  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vx v8, v23, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vv v10, v13, v28

  li t2, 0xd7b816d94ffd9647
  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vx v11, v10, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vv v10, v12, v20

  li t2, 0x75406fbeebd81357
  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vx v25, v14, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vv v27, v18, v1

  li t2, 0x796a98b9026cd407
  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vx v8, v27, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vv v15, v26, v3

  li t2, 0x4607fe86df52d861
  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vx v7, v5, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vv v12, v19, v28

  li t2, 0x5bd7d5d5247ae0da
  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vx v3, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vv v26, v5, v25

  li t2, 0x9fcd9642a7d66a37
  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vx v22, v10, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vv v21, v27, v12

  li t2, 0xff8832a034a8f1a8
  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vx v9, v7, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vv v11, v16, v4

  li t2, 0x36108bb8ae11ec8e
  vsetvli t1, t0, e16, m1, ta, ma
  vsmul.vx v4, v21, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vv v18, v14, v22

  li t2, 0x6444c754c48b7ffe
  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vx v14, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vv v12, v30, v8

  li t2, 0xa569845829dd27b3
  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vx v4, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vv v14, v30, v8

  li t2, 0xd1e0996da8864fc7
  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vx v28, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vv v8, v28, v16

  li t2, 0xea1d3c5d88b56fc1
  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vx v14, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vv v12, v10, v24

  li t2, 0x5e300d218e59e59a
  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vx v24, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vv v18, v2, v8

  li t2, 0x20cdd6280e518721
  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vx v20, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vv v12, v22, v16

  li t2, 0x352654ba1e8913c7
  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vx v30, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vv v16, v24, v10

  li t2, 0xc5503b839127582f
  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vx v20, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vv v16, v22, v6

  li t2, 0xa9b16135b1aa31eb
  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vx v28, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vv v22, v30, v14

  li t2, 0x9c669bc04e050fbc
  vsetvli t1, t0, e16, m2, ta, ma
  vsmul.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vv v8, v28, v12

  li t2, 0x57f597896b38a417
  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vx v24, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vv v20, v16, v8

  li t2, 0xc3f93d185d897c63
  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vv v8, v28, v16

  li t2, 0xd851638934ae303e
  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vv v28, v24, v16

  li t2, 0xf2dd93e0a9c308c7
  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vx v28, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vv v24, v4, v12

  li t2, 0x00f67189397cf352
  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vx v4, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vv v24, v20, v4

  li t2, 0xb2b25a7a3769c4c0
  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vx v24, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vv v16, v28, v8

  li t2, 0x6ea40be06c9db786
  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vx v20, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vv v20, v4, v24

  li t2, 0xbf42e14e71c6dc37
  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vx v28, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vv v16, v4, v20

  li t2, 0xff32ce797ec51d62
  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vx v12, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vv v20, v24, v4

  li t2, 0x3fc651e12cf07feb
  vsetvli t1, t0, e16, m4, ta, ma
  vsmul.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vv v24, v16, v8

  li t2, 0xbafce0692561fe53
  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vv v16, v8, v24

  li t2, 0x3d05381765f3a3ca
  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vv v16, v8, v24

  li t2, 0x43177223cd1dc9d7
  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vv v8, v16, v24

  li t2, 0xa3dc78c0a6e5917c
  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vv v24, v8, v16

  li t2, 0x9355e2a6d5c40da0
  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vv v16, v24, v8

  li t2, 0xd419084c8ed498a3
  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vv v8, v16, v24

  li t2, 0x01735ec47068742c
  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vv v8, v16, v24

  li t2, 0x7882fd1909d6ca92
  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vv v8, v16, v24

  li t2, 0xb3eb2424951e902f
  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vv v24, v8, v16

  li t2, 0xec2586e7c313bf23
  vsetvli t1, t0, e16, m8, ta, ma
  vsmul.vx v24, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vv v31, v17, v18

  li t2, 0xa36481f330320cb0
  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vx v27, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vv v21, v5, v28

  li t2, 0x83490e85b075f19f
  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vx v23, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vv v20, v29, v24

  li t2, 0xe46fbea8575ce148
  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vx v3, v11, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vv v18, v24, v16

  li t2, 0xc7c495b03e87960a
  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vx v25, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vv v25, v24, v23

  li t2, 0xc7ac60247a1917a2
  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vx v16, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vv v18, v6, v10

  li t2, 0x917a27c8e97ec158
  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vx v21, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vv v17, v13, v16

  li t2, 0x044fdc65556cc085
  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vx v18, v30, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vv v21, v16, v19

  li t2, 0x47b78a715c37bac1
  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vx v15, v28, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vv v11, v6, v31

  li t2, 0x99d110da9c2e8fa2
  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vx v7, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vv v20, v17, v1

  li t2, 0x5146203f9a9548f0
  vsetvli t1, t0, e32, m1, ta, ma
  vsmul.vx v18, v9, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vv v30, v20, v16

  li t2, 0xf155c2ac0d929a9c
  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vx v16, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vv v30, v18, v12

  li t2, 0xd0ed96b36f8d607a
  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vx v16, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vv v10, v22, v28

  li t2, 0x17543cf16f17cc77
  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vx v20, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vv v28, v16, v12

  li t2, 0x918648642825b1c5
  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vx v26, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vv v8, v2, v24

  li t2, 0x451bdaf3ad9f2f26
  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vx v6, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vv v6, v24, v2

  li t2, 0x75615a2596b1d0f2
  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vx v26, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vv v24, v22, v6

  li t2, 0x98365fe45b8f472d
  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vx v8, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vv v12, v20, v26

  li t2, 0xf255e6b5d88bf28f
  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vx v18, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vv v22, v20, v12

  li t2, 0x3d474305ab15620a
  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vx v22, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vv v28, v26, v2

  li t2, 0xbdd8448de167a0c8
  vsetvli t1, t0, e32, m2, ta, ma
  vsmul.vx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vv v24, v20, v8

  li t2, 0x7e348f5c3a40b355
  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vx v20, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vv v16, v12, v20

  li t2, 0x4493b8931fffca06
  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vx v24, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vv v12, v8, v4

  li t2, 0xaf33d037c0985b04
  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vx v4, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vv v12, v20, v16

  li t2, 0x8143a061c79f0e2c
  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vx v4, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vv v20, v16, v24

  li t2, 0x8d36d052dbc353c5
  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vx v28, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vv v28, v12, v4

  li t2, 0x14131d15ec3bd90f
  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vx v4, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vv v12, v28, v8

  li t2, 0x196c84b21fc86f7d
  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vx v24, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vv v8, v12, v16

  li t2, 0x9839c29de20cf193
  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vx v20, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vv v12, v28, v20

  li t2, 0xca89efddeaec18a0
  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vx v28, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vv v28, v12, v4

  li t2, 0x9d05d1eefa72e43c
  vsetvli t1, t0, e32, m4, ta, ma
  vsmul.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vv v8, v16, v24

  li t2, 0x53683561075eb159
  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vv v16, v8, v24

  li t2, 0x95d535702ddaf49b
  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vv v8, v16, v24

  li t2, 0xf00849a257a4eddb
  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vv v8, v16, v24

  li t2, 0xb913446ec3652787
  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vv v16, v24, v8

  li t2, 0x190aaae8ac33a23c
  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vv v24, v16, v8

  li t2, 0x302d7fa8a7d53fe3
  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vv v24, v16, v8

  li t2, 0x4a329a48be429f3f
  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vv v16, v24, v8

  li t2, 0xb2f3ae14e9376036
  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vv v24, v16, v8

  li t2, 0xff22f555fb72393a
  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vv v16, v8, v24

  li t2, 0x8335edfbc02bacc1
  vsetvli t1, t0, e32, m8, ta, ma
  vsmul.vx v16, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vv v17, v7, v18

  li t2, 0xf85bf73a972ce661
  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vx v17, v3, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vv v26, v9, v2

  li t2, 0x476e4dcb9f0f3532
  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vx v16, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vv v29, v2, v1

  li t2, 0x367c5ead72865a9a
  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vx v5, v6, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vv v7, v14, v23

  li t2, 0x9f50c8a679b7083c
  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vx v6, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vv v26, v27, v13

  li t2, 0xd7512383607138ab
  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vx v26, v17, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vv v18, v16, v31

  li t2, 0x3a27b4e2a8c1c4d4
  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vx v23, v10, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vv v16, v21, v28

  li t2, 0x037438276a2a1034
  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vx v27, v29, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vv v1, v6, v13

  li t2, 0x371c5b6b718cd45e
  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vx v30, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vv v7, v8, v31

  li t2, 0x4d0a883fb3249093
  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vx v22, v9, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vv v9, v19, v12

  li t2, 0xef7dc955b91d4f21
  vsetvli t1, t0, e64, m1, ta, ma
  vsmul.vx v27, v21, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vv v10, v6, v14

  li t2, 0x8497515e73bfe1f2
  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vx v12, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vv v20, v22, v10

  li t2, 0x875432c3c1e85251
  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vx v14, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vv v16, v2, v22

  li t2, 0x8952c1b70b9e77b9
  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vx v28, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vv v22, v20, v12

  li t2, 0x4c557cefc244a58e
  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vx v10, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vv v28, v8, v22

  li t2, 0x41b897c486422668
  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vx v16, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vv v18, v28, v2

  li t2, 0x4519f4f9d76f88ae
  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vx v2, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vv v22, v20, v6

  li t2, 0x6e2db0a206b91375
  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vx v22, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vv v2, v30, v8

  li t2, 0xc09b084fe1217e6f
  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vx v26, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vv v4, v12, v10

  li t2, 0xb2f753e385b3fcfc
  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vx v6, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vv v2, v12, v10

  li t2, 0x70f508af31bdaa33
  vsetvli t1, t0, e64, m2, ta, ma
  vsmul.vx v30, v2, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vv v16, v28, v8

  li t2, 0xfe778799f44f6a84
  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vx v8, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vv v8, v24, v20

  li t2, 0xfd8e322291314c85
  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vv v8, v4, v24

  li t2, 0x0fd9d9828d3fd296
  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vv v8, v20, v16

  li t2, 0xc5515b9a9178acc1
  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vx v20, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vv v28, v8, v20

  li t2, 0xd01d28b8c2786c84
  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vx v12, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vv v16, v20, v28

  li t2, 0x7af3d00f1c4f0b42
  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vx v24, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vv v12, v4, v8

  li t2, 0xed2784591b993683
  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vx v16, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vv v28, v12, v8

  li t2, 0x27ea87334e819638
  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vv v20, v16, v28

  li t2, 0xe8dc6b829dce842a
  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vx v16, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vv v24, v20, v12

  li t2, 0x7478455eca575e33
  vsetvli t1, t0, e64, m4, ta, ma
  vsmul.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vv v24, v8, v16

  li t2, 0xf541909fa90f26ea
  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vv v24, v16, v8

  li t2, 0xb1a3e61f7e826568
  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vv v24, v16, v8

  li t2, 0x85b41eab5c99f43c
  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vv v8, v16, v24

  li t2, 0xd67ac782cbab67ee
  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vv v24, v16, v8

  li t2, 0x9e9e85d6451a034d
  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vv v24, v8, v16

  li t2, 0xa16352753b5a4130
  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vv v8, v24, v16

  li t2, 0xab24228d34424fc2
  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vv v16, v8, v24

  li t2, 0x4aed8f1d33b641d3
  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vv v24, v16, v8

  li t2, 0xc598b9003d2e0f57
  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vv v16, v24, v8

  li t2, 0x22c1d449868da4e0
  vsetvli t1, t0, e64, m8, ta, ma
  vsmul.vx v8, v24, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
