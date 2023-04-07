#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vv v20, v13, v9

  li t2, 0x3d9e7883a38fab46
  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vx v25, v13, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vv v4, v13, v14

  li t2, 0x2fb149b8574fce3b
  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vx v13, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vv v28, v9, v5

  li t2, 0x5f0c738b2c5de8fc
  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vx v10, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vv v26, v11, v16

  li t2, 0x1c10b73fa968c04f
  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vx v4, v26, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vv v21, v25, v27

  li t2, 0xf8d7dc87ebd8330f
  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vx v14, v27, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vv v18, v1, v7

  li t2, 0x9fbf11803f645996
  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vx v19, v24, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vv v31, v22, v26

  li t2, 0x47d998535d61fea1
  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vx v10, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vv v6, v7, v22

  li t2, 0xe034568ccd7909ac
  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vx v20, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vv v3, v26, v22

  li t2, 0x547447b30273f4c5
  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vx v6, v17, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vv v21, v29, v26

  li t2, 0x07588e833d805397
  vsetvli t1, t0, e8, m1, ta, ma
  vaaddu.vx v6, v13, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vv v16, v20, v10

  li t2, 0x46737add3659e712
  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vx v28, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vv v28, v26, v12

  li t2, 0x63fa778913c1c194
  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vx v4, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vv v6, v12, v8

  li t2, 0xe9c1fc5ee98f9b01
  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vx v12, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vv v22, v14, v28

  li t2, 0x84a4a508325575d4
  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vx v8, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vv v16, v18, v12

  li t2, 0x9263d154e237d11c
  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vx v22, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vv v8, v4, v28

  li t2, 0x46ff371eb99b1db2
  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vx v6, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vv v18, v16, v24

  li t2, 0x97715503acc8b343
  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vx v22, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vv v30, v8, v12

  li t2, 0x159b81a118c1c289
  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vx v26, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vv v2, v14, v22

  li t2, 0xe5a5b67c2ee5185b
  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vx v28, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vv v26, v16, v28

  li t2, 0xcdfa69ccf9589118
  vsetvli t1, t0, e8, m2, ta, ma
  vaaddu.vx v12, v30, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vv v16, v12, v8

  li t2, 0xf61ce6fd727eeab5
  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vv v4, v16, v24

  li t2, 0xc7ce73a22ee54db5
  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vx v16, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vv v24, v8, v28

  li t2, 0x773df677d902e1a3
  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vx v8, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vv v16, v20, v8

  li t2, 0x1e2b344c7c9a6608
  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vx v24, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vv v8, v28, v12

  li t2, 0x70a7eef4cea1f3e8
  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vx v16, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vv v12, v24, v20

  li t2, 0xf57eb09ec3e59e28
  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vv v24, v28, v4

  li t2, 0xc755956b8e7cade5
  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vx v28, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vv v24, v20, v28

  li t2, 0x5a4b11c1c1736518
  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vx v16, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vv v8, v4, v28

  li t2, 0x5b061cf9da8dab9d
  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vx v20, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vv v4, v12, v24

  li t2, 0x35553991d9d35cdf
  vsetvli t1, t0, e8, m4, ta, ma
  vaaddu.vx v8, v4, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vv v16, v8, v24

  li t2, 0x412fdd12e4556470
  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vv v8, v24, v16

  li t2, 0xe58b1014e16c27ff
  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vv v8, v24, v16

  li t2, 0x91da2a710db408e2
  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vv v8, v16, v24

  li t2, 0x8f3f1d0dfd5767ef
  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vv v24, v16, v8

  li t2, 0x54c95ce432c06854
  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vv v24, v16, v8

  li t2, 0x35e5dafdea6147e3
  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vv v8, v24, v16

  li t2, 0xaf2a55b11c3c9e88
  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vv v8, v24, v16

  li t2, 0xc89fcfc3d31ca6f6
  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vv v24, v8, v16

  li t2, 0x547ab5121d3e1d27
  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vv v24, v8, v16

  li t2, 0xae166188c4c7944a
  vsetvli t1, t0, e8, m8, ta, ma
  vaaddu.vx v16, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vv v5, v7, v17

  li t2, 0xe064e5bf22b924ed
  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vx v12, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vv v29, v5, v16

  li t2, 0x2fc6b2ebd34d4a03
  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vx v13, v23, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vv v27, v16, v12

  li t2, 0x3f1412452974d8d7
  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vx v7, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vv v4, v15, v9

  li t2, 0xd2547e9de5683dbc
  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vx v24, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vv v27, v9, v8

  li t2, 0x92467d416c0cdba1
  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vx v2, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vv v8, v23, v6

  li t2, 0x18b070fbeec90c77
  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vx v15, v26, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vv v25, v7, v12

  li t2, 0xfe58969727aa6f86
  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vx v7, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vv v17, v4, v25

  li t2, 0xcd51940db96f6826
  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vx v12, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vv v5, v3, v16

  li t2, 0x8b40043e60df011a
  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vx v30, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vv v11, v23, v20

  li t2, 0x4c042e75449a285c
  vsetvli t1, t0, e16, m1, ta, ma
  vaaddu.vx v14, v25, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vv v30, v12, v4

  li t2, 0x68463855584fb6ed
  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vx v4, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vv v14, v30, v10

  li t2, 0xd6211ce08a204f12
  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vx v4, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vv v24, v16, v30

  li t2, 0x9e49e20595602a34
  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vx v8, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vv v10, v12, v18

  li t2, 0x4d89a212bc25913d
  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vx v24, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vv v6, v4, v20

  li t2, 0x6dac6588b55367cc
  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vx v30, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vv v20, v28, v10

  li t2, 0xf934e9214a3dbedc
  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vx v22, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vv v26, v16, v14

  li t2, 0x775bdce7b2e7858e
  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vx v22, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vv v16, v4, v12

  li t2, 0xefafa5ebbcde29e8
  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vx v12, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vv v30, v26, v8

  li t2, 0xd6a5e6b043cf4bb2
  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vx v2, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vv v16, v30, v22

  li t2, 0xa0e1469d077951eb
  vsetvli t1, t0, e16, m2, ta, ma
  vaaddu.vx v24, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vv v4, v20, v28

  li t2, 0x60490160c7a003f3
  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vx v20, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vv v24, v20, v16

  li t2, 0xc06208b95c30a9af
  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vx v12, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vv v20, v8, v16

  li t2, 0x34f5b50f8d1541f6
  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vx v20, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vv v20, v12, v8

  li t2, 0xd15c346908e9c65a
  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vx v24, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vv v20, v4, v28

  li t2, 0x5c07a48e40815d92
  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vx v24, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vv v12, v20, v4

  li t2, 0xeb17fa9824be8364
  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vx v20, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vv v8, v28, v16

  li t2, 0xf2b25842a8444d3e
  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vx v28, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vv v24, v4, v16

  li t2, 0xa93a415a0f1890a8
  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vx v28, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vv v28, v4, v12

  li t2, 0x0ec0d0bd9f068b6c
  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vx v8, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vv v16, v28, v8

  li t2, 0x60f83201672a6f78
  vsetvli t1, t0, e16, m4, ta, ma
  vaaddu.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vv v16, v8, v24

  li t2, 0xb0069c3aacb93ae5
  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vv v16, v8, v24

  li t2, 0x8f146731688e46d1
  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vv v16, v24, v8

  li t2, 0xe6354cf295ebe4ff
  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vv v24, v8, v16

  li t2, 0xe62e3b5e9b50fb0e
  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vv v24, v16, v8

  li t2, 0x2a89f22027d01492
  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vv v8, v16, v24

  li t2, 0xa9a094804c14078b
  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vv v8, v16, v24

  li t2, 0x1f0858dfe647b173
  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vv v8, v24, v16

  li t2, 0x4bbdb2016566a17c
  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vv v16, v8, v24

  li t2, 0x449f142ff2f2bb97
  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vv v8, v16, v24

  li t2, 0xb1eb74940a9c428d
  vsetvli t1, t0, e16, m8, ta, ma
  vaaddu.vx v24, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vv v30, v19, v3

  li t2, 0xbbb94f13ff50b353
  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vx v25, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vv v8, v6, v11

  li t2, 0xb565434f272f230d
  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vx v28, v17, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vv v6, v19, v16

  li t2, 0x6c308065ffc2669e
  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vx v16, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vv v25, v1, v17

  li t2, 0xd47c7a82cd8c6c63
  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vx v2, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vv v24, v9, v27

  li t2, 0x4cb82d2be95394ad
  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vx v30, v17, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vv v9, v19, v22

  li t2, 0xe6edb8ed0dd3ceb8
  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vx v27, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vv v11, v21, v12

  li t2, 0x76232214dbc59922
  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vx v30, v27, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vv v26, v31, v27

  li t2, 0x422514f62ba2dd8e
  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vx v8, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vv v15, v17, v1

  li t2, 0xf120754eac8b2c06
  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vx v30, v27, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vv v24, v25, v13

  li t2, 0x0d9dbb748083d2f6
  vsetvli t1, t0, e32, m1, ta, ma
  vaaddu.vx v17, v9, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vv v4, v28, v18

  li t2, 0x4be27598192c3bc0
  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vx v30, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vv v20, v10, v2

  li t2, 0x3dc387bfc83d5014
  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vx v8, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vv v8, v6, v4

  li t2, 0x6a43da65b9939da8
  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vx v20, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vv v10, v4, v26

  li t2, 0x9247b250e3d51606
  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vx v10, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vv v4, v18, v20

  li t2, 0x747162ab0028e8ee
  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vx v30, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vv v18, v12, v30

  li t2, 0xb1413100729ab04b
  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vx v8, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vv v16, v30, v28

  li t2, 0xa45baeb76064f189
  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vx v20, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vv v4, v8, v20

  li t2, 0x2c0c4b7cd824b2e2
  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vx v28, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vv v22, v20, v28

  li t2, 0x985417d71234318f
  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vx v10, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vv v10, v6, v24

  li t2, 0x68a7835a575ebb71
  vsetvli t1, t0, e32, m2, ta, ma
  vaaddu.vx v26, v6, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vv v24, v28, v12

  li t2, 0xae7ca5c967632374
  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vx v12, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vv v8, v20, v28

  li t2, 0x1715c3c5cfd9e134
  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vx v28, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vv v28, v8, v12

  li t2, 0x8475b46eaea8e6e0
  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vx v28, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vv v16, v12, v24

  li t2, 0x970a5bf1989b353c
  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vx v12, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vv v20, v12, v4

  li t2, 0x0c60c99654d0dd58
  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vv v12, v16, v20

  li t2, 0xff51637d4c23d7b0
  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vv v4, v24, v8

  li t2, 0x114f6bf04a00dccc
  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vx v20, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vv v4, v28, v20

  li t2, 0x15eb2a00865b2f0b
  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vx v12, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vv v24, v12, v16

  li t2, 0xcd0083f34a4a07a4
  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vx v12, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vv v12, v4, v8

  li t2, 0xb89d2a66d794817f
  vsetvli t1, t0, e32, m4, ta, ma
  vaaddu.vx v28, v4, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vv v16, v24, v8

  li t2, 0x35863ed389e630c5
  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vv v16, v24, v8

  li t2, 0x640fd9fa2b6c1e47
  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vv v8, v24, v16

  li t2, 0x0bbe8d9a127d9fc0
  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vv v16, v8, v24

  li t2, 0x6bda74b3a0ad105d
  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vv v8, v24, v16

  li t2, 0xb0e5cd9e376bb43c
  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vv v24, v8, v16

  li t2, 0x01c2762f98f907df
  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vv v8, v16, v24

  li t2, 0x771f15919ac9f686
  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vv v24, v8, v16

  li t2, 0xbf151825819ac3a9
  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vv v24, v8, v16

  li t2, 0xfcd36f10ddc5d94d
  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vv v8, v24, v16

  li t2, 0x7f768c3c7e45c297
  vsetvli t1, t0, e32, m8, ta, ma
  vaaddu.vx v24, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vv v29, v15, v31

  li t2, 0xe15d93bf00122bdf
  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vx v19, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vv v2, v12, v17

  li t2, 0xeb3baa725fb32463
  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vx v26, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vv v12, v10, v30

  li t2, 0xbfc3b7f9083e58b0
  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vx v3, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vv v1, v11, v14

  li t2, 0x50a21b4761d895d2
  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vx v7, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vv v26, v10, v22

  li t2, 0x243c7af0256e51e0
  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vx v26, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vv v29, v8, v19

  li t2, 0x002618bf3a77d02e
  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vx v18, v12, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vv v16, v26, v6

  li t2, 0xb4832dcc031b126c
  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vx v5, v22, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vv v27, v21, v29

  li t2, 0xb7932a36eaeec8af
  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vx v8, v23, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vv v22, v27, v10

  li t2, 0x3de5d005da03967e
  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vx v12, v11, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vv v21, v10, v26

  li t2, 0x4d3b7ce67653ff19
  vsetvli t1, t0, e64, m1, ta, ma
  vaaddu.vx v7, v1, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vv v30, v24, v14

  li t2, 0x0e63543fa7ab63c4
  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vx v30, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vv v4, v28, v12

  li t2, 0xea6e726cae5be500
  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vx v18, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vv v4, v26, v14

  li t2, 0x2e6ba35518ee22ea
  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vx v8, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vv v16, v2, v12

  li t2, 0x5901210c99496423
  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vx v18, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vv v16, v2, v22

  li t2, 0x1d14c974b5bf78c5
  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vx v2, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vv v18, v4, v28

  li t2, 0x6d8550738f4b2662
  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vx v26, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vv v24, v6, v28

  li t2, 0x98b571d730205a25
  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vx v6, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vv v20, v24, v2

  li t2, 0x283097772f12fdcd
  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vx v28, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vv v20, v10, v6

  li t2, 0xb03879d081a42760
  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vx v12, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vv v24, v8, v14

  li t2, 0x6b0f8a63bff00542
  vsetvli t1, t0, e64, m2, ta, ma
  vaaddu.vx v22, v30, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vv v12, v24, v20

  li t2, 0xfde78dc77b436d51
  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vx v8, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vv v24, v20, v28

  li t2, 0x9d3205c5575528e4
  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vx v12, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vv v8, v16, v4

  li t2, 0x3d125d499fc37895
  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vv v24, v16, v12

  li t2, 0x5c6b646427651701
  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vx v4, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vv v24, v8, v20

  li t2, 0x883562607041874d
  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vx v20, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vv v24, v12, v8

  li t2, 0xfae14d38fa1c858c
  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vx v28, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vv v4, v28, v20

  li t2, 0xec8e6b16b089c78c
  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vv v4, v8, v16

  li t2, 0xc8156719895c798d
  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vx v16, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vv v28, v20, v12

  li t2, 0xb37a7f22f98ccd99
  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vx v12, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vv v24, v4, v20

  li t2, 0xb42c2d7a0b8e9f23
  vsetvli t1, t0, e64, m4, ta, ma
  vaaddu.vx v12, v4, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vv v24, v8, v16

  li t2, 0xeeee3f8c31385b81
  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vv v16, v8, v24

  li t2, 0xe59e3ca81859f4a4
  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vv v8, v24, v16

  li t2, 0x1758e47a2359478f
  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vv v16, v8, v24

  li t2, 0x4fe2231bcc89ee53
  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vv v16, v24, v8

  li t2, 0x25d346ae46d29915
  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vv v8, v16, v24

  li t2, 0x220d78ca929cf1a5
  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vv v24, v16, v8

  li t2, 0xda0fb4867d72adc7
  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vv v24, v16, v8

  li t2, 0x4b6c8453ffa99082
  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vv v24, v8, v16

  li t2, 0xc7ec8d218b151307
  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vv v8, v16, v24

  li t2, 0x7e0760fb4b6bcc3e
  vsetvli t1, t0, e64, m8, ta, ma
  vaaddu.vx v24, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
