#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmv.v.v v4, v7

  li t2, 0x90984935d7da289d
  vmv.v.x v20, t2

  vmv.v.i v26, 4

  vmv.v.v v9, v21

  li t2, 0x54f97265d02d2a7d
  vmv.v.x v29, t2

  vmv.v.i v7, 11

  vmv.v.v v1, v23

  li t2, 0x7a8c1081afd80569
  vmv.v.x v2, t2

  vmv.v.i v27, 12

  vmv.v.v v11, v17

  li t2, 0xa98d54a61aca8752
  vmv.v.x v3, t2

  vmv.v.i v6, -5

  vmv.v.v v15, v20

  li t2, 0x3c0c4cfcdf1c781d
  vmv.v.x v31, t2

  vmv.v.i v10, -6

  vmv.v.v v19, v21

  li t2, 0x0526166c9c743db2
  vmv.v.x v28, t2

  vmv.v.i v27, 3

  vmv.v.v v23, v7

  li t2, 0x5817998ec57b6e12
  vmv.v.x v10, t2

  vmv.v.i v9, 0

  vmv.v.v v24, v13

  li t2, 0x08d5224688dcac38
  vmv.v.x v13, t2

  vmv.v.i v28, 14

  vmv.v.v v9, v4

  li t2, 0xfaee4635986798e5
  vmv.v.x v21, t2

  vmv.v.i v17, -9

  vmv.v.v v21, v6

  li t2, 0xf337a3b11b8e7b26
  vmv.v.x v1, t2

  vmv.v.i v3, 4

  vsetvli t1, t0, e8, m2, ta, ma
  vmv.v.v v30, v26

  li t2, 0xa801f035492453ee
  vmv.v.x v28, t2

  vmv.v.i v30, -1

  vmv.v.v v4, v6

  li t2, 0x25a8d2a92fdfdb6a
  vmv.v.x v10, t2

  vmv.v.i v10, 3

  vmv.v.v v10, v20

  li t2, 0x2d73fe3517bbfbff
  vmv.v.x v16, t2

  vmv.v.i v14, -2

  vmv.v.v v14, v10

  li t2, 0xaab24467dc4d066d
  vmv.v.x v26, t2

  vmv.v.i v24, -12

  vmv.v.v v26, v12

  li t2, 0x234a408fc67a9634
  vmv.v.x v10, t2

  vmv.v.i v24, 2

  vmv.v.v v4, v26

  li t2, 0x414f124b2f421efe
  vmv.v.x v8, t2

  vmv.v.i v8, -14

  vmv.v.v v24, v6

  li t2, 0x6c1813d4ef84b789
  vmv.v.x v24, t2

  vmv.v.i v2, 4

  vmv.v.v v20, v2

  li t2, 0xcbf94fae0380ab8f
  vmv.v.x v26, t2

  vmv.v.i v12, -11

  vmv.v.v v4, v24

  li t2, 0x364f43261056f8c8
  vmv.v.x v16, t2

  vmv.v.i v2, 8

  vmv.v.v v28, v18

  li t2, 0xfa971ecf4381545c
  vmv.v.x v18, t2

  vmv.v.i v6, -16

  vsetvli t1, t0, e8, m4, ta, ma
  vmv.v.v v12, v8

  li t2, 0x0cae9c1360d135f3
  vmv.v.x v28, t2

  vmv.v.i v20, -7

  vmv.v.v v20, v8

  li t2, 0xee123af9e5c53965
  vmv.v.x v28, t2

  vmv.v.i v24, -14

  vmv.v.v v28, v16

  li t2, 0x8bc6652b4d8dff1b
  vmv.v.x v8, t2

  vmv.v.i v4, -5

  vmv.v.v v16, v28

  li t2, 0xbf070f184faa7d1f
  vmv.v.x v12, t2

  vmv.v.i v16, 9

  vmv.v.v v24, v16

  li t2, 0xc908afff5d0696ed
  vmv.v.x v20, t2

  vmv.v.i v8, 3

  vmv.v.v v4, v16

  li t2, 0x8296811612e69ad3
  vmv.v.x v16, t2

  vmv.v.i v8, -14

  vmv.v.v v12, v28

  li t2, 0xb669967c64309409
  vmv.v.x v28, t2

  vmv.v.i v12, -11

  vmv.v.v v4, v8

  li t2, 0xcf3b47b8d7c9b34a
  vmv.v.x v8, t2

  vmv.v.i v28, 6

  vmv.v.v v20, v8

  li t2, 0xcab8973781eec4a2
  vmv.v.x v4, t2

  vmv.v.i v16, 1

  vmv.v.v v20, v12

  li t2, 0xe7e1d2190ea4e0e5
  vmv.v.x v28, t2

  vmv.v.i v4, 15

  vsetvli t1, t0, e8, m8, ta, ma
  vmv.v.v v16, v8

  li t2, 0x01b365f8087d701c
  vmv.v.x v8, t2

  vmv.v.i v16, -9

  vmv.v.v v16, v24

  li t2, 0x83b4bdc49c0efe2f
  vmv.v.x v16, t2

  vmv.v.i v8, -10

  vmv.v.v v8, v16

  li t2, 0xf2ae3c8a63f534b7
  vmv.v.x v8, t2

  vmv.v.i v8, 2

  vmv.v.v v24, v8

  li t2, 0xeb9690d4e43b6156
  vmv.v.x v16, t2

  vmv.v.i v16, -15

  vmv.v.v v24, v8

  li t2, 0x202663be2e9a009e
  vmv.v.x v16, t2

  vmv.v.i v24, 8

  vmv.v.v v24, v8

  li t2, 0x8c0a3c00370fa0dd
  vmv.v.x v8, t2

  vmv.v.i v24, 15

  vmv.v.v v8, v16

  li t2, 0xcf5e55ea654fbb7b
  vmv.v.x v24, t2

  vmv.v.i v24, -11

  vmv.v.v v8, v24

  li t2, 0x61020f4d9e3e2173
  vmv.v.x v24, t2

  vmv.v.i v8, 4

  vmv.v.v v24, v8

  li t2, 0xc210ee720365a2f8
  vmv.v.x v8, t2

  vmv.v.i v16, 4

  vmv.v.v v8, v16

  li t2, 0x53f870b35ecdbcb1
  vmv.v.x v16, t2

  vmv.v.i v24, -3

  vsetvli t1, t0, e16, m1, ta, ma
  vmv.v.v v13, v19

  li t2, 0x71af74d951b0cc8d
  vmv.v.x v10, t2

  vmv.v.i v26, 3

  vmv.v.v v25, v2

  li t2, 0x841242076c6f008a
  vmv.v.x v1, t2

  vmv.v.i v8, -8

  vmv.v.v v9, v3

  li t2, 0xae68dca2c54d406e
  vmv.v.x v15, t2

  vmv.v.i v21, -6

  vmv.v.v v14, v11

  li t2, 0x3193641e2567c479
  vmv.v.x v5, t2

  vmv.v.i v24, -14

  vmv.v.v v20, v9

  li t2, 0x3aa35573aa75ba32
  vmv.v.x v1, t2

  vmv.v.i v21, 4

  vmv.v.v v15, v12

  li t2, 0xf9a9fb62e4bc8918
  vmv.v.x v27, t2

  vmv.v.i v24, 11

  vmv.v.v v20, v22

  li t2, 0xc6ca73eea27f2b84
  vmv.v.x v14, t2

  vmv.v.i v31, 13

  vmv.v.v v29, v27

  li t2, 0x96a78eaf9213281c
  vmv.v.x v5, t2

  vmv.v.i v3, -16

  vmv.v.v v15, v16

  li t2, 0x1db38945852571c3
  vmv.v.x v3, t2

  vmv.v.i v20, 8

  vmv.v.v v7, v9

  li t2, 0xd0a4a9249d64dcd1
  vmv.v.x v25, t2

  vmv.v.i v14, -1

  vsetvli t1, t0, e16, m2, ta, ma
  vmv.v.v v14, v24

  li t2, 0xf12b367976035d0d
  vmv.v.x v10, t2

  vmv.v.i v20, 5

  vmv.v.v v20, v26

  li t2, 0x026b6aa716c7e854
  vmv.v.x v26, t2

  vmv.v.i v24, -1

  vmv.v.v v2, v24

  li t2, 0x16448e54fc38b5d7
  vmv.v.x v16, t2

  vmv.v.i v14, -6

  vmv.v.v v6, v14

  li t2, 0x7a43efd08ff90d27
  vmv.v.x v12, t2

  vmv.v.i v2, -5

  vmv.v.v v4, v22

  li t2, 0x222017f6a53113d0
  vmv.v.x v26, t2

  vmv.v.i v14, -7

  vmv.v.v v14, v8

  li t2, 0xc3e5577015035cd9
  vmv.v.x v28, t2

  vmv.v.i v4, -7

  vmv.v.v v6, v8

  li t2, 0x641f6493babe7b91
  vmv.v.x v24, t2

  vmv.v.i v8, 0

  vmv.v.v v14, v2

  li t2, 0x3fc20be67476b2e0
  vmv.v.x v14, t2

  vmv.v.i v20, 15

  vmv.v.v v10, v8

  li t2, 0x81c07677f79fb15d
  vmv.v.x v18, t2

  vmv.v.i v16, -16

  vmv.v.v v4, v18

  li t2, 0x73441335e21c13ef
  vmv.v.x v12, t2

  vmv.v.i v16, -6

  vsetvli t1, t0, e16, m4, ta, ma
  vmv.v.v v4, v24

  li t2, 0xab46f549f6206891
  vmv.v.x v8, t2

  vmv.v.i v20, 0

  vmv.v.v v20, v4

  li t2, 0xe7bad41a9fc99914
  vmv.v.x v12, t2

  vmv.v.i v24, 11

  vmv.v.v v16, v8

  li t2, 0xfcd44226395a1a29
  vmv.v.x v24, t2

  vmv.v.i v16, -6

  vmv.v.v v8, v12

  li t2, 0x8b0f3f50c7f948ca
  vmv.v.x v16, t2

  vmv.v.i v24, 12

  vmv.v.v v24, v8

  li t2, 0x263b93b5ed5659a1
  vmv.v.x v20, t2

  vmv.v.i v20, -14

  vmv.v.v v28, v8

  li t2, 0x489c517da6e86281
  vmv.v.x v24, t2

  vmv.v.i v16, -1

  vmv.v.v v24, v28

  li t2, 0xf47708cef1056c2b
  vmv.v.x v4, t2

  vmv.v.i v20, -9

  vmv.v.v v24, v20

  li t2, 0x9010b1c248ec6ffc
  vmv.v.x v16, t2

  vmv.v.i v20, 5

  vmv.v.v v28, v12

  li t2, 0xc39bfb7e5165e69b
  vmv.v.x v8, t2

  vmv.v.i v4, -12

  vmv.v.v v28, v24

  li t2, 0xe7e5ef64d18a526e
  vmv.v.x v20, t2

  vmv.v.i v16, 14

  vsetvli t1, t0, e16, m8, ta, ma
  vmv.v.v v24, v8

  li t2, 0xf46729aa06d3426f
  vmv.v.x v24, t2

  vmv.v.i v24, -10

  vmv.v.v v24, v8

  li t2, 0xd68c99a90c3ac67b
  vmv.v.x v16, t2

  vmv.v.i v16, 12

  vmv.v.v v8, v24

  li t2, 0x9756c75602b13b73
  vmv.v.x v24, t2

  vmv.v.i v16, -3

  vmv.v.v v8, v16

  li t2, 0xd129aed9adc13b58
  vmv.v.x v24, t2

  vmv.v.i v24, 7

  vmv.v.v v24, v16

  li t2, 0xb843c6e5cb2c70ca
  vmv.v.x v16, t2

  vmv.v.i v16, 11

  vmv.v.v v16, v8

  li t2, 0x2b7529bfd29724cf
  vmv.v.x v8, t2

  vmv.v.i v16, -14

  vmv.v.v v8, v24

  li t2, 0x662b02910aaf66c8
  vmv.v.x v24, t2

  vmv.v.i v24, -7

  vmv.v.v v8, v24

  li t2, 0x54cb2f55e8c51ba8
  vmv.v.x v8, t2

  vmv.v.i v8, 15

  vmv.v.v v24, v16

  li t2, 0x81d50361beff642f
  vmv.v.x v8, t2

  vmv.v.i v8, 11

  vmv.v.v v24, v16

  li t2, 0x92c9ffb646f4f964
  vmv.v.x v8, t2

  vmv.v.i v24, 8

  vsetvli t1, t0, e32, m1, ta, ma
  vmv.v.v v14, v30

  li t2, 0xc59c86075440720b
  vmv.v.x v28, t2

  vmv.v.i v17, -9

  vmv.v.v v27, v28

  li t2, 0xe901aae816a32e56
  vmv.v.x v8, t2

  vmv.v.i v16, -16

  vmv.v.v v23, v4

  li t2, 0x1ac76671c09066be
  vmv.v.x v23, t2

  vmv.v.i v1, -10

  vmv.v.v v10, v22

  li t2, 0xc5bb0f05e62762e4
  vmv.v.x v12, t2

  vmv.v.i v7, 10

  vmv.v.v v2, v31

  li t2, 0x3a589a683c2eac59
  vmv.v.x v22, t2

  vmv.v.i v19, 2

  vmv.v.v v1, v6

  li t2, 0x18e7d2910c9cf383
  vmv.v.x v31, t2

  vmv.v.i v18, 8

  vmv.v.v v4, v30

  li t2, 0xef33555df2ec9d14
  vmv.v.x v1, t2

  vmv.v.i v7, -14

  vmv.v.v v27, v23

  li t2, 0x82df5fb5a013a529
  vmv.v.x v24, t2

  vmv.v.i v30, -8

  vmv.v.v v17, v24

  li t2, 0x05fa9a21e28c2a7b
  vmv.v.x v31, t2

  vmv.v.i v6, -12

  vmv.v.v v13, v2

  li t2, 0x8170327b7ef60e2b
  vmv.v.x v27, t2

  vmv.v.i v30, 4

  vsetvli t1, t0, e32, m2, ta, ma
  vmv.v.v v2, v4

  li t2, 0xea703efba4e5424e
  vmv.v.x v6, t2

  vmv.v.i v10, -15

  vmv.v.v v10, v24

  li t2, 0x6d6ed83b7935fee8
  vmv.v.x v12, t2

  vmv.v.i v18, -14

  vmv.v.v v12, v30

  li t2, 0x76b32a141d49d9f9
  vmv.v.x v24, t2

  vmv.v.i v12, -1

  vmv.v.v v14, v22

  li t2, 0x36efc4ab6e578729
  vmv.v.x v6, t2

  vmv.v.i v4, -5

  vmv.v.v v20, v26

  li t2, 0xe47aefe71fe8fccc
  vmv.v.x v14, t2

  vmv.v.i v18, -15

  vmv.v.v v8, v6

  li t2, 0x53a5e7955e31fb10
  vmv.v.x v6, t2

  vmv.v.i v22, -7

  vmv.v.v v26, v6

  li t2, 0xf2c6abc809198b37
  vmv.v.x v16, t2

  vmv.v.i v18, 12

  vmv.v.v v18, v16

  li t2, 0xd60e5669d43d0fa1
  vmv.v.x v28, t2

  vmv.v.i v20, 7

  vmv.v.v v24, v2

  li t2, 0x2636b6d427e4d11a
  vmv.v.x v14, t2

  vmv.v.i v10, -15

  vmv.v.v v24, v20

  li t2, 0xd50f0e62c574d3e3
  vmv.v.x v24, t2

  vmv.v.i v18, 7

  vsetvli t1, t0, e32, m4, ta, ma
  vmv.v.v v4, v8

  li t2, 0xb7c57f4499e72c5e
  vmv.v.x v20, t2

  vmv.v.i v8, -7

  vmv.v.v v24, v16

  li t2, 0x3a6bf6f0421c82e9
  vmv.v.x v28, t2

  vmv.v.i v4, -2

  vmv.v.v v24, v4

  li t2, 0xb395aa82da807571
  vmv.v.x v12, t2

  vmv.v.i v12, 10

  vmv.v.v v12, v4

  li t2, 0xd153b9f45908fdd0
  vmv.v.x v8, t2

  vmv.v.i v16, 10

  vmv.v.v v16, v24

  li t2, 0x81418155919826e5
  vmv.v.x v24, t2

  vmv.v.i v24, 13

  vmv.v.v v12, v8

  li t2, 0xe4ae6852fbf9c71f
  vmv.v.x v8, t2

  vmv.v.i v24, -6

  vmv.v.v v12, v24

  li t2, 0x770f70ef53e1a837
  vmv.v.x v12, t2

  vmv.v.i v16, -11

  vmv.v.v v12, v28

  li t2, 0xc588b09beb6aa53d
  vmv.v.x v8, t2

  vmv.v.i v4, 11

  vmv.v.v v4, v16

  li t2, 0xdca461fe77a993e4
  vmv.v.x v8, t2

  vmv.v.i v4, 10

  vmv.v.v v12, v16

  li t2, 0x125ab0fc2c79674a
  vmv.v.x v12, t2

  vmv.v.i v4, -6

  vsetvli t1, t0, e32, m8, ta, ma
  vmv.v.v v24, v16

  li t2, 0x088baa3a8f2a82cb
  vmv.v.x v16, t2

  vmv.v.i v8, 12

  vmv.v.v v8, v24

  li t2, 0xfc8f4dfaffce5573
  vmv.v.x v8, t2

  vmv.v.i v16, -9

  vmv.v.v v8, v16

  li t2, 0xed0a69d18f4c644c
  vmv.v.x v16, t2

  vmv.v.i v8, -15

  vmv.v.v v16, v8

  li t2, 0x98e8b3386678c457
  vmv.v.x v24, t2

  vmv.v.i v24, 10

  vmv.v.v v24, v16

  li t2, 0x261bd807c2bae95c
  vmv.v.x v24, t2

  vmv.v.i v24, 0

  vmv.v.v v24, v8

  li t2, 0x2989c2ece321e599
  vmv.v.x v24, t2

  vmv.v.i v24, -14

  vmv.v.v v8, v24

  li t2, 0x6a3154ab1fc4d2d7
  vmv.v.x v16, t2

  vmv.v.i v16, -10

  vmv.v.v v24, v8

  li t2, 0x043f1fa3842fc479
  vmv.v.x v8, t2

  vmv.v.i v8, -7

  vmv.v.v v8, v16

  li t2, 0xf32140904bfe0ced
  vmv.v.x v24, t2

  vmv.v.i v24, 4

  vmv.v.v v24, v8

  li t2, 0xd2e7ace58b287619
  vmv.v.x v24, t2

  vmv.v.i v8, -11

  vsetvli t1, t0, e64, m1, ta, ma
  vmv.v.v v28, v22

  li t2, 0x96498c04c7aa2dc9
  vmv.v.x v4, t2

  vmv.v.i v1, 5

  vmv.v.v v28, v21

  li t2, 0xa5c11c9466efc957
  vmv.v.x v6, t2

  vmv.v.i v25, 4

  vmv.v.v v30, v23

  li t2, 0x880b0b4354028769
  vmv.v.x v4, t2

  vmv.v.i v7, 2

  vmv.v.v v29, v21

  li t2, 0xef409c956d3a4446
  vmv.v.x v16, t2

  vmv.v.i v8, 1

  vmv.v.v v13, v11

  li t2, 0x6f85e9d7c80f24e1
  vmv.v.x v18, t2

  vmv.v.i v4, 0

  vmv.v.v v5, v2

  li t2, 0xc246bb4ca9d0480a
  vmv.v.x v4, t2

  vmv.v.i v11, 8

  vmv.v.v v23, v30

  li t2, 0x31a5c3c3b8640a65
  vmv.v.x v6, t2

  vmv.v.i v20, -15

  vmv.v.v v1, v15

  li t2, 0xf85dbe6c536226af
  vmv.v.x v13, t2

  vmv.v.i v22, 12

  vmv.v.v v31, v1

  li t2, 0x3db9e93f67062c51
  vmv.v.x v9, t2

  vmv.v.i v23, -12

  vmv.v.v v3, v16

  li t2, 0xc36060efb260755c
  vmv.v.x v6, t2

  vmv.v.i v16, -1

  vsetvli t1, t0, e64, m2, ta, ma
  vmv.v.v v26, v2

  li t2, 0xaa8c54df14816859
  vmv.v.x v18, t2

  vmv.v.i v26, 13

  vmv.v.v v28, v12

  li t2, 0xfc7b240de3152731
  vmv.v.x v22, t2

  vmv.v.i v12, -14

  vmv.v.v v2, v26

  li t2, 0x4e34a1d0f5704a5a
  vmv.v.x v8, t2

  vmv.v.i v28, -14

  vmv.v.v v18, v6

  li t2, 0x4c6168310a42eb4c
  vmv.v.x v28, t2

  vmv.v.i v14, -13

  vmv.v.v v24, v14

  li t2, 0x88912edea2e21540
  vmv.v.x v14, t2

  vmv.v.i v30, 5

  vmv.v.v v26, v22

  li t2, 0x83d86f870bf5e691
  vmv.v.x v20, t2

  vmv.v.i v4, 14

  vmv.v.v v12, v6

  li t2, 0xc4c662ef6c6dd641
  vmv.v.x v8, t2

  vmv.v.i v30, 14

  vmv.v.v v8, v14

  li t2, 0xa65426fd8cec91fd
  vmv.v.x v8, t2

  vmv.v.i v8, 14

  vmv.v.v v16, v8

  li t2, 0xbde32172d8079889
  vmv.v.x v4, t2

  vmv.v.i v28, -4

  vmv.v.v v8, v10

  li t2, 0x55f7feb12f922ebc
  vmv.v.x v14, t2

  vmv.v.i v2, -12

  vsetvli t1, t0, e64, m4, ta, ma
  vmv.v.v v28, v12

  li t2, 0x8297d2e525451632
  vmv.v.x v12, t2

  vmv.v.i v20, -6

  vmv.v.v v4, v16

  li t2, 0x9e50235a390bf647
  vmv.v.x v24, t2

  vmv.v.i v4, -6

  vmv.v.v v8, v16

  li t2, 0x3d1abebd91a7086b
  vmv.v.x v8, t2

  vmv.v.i v8, 10

  vmv.v.v v12, v8

  li t2, 0xca79b7ed33d3a7e0
  vmv.v.x v4, t2

  vmv.v.i v24, -6

  vmv.v.v v12, v16

  li t2, 0x2dda59096b5e1931
  vmv.v.x v4, t2

  vmv.v.i v4, 9

  vmv.v.v v4, v20

  li t2, 0x3342c3f4c6ed0f68
  vmv.v.x v20, t2

  vmv.v.i v12, -1

  vmv.v.v v24, v4

  li t2, 0x93664a5c7e76c9e7
  vmv.v.x v12, t2

  vmv.v.i v16, 4

  vmv.v.v v24, v12

  li t2, 0x91efcbdc910950ed
  vmv.v.x v20, t2

  vmv.v.i v28, -5

  vmv.v.v v20, v16

  li t2, 0xa67ffe5cfa7efbe4
  vmv.v.x v20, t2

  vmv.v.i v4, 15

  vmv.v.v v16, v24

  li t2, 0x3cdfe561343ea98e
  vmv.v.x v20, t2

  vmv.v.i v24, -8

  vsetvli t1, t0, e64, m8, ta, ma
  vmv.v.v v24, v8

  li t2, 0x9a89682fa67b7625
  vmv.v.x v8, t2

  vmv.v.i v24, 11

  vmv.v.v v16, v8

  li t2, 0x765637cf55f45be9
  vmv.v.x v24, t2

  vmv.v.i v24, 13

  vmv.v.v v24, v8

  li t2, 0x37d8086d58a956f8
  vmv.v.x v8, t2

  vmv.v.i v8, -13

  vmv.v.v v24, v16

  li t2, 0x2a2979b27a965135
  vmv.v.x v16, t2

  vmv.v.i v24, -3

  vmv.v.v v24, v16

  li t2, 0xc1aa084b8e638534
  vmv.v.x v8, t2

  vmv.v.i v8, 1

  vmv.v.v v24, v16

  li t2, 0xd3fb81ec3e842a4c
  vmv.v.x v16, t2

  vmv.v.i v24, -5

  vmv.v.v v24, v16

  li t2, 0xa80156e8549283da
  vmv.v.x v16, t2

  vmv.v.i v24, 6

  vmv.v.v v16, v8

  li t2, 0xa4019184bd1d4801
  vmv.v.x v8, t2

  vmv.v.i v24, 2

  vmv.v.v v8, v24

  li t2, 0xc01cab53e1882155
  vmv.v.x v16, t2

  vmv.v.i v16, 13

  vmv.v.v v16, v24

  li t2, 0x30c890e8b86df293
  vmv.v.x v24, t2

  vmv.v.i v8, 12

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
