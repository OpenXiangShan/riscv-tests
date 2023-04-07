#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wv v20, v8, v6

  li t2, 0xb849e73a99ce649e
  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wx v20, v14, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wi v8, v18, 5

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wv v10, v30, v24

  li t2, 0x0d1f4ea584511c9e
  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wx v6, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wi v28, v24, 4

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wv v6, v30, v22

  li t2, 0x0a626f73be4e4f50
  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wx v12, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wi v18, v30, 27

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wv v18, v10, v16

  li t2, 0x67a7b44816f32fdb
  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wx v2, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wi v12, v10, 10

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wv v12, v8, v4

  li t2, 0xe15cf50b0ea32055
  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wx v4, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wi v18, v10, 16

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wv v2, v6, v18

  li t2, 0x29225c97b6b4394c
  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wx v20, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wi v22, v24, 20

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wv v28, v22, v30

  li t2, 0x057153ab25d7d089
  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wx v12, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wi v2, v12, 5

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wv v24, v20, v30

  li t2, 0x90ec1caf5b9c9571
  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wx v2, v30, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wi v18, v24, 6

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wv v2, v14, v30

  li t2, 0x4bc6dc51338d0832
  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wx v26, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wi v28, v24, 14

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wv v10, v30, v4

  li t2, 0x3e1d780c5c049275
  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wx v26, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclipu.wi v4, v6, 7

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wv v16, v28, v12

  li t2, 0x688666bb87bb6d6b
  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wx v16, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wi v8, v16, 16

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wv v28, v24, v4

  li t2, 0x77d6be8f1384143d
  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wx v28, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wi v16, v28, 24

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wv v28, v16, v8

  li t2, 0x43d8ed11e0e9bf0b
  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wx v4, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wi v8, v28, 3

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wv v4, v16, v24

  li t2, 0xe480f46888a2b597
  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wx v4, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wi v24, v12, 9

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wv v16, v8, v20

  li t2, 0xad25048f09671b02
  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wx v4, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wi v16, v12, 9

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wv v20, v16, v12

  li t2, 0x4a1e719db159bade
  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wx v20, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wi v4, v20, 10

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wv v12, v4, v20

  li t2, 0x69e9f3b2a66da81a
  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wx v24, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wi v16, v12, 26

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wv v20, v12, v24

  li t2, 0x053905c17029e503
  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wx v28, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wi v20, v8, 10

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wv v4, v28, v16

  li t2, 0x6d7868ba993fa2c9
  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wx v28, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wi v12, v4, 26

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wv v8, v20, v4

  li t2, 0xacd4994bb939ae13
  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wx v28, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclipu.wi v12, v24, 3

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wv v16, v8, v24

  li t2, 0xe7ecc7b1f1d41878
  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wi v8, v16, 5

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wv v8, v16, v24

  li t2, 0xe88463dba5c23cb5
  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wi v16, v8, 5

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wv v24, v16, v8

  li t2, 0x9d4e247d92c373a0
  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wi v24, v8, 29

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wv v8, v16, v24

  li t2, 0x79274a2731a73c17
  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wi v8, v16, 5

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wv v8, v24, v16

  li t2, 0xc4ce7cd9ed89e044
  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wi v24, v16, 15

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wv v8, v16, v24

  li t2, 0x24e911393a4aa40d
  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wi v8, v24, 10

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wv v16, v24, v8

  li t2, 0x44a483589ebaef5b
  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wi v24, v8, 21

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wv v16, v24, v8

  li t2, 0xce6591bb5651f95d
  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wi v24, v16, 31

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wv v24, v16, v8

  li t2, 0xc28a19326653fee6
  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wx v24, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wi v8, v16, 5

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wv v8, v16, v24

  li t2, 0xb01973773f44150a
  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclipu.wi v24, v8, 9

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wv v26, v28, v30

  li t2, 0xc0c05abf499d13f9
  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wx v16, v6, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wi v24, v2, 17

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wv v28, v22, v8

  li t2, 0x2f33dfe9605bea79
  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wx v26, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wi v30, v24, 20

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wv v16, v30, v4

  li t2, 0xd7c0847cd85a8742
  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wx v4, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wi v24, v20, 19

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wv v2, v24, v18

  li t2, 0x8c4fcf9127e15a10
  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wx v2, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wi v16, v8, 15

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wv v6, v2, v20

  li t2, 0xaebf162ae33c4635
  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wx v16, v30, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wi v6, v24, 13

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wv v28, v14, v16

  li t2, 0x50164893b546671b
  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wx v30, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wi v20, v12, 23

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wv v14, v26, v2

  li t2, 0xa73a3ebe3728f9a6
  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wx v26, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wi v12, v28, 24

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wv v4, v26, v20

  li t2, 0x6a4d7f7f4d615520
  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wx v8, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wi v16, v8, 10

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wv v26, v24, v14

  li t2, 0x51d89ce8062ea211
  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wx v4, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wi v2, v8, 30

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wv v2, v4, v14

  li t2, 0x28658cc7430974a1
  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wx v12, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclipu.wi v24, v16, 25

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wv v12, v8, v16

  li t2, 0xd5b3eac4a3487378
  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wx v20, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wi v28, v4, 23

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wv v24, v8, v16

  li t2, 0x55d3fba79b71daad
  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wx v28, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wi v28, v12, 9

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wv v24, v20, v12

  li t2, 0x994b87547acc7477
  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wx v8, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wi v12, v16, 0

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wv v28, v16, v4

  li t2, 0x6e91ccdefe329ce6
  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wx v24, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wi v16, v24, 9

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wv v28, v8, v12

  li t2, 0xb5da6722c3724666
  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wx v12, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wi v12, v16, 19

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wv v4, v12, v28

  li t2, 0x08bce16efd9e4eab
  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wi v8, v24, 28

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wv v24, v28, v16

  li t2, 0x521d48ac6d133543
  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wx v4, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wi v12, v4, 12

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wv v12, v8, v24

  li t2, 0x832cdfbdbe563bbb
  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wx v28, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wi v20, v12, 21

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wv v24, v12, v4

  li t2, 0x984c6807697f7263
  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wx v16, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wi v28, v8, 27

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wv v4, v20, v24

  li t2, 0x6e376bcaa03c006f
  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wx v4, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclipu.wi v12, v16, 17

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wv v8, v24, v16

  li t2, 0xfbe17efad372c4b6
  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wx v8, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wi v8, v24, 17

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wv v16, v24, v8

  li t2, 0xe2c989f8f84fc53d
  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wi v16, v24, 14

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wv v24, v8, v16

  li t2, 0x8b363536bcb30e16
  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wi v24, v16, 18

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wv v16, v24, v8

  li t2, 0xe1bdf51570f0ffc1
  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wi v16, v24, 9

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wv v16, v8, v24

  li t2, 0x5d1d2f5c5be7f220
  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wi v24, v8, 20

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wv v24, v8, v16

  li t2, 0x154b80704ef17564
  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wx v8, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wi v24, v8, 11

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wv v16, v8, v24

  li t2, 0x1d43351199f81c04
  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wx v8, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wi v16, v8, 19

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wv v8, v16, v24

  li t2, 0xc636805c7519e066
  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wx v24, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wi v16, v24, 4

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wv v16, v24, v8

  li t2, 0xad160704503765a9
  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wi v8, v16, 27

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wv v8, v16, v24

  li t2, 0xd14050edba3f7f19
  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclipu.wi v16, v24, 22

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wv v24, v22, v2

  li t2, 0x45a0359be17d9e6c
  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wx v10, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wi v12, v14, 18

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wv v4, v10, v6

  li t2, 0xfbd7d24474079bf8
  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wx v20, v2, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wi v28, v6, 24

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wv v8, v4, v26

  li t2, 0x063dd347485e10b4
  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wx v26, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wi v28, v4, 30

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wv v10, v18, v12

  li t2, 0x5efac965f0ee0b55
  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wx v8, v14, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wi v2, v30, 9

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wv v30, v8, v4

  li t2, 0x17a3c3f097768c5b
  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wx v18, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wi v10, v16, 24

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wv v4, v22, v20

  li t2, 0x210344a548d4319e
  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wx v16, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wi v22, v14, 8

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wv v18, v8, v6

  li t2, 0xdf6a576340184779
  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wx v30, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wi v20, v10, 22

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wv v8, v24, v22

  li t2, 0x937e0dfe2ccae6a0
  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wx v20, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wi v30, v6, 9

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wv v22, v6, v4

  li t2, 0x48bd05a288a8d218
  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wx v2, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wi v24, v18, 8

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wv v28, v2, v18

  li t2, 0x83b44ab4b31aea58
  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wx v26, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclipu.wi v14, v26, 29

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wv v12, v20, v28

  li t2, 0xa4f45e94440e0f9d
  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wx v16, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wi v16, v20, 1

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wv v12, v16, v28

  li t2, 0x263b9ae4de0cc071
  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wx v12, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wi v24, v4, 16

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wv v12, v24, v28

  li t2, 0x21b7afa9ead818b9
  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wx v12, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wi v12, v8, 9

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wv v12, v4, v20

  li t2, 0x36cf4794fc01c9e6
  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wx v16, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wi v20, v4, 21

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wv v8, v16, v12

  li t2, 0x8cf1e1356451bd49
  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wx v4, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wi v16, v28, 12

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wv v4, v16, v24

  li t2, 0x0e4fecc8da9ff1f1
  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wx v4, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wi v20, v8, 31

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wv v28, v4, v8

  li t2, 0xb5e303b5c186d38a
  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wx v8, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wi v12, v8, 17

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wv v8, v12, v4

  li t2, 0xcbe13bd64599f34e
  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wx v24, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wi v20, v24, 25

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wv v4, v20, v28

  li t2, 0x748d4e3e0a119c98
  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wx v16, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wi v24, v4, 12

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wv v28, v8, v24

  li t2, 0xc3d3b1c62a4641d0
  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wx v16, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclipu.wi v4, v20, 31

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wv v24, v8, v16

  li t2, 0x6b1a9f96f448a3db
  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wx v16, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wi v16, v24, 14

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wv v8, v16, v24

  li t2, 0xdbde59b5442f9556
  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wx v24, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wi v24, v16, 9

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wv v8, v16, v24

  li t2, 0x873b9971a0e6c855
  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wi v8, v24, 13

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wv v24, v16, v8

  li t2, 0x73c0961e9e4c0b42
  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wi v16, v24, 7

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wv v8, v16, v24

  li t2, 0xc1697d0dc981a06e
  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wx v16, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wi v24, v16, 5

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wv v8, v16, v24

  li t2, 0xe3ad3708dc8c4577
  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wi v8, v16, 9

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wv v8, v24, v16

  li t2, 0x4e8382b1154bec97
  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wx v24, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wi v8, v24, 19

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wv v24, v16, v8

  li t2, 0x0037082618133925
  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wx v16, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wi v24, v16, 20

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wv v16, v8, v24

  li t2, 0xa155b6ecb7294fea
  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wx v8, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wi v8, v24, 25

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wv v8, v24, v16

  li t2, 0x2b248ae4ba07eab9
  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclipu.wi v24, v8, 9

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
