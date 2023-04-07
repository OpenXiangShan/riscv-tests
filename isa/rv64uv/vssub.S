#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vv v15, v10, v27

  li t2, 0x4fbd26c952360ce8
  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vx v25, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vv v14, v18, v31

  li t2, 0x4fafef42f91d8400
  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vx v10, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vv v3, v21, v17

  li t2, 0x12b095c3e921c4d2
  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vx v28, v14, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vv v24, v22, v17

  li t2, 0x21ef28889edf01fd
  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vx v22, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vv v26, v16, v4

  li t2, 0xbc22295530d1102f
  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vx v15, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vv v30, v2, v28

  li t2, 0xce262ccb16e88528
  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vx v31, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vv v30, v28, v15

  li t2, 0x5bfd288e42e990ad
  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vx v14, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vv v17, v11, v27

  li t2, 0xaa8b0182e4128898
  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vx v14, v1, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vv v11, v20, v28

  li t2, 0xe4abdaecbc25c078
  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vx v6, v3, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vv v31, v28, v24

  li t2, 0x4d7715d1a8e63a86
  vsetvli t1, t0, e8, m1, ta, ma
  vssub.vx v15, v27, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vv v14, v20, v8

  li t2, 0xb2abe046dfbaa303
  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vx v30, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vv v2, v12, v16

  li t2, 0x022b095299ab4b21
  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vx v18, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vv v26, v4, v6

  li t2, 0x6bacc7622954050c
  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vx v16, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vv v24, v28, v30

  li t2, 0x6096aa1a104592af
  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vx v2, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vv v10, v28, v12

  li t2, 0xec86adc887c49641
  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vx v8, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vv v28, v14, v4

  li t2, 0xcebf6097a8bc2e7c
  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vx v14, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vv v26, v16, v30

  li t2, 0x3ca0d5c600567a4e
  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vx v26, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vv v2, v18, v10

  li t2, 0x787c821923485eca
  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vx v20, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vv v18, v8, v6

  li t2, 0x924883de0a9563a3
  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vx v24, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vv v12, v14, v20

  li t2, 0xd9cdee4cef2eb2ed
  vsetvli t1, t0, e8, m2, ta, ma
  vssub.vx v14, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vv v12, v28, v4

  li t2, 0x26399d3bf45da45f
  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vx v24, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vv v12, v8, v16

  li t2, 0xd6e4f5c5f133f378
  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vx v16, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vv v20, v4, v28

  li t2, 0xd0bdcfc4bf3b2648
  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vx v28, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vv v28, v16, v4

  li t2, 0xbd69b3d0a1ebd950
  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vx v28, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vv v20, v28, v12

  li t2, 0xda9cbb37a6702962
  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vx v16, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vv v24, v8, v16

  li t2, 0xb367b4ac1371746a
  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vv v28, v4, v8

  li t2, 0x253c821b417cea0e
  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vx v24, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vv v24, v28, v12

  li t2, 0x9973374cd1a12efe
  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vx v28, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vv v28, v12, v24

  li t2, 0xa0a647d205c333e3
  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vv v20, v8, v24

  li t2, 0x75de6eb661982394
  vsetvli t1, t0, e8, m4, ta, ma
  vssub.vx v12, v20, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vv v24, v16, v8

  li t2, 0x5336b7548f16759b
  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vv v8, v16, v24

  li t2, 0x6c81f228cda163ba
  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vv v24, v16, v8

  li t2, 0x04feb8dbf7a909b6
  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vv v16, v8, v24

  li t2, 0xae845c279ecf24d9
  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vv v16, v24, v8

  li t2, 0xa18f54fbbfd1ad33
  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vv v8, v16, v24

  li t2, 0x825b07000c7d5378
  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vv v16, v24, v8

  li t2, 0x65471db3a4b37342
  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vv v8, v16, v24

  li t2, 0xa7c535212958ac51
  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vv v16, v8, v24

  li t2, 0x5d7f38be363c1bd8
  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vv v24, v16, v8

  li t2, 0x03ec7c000358a201
  vsetvli t1, t0, e8, m8, ta, ma
  vssub.vx v16, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vv v3, v29, v23

  li t2, 0xaf6f903b1f33bacd
  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vx v6, v23, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vv v9, v28, v17

  li t2, 0x5dd8b744b8876205
  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vx v26, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vv v17, v24, v30

  li t2, 0xc5c4dc7e995543cb
  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vx v22, v31, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vv v30, v16, v7

  li t2, 0x381f3a2401f57819
  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vx v6, v26, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vv v29, v15, v18

  li t2, 0x2b532f3d940c262b
  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vx v1, v26, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vv v7, v21, v27

  li t2, 0x335946a70671db88
  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vx v27, v3, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vv v17, v30, v28

  li t2, 0x10bf41e8d7be9f1d
  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vx v2, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vv v20, v5, v12

  li t2, 0xc7282a6b27dd05eb
  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vx v6, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vv v19, v28, v16

  li t2, 0x65223997d7662d78
  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vx v12, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vv v2, v18, v24

  li t2, 0x417acc2e3f700440
  vsetvli t1, t0, e16, m1, ta, ma
  vssub.vx v4, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vv v26, v16, v2

  li t2, 0x2efa09a98ea7dc15
  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vx v10, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vv v2, v12, v16

  li t2, 0x5e4fda90829ae1d2
  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vx v26, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vv v24, v4, v10

  li t2, 0x669fe4cdde33513f
  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vx v2, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vv v6, v30, v2

  li t2, 0xac4531eaf1b40902
  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vx v26, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vv v30, v22, v16

  li t2, 0x81bbc02741ffbb79
  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vx v10, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vv v4, v8, v12

  li t2, 0x175c7b02cf7724bb
  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vx v2, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vv v30, v2, v26

  li t2, 0x1e06880517ba66f3
  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vx v18, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vv v20, v10, v16

  li t2, 0x1c0f1be03e65a3c6
  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vx v8, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vv v26, v10, v20

  li t2, 0x6a52607f170af947
  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vx v2, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vv v2, v24, v6

  li t2, 0xe45c352a6fa266bf
  vsetvli t1, t0, e16, m2, ta, ma
  vssub.vx v26, v22, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vv v8, v12, v16

  li t2, 0xcffc919c25df23e2
  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vx v4, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vv v16, v8, v24

  li t2, 0x5afb22eb690f3fcb
  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vv v12, v24, v4

  li t2, 0x205f15789d23089d
  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vx v4, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vv v8, v4, v12

  li t2, 0xe6bcbf99b9af4752
  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vx v20, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vv v20, v16, v28

  li t2, 0x443e765bf7e80724
  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vv v20, v16, v4

  li t2, 0x1fdc01d9908b7f0d
  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vx v12, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vv v16, v12, v8

  li t2, 0x725eb4838603c825
  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vx v24, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vv v12, v28, v24

  li t2, 0x2834c7bb0bb1c8a7
  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vx v16, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vv v16, v24, v12

  li t2, 0x0e1c3e09490738cd
  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vx v16, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vv v24, v16, v8

  li t2, 0x2b293a8a5255f7df
  vsetvli t1, t0, e16, m4, ta, ma
  vssub.vx v4, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vv v16, v8, v24

  li t2, 0x2d3663cd64e61c41
  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vv v24, v8, v16

  li t2, 0xd90c1f60c00c62b9
  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vv v8, v16, v24

  li t2, 0x78fd27d3b1c41c3d
  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vv v24, v16, v8

  li t2, 0x8df32fbb08b6a879
  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vv v8, v24, v16

  li t2, 0xd1aaaa5eda1564b0
  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vv v8, v16, v24

  li t2, 0x3dea5edf9d946581
  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vv v16, v24, v8

  li t2, 0xeda66d14f5cee86a
  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vv v16, v24, v8

  li t2, 0x82d935de2986cedb
  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vv v16, v24, v8

  li t2, 0xfb156878a6f9d634
  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vv v8, v16, v24

  li t2, 0x416865d288d3aaa9
  vsetvli t1, t0, e16, m8, ta, ma
  vssub.vx v24, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vv v26, v1, v29

  li t2, 0xa45cefdc2460c544
  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vx v7, v14, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vv v19, v3, v12

  li t2, 0x35ba2c5cbec0f106
  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vx v4, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vv v23, v12, v24

  li t2, 0x361a76dc30eee23d
  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vx v30, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vv v19, v11, v26

  li t2, 0xa7df57a1d489f0da
  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vx v4, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vv v23, v29, v6

  li t2, 0xcf0316ce287284f3
  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vx v7, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vv v30, v26, v12

  li t2, 0xdfde6dfbf4927fa5
  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vx v25, v2, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vv v18, v4, v29

  li t2, 0x7c03c2d8f37bc15d
  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vx v29, v26, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vv v6, v30, v14

  li t2, 0x4e6427223b93acc5
  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vx v21, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vv v6, v13, v4

  li t2, 0x0aa70649a4edaac1
  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vx v5, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vv v23, v20, v24

  li t2, 0xa0a92fa181e91955
  vsetvli t1, t0, e32, m1, ta, ma
  vssub.vx v5, v11, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vv v16, v24, v6

  li t2, 0x187354276e21dfbd
  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vx v18, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vv v22, v10, v24

  li t2, 0x3529f0029fb98df3
  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vx v26, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vv v8, v26, v12

  li t2, 0x86269d560ab5d8fa
  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vx v16, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vv v6, v10, v18

  li t2, 0xdac7ade38223138f
  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vx v20, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vv v28, v8, v16

  li t2, 0xef6c7bff7797e4b0
  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vx v16, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vv v24, v14, v16

  li t2, 0x993ed62792c0e18c
  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vx v14, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vv v26, v2, v24

  li t2, 0x9a76073866e4a7fc
  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vx v18, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vv v24, v4, v2

  li t2, 0x8e6e719d64a32ef6
  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vx v14, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vv v4, v14, v30

  li t2, 0x743d37281c62d733
  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vx v24, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vv v24, v30, v6

  li t2, 0x09012e11db5604d9
  vsetvli t1, t0, e32, m2, ta, ma
  vssub.vx v2, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vv v24, v16, v4

  li t2, 0x37819ced2ca131ce
  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vv v20, v24, v8

  li t2, 0x5944c3d3dca9a9ea
  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vv v12, v28, v24

  li t2, 0x146686b6a7eb7660
  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vv v8, v4, v12

  li t2, 0x66e6e24e585b6dc6
  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vx v20, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vv v16, v4, v12

  li t2, 0x60a934c41d7bbe5a
  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vx v16, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vv v20, v28, v24

  li t2, 0x25e49901d0fabdca
  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vv v24, v12, v16

  li t2, 0x4f1c2ae776823d88
  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vv v4, v28, v16

  li t2, 0xa31ea28bf2d7b0d3
  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vx v28, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vv v20, v4, v8

  li t2, 0x1091c59dc8596c8e
  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vx v8, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vv v20, v28, v24

  li t2, 0x34a6645d8cf2cec7
  vsetvli t1, t0, e32, m4, ta, ma
  vssub.vx v12, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vv v24, v8, v16

  li t2, 0x95c498db28b28739
  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vv v24, v16, v8

  li t2, 0x5adaaf9597fa8dd9
  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vv v8, v24, v16

  li t2, 0x1197ea0a91e992de
  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vv v24, v8, v16

  li t2, 0xfe6fed9a611f3e11
  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vv v24, v16, v8

  li t2, 0xf6729dfcb0e917b3
  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vv v8, v24, v16

  li t2, 0x8b8e9b85ab9fe1bb
  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vv v24, v16, v8

  li t2, 0x76a2cc87a9488466
  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vv v16, v8, v24

  li t2, 0x865cdf38ad845891
  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vv v24, v8, v16

  li t2, 0xdd6dca1eb714675d
  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vv v8, v24, v16

  li t2, 0x6254dda1900d3046
  vsetvli t1, t0, e32, m8, ta, ma
  vssub.vx v16, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vv v3, v4, v10

  li t2, 0x51c0cfb96bca04ec
  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vx v16, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vv v24, v14, v17

  li t2, 0x0d8e4100f323f645
  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vx v18, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vv v19, v22, v29

  li t2, 0x4a639f3885581eec
  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vx v15, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vv v10, v15, v23

  li t2, 0x975174bfc53d0626
  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vx v27, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vv v29, v10, v27

  li t2, 0x0174b85be12edaf0
  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vx v15, v26, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vv v30, v14, v28

  li t2, 0xe3c3c2737aaede22
  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vx v25, v6, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vv v21, v12, v31

  li t2, 0x8d9b8b9fd27b902c
  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vx v25, v26, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vv v14, v20, v15

  li t2, 0xf702c57f75cf9714
  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vx v18, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vv v6, v24, v20

  li t2, 0x789f49bf61a59d39
  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vx v13, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vv v9, v25, v22

  li t2, 0x4defc29bbeac86c6
  vsetvli t1, t0, e64, m1, ta, ma
  vssub.vx v19, v27, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vv v4, v10, v24

  li t2, 0x1e9301fd6012c783
  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vx v10, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vv v4, v14, v24

  li t2, 0x50a7dd86e021ff44
  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vx v30, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vv v6, v12, v14

  li t2, 0xeded5f651dfb0b73
  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vx v24, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vv v16, v6, v14

  li t2, 0x1bee7804dcb26d08
  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vx v8, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vv v2, v22, v14

  li t2, 0x6c3dee7eb83f3116
  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vx v16, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vv v20, v28, v22

  li t2, 0x3ee153cdde465719
  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vx v16, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vv v24, v2, v30

  li t2, 0x952424fd1eac002b
  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vx v22, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vv v30, v28, v20

  li t2, 0xbf4b2b2492de26be
  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vx v20, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vv v22, v18, v6

  li t2, 0x5776924fde764449
  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vx v12, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vv v10, v4, v12

  li t2, 0x9ad37681ffd58a8f
  vsetvli t1, t0, e64, m2, ta, ma
  vssub.vx v10, v30, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vv v12, v24, v16

  li t2, 0x0a3751c8af2e3628
  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vx v4, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vv v24, v20, v16

  li t2, 0x5fde48f07048262f
  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vx v24, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vv v24, v12, v16

  li t2, 0x2bfbcd796754665b
  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vx v12, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vv v8, v16, v20

  li t2, 0xca84ed6e9b7d2fae
  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vx v8, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vv v8, v24, v4

  li t2, 0x2bf2bd8bf6aa94b4
  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vx v28, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vv v4, v16, v8

  li t2, 0x639ccecd613943c1
  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vx v16, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vv v28, v16, v12

  li t2, 0x0d0a59bbbd531781
  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vx v20, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vv v4, v8, v28

  li t2, 0x9f1a3d66d699a498
  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vx v16, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vv v8, v20, v28

  li t2, 0x110741a13b0fcbb0
  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vx v24, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vv v12, v20, v28

  li t2, 0x6fd61bcfd7693321
  vsetvli t1, t0, e64, m4, ta, ma
  vssub.vx v4, v20, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vv v8, v24, v16

  li t2, 0x0d977320c364a21d
  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vv v8, v16, v24

  li t2, 0x522a83369a5c2824
  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vv v8, v24, v16

  li t2, 0x75e5c154529aaff9
  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vv v24, v16, v8

  li t2, 0xad94ac8d5c7e08ef
  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vv v16, v24, v8

  li t2, 0x3e85f17252a670af
  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vv v16, v8, v24

  li t2, 0x27953c3d08fe7ba5
  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vv v16, v24, v8

  li t2, 0x147096c861098619
  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vv v16, v8, v24

  li t2, 0xd310331f3276b162
  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vv v16, v8, v24

  li t2, 0xfc52682ee85caa37
  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vv v8, v24, v16

  li t2, 0xf7e688a130ae6d54
  vsetvli t1, t0, e64, m8, ta, ma
  vssub.vx v16, v8, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
