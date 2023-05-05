#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  li t2, 0x3f643f5f3deeb6dc
  fmv.s.x ft2, t2
  vsetvli t1, t0, e32, m1, ta, ma
  vfmv.s.f v15, ft2

  li t2, 0x3f4b0b5e3ee4429c
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3e482d8f3f4286d8
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3f28afd53f589dce
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f0785643e512931
  fmv.s.x ft2, t2
  vfmv.s.f v25, ft2

  li t2, 0x3e56170d3ea00c96
  fmv.s.x ft2, t2
  vfmv.s.f v15, ft2

  li t2, 0x3d85481c3f5d2c1d
  fmv.s.x ft2, t2
  vfmv.s.f v3, ft2

  li t2, 0x3e990e063eb5c7a1
  fmv.s.x ft2, t2
  vfmv.s.f v31, ft2

  li t2, 0x3ec357c53e848e08
  fmv.s.x ft2, t2
  vfmv.s.f v5, ft2

  li t2, 0x3f5ab1603ded514a
  fmv.s.x ft2, t2
  vfmv.s.f v15, ft2

  li t2, 0x3ea109263e0735d8
  fmv.s.x ft2, t2
  vfmv.s.f v21, ft2

  li t2, 0x3f42cb8f3f767e86
  fmv.s.x ft2, t2
  vfmv.s.f v11, ft2

  li t2, 0x3ec24a283e7681c7
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3d5e8bd23f4bb4e9
  fmv.s.x ft2, t2
  vfmv.s.f v23, ft2

  li t2, 0x3f17a74b3e2c61cf
  fmv.s.x ft2, t2
  vfmv.s.f v25, ft2

  li t2, 0x3e721cf03f039df7
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3f29bf8a3e8e98c8
  fmv.s.x ft2, t2
  vfmv.s.f v9, ft2

  li t2, 0x3dff5a553ea3723e
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f1196593dc14f6e
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f3da8e43e5a5a26
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3e5db06e3f2e13f2
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3f3e968e3f179743
  fmv.s.x ft2, t2
  vfmv.s.f v7, ft2

  li t2, 0x3ec62a2e3df0891e
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3f51740c3f4cfc1c
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f6b38553f4ea11d
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f4d3b653f06b12d
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3ef1b7b53ea566d9
  fmv.s.x ft2, t2
  vfmv.s.f v3, ft2

  li t2, 0x3f4a446f3d09dd97
  fmv.s.x ft2, t2
  vfmv.s.f v30, ft2

  li t2, 0x3f3bb1403e873f49
  fmv.s.x ft2, t2
  vfmv.s.f v3, ft2

  li t2, 0x3e8be0573ef795de
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3f77ff353f0057eb
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3dd388183e467c45
  fmv.s.x ft2, t2
  vfmv.s.f v25, ft2

  li t2, 0x3f35e42d3e9a6992
  fmv.s.x ft2, t2
  vfmv.s.f v29, ft2

  li t2, 0x3ec9057c3f2c234b
  fmv.s.x ft2, t2
  vfmv.s.f v17, ft2

  li t2, 0x3f2d9ea13e48f3b0
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3dcd52393e0b3d5d
  fmv.s.x ft2, t2
  vfmv.s.f v21, ft2

  li t2, 0x3f72814f3f491c5b
  fmv.s.x ft2, t2
  vfmv.s.f v13, ft2

  li t2, 0x3da900c13f34fc60
  fmv.s.x ft2, t2
  vfmv.s.f v31, ft2

  li t2, 0x3f33f2983dd4ce14
  fmv.s.x ft2, t2
  vfmv.s.f v31, ft2

  li t2, 0x3f60745e3f4580af
  fmv.s.x ft2, t2
  vfmv.s.f v25, ft2

  li t2, 0x3e72e8593e0acec9
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3e70ba963e9b238a
  fmv.s.x ft2, t2
  vfmv.s.f v17, ft2

  li t2, 0x3d5a93c13e940eb1
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3e3c04bd3e6d9bd7
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3f39506c3efab5a6
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3f2c837c3e93c689
  fmv.s.x ft2, t2
  vfmv.s.f v9, ft2

  li t2, 0x3ed2bb323e832f6b
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3e60953a3e97ace4
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3cefb0403f60463e
  fmv.s.x ft2, t2
  vfmv.s.f v31, ft2

  li t2, 0x3f7b420d3f6f40c3
  fmv.s.x ft2, t2
  vfmv.s.f v13, ft2

  li t2, 0x3c1e3cba39e26c40
  fmv.s.x ft2, t2
  vfmv.s.f v21, ft2

  li t2, 0x3e15e5663f6e81be
  fmv.s.x ft2, t2
  vfmv.s.f v23, ft2

  li t2, 0x3f350c303f01c26e
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3e9f75083e538f9a
  fmv.s.x ft2, t2
  vfmv.s.f v9, ft2

  li t2, 0x3e4d1e4b3f00f0d2
  fmv.s.x ft2, t2
  vfmv.s.f v17, ft2

  li t2, 0x3c7d14883e413363
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3f58bcde3f6451db
  fmv.s.x ft2, t2
  vfmv.s.f v30, ft2

  li t2, 0x3f1d55413f00f298
  fmv.s.x ft2, t2
  vfmv.s.f v17, ft2

  li t2, 0x3efd9c763da031bf
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3e96c97b3f6fc2dc
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3edf0eb93f4043fd
  fmv.s.x ft2, t2
  vfmv.s.f v21, ft2

  li t2, 0x3f7b07493f6b6797
  fmv.s.x ft2, t2
  vfmv.s.f v29, ft2

  li t2, 0x3f6863663f752992
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3f119d173e360164
  fmv.s.x ft2, t2
  vfmv.s.f v3, ft2

  li t2, 0x3ee429da3ee74bb1
  fmv.s.x ft2, t2
  vfmv.s.f v13, ft2

  li t2, 0x3ee8a5583ce32581
  fmv.s.x ft2, t2
  vfmv.s.f v11, ft2

  li t2, 0x3f55824f3e05942f
  fmv.s.x ft2, t2
  vfmv.s.f v13, ft2

  li t2, 0x3ed749503ecbe26f
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3f18206c3ec52aeb
  fmv.s.x ft2, t2
  vfmv.s.f v1, ft2

  li t2, 0x3f1e057e3f498774
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3e85d6183eecf741
  fmv.s.x ft2, t2
  vfmv.s.f v25, ft2

  li t2, 0x3ec6613a3f7b0ff7
  fmv.s.x ft2, t2
  vfmv.s.f v17, ft2

  li t2, 0x3d0cca603f4141c3
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f2f879d3ed51ac0
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f55e3653ede784c
  fmv.s.x ft2, t2
  vfmv.s.f v3, ft2

  li t2, 0x3f31e1d73e83f19a
  fmv.s.x ft2, t2
  vfmv.s.f v9, ft2

  li t2, 0x3ee745153eb083b9
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3ea2a1d83f43b7ba
  fmv.s.x ft2, t2
  vfmv.s.f v19, ft2

  li t2, 0x3e4a659a3eaa3888
  fmv.s.x ft2, t2
  vfmv.s.f v23, ft2

  li t2, 0x3f4ca8803ef01d11
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3e38932f3eb01142
  fmv.s.x ft2, t2
  vfmv.s.f v3, ft2

  li t2, 0x3f1f03863df4cdfc
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3e0500233f74d5d4
  fmv.s.x ft2, t2
  vfmv.s.f v1, ft2

  li t2, 0x3f3bc8833ecee155
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3e2dead13f594206
  fmv.s.x ft2, t2
  vfmv.s.f v1, ft2

  li t2, 0x3f1632b13f6645e7
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3dfe31ed3f209588
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3f3b71933e41495a
  fmv.s.x ft2, t2
  vfmv.s.f v27, ft2

  li t2, 0x3e819d693f42666b
  fmv.s.x ft2, t2
  vfmv.s.f v15, ft2

  li t2, 0x3f44fecd3f356718
  fmv.s.x ft2, t2
  vfmv.s.f v25, ft2

  li t2, 0x3cf69b283eec704b
  fmv.s.x ft2, t2
  vfmv.s.f v15, ft2

  li t2, 0x3e2bbcb23f3b751d
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3ebdbada3f645368
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3f0cd2303f696aca
  fmv.s.x ft2, t2
  vfmv.s.f v1, ft2

  li t2, 0x3ddab0403f114e8c
  fmv.s.x ft2, t2
  vfmv.s.f v23, ft2

  li t2, 0x3f7462203f7432a2
  fmv.s.x ft2, t2
  vfmv.s.f v9, ft2

  li t2, 0x3eafa0d23eac5416
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3f0d510b3f13529f
  fmv.s.x ft2, t2
  vfmv.s.f v19, ft2

  li t2, 0x3f55af1f3eeb8040
  fmv.s.x ft2, t2
  vfmv.s.f v15, ft2

  li t2, 0x3ea1a1b43f43654f
  fmv.s.x ft2, t2
  vfmv.s.f v17, ft2

  li t2, 0x3e897aee3ef0920d
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3ed3c2ec3c0420f7
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3d142eea3ec71f9b
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f27c05f3ed7962f
  fmv.s.x ft2, t2
  vfmv.s.f v30, ft2

  li t2, 0x3d4721603ee9141a
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3f498fbe3f2ad0a9
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3ed6e2a63c4230bd
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3f4f44833f103567
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3f2288913f2b4380
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f350ff53ee14e2a
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f1d72d93f607efe
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3f3483253e9184fc
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3f7e5a8f3e4645bb
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f7b34bc3ed56940
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f148c3c3f5d8a9b
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3e0eec6b3ec1831c
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f729fc03e571d54
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3ebf993a3e4dc4d5
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f504f263f101e05
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f4010f73e1e2896
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3eb09fc53f338f0c
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3ed7e22e3e96b44f
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3f1e45c33def0660
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3f7586af3ee3f5e7
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3ebad52e3eb3839e
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3f4dd2033f47add0
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3f5f887e3f01179f
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f5a0c023e763813
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3f537e023f4052fc
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3ecc78cc3f3cf686
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3f2c25f73ebf32ee
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3f34983e3ee0ab86
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3f7fe4143ee372b8
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3f5bc8bd3e9df648
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3c8b622c3f07e706
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3f06289d3e5a3a3b
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f75cc543ea8262c
  fmv.s.x ft2, t2
  vfmv.s.f v30, ft2

  li t2, 0x3ee94b203ec7e639
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3e36d81f3f59bf7b
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f6735f63f55d574
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f5b93353e3bda60
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3f4f7f2e3e967b1a
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3f2a584b3e8acede
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3e650d923ed969ff
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3e6428933ebc25ed
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3ee758883e637561
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3f6f07c03f6b7084
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3f7db1643f747cd5
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3f6d4aee3f748262
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3f4bfed93e53b16e
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3e6bb2c23eaa8745
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3e0dfe0d3ee06cf9
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3f30692c3f470284
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3e8b4fbe3ef85319
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3f1c8ba93f6e352a
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3d0ac7173f5620f3
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3e5581873f3d16d0
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3f480eb23c3ed9ce
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3f3a38cd3f0bc0c2
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3f0606973f4e3016
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f0d492e3eefecc0
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3f11dd543edef568
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3f5d57213e1cb078
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3ea219a83d90ef76
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f5a37833e8c25ed
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3f16935e3f3dcab1
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3dd7593b3f0f43b4
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3f3435583f247f5e
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3e8c119e3e5f1f73
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3f3e14283f71f3ba
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3f1cf7bf3e9c11ee
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3f6850df3e5fa98a
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3e143f4e3f462a0a
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3d9727ad3ed80bc5
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3cb7508a3eb54e5a
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3e809b6b3e62b5c6
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3ead44233f33d359
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f6249f83efb123d
  fmv.s.x ft2, t2
  vfmv.s.f v30, ft2

  li t2, 0x3f1c86623f4c5516
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3e5c1f183ef3b0d7
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3d8ba5823e293a84
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3ebea70c3d98ec76
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3f177f053e20891c
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3ecf43a73f643169
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3b0db6083e4171cc
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3f4415ad3da3e9ba
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3f6255f03ef90551
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f6227d93f51dad8
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3d2f8c8f3d4e05d3
  fmv.s.x ft2, t2
  vfmv.s.f v30, ft2

  li t2, 0x3e020fbc3f627d6c
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3f59e6f13ee45d75
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3ed924633f55f46f
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3eb42a4e3d907ff0
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3ed8e8da3d1dab66
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f69ed943f41f185
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f28dd013f16ee41
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f44a9243ddeb9d6
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3f3b33ba3e82f599
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3f52b8443f7e6f11
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3f1542ff3f3eb30d
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3f48583d3f2309b8
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3f2b44ae3e2b7866
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f5fac513ed68794
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3f5616583f03eb5c
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3d1cb7df3eb3bf78
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f5afcdf3f6b783a
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3f1d95f13f102301
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3f450cc33f5d2043
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3eacb0c83ece6442
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3eb37fcf3f02c0dd
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3f69b6bb3f14e294
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3f382f3b3f4b0a5f
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f0bb21e3ee54dcd
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f67c8113dfd2f89
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f06af723f6c90f6
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3e7ea3f43db2b12a
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3d29880f3ddde6e4
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3f36602d3f09c1e4
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f089e7e3f6011cb
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3e7c36ad3f071fa1
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f2f03543f0c2ba5
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f5016a93e195abe
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3dd0530a3f3a5051
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f2092463ec0b436
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3e8981863d3dfa59
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f057d353eee529c
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3ee766b23ea45d77
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3f09b83a3e881906
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3dcf03603f51c05a
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f2ca4713edcfda5
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3ee827ce3e79546d
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3eb251693f658309
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f7d54163f3e50ad
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3ec593503dc8aa97
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f0898803d64c513
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f42e70d3f6438d2
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3e9f63323f76193c
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f12568c3e377cb9
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f1f58293f36fc6d
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3e23fc083ef301e7
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3d816ac53e923422
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f36a7ec3f655c27
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3ee4f30b3dcc9bb5
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f4f6cd73f6e8719
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3ead6f083f141ce0
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f3e5a433f796e74
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f229e243e3c47a4
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f2958a23f1c15c7
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3f1627063e209118
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3ea307a93f348603
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3e0f49ae3ee2cb2d
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3e1158f13f06bd3e
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f65391b3f4cf5a7
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3f0904ea3ddbb7b1
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3f289fe03f69a837
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3ed0ae473eb50ff5
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3efda72d3f73578e
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f00ceb93dbbca4f
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3ea722733edf95fc
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3d9af0323cdfb034
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f76d6313d18dc13
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f4aec913dc9eff9
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f1caeee3f2e86c7
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3ee9cc523f2b77fb
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3e4c95703f1a2b68
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3ea467913d63d0fc
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f0648313e9757ad
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3f0be4423d880fbc
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3f068bdf3f362971
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3efbb9013f7bcf86
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f7b22e03dc67205
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3f24895e3f7e6ee3
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3f79ae903ec05022
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3f4620b13ea0698c
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3f1988703e9a2bdd
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3e02ffb83ed57727
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f64eb193e20bd5b
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3eaa20a23eb18e0a
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3edaf7d43f1a1e3d
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3dfbc0af3f7a1347
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3e8579273efaf115
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f3dee303f7019dc
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3db7952d3f3ed636
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3e62f8003ea645a3
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3eb87eeb3e4c4f17
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3e9f9ff33f572d5d
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3afebaac3f3444e2
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3d469a623e9527a5
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3eee868e3f7bce09
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f60b4903f2cf8ae
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3ec3a5913f3669e6
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3dc170923e888a65
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3ef992ec3f18f66c
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3f129dd13e71ce31
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3d9d86ad3eb53764
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3ebc42573ec8fa5c
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f5a08513f627bfc
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f4ee6c43d84cb4b
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3f4e11773e18cc77
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3f1579563eb6e009
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f26144c3e3bad4c
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f43c2483f1e6e27
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f7d9ef03eb7b039
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3cd21a8b3ef1b51f
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f29e6dd3f443ef6
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3dd8fb973eed4879
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f131dd83ef545c8
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f7fa24d3f79b5d9
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f4a186b3f1599ad
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f62eb6d3f5ba099
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f5592003acc7878
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f01d62c3e716223
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f7068e33f75262f
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f6257a63e45a971
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f228c7f3f050047
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f2765233e1043f9
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f7478793eed5fef
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3ebb04ce3f54a7b8
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3e94e87e3f6457f9
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3da0b0b13ea4fc8c
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3e50ccca3ec14ab4
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f4db5663c59aa82
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f2c40e43f55c9e1
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3e05c7773f560097
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3eb497783f79aff7
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f20d79d3f001da5
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3e1ba0283dd9486a
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f6aae9e3f1dceeb
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3dfe18553ecc2882
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3ebeb2bc3f0f4988
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f74c9ae3e9822d5
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3e5e32473eac6095
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f0d5d093f6f1145
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3da3b1843dd233d8
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f160b153d514ba8
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f70f80a3f4c250e
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f2bd8b83f374533
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f32f83d3d448f79
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f51d6433ed57b8d
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f3ce7043ec1fdc3
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3c44f0b33ef3815b
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3ef5de053f0b33be
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3eabf1993f046a21
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f14831f3ef0fdc1
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3ebc0ada3f040537
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f1846af3f74120b
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3e5b31373f6f4c77
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3b66c8063e9d5715
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3e63fb003f6ab7a0
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f49c6dd3eda36aa
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f7d67b33e93e249
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3e6f4c723ec8457d
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3efe938d3f028a88
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3ea912a43f713b4c
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f7c99583e5b2974
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f29db1a3f7549ef
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3ee9ec853f46a14f
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f7a4fa63e246218
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3dc8f0eb3ef02f5e
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f74e1a53f5c0040
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f583f323ead7938
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f5870143d93d311
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f4b60563f13486c
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3ec34aa23d1c7646
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f1606e23ef13890
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f13d0c73e9a4b3b
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3ed5d41f3e9456a0
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3e7ac4bc3f0e3668
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3efe63143f3d6589
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f6fe2f73f4b47e7
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3e90cb5b3f1a4e05
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f6b33073f72ac3f
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f4ff11d3f1b01c0
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3e766cb73f72e349
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f786c8d3e6db006
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f4890ee3f210385
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3eb619bc3f19f63e
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f1dc0ad3d18ed3b
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3e3639523eb61b55
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f6397aa3f2fad78
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3e58d5f03f5ceadd
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3e8487fe3e80b101
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3e6607ed3f3cbcec
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3df509963f1f5b6a
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3e496b943bb85f51
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f4c6dca3f3d9295
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f65e1b33e3d6a3d
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3e6745b13d2deeb9
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f002f613e64aaf7
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f10845d3f7360dc
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3e55d5b93e466dd4
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f708fe93f7d7823
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f5824f93f677aa0
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f56af623f38b57f
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3eb49c633ecf0f96
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3f2978793f7d1d89
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f5ca5fa3de62cbc
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3e0f4b5b3f7bd198
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f2c4a983e2328b9
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3d80120a3f6a168e
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fde302a32bc6054
  fmv.s.x ft2, t2
  vsetvli t1, t0, e64, m1, ta, ma
  vfmv.s.f v12, ft2

  li t2, 0x3fdbd46f4237a8df
  fmv.s.x ft2, t2
  vfmv.s.f v27, ft2

  li t2, 0x3fec13ef74f827df
  fmv.s.x ft2, t2
  vfmv.s.f v23, ft2

  li t2, 0x3fc930b2ae326165
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fec2ab4f4f8556a
  fmv.s.x ft2, t2
  vfmv.s.f v21, ft2

  li t2, 0x3fe999e44ef333c9
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fefd8cfebffb1a0
  fmv.s.x ft2, t2
  vfmv.s.f v7, ft2

  li t2, 0x3fe199c4f0e3338a
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3fdfd43c03bfa878
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3fe0d6f19861ade3
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fed2684a1fa4d09
  fmv.s.x ft2, t2
  vfmv.s.f v7, ft2

  li t2, 0x3fe43622f4286c46
  fmv.s.x ft2, t2
  vfmv.s.f v1, ft2

  li t2, 0x3fec51a9a578a353
  fmv.s.x ft2, t2
  vfmv.s.f v21, ft2

  li t2, 0x3f85253f702a4a7f
  fmv.s.x ft2, t2
  vfmv.s.f v21, ft2

  li t2, 0x3fabaee480375dc9
  fmv.s.x ft2, t2
  vfmv.s.f v5, ft2

  li t2, 0x3fd6e6972cadcd2e
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3fd294b4fc25296a
  fmv.s.x ft2, t2
  vfmv.s.f v21, ft2

  li t2, 0x3fae17e7b03c2fcf
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fb0bb547c2176a9
  fmv.s.x ft2, t2
  vfmv.s.f v11, ft2

  li t2, 0x3fca58232a34b046
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3fb96d32fe32da66
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fd25619b7a4ac33
  fmv.s.x ft2, t2
  vfmv.s.f v13, ft2

  li t2, 0x3fe09c602ca138c0
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe476a04da8ed41
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fee18bbf2fc3178
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3fe35f0b1ce6be16
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3fc13c9ad2227936
  fmv.s.x ft2, t2
  vfmv.s.f v25, ft2

  li t2, 0x3fdeeb89633dd713
  fmv.s.x ft2, t2
  vfmv.s.f v17, ft2

  li t2, 0x3fe16de0bca2dbc1
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3f9d8080e03b0102
  fmv.s.x ft2, t2
  vfmv.s.f v29, ft2

  li t2, 0x3fb593dbe62b27b8
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3faff60fd43fec20
  fmv.s.x ft2, t2
  vfmv.s.f v25, ft2

  li t2, 0x3fe88976e97112ee
  fmv.s.x ft2, t2
  vfmv.s.f v30, ft2

  li t2, 0x3fe8e4f8cbf1c9f2
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3fc02df0f5205be2
  fmv.s.x ft2, t2
  vfmv.s.f v25, ft2

  li t2, 0x3fea70cf0874e19e
  fmv.s.x ft2, t2
  vfmv.s.f v29, ft2

  li t2, 0x3fc24d60ba249ac1
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe290eea72521dd
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3fb5da082c2bb410
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fb78b00082f1600
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe5208294ea4105
  fmv.s.x ft2, t2
  vfmv.s.f v9, ft2

  li t2, 0x3fce2145033c428a
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fee656f8e3ccadf
  fmv.s.x ft2, t2
  vfmv.s.f v30, ft2

  li t2, 0x3fbd4667be3a8ccf
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fd8b4666bb168cd
  fmv.s.x ft2, t2
  vfmv.s.f v23, ft2

  li t2, 0x3fec2a69573854d3
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fc7869eba2f0d3d
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3fe103f766e207ef
  fmv.s.x ft2, t2
  vfmv.s.f v11, ft2

  li t2, 0x3fba74aa1c34e954
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe9119bae322337
  fmv.s.x ft2, t2
  vfmv.s.f v31, ft2

  li t2, 0x3fec45ebc7788bd8
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3fe6cc828ead9905
  fmv.s.x ft2, t2
  vfmv.s.f v30, ft2

  li t2, 0x3fc2949028252920
  fmv.s.x ft2, t2
  vfmv.s.f v23, ft2

  li t2, 0x3fedb545c57b6a8c
  fmv.s.x ft2, t2
  vfmv.s.f v15, ft2

  li t2, 0x3fda7d206334fa41
  fmv.s.x ft2, t2
  vfmv.s.f v9, ft2

  li t2, 0x3fd898675bb130cf
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3feed3a69b3da74d
  fmv.s.x ft2, t2
  vfmv.s.f v11, ft2

  li t2, 0x3fe786a9acef0d53
  fmv.s.x ft2, t2
  vfmv.s.f v13, ft2

  li t2, 0x3fe4675ab0e8ceb5
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fcc5c365e38b86d
  fmv.s.x ft2, t2
  vfmv.s.f v1, ft2

  li t2, 0x3fdeaa99a8bd5533
  fmv.s.x ft2, t2
  vfmv.s.f v15, ft2

  li t2, 0x3fe630177c2c602f
  fmv.s.x ft2, t2
  vfmv.s.f v17, ft2

  li t2, 0x3fe588bfc6eb1180
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fee4ef11cfc9de2
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fe2480861e49011
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fe0480191e09003
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3fe32c8492665909
  fmv.s.x ft2, t2
  vfmv.s.f v27, ft2

  li t2, 0x3fe53a0575ea740b
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fd7a9f3a22f53e7
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fe2c1a030658340
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fae802d803d005b
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3fca1b8802343710
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fc0c35e902186bd
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fc9668f0032cd1e
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3fd2829ce625053a
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3fe9f2599bb3e4b3
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fdf8a9a503f1535
  fmv.s.x ft2, t2
  vfmv.s.f v11, ft2

  li t2, 0x3fe4cd2d0aa99a5a
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fe7bcde03af79bc
  fmv.s.x ft2, t2
  vfmv.s.f v17, ft2

  li t2, 0x3fc854772c30a8ee
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3fef679b223ecf36
  fmv.s.x ft2, t2
  vfmv.s.f v23, ft2

  li t2, 0x3fe66ee44bacddc9
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3feeae20087d5c40
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3fd18d9925231b32
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3fe408369d68106d
  fmv.s.x ft2, t2
  vfmv.s.f v19, ft2

  li t2, 0x3fe6838d6ced071b
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3fec95a3c5f92b48
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3feaf66d3275ecda
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fe4c72854298e51
  fmv.s.x ft2, t2
  vfmv.s.f v5, ft2

  li t2, 0x3fe6c277c3ed84f0
  fmv.s.x ft2, t2
  vfmv.s.f v30, ft2

  li t2, 0x3fd268fb2ba4d1f6
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3fdde8673d3bd0ce
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3feb4a12c7b69426
  fmv.s.x ft2, t2
  vfmv.s.f v30, ft2

  li t2, 0x3fec1196dd78232e
  fmv.s.x ft2, t2
  vfmv.s.f v7, ft2

  li t2, 0x3fe58e4fc76b1ca0
  fmv.s.x ft2, t2
  vfmv.s.f v15, ft2

  li t2, 0x3fef0a7a78fe14f5
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fa82c68983058d1
  fmv.s.x ft2, t2
  vfmv.s.f v21, ft2

  li t2, 0x3fea853966f50a73
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe1ca250c63944a
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3fd258416ea4b083
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3fecfaa75cb9f54f
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fee2ec6933c5d8d
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe9844e6973089d
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3fe807d458700fa9
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fd49e33d6a93c68
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3fed6139fc7ac274
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3fc93471fb3268e4
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3fe4f2d6dda9e5ae
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fd70cc923ae1992
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fc549ce1f2a939c
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3febab7ef1f756fe
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3fe87c065db0f80d
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fea19340b343268
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fd14c565a2298ad
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3fc2a3baa9254775
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fe986a29ab30d45
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fd7dc1a452fb835
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fd6afc9702d5f93
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe45a7fbfa8b4ff
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3fe4f4ef4869e9df
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fe6e570582dcae1
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fe75660496eacc1
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3f7085d160210ba3
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fd461474428c28f
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3fea79a69cf4f34d
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fdd9b33c1bb3668
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fd848182b309030
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe2e27fbee5c4ff
  fmv.s.x ft2, t2
  vfmv.s.f v30, ft2

  li t2, 0x3fd8021b76b00437
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3fe343598ba686b3
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3fe53a0b826a7417
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3fe375bd9a66eb7b
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3f4119470022328e
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fd34ffa8da69ff5
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3fb8e1b36a31c367
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fb4884b7c291097
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fe9e454fbf3c8aa
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fc0f3bec021e77e
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fc2f3f9ef25e7f4
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fea0a9297f41525
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fd40e29c0a81c54
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3f9dc5ae483b8b5d
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3fe34953f56692a8
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fd310760aa620ec
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fcb50138a36a027
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3fc7a7670a2f4ece
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fe0d58fca61ab20
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fd89f524bb13ea5
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fb5d4cbca2ba998
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3feb4a35d936946c
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fda1dc89bb43b91
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3fe0de4b9721bc97
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3fe4f6f9c1a9edf4
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3fe4ac766b2958ed
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fe5e1917f6bc323
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3fe9ded8b733bdb1
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fd1e610b2a3cc21
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3fc7a64eb72f4c9d
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3feebc6e1efd78dc
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3feeaab222fd5564
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3feda15e39bb42bc
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fa643c2342c8784
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3fddb9c7123b738e
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fdeaccacdbd5996
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe4d7b4f5e9af6a
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fd24dc8c2a49b92
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fe8a86dbd3150db
  fmv.s.x ft2, t2
  vfmv.s.f v10, ft2

  li t2, 0x3fc7eb7e682fd6fd
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fbb5f42f836be86
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3f930a5fe02614c0
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3fd2fe85b0a5fd0b
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fe39a301f673460
  fmv.s.x ft2, t2
  vfmv.s.f v26, ft2

  li t2, 0x3fd9a9be82b3537d
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fe7ae52646f5ca5
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3fe7a8eeed2f51de
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fed2e8b4bfa5d17
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3fe7d6e3b5efadc7
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fdf2779c23e4ef4
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3fd0cbe7f92197d0
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fbaebf1f635d7e4
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3fe5e714812bce29
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3fda07b8a7b40f71
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe8eed0c071dda2
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fb64b56be2c96ad
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fd457fe2b28affc
  fmv.s.x ft2, t2
  vfmv.s.f v14, ft2

  li t2, 0x3fed070fe6fa0e20
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fe8032fe3b00660
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fe1d6f77923adef
  fmv.s.x ft2, t2
  vfmv.s.f v2, ft2

  li t2, 0x3fdef0929c3de125
  fmv.s.x ft2, t2
  vfmv.s.f v22, ft2

  li t2, 0x3fe92695edf24d2c
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fe7c9875f6f930f
  fmv.s.x ft2, t2
  vfmv.s.f v18, ft2

  li t2, 0x3fc9dc365733b86d
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fe954a31732a946
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fd2d1c2a725a385
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe6762a602cec55
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fa288b404251168
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe1342071226841
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3feb83fd843707fb
  fmv.s.x ft2, t2
  vfmv.s.f v30, ft2

  li t2, 0x3fd12391bd224723
  fmv.s.x ft2, t2
  vfmv.s.f v6, ft2

  li t2, 0x3fc61122122c2244
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fc736c32b2e6d86
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe3f8094867f013
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fe6b7b6b06d6f6d
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fed6089377ac112
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe2c6397ea58c73
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fe13d2320227a46
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fc2a3a962254753
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fe968e95232d1d3
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fd61b5edaac36be
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fe3c4f3b32789e7
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fd36e765ba6dced
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3febde30f577bc62
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fe489d6092913ac
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fea625c0674c4b8
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fde9937753d326f
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe34d4c40e69a99
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fdfad91ef3f5b24
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe01aa03ca03540
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fefb3b65cbf676d
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fd2398b17a47316
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe451231a68a246
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fcf317a8b3e62f5
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fd5c658acab8cb1
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe7e8c200efd184
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe971436c72e287
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fa25a56b824b4ad
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fb965570832caae
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fc86b0f7d30d61f
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fdaf15a0035e2b4
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fc96d32f032da66
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fe50809626a1013
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe76d21236eda42
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3feb4bf1503697e3
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fdf45bb54be8b77
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fb39a2b94273457
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3faaef143035de28
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fc5a5381c2b4a70
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fecdbae14f9b75c
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fe95a70edb2b4e2
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fd52553212a4aa6
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fcc2cfa033859f4
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fe735a3dfae6b48
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe33e374c667c6f
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fd0e1c4e121c38a
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3f824484c024890a
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fdaf83fab35f07f
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fe505ef95ea0bdf
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fcd0233873a0467
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3f55eb6b002bd6d6
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fc7155d782e2abb
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe014f5422029eb
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fecbca9e9b97954
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3feea488e93d4912
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3feffbf58f3ff7eb
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fe233d76e2467af
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fba40b0aa348161
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fdf6aa5ab3ed54b
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fefa8df65bf51bf
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe094ba60612975
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3feb58e48f76b1c9
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fe8fc8e8a71f91d
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fd3e9dbe5a7d3b8
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3feb8aaba7371557
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fb0adc266215b85
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fd4c09a9ca98135
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fca875172350ea3
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fb0254fb8204a9f
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fd933c20c326784
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe792af9bef255f
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe850cd8230a19b
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fd5644bcb2ac898
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe98ecaeeb31d96
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fd52261afaa44c3
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fe97b1403f2f628
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fec9ec318793d86
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fd8dcddc731b9bc
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3feb7c1d7276f83b
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fdd4a0e84ba941d
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe99d4a4ef33a95
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3fee15acc37c2b5a
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fd99ee9d6b33dd4
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fe63088be6c6111
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fec3c00a9b87801
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fdced10bbb9da21
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fd3de9fd127bd40
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fd59759e7ab2eb4
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe95d1cbdf2ba39
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe381e51de703ca
  fmv.s.x ft2, t2
  vfmv.s.f v28, ft2

  li t2, 0x3fe72ff184ae5fe3
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fb48fedf2291fdc
  fmv.s.x ft2, t2
  vfmv.s.f v12, ft2

  li t2, 0x3feeeec9233ddd92
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fd4f61fa429ec3f
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fc7b798482f6f31
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fc5f0fce42be1fa
  fmv.s.x ft2, t2
  vfmv.s.f v4, ft2

  li t2, 0x3fcbd09e8337a13d
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fdbe0bc0137c178
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fd85fda0a30bfb4
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fda861421b50c28
  fmv.s.x ft2, t2
  vfmv.s.f v20, ft2

  li t2, 0x3fc45c15d228b82c
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fdd7f0fa0bafe1f
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe7f44e1b2fe89c
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fc3d21d9c27a43b
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe973abd372e758
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe62526096c4a4c
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fdd5ea68bbabd4d
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe5cde56bab9bcb
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fb411f1ba2823e3
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe5bc6382ab78c7
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fc4fb83ca29f708
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fcced1cc639da3a
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fdcf47844b9e8f1
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe7a07857af40f1
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe5ddf9c02bbbf4
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fdbd0b0bc37a161
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe60081ccec0104
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fefcfde227f9fbc
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe58af22c6b15e4
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3feef531c2bdea64
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fea6c178c34d82f
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fef03f74fbe07ef
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fa2228c6c244519
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe9a1297c334253
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fed6c9fa97ad93f
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe4dd319da9ba63
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fde9a4a603d3495
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe7e044c8afc08a
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe56f772a6adeee
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fd45da145a8bb43
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fa118fc582231f9
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fba4fc816349f90
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe874dc0770e9b8
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe003dd5f2007bb
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fdc796a4138f2d5
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fdd957f783b2aff
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe013418a602683
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe17a4834e2f490
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fded913b33db227
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe4f29ecaa9e53e
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe2be7c3e257cf8
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3feb5810c376b022
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3feb569e9936ad3d
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe56e2323aadc46
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fcf37850a3e6f0a
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe553f38aaaa7e7
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fdb59f9f2b6b3f4
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe4387f2e6870fe
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe49cdf4c2939bf
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe321805f664301
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fc583f31c2b07e6
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe8d164efb1a2ca
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe5b4d7ab6b69af
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fbf6216703ec42d
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fba65ab6634cb57
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe55b626a2ab6c5
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fc8782b6830f057
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fdae75ce535ceba
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fb95d402a32ba80
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3f9ce25dc039c4bc
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe175e5e422ebcc
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fd7305fea2e60c0
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fdefc7cc2bdf8fa
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fd0ac8c0aa15918
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fcb8663c3370cc8
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fd052bad7a0a576
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe47003bda8e007
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fd0be7888a17cf1
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe9b74e42b36e9d
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe5ef3c4d6bde79
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fc55cb7ff2ab970
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe14f91fa629f24
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe92b6e437256dd
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fc5040a052a0814
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fca7340b034e681
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fed4c63cd3a98c8
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fefa636e7ff4c6e
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe77a5e0f2ef4bc
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fdce1ad8039c35b
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe0d363d121a6c8
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe9a1d25db343a5
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fcc1f29c8383e54
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fd050ad3b20a15a
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fecc1b1acb98363
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fb81c4100303882
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe035c205a06b84
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fc3771df726ee3c
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fdf95d0c33f2ba2
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fba3af3f63475e8
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fd9c1dcae3383b9
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fd121d4f32243aa
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fbf99f0f23f33e2
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fc055dfdb20abc0
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  li t2, 0x3fe2655bf264cab8
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fd7b4bc492f6979
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fe7e47211afc8e4
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fdc46a850b88d51
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fd70f514e2e1ea3
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fdeb3f7b6bd67ef
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fe85bdfc8b0b7c0
  fmv.s.x ft2, t2
  vfmv.s.f v24, ft2

  li t2, 0x3fc5bffdd72b7ffc
  fmv.s.x ft2, t2
  vfmv.s.f v16, ft2

  li t2, 0x3fcca4bfab39497f
  fmv.s.x ft2, t2
  vfmv.s.f v8, ft2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
