#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v6, v2, v17, v0

  li t2, 0x0151f6caeddba2ed
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v7, v8, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v26, v25, -7, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v28, v27, v29, v0

  li t2, 0xca710351eb3d63af
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v22, v21, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v6, v4, 10, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v8, v14, v11, v0

  li t2, 0x62e72f2430bf5cbe
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v9, v13, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v29, v24, 8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v30, v22, v15, v0

  li t2, 0x531a0098610d577b
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v29, v7, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v1, v10, 5, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v16, v17, v29, v0

  li t2, 0x246dbad0be50dcf3
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v9, v6, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v17, v6, -8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v31, v18, v22, v0

  li t2, 0x7509d5a3ae729cf4
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v22, v31, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v25, v26, -11, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v22, v16, v8, v0

  li t2, 0x5535bfae5d05c0be
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v8, v9, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v22, v5, -12, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v16, v28, v27, v0

  li t2, 0x68a6758bac4fb106
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v16, v5, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v23, v24, 11, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v7, v5, v18, v0

  li t2, 0xed82645bde543266
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v11, v30, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v15, v29, 6, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v6, v3, v24, v0

  li t2, 0x4e73bbcc3e09162b
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v31, v28, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v1, v11, 10, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v5, v18, v14, v0

  li t2, 0x4d20680ac83dc63d
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v29, v16, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v14, v29, 0, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v24, v21, v10, v0

  li t2, 0x90b97feaf325bdc3
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v23, v7, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v8, v4, -13, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v3, v8, v1, v0

  li t2, 0x2edf58b0739b1d0a
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v7, v25, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v8, v9, -2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v26, v27, v14, v0

  li t2, 0xb87400239beb2d24
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v5, v31, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v29, v2, 9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v13, v6, v18, v0

  li t2, 0x2c2662c7a4dd7370
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v1, v25, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v2, v11, -10, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v7, v17, v10, v0

  li t2, 0x84c56220cdde7e5d
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v20, v1, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v9, v15, 5, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v14, v13, v30, v0

  li t2, 0x3127a66ae6170c87
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v13, v21, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v14, v12, 0, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v9, v1, v2, v0

  li t2, 0xf6b89ef293c40f0d
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v11, v17, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v15, v25, -6, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v15, v10, v20, v0

  li t2, 0x98a03bac3cc2d6c0
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v10, v5, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v26, v31, 12, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v2, v17, v6, v0

  li t2, 0xe89042b97499adee
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v16, v27, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v15, v2, 4, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v26, v11, v17, v0

  li t2, 0x9aadebfe4dfa3268
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v16, v18, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v8, v16, 8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v20, v18, v25, v0

  li t2, 0x862b74792ee88673
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v16, v29, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v23, v5, -16, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v12, v17, v11, v0

  li t2, 0x383faf09afd66497
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v28, v19, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v29, v24, -9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v9, v3, v12, v0

  li t2, 0x6a5ef396c93ad369
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v7, v12, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v5, v22, 4, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v30, v20, v16, v0

  li t2, 0xcba470836acc7f8d
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v27, v16, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v7, v5, -6, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v29, v31, v22, v0

  li t2, 0x49a71b0daa177476
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v5, v13, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v29, v19, 9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v28, v8, v15, v0

  li t2, 0x2d82000cd7ec43a1
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v16, v26, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v3, v16, 2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v5, v15, v9, v0

  li t2, 0xe3c2e43dbbe6305c
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v26, v27, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v11, v1, 15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v14, v20, v2, v0

  li t2, 0xe3c7b48c9cf4f623
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v18, v15, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v25, v1, -15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v23, v16, v17, v0

  li t2, 0xb4d54aa088c7d6f3
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v2, v29, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v21, v24, -2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v26, v31, v21, v0

  li t2, 0x70abd9874b43a822
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v23, v9, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v13, v23, -15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v4, v30, v15, v0

  li t2, 0x67d36425a3724b41
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v19, v27, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v5, v18, -6, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v5, v3, v9, v0

  li t2, 0x6db46768c7cc17d3
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v18, v30, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v27, v15, 6, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v13, v10, v14, v0

  li t2, 0x7ea4cf93d39d7a1c
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v8, v14, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v2, v4, -2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v13, v24, v29, v0

  li t2, 0x3f39d477602d2dbd
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v26, v3, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v29, v9, -2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v23, v15, v26, v0

  li t2, 0x3560f35e0d311f38
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v12, v7, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v24, v15, -13, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v2, v12, v7, v0

  li t2, 0x3082913df549a0b4
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v28, v31, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v16, v30, -13, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v14, v1, v24, v0

  li t2, 0xf1823abf98750d49
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v29, v10, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v3, v19, -4, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v29, v7, v20, v0

  li t2, 0xc687fec0c64d692a
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v11, v5, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v7, v8, 13, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v26, v10, v27, v0

  li t2, 0xc6c2b9db443a33b7
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v27, v29, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v17, v4, 15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v24, v13, v16, v0

  li t2, 0x81b0f72c8ae8c9cd
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v4, v7, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v10, v27, -16, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v7, v13, v24, v0

  li t2, 0xa50c73aa7aa6c16c
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v30, v4, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v12, v29, 12, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v19, v25, v22, v0

  li t2, 0x2bb287022c0bcb02
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v30, v9, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v8, v13, 11, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v13, v26, v27, v0

  li t2, 0x7c91eb3a7c328d4b
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v13, v4, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v18, v21, 2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v3, v15, v13, v0

  li t2, 0x7f6ba842f3174680
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v26, v7, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v22, v23, 2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v4, v6, v15, v0

  li t2, 0x77573989be170174
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v24, v3, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v24, v5, -2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v1, v28, v31, v0

  li t2, 0x4857e0de71d79471
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v14, v30, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v11, v25, 10, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v18, v7, v31, v0

  li t2, 0x1f9ce4b31b2cc16c
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v12, v5, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v27, v23, -16, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v23, v12, v10, v0

  li t2, 0xca9259184bc3b635
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v18, v23, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v16, v17, 10, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v17, v31, v23, v0

  li t2, 0x0b3774a2b1cb2b37
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v17, v30, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v14, v30, -8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v4, v21, v26, v0

  li t2, 0x62b24c53d231f76e
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v17, v14, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v17, v6, 3, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v11, v16, v19, v0

  li t2, 0x9354db9c1285ca72
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v15, v4, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v24, v10, 0, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v22, v15, v2, v0

  li t2, 0x10d977d0593b7a15
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v6, v7, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v22, v17, 2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v9, v4, v21, v0

  li t2, 0x993451dcbaaf138e
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v11, v14, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v4, v6, -13, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v9, v25, v3, v0

  li t2, 0x4325cd06f76ae5f3
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v2, v13, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v20, v10, -8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v8, v22, v18, v0

  li t2, 0x53baa0f255532436
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v6, v17, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v3, v2, 14, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v8, v27, v25, v0

  li t2, 0xe71af158e37df027
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v17, v14, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v25, v14, 12, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v4, v3, v20, v0

  li t2, 0xdb8ae98b4a9fdf79
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v20, v25, -16, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v23, v24, v8, v0

  li t2, 0x73435f8a9a0ba916
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v31, v22, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v1, v24, 13, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v21, v27, v11, v0

  li t2, 0x879b555b26f76e6e
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v8, v7, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v25, v15, 3, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v5, v2, v10, v0

  li t2, 0x199c9bc3a2db4e8c
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v27, v23, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v28, v9, -8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v18, v19, v29, v0

  li t2, 0x17556db402436c3d
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v28, v22, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v12, v13, 7, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v8, v3, v9, v0

  li t2, 0xf7c6955c61d9d1a6
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v25, v31, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v19, v26, 9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v20, v13, v21, v0

  li t2, 0xaacbf71622920f55
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v18, v3, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v19, v7, -15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v19, v4, v13, v0

  li t2, 0xde1b6d988071c8e5
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v23, v25, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v26, v20, 5, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v23, v20, v31, v0

  li t2, 0xaaba59d0572a65ad
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v8, v3, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v31, v11, -5, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v22, v12, v28, v0

  li t2, 0x97bff56d2e9357a6
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v13, v30, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v12, v2, -10, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v2, v26, v1, v0

  li t2, 0x5edafe9617fa2e7a
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v8, v10, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v17, v7, -2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v8, v28, v18, v0

  li t2, 0x37be49a59d05a2f1
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v2, v31, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v21, v12, 12, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v27, v14, v31, v0

  li t2, 0x385e8da49dd3fca6
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v18, v19, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v9, v3, 13, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v4, v11, v29, v0

  li t2, 0xdfd73cb1eefc5687
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v18, v10, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v27, v25, -10, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v23, v18, v2, v0

  li t2, 0x18c7ee3c9d5a46e8
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v9, v27, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v11, v29, 8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v18, v24, v1, v0

  li t2, 0xb55de253b29b2e3b
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v30, v26, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v5, v17, -13, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v15, v13, v4, v0

  li t2, 0x03403122f6abbd39
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v11, v31, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v19, v1, -9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v14, v17, v18, v0

  li t2, 0x674d5f254a91950d
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v31, v14, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v26, v31, 5, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v7, v28, v15, v0

  li t2, 0xadda5b759165d159
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v11, v15, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v1, v23, -7, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v16, v2, v27, v0

  li t2, 0xc3624e0a5e2562e3
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v28, v9, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v30, v11, -14, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v16, v3, v5, v0

  li t2, 0x91ece8b73b3f13b2
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v3, v23, 14, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v27, v9, v13, v0

  li t2, 0xe88b4073f2613eca
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v26, v3, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v25, v14, 2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v25, v1, v29, v0

  li t2, 0x20ab8c63acef88f1
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v3, v25, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v30, v7, -15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v31, v5, v28, v0

  li t2, 0x4154515359a817ee
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v17, v25, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v21, v2, -8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v28, v31, v11, v0

  li t2, 0xf8780689a2fbd373
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v26, v19, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v8, v29, 11, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v26, v9, v19, v0

  li t2, 0xb6ab2c3b49ff2025
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v22, v1, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v16, v22, -5, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v14, v30, v26, v0

  li t2, 0x22ee5fbf8f6fbc93
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v18, v12, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v4, v20, -3, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v5, v25, v4, v0

  li t2, 0x85c87b3423323743
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v3, v14, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v18, v31, 9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v21, v13, v23, v0

  li t2, 0xcbf0ce33642dbdfe
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v20, v11, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v15, v2, 15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v23, v25, v15, v0

  li t2, 0x4051a114fb6ac1ed
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v17, v28, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v20, v17, -2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v30, v9, v28, v0

  li t2, 0x7733c3303185b423
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v29, v13, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v1, v19, -6, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v16, v28, v19, v0

  li t2, 0x6033835833884a9c
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v18, v2, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v4, v31, 3, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v27, v9, v26, v0

  li t2, 0xb510f72ef9dfcd92
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v30, v25, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v22, v6, -8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v13, v30, v25, v0

  li t2, 0xb9b07b8ad39febbf
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v5, v24, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v26, v5, -11, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v29, v10, v9, v0

  li t2, 0x1443aebfffc0507b
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v25, v11, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v28, v19, 2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v24, v20, v19, v0

  li t2, 0x08c6c4aca382bf20
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v6, v20, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v15, v18, 14, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v2, v27, v16, v0

  li t2, 0x507e8f85d937d44d
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v17, v12, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v25, v10, 0, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v21, v25, v10, v0

  li t2, 0x6f097fb80966f861
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v1, v19, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v23, v6, -10, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v6, v30, v12, v0

  li t2, 0xf6f0565779b381cf
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v12, v30, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v20, v2, -6, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v16, v23, v18, v0

  li t2, 0x426bafabdd4313ce
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v18, v25, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v16, v14, 15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v18, v12, v13, v0

  li t2, 0xca7892ba55b856a5
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v25, v29, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v5, v24, 3, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v3, v13, v1, v0

  li t2, 0xe73f54f79124613f
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v15, v1, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v6, v16, -8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v9, v5, v28, v0

  li t2, 0xbba0ee7b4019dd94
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v8, v13, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v7, v12, -13, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v12, v4, v18, v0

  li t2, 0xdc8739942d6ca423
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v2, v22, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v26, -16, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v20, v8, v24, v0

  li t2, 0x7ca88f36f5a98809
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v22, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v28, v6, -16, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v28, v24, v12, v0

  li t2, 0xc32de03161171334
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v28, 3, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v30, v10, v12, v0

  li t2, 0xdaf096117cbc19fe
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v6, v10, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v16, 0, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v22, v28, v10, v0

  li t2, 0x94503e65bd17d733
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v20, v22, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v26, -8, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v20, v12, v0

  li t2, 0x1e0cda047f2a2965
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v10, v2, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v12, v18, 1, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v4, v8, v0

  li t2, 0x88c8454a7371ed76
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v18, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v6, v4, 10, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v28, v26, v30, v0

  li t2, 0x48faf280c4682245
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v10, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v20, v18, -2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v4, v8, v0

  li t2, 0xb4c2d5953cb14f56
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v6, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v22, 14, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v30, v18, v16, v0

  li t2, 0x322f5c8dd7c938d2
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v10, v12, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v2, v8, 11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v2, v20, v0

  li t2, 0x546e736261ad5b77
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v4, -11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v12, v14, v4, v0

  li t2, 0x0d4639d82de2c769
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v2, v10, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v22, v6, 11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v8, v10, v24, v0

  li t2, 0x47589ca186df19b3
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v28, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v8, v20, -13, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v18, v8, v0

  li t2, 0xebf55f17db2091dc
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v6, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v14, v18, 13, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v30, v22, v0

  li t2, 0xcb3a8c0053d7235e
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v30, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v14, v26, -3, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v26, v4, v0

  li t2, 0xb9c7d3c072fd3e06
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v28, v6, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v10, 8, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v10, v12, v0

  li t2, 0xe949c2a74a6c7963
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v16, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v20, v30, 14, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v10, v20, v26, v0

  li t2, 0xf31b60cfd4affcc0
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v18, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v14, -1, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v28, v24, v16, v0

  li t2, 0x1b674fdde41abdcd
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v4, v26, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v12, 6, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v20, v4, v18, v0

  li t2, 0xe8fa1cea16e701e7
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v8, v4, 11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v8, v22, v0

  li t2, 0x6e09e0185cfb79cc
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v18, v24, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v12, v6, 10, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v28, v22, v26, v0

  li t2, 0x0cc12144aed73117
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v22, v26, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v2, 4, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v4, v2, v0

  li t2, 0x7734ab36203b9bf7
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v28, v10, -2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v20, v10, v6, v0

  li t2, 0x2e429da5de342736
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v2, -8, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v2, v22, v6, v0

  li t2, 0x59d6f6380302a027
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v16, v2, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v4, -2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v14, v6, v16, v0

  li t2, 0xd9ad56cd4600bfb3
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v16, 2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v10, v8, v30, v0

  li t2, 0xc69d21500b6945c4
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v28, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v20, 0, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v20, v4, v12, v0

  li t2, 0xff7687e6230c2d61
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v2, v10, -10, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v12, v14, v6, v0

  li t2, 0x09f5f8c9d5aac76e
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v28, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v20, v4, 15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v18, v20, v0

  li t2, 0xc8c341d75aefcefa
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v10, v30, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v28, 7, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v26, v20, v16, v0

  li t2, 0xf1cc0dade1641aa7
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v20, v4, 11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v10, v26, v0

  li t2, 0x1b6a547f33f611b1
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v6, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v24, v20, -9, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v26, v20, v0

  li t2, 0x2f0bfdc7df0d704c
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v16, v26, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v4, v20, -12, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v12, v2, v22, v0

  li t2, 0xc389be5ee2ad69e7
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v16, v2, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v16, -5, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v8, v20, v0

  li t2, 0x98d78909c6725644
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v12, -16, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v14, v18, v0

  li t2, 0x8bb6b026592633b5
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v26, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v20, v18, -7, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v8, v6, v12, v0

  li t2, 0x48bc2017aeb0e349
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v2, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v10, 6, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v2, v30, v12, v0

  li t2, 0xec74f9d1edf6c61b
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v26, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v28, 0, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v20, v4, v10, v0

  li t2, 0xbe37b4c74d83841e
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v4, v14, 11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v26, v2, v24, v0

  li t2, 0xfcb5d3aecae67ead
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v26, v16, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v24, v26, -9, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v22, v6, v18, v0

  li t2, 0x9400a7f33da47965
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v2, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v8, v6, 11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v22, v20, v30, v0

  li t2, 0xf3733ab97fafa35e
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v6, v24, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v12, v20, -8, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v14, v6, v0

  li t2, 0xb118c9ab9fba2861
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v2, v26, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v14, v6, 0, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v20, v16, v24, v0

  li t2, 0x685ca745bb25562e
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v10, v4, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v24, -4, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v10, v20, v0

  li t2, 0xba1a9a9558fb9a2d
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v26, v30, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v14, v22, 15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v28, v2, v4, v0

  li t2, 0xed1dafff786961fc
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v8, v26, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v24, v22, 2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v12, v14, v2, v0

  li t2, 0x88afaba0df93d830
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v2, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v24, v26, -16, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v30, v24, v10, v0

  li t2, 0x26171f45b213488a
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v4, v22, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v12, v16, -4, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v26, v28, v0

  li t2, 0xb9347709d0610b7f
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v26, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v6, v30, -3, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v8, v22, v30, v0

  li t2, 0xb60b83136ea764e8
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v28, v22, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v4, 14, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v24, v14, v0

  li t2, 0xcbb43359b52333a5
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v18, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v8, v22, 15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v2, v10, v4, v0

  li t2, 0x6a1b039317adec8d
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v18, 14, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v12, v30, v4, v0

  li t2, 0xc72991b21a3c3b3d
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v24, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v20, v18, -13, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v22, v12, v20, v0

  li t2, 0xee7fc0a4620084cc
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v6, v24, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v8, v24, 5, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v2, v4, v30, v0

  li t2, 0x947786c40820120e
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v8, v2, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v16, -4, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v30, v20, v0

  li t2, 0x5512cd6f6010fed5
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v26, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v18, -8, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v12, v4, v0

  li t2, 0x6d4e11eff7d7b1ef
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v24, 7, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v30, v14, v12, v0

  li t2, 0xcfd219071626eac3
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v26, v6, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v4, v28, 1, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v8, v14, v0

  li t2, 0x453c8ff31396a1cc
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v6, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v24, v16, -2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v20, v14, v0

  li t2, 0x0da64704cbce668a
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v8, v10, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v14, v4, 0, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v22, v26, v12, v0

  li t2, 0xee2a0114f82aa15c
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v20, v22, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v28, v2, 3, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v8, v16, v2, v0

  li t2, 0xf8a970ed7852b4ff
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v18, v30, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v4, -3, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v6, v12, v0

  li t2, 0x0d0590a229efea06
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v18, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v20, 6, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v10, v14, v30, v0

  li t2, 0x41a3fdb86299841a
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v22, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v6, -7, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v10, v8, v26, v0

  li t2, 0xe26986b3edf1ab4c
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v2, -8, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v24, v26, v0

  li t2, 0x285b9f26a0615f49
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v8, v2, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v24, v20, 0, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v10, v8, v30, v0

  li t2, 0x8712f293d182470c
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v4, 15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v22, v28, v0

  li t2, 0xe517bad2c0341bdf
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v4, v26, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v14, v8, -11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v28, v4, v8, v0

  li t2, 0x0b733cfc0f5cd308
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v24, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v20, v2, 15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v10, v8, v0

  li t2, 0x7d5d10053549cf9f
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v24, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v8, -11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v12, v8, v14, v0

  li t2, 0x3db05c0ebc70e06e
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v26, v24, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v28, 14, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v4, v12, v2, v0

  li t2, 0x5462956ce1e41359
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v6, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v20, -10, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v20, v14, v26, v0

  li t2, 0x9a811e59e4fbc834
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v10, v18, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v2, 4, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v2, v16, v4, v0

  li t2, 0x74df266ca1217d97
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v4, v22, 8, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v2, v8, v4, v0

  li t2, 0x3931b1e900728201
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v2, v26, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v30, -8, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v22, v2, v0

  li t2, 0x9cbbe292391dd9c8
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v22, v2, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v10, 11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v4, v8, v0

  li t2, 0xf3bc2a0e1f6941a7
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v24, v30, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v2, v14, 12, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v10, v20, v0

  li t2, 0x27d2691b9850c3a9
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v20, v10, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v8, v6, 6, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v20, v28, v2, v0

  li t2, 0x542ffef0dec2fe6b
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v18, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v10, -14, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v28, v12, v22, v0

  li t2, 0xbe30abdb53e70e84
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v6, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v20, -16, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v26, v22, v8, v0

  li t2, 0x8fbe9941e8abe34c
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v18, v16, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v4, v22, -2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v16, v22, v0

  li t2, 0xf3a4e1833802992e
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v18, v12, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v8, v18, -5, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v14, v10, v24, v0

  li t2, 0x4aa7f6bdd0128813
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v26, -15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v28, v24, v12, v0

  li t2, 0x23147d3ded0d5377
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v10, v4, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v2, v4, 4, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v6, v30, v0

  li t2, 0xb7df3540623b844f
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v8, v26, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v8, -16, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v10, v22, v14, v0

  li t2, 0x601f3dbe97172dbf
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v30, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v12, v2, -9, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v4, v10, v22, v0

  li t2, 0x42f071f58a3fd4f2
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v6, v28, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v8, v20, 10, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v26, v6, v12, v0

  li t2, 0x7d106f081fda291e
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v14, -11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v12, v6, v30, v0

  li t2, 0x764d9ac51b71d283
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v4, v10, -15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v10, v16, v20, v0

  li t2, 0xe847576b15fbbf74
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v22, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v10, 2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v12, v20, v0

  li t2, 0x3a08edb992c23a8d
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v16, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v4, v24, 4, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v14, v6, v24, v0

  li t2, 0xb3a0c6f6f821cef1
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v12, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v24, -4, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v30, v2, v16, v0

  li t2, 0xef1f810023da2a09
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v2, v6, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v18, -1, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v28, v22, v30, v0

  li t2, 0x0575b79a788c0384
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v22, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v14, 3, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v22, v8, v30, v0

  li t2, 0x81a4ba587521d0f6
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v18, v22, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v20, v22, 12, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v8, v22, v2, v0

  li t2, 0xd2a7a6faa73413d9
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v8, v14, 12, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v8, v22, v0

  li t2, 0x73c126e647acddff
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v20, v18, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v28, 14, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v2, v26, v20, v0

  li t2, 0x28fccc8ef1011b09
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v2, v12, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v30, 8, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v8, v4, v2, v0

  li t2, 0x90e14bcab15adf90
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v8, -4, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v8, v28, v0

  li t2, 0x25fc7d8d7a3ceedd
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v6, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v4, v28, -14, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v12, v20, v0

  li t2, 0xc3a94c3518d6bca6
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v24, -8, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v16, v20, v0

  li t2, 0x3bbb01a67ade4d3e
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v8, -4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v24, v16, v0

  li t2, 0x6466e391c87cb9c1
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v28, -5, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v24, v12, v0

  li t2, 0x8e33822454e1e10f
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v4, -9, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v8, v20, v0

  li t2, 0x9450c58c20e14f4d
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v24, 8, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v8, v24, v0

  li t2, 0x67ea7f869a210258
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v8, 4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v28, v16, v0

  li t2, 0x896ce69f601bc229
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v28, 10, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v20, v28, v0

  li t2, 0x457b90ecd08beccd
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v8, 6, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v28, v4, v0

  li t2, 0xad1014f41284c005
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v24, 6, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v20, v24, v0

  li t2, 0xcd2b78360faddeb8
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v20, -14, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v24, v12, v0

  li t2, 0x823fbba3b39dc3b1
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v4, -4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v20, v8, v0

  li t2, 0x1b2eb652484a8361
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v24, -10, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v24, v20, v0

  li t2, 0xb81b636e9280e0e7
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v28, 2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v12, v20, v0

  li t2, 0x49f0757aded961a2
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v8, -1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v8, v16, v0

  li t2, 0x8c2abb913a656a04
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v16, -12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v12, v8, v0

  li t2, 0x6f38498af116da96
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v4, 6, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v28, v20, v0

  li t2, 0xa36cf073b022c23d
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v24, 11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v12, v16, v0

  li t2, 0x22945c0b747c7bd2
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v4, 1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v28, v4, v0

  li t2, 0xddf9fc707f853045
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v20, -2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v20, v12, v0

  li t2, 0x9b338b72528727d6
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v20, -3, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v8, v16, v0

  li t2, 0xf8ae2afc8a08c7a0
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v20, -15, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v24, v28, v0

  li t2, 0x1fe9a78a9af06239
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v4, 14, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v8, v12, v0

  li t2, 0xfdab0a5fee408d5d
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v8, -7, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v24, v28, v0

  li t2, 0xf1fa0bad7d853e0c
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v8, -12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v12, v24, v0

  li t2, 0x13232ee81ddd40a2
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v16, -16, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v28, v24, v0

  li t2, 0xe3e89ce751b73b94
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v4, 13, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v4, v20, v0

  li t2, 0x2e457a61057547d3
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v12, -4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v20, v8, v0

  li t2, 0x48a990a92a02e745
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v24, -10, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v8, v20, v0

  li t2, 0x10c832fb2786a95e
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v16, -16, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v28, v12, v0

  li t2, 0x9f30441cbb553961
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v4, -15, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v16, v20, v0

  li t2, 0x2acb1067399869d7
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v16, 7, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v28, v8, v0

  li t2, 0x56357bd65959b086
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v4, 13, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v8, v16, v0

  li t2, 0xfcd5bb2e070ce963
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v8, -9, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v8, v16, v0

  li t2, 0x8eb818f98e013297
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v28, -11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v16, v12, v0

  li t2, 0x5192f1db3df07369
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v20, -1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v8, v20, v0

  li t2, 0xcdda874eb7fd2bbe
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v24, -11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v8, v20, v0

  li t2, 0x22ba3e6718474837
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v28, 1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v16, v8, v0

  li t2, 0x5652e8ba6c48778a
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v28, 15, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v12, v24, v0

  li t2, 0x35fd92602f2bb886
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v12, 14, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v16, v20, v0

  li t2, 0x4d15c54f5ee36add
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v16, 1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v24, v4, v0

  li t2, 0xadac91147ded7993
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v28, 0, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v4, v8, v0

  li t2, 0x25a00448965575c7
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v20, 15, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v28, v12, v0

  li t2, 0x5cbea03fe15555b7
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v24, -3, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v12, v28, v0

  li t2, 0xbf940951e519bbed
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v12, -7, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v28, v16, v0

  li t2, 0x8668599a24b31e22
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v16, 3, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v16, v20, v0

  li t2, 0x87cf699185f18de1
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v24, 12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v28, v16, v0

  li t2, 0x413437ca83d382a7
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v12, 2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v16, v12, v0

  li t2, 0xddecf38cc5cee04c
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v4, 1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v8, v20, v0

  li t2, 0xce8543475311fd2d
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v16, -13, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v8, v12, v0

  li t2, 0xd772ba4b67ed3a05
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v16, -15, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v28, v8, v0

  li t2, 0x89486449a33484a6
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v8, -16, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v8, v28, v0

  li t2, 0x24ec66d105bef68f
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v12, -11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v8, v20, v0

  li t2, 0x498322092a32a65f
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v20, 4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v16, v4, v0

  li t2, 0x63716a47f8c70f95
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v4, 1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v28, v12, v0

  li t2, 0xc32787a1a8b7369d
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v12, -2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v24, v4, v0

  li t2, 0x134bb48b3d785ef9
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v4, -9, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v12, v16, v0

  li t2, 0xd04d9341013c3506
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v8, -10, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v12, v16, v0

  li t2, 0xa3e57b8cda83f1e2
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v16, 8, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v20, v4, v0

  li t2, 0xd611aafe614b9524
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v28, -4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v16, v8, v0

  li t2, 0x3e66b53b0ce4f24e
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v8, 4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v28, v16, v0

  li t2, 0xd196b6bafdedbe76
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v4, -12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v28, v4, v0

  li t2, 0x9614846f48c09d94
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v28, -15, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v24, v28, v0

  li t2, 0x938b961aaef6e141
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v8, 0, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v20, v8, v0

  li t2, 0x3cf26d5f3ecb8593
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v16, 11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v4, v28, v0

  li t2, 0x47b303a41bca0197
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v20, 12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v12, v20, v0

  li t2, 0xc6a87de51caaae28
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v4, 5, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v8, v28, v0

  li t2, 0xf64882d5b11a5a1d
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v12, -16, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v16, v4, v0

  li t2, 0x92fe3ca509bdfc6d
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v24, -16, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v28, v4, v0

  li t2, 0x3e3b09a3120a7401
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v28, -5, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v12, v20, v0

  li t2, 0x4271fc4b8f6839e1
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v20, -6, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v8, v4, v0

  li t2, 0xb0ccbc215399c212
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v8, 8, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v4, v12, v0

  li t2, 0x93cea421f1b98da0
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v28, -11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v16, v24, v0

  li t2, 0x5669dae9b51c9b66
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v12, 7, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v20, v16, v0

  li t2, 0x5d36bb1d94129836
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v24, 5, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v4, v12, v0

  li t2, 0xad3d3c9590d94fa7
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v16, -7, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v16, v20, v0

  li t2, 0x916db5578f595a52
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v4, 4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v20, v24, v0

  li t2, 0x514e02e7ccf1f8d3
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v4, -10, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v4, v12, v0

  li t2, 0xf8b8b63afe3b13b5
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v16, -8, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v4, v8, v0

  li t2, 0xa182b7c2b8748b7c
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v12, 1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v20, v8, v0

  li t2, 0xf519d3ebd6f310d9
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v16, -1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v20, v24, v0

  li t2, 0x96249edfc36bd81b
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v8, 8, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v8, v20, v0

  li t2, 0xda9b689289b5bc08
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v12, -1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v28, v16, v0

  li t2, 0x3675f51577072ed0
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v16, 15, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v24, v4, v0

  li t2, 0x1dc83e1f4fcb702b
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v24, -2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v4, v8, v0

  li t2, 0x7fcdce657b9ee0b6
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v24, 10, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v8, v12, v0

  li t2, 0x5f76c15e061f2888
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v8, -16, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v20, v24, v0

  li t2, 0x8a34ea2476c626c9
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v4, 12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v20, v24, v0

  li t2, 0x1b2da402d4391587
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v20, 11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v24, v12, v0

  li t2, 0x5b804b545ba8322a
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v24, -6, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v4, v28, v0

  li t2, 0x284d73f7c6fb4845
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v20, 10, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v4, v8, v0

  li t2, 0xef1bb49382d65c3a
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v24, -3, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v12, v4, v0

  li t2, 0x658e2b6951a75379
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v8, -11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v12, v16, v0

  li t2, 0x00652e9a97f19421
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v16, -1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v20, v24, v0

  li t2, 0x21efbb3a6949842f
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v8, -2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v12, v4, v0

  li t2, 0x47d35c787b287a3e
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v24, -2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v20, v8, v0

  li t2, 0x88b0d68504ac7325
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v12, 4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v28, v8, v0

  li t2, 0x763c2fe634a902a7
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v16, 12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v24, v20, v0

  li t2, 0xda769dd84370abbf
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v16, 8, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v16, v24, v0

  li t2, 0xd048b80456c0cc29
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v4, -6, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v24, v20, v0

  li t2, 0x74199009366690c0
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v28, 15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xdda4e60f30a7363a
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 13, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x2d6a341a2300d335
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x82e810ec19df17e1
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -16, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xf90ce36fa17c1d19
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -14, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xea9fa61523008ee4
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -9, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x6feb1fbb1c32078e
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, 12, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xba1fd8e44cd01dc0
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, 1, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x38c23c3fcfe88ee2
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -9, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xf7b1bbf84f8c7662
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xc45a9d05b751053c
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, -11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x5e642ca82eba748f
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -4, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xbed6b471cce24882
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, 2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x80c23f23d4184cd0
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, -16, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xccf050d9e5578ec2
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, 3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x1245a142451e2f79
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x234f2529cbf1646d
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -10, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x5d3a76e66e808b21
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, 11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x43657606af24efe8
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x5f894b0839d3654f
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, 5, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xc1f8373bd30d8e85
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x87c16fb9d46194e0
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -13, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xf3dc6f074d76540e
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x26f116d7b57585c6
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xf6a577b1f93979c7
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x1db21b173d8ae81e
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, -10, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xd6a5295cdcb5c564
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 8, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x0de7bcc4a11c5ce4
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 12, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x155164a414573a48
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, 10, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x490544bd8e797f37
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -7, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xe2eba6d937bc27e2
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 12, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xe32dfc3176e26704
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x13ce22ff977bca89
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 7, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xa94833c12a195b33
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x154a33776d2d0c5d
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -7, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x307bcc49d7fc0c2f
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, 11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x6df39516908115bf
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 8, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x90c91da01dfddd5c
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -13, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xe19bf15bdee91c6d
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, -3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x865d5b0d58573fd0
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, 5, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x679bd0fd59ef3180
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x4636892a976d7fd2
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -1, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x7e7783e9c94fe471
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -16, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xa0b219ebfd232043
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, -1, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xfa6e9cad06dc1420
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 0, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xa6858e9c419f97b6
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, 13, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x84f6f55b4ef13de0
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -14, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x0d07e5bd61e71383
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -16, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xaa904e6f26796544
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -1, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x2f111588c1f5a8ec
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x0088ea4a306dfb8a
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -1, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xcfc2ba80a01e4889
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x0ab586d0c1e18504
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -14, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x17c985de5614451c
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 9, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x036b5aabd4624cb6
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -8, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xa4d685b7e9c6b094
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -16, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xfaee834cfaa9253e
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 7, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x55ee7a475b4ffe87
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x412e5c52f636dc18
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -14, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xe2bb697b6d32e6c3
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, -1, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x3b7ad9666beeef81
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, -16, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xbf8c486ed7e08cbd
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 6, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xaa150201ce64ca75
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -5, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x2124d647cf29c0a8
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, 7, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x33c91c17feae9a41
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, -7, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x89386e8150bc4386
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -5, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x214913d47fcb6b4a
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -16, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x29612b1c7b5f6b21
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, 8, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xc3fc54471d7bed99
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x538e20d69d22a992
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 0, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xa95d06c5c1cd6581
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -1, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xf069f48a32152ada
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x756a4010cb79fa4f
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -8, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xf107159adf6da02e
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, -9, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x079e691060212869
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, 11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xcb3d336973a1e615
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, -9, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xb1dd0bf45d0059a1
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, 4, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x9b05396226c2977e
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 5, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x5f7d723fe921ada9
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 14, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x8a695a46b4f4bd9b
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, 4, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xd79be36fa143d711
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x93f7ab7bbfabf67c
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, -4, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xa7128265486f7ca4
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, 11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x6fdb3d22f3d7b4da
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, 7, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xc4194275f6b02e4a
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x9ec64a7c9599b883
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -16, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xa4d4ffe7d01be385
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, -3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x73510ce7c3e4fb46
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, 9, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xcb991f825c3e2a1f
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x6f84729210b245ad
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -5, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x1ab68fd69c11e660
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 6, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x6961e7af8695a25a
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, 15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xd33bb80c1a4afb89
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -4, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x7d1ae77742519cbd
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -9, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xe4ed7c644beab1bb
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, -4, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xcac0ac3f034c1b83
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xc43776af54ca25f2
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 13, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x521e320a253f4725
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -5, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xefdded291acbd9c2
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -10, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xf247f34f73142d4a
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 4, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x51d5b15def9431c1
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -8, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v8, v13, v26, v0

  li t2, 0x2a151c00f85697f3
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v15, v30, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v26, v7, 14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v12, v18, v15, v0

  li t2, 0x0653b66103d45a5e
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v2, v27, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v12, v26, -10, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v24, v16, v5, v0

  li t2, 0xca2d152ec1e4ecb1
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v11, v28, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v17, v1, -11, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v23, v22, v27, v0

  li t2, 0x1962b5d527c5ee1e
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v25, v2, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v9, v25, -9, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v28, v5, v1, v0

  li t2, 0xc3d43e00f68a7ccc
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v2, v5, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v23, v2, 11, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v14, v5, v11, v0

  li t2, 0x05a905aad1f3f3a5
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v26, v17, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v5, v10, -7, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v13, v20, v23, v0

  li t2, 0xfa56d8bd29f0cdca
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v19, v23, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v3, v4, -16, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v12, v17, v27, v0

  li t2, 0xbb1d21cd2f71d20f
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v20, v23, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v31, v24, 11, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v12, v23, v8, v0

  li t2, 0x0088517c89ade0ee
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v22, v7, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v10, v24, 0, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v2, v23, v11, v0

  li t2, 0x0606ce93a6c3aa86
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v31, v7, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v9, v15, 5, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v28, v18, v6, v0

  li t2, 0x1355ea93977d1188
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v19, v22, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v31, v28, 8, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v20, v21, v14, v0

  li t2, 0xbe041819994f9a58
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v4, v7, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v29, v14, 6, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v1, v6, v8, v0

  li t2, 0xb53dbd865d384dac
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v23, v7, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v7, v17, 7, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v5, v10, v15, v0

  li t2, 0xafd85bb841b1be64
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v19, v2, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v19, v6, -13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v22, v3, v28, v0

  li t2, 0xec3d9d57878d6043
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v23, v25, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v6, v10, 0, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v2, v15, v28, v0

  li t2, 0xebca5446fd125bc4
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v30, v2, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v30, v14, 10, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v28, v21, v17, v0

  li t2, 0x14d3f7a95194c3a0
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v25, v15, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v25, v29, 13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v9, v28, v16, v0

  li t2, 0x1066881c7cbed43c
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v27, v23, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v12, v9, -5, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v8, v16, v12, v0

  li t2, 0xc0b4647a4d192686
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v31, v8, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v24, v18, -12, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v21, v25, v6, v0

  li t2, 0x64336285ecc5a1d1
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v10, v26, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v4, v18, -2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v7, v15, v29, v0

  li t2, 0xf295a087fa27842f
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v18, v27, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v5, v13, 7, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v24, v28, v4, v0

  li t2, 0xe659baa7289e2c8e
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v13, v14, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v22, v27, -5, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v7, v30, v8, v0

  li t2, 0xecab31a1270bb56e
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v1, v14, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v24, v27, -6, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v26, v29, v23, v0

  li t2, 0x5e689a177e0abef4
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v29, v2, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v5, v11, 2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v8, v17, v1, v0

  li t2, 0x47c6a9f5eaddb5c1
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v28, v13, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v9, v7, 14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v6, v3, v24, v0

  li t2, 0x8786d8139726d9da
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v23, v15, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v20, v13, -6, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v11, v16, v5, v0

  li t2, 0xee69278b9368111e
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v9, v8, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v21, v15, 7, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v20, v21, v4, v0

  li t2, 0xed0a1e86ac04d3bd
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v12, v14, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v2, v30, 3, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v8, v25, v9, v0

  li t2, 0xc5e9d83024389d03
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v14, v6, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v13, v29, 8, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v2, v22, v6, v0

  li t2, 0x62979d42f8545fc8
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v16, v14, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v23, v6, -7, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v19, v3, v18, v0

  li t2, 0xaeae450b8d016e26
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v16, v10, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v6, v3, 4, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v11, v2, v17, v0

  li t2, 0x1a53084b86202026
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v16, v17, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v2, v17, 0, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v31, v12, v8, v0

  li t2, 0xa3947d2b14c273ea
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v27, v5, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v17, v19, -10, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v20, v29, v22, v0

  li t2, 0xccf1e3e9ff3f1860
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v25, v12, -6, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v3, v31, v11, v0

  li t2, 0xe2bb26fcd794f8d0
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v23, v18, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v10, v22, -2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v25, v11, v24, v0

  li t2, 0xba6c5fb7fec2733a
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v20, v15, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v13, v4, 13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v24, v9, v18, v0

  li t2, 0x94df825cad54ccc8
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v7, v19, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v4, v13, -13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v29, v30, v9, v0

  li t2, 0x2394a9ae59ddd69e
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v11, v22, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v25, v14, -7, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v7, v29, v26, v0

  li t2, 0x8bc3cab23683bcf3
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v28, v11, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v26, v11, -4, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v4, v12, v11, v0

  li t2, 0xe888ea7df7810b2a
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v9, v4, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v1, v26, 15, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v28, v31, v5, v0

  li t2, 0x6080d10eade92a0d
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v4, v5, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v2, v8, 10, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v15, v26, v17, v0

  li t2, 0xeadfecb4da08b106
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v9, v25, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v15, v29, 4, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v7, v19, v29, v0

  li t2, 0xc31d32ca4cb0ebb4
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v3, v22, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v5, v15, -16, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v11, v22, v4, v0

  li t2, 0x47e65c54c9dac1d8
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v27, v10, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v30, v26, -3, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v7, v1, v2, v0

  li t2, 0x3a2effa2a75e139f
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v13, v20, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v14, v15, 12, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v2, v28, v16, v0

  li t2, 0x615c4565cb3aa9e8
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v1, v22, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v24, v16, -10, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v10, v29, v26, v0

  li t2, 0x56e03b259b17643c
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v3, v28, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v7, v29, -10, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v7, v8, v11, v0

  li t2, 0xc7fc0877efc1ca7d
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v22, v21, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v8, v11, 12, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v21, v1, v14, v0

  li t2, 0x966728d55da2fb21
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v30, v17, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v16, v27, -3, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v3, v6, v30, v0

  li t2, 0xe2026b3c67ae2d16
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v17, v9, 14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v24, v27, v21, v0

  li t2, 0x5ac513a87ac0055b
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v4, v21, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v17, v14, -14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v11, v15, v8, v0

  li t2, 0x8fc3340055b62d9e
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v13, v21, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v25, v31, 2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v2, v22, v24, v0

  li t2, 0x2eec421cf2d79d41
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v26, v7, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v30, v6, -15, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v21, v20, v29, v0

  li t2, 0x24a0cd6bc635b337
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v20, v15, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v7, v31, 6, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v3, v25, v17, v0

  li t2, 0x10fd8b852a130996
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v29, v23, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v7, v12, -2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v22, v6, v12, v0

  li t2, 0x4d916b7dc27e16c0
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v16, v30, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v10, v20, -13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v4, v1, v9, v0

  li t2, 0xdb4450876a0faff8
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v6, v4, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v10, v23, -16, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v13, v9, v27, v0

  li t2, 0x7cba5c1f505cba9f
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v27, v5, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v26, v10, 1, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v30, v13, v18, v0

  li t2, 0x9ec46bfbbf0b43c1
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v25, v7, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v28, v7, -9, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v10, v8, v16, v0

  li t2, 0x8534d98fe47ffba3
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v23, v15, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v16, v15, 13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v12, v1, v13, v0

  li t2, 0xda0ecf09618a5748
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v16, v22, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v7, v20, 4, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v18, v2, v7, v0

  li t2, 0x8daabe22c854e3e2
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v6, v29, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v22, v4, -5, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v21, v5, v25, v0

  li t2, 0xe978512c97adb2bf
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v31, v5, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v4, v25, -8, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v18, v11, v1, v0

  li t2, 0x5cd2f2dd7b3fd2dc
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v8, v11, -3, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v6, v20, v8, v0

  li t2, 0x17e79db8ace51830
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v29, v17, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v18, v17, -2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v21, v25, v30, v0

  li t2, 0x4fe9c11728fd3925
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v25, v13, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v15, v31, -7, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v5, v9, v29, v0

  li t2, 0x6cdd4b045791a539
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v9, v14, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v4, v11, -16, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v22, v21, v24, v0

  li t2, 0xa36898c423e395db
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v18, v31, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v15, v18, -7, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v19, v3, v25, v0

  li t2, 0xc00a79ecb06fb7ac
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v30, v26, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v30, v29, -15, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v14, v21, v13, v0

  li t2, 0xce96ec8e0945d194
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v28, v11, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v11, v30, -1, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v17, v8, v30, v0

  li t2, 0x16d4b02d5f07592e
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v26, v4, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v11, v5, 9, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v24, v6, v25, v0

  li t2, 0xb668b5fdbea82c42
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v3, v22, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v12, v31, 7, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v31, v10, v27, v0

  li t2, 0x5b413b5c658f1411
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v28, v18, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v9, v16, 10, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v2, v19, v11, v0

  li t2, 0x8cf5dcc83bdf8590
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v25, v26, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v1, v28, -13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v17, v28, v23, v0

  li t2, 0xc0a1ea54bf3ad703
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v9, v13, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v8, v2, -3, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v27, v30, v25, v0

  li t2, 0x2582633b44950017
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v20, v21, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v28, v10, 8, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v13, v16, v28, v0

  li t2, 0x62c9b8c18f2af8dc
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v28, v12, 14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v25, v8, v2, v0

  li t2, 0xa88b5ea40397341b
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v8, v11, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v8, v22, -1, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v21, v11, v28, v0

  li t2, 0x8b68d82f44349f15
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v2, v5, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v5, v18, 0, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v31, v19, v13, v0

  li t2, 0x691d7890f6cd2582
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v6, v18, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v8, v12, 1, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v2, v25, v4, v0

  li t2, 0x5cc4bf11288c9433
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v14, v2, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v12, v8, -2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v16, v9, v5, v0

  li t2, 0xa35e10fda94c09ee
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v1, v6, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v6, v18, -3, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v3, v7, v4, v0

  li t2, 0x6ce4ef8045321d3d
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v13, v4, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v18, v21, 0, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v10, v27, v11, v0

  li t2, 0x0bb249795c67227a
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v9, v18, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v6, v4, 4, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v24, v13, v28, v0

  li t2, 0xd905a5a52c304531
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v15, v6, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v18, v22, -16, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v16, v3, v6, v0

  li t2, 0x90056eda3bb36955
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v29, v20, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v23, v14, 14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v2, v28, v21, v0

  li t2, 0x09984f1064359f08
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v8, v19, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v31, v17, -1, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v27, v4, v10, v0

  li t2, 0x6838740f5e6aea49
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v19, v14, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v19, v15, -13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v30, v25, v26, v0

  li t2, 0xaaf8a60f80471797
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v10, v14, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v12, v13, 0, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v17, v9, v24, v0

  li t2, 0xdee9ffe4b353414e
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v26, v16, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v6, v16, 0, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v18, v2, v8, v0

  li t2, 0x65e88b3b601ef8b8
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v18, v30, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v23, v10, 14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v18, v15, v23, v0

  li t2, 0x23289b5e1222261b
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v13, v11, -7, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v13, v3, v22, v0

  li t2, 0xdf90a7dee86eda2c
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v5, v28, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v22, v1, 3, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v21, v22, v1, v0

  li t2, 0xbe38e6ca0b9bc64c
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v3, v23, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v13, v6, -5, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v10, v12, v26, v0

  li t2, 0xfe64b3ed0d3d7aaf
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v15, v30, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v2, v25, 2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v27, v14, v12, v0

  li t2, 0x64781eea1d91e383
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v28, v31, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v14, v11, -4, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v15, v31, v20, v0

  li t2, 0xc6a5063a9d580a78
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v22, v23, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v12, v26, -8, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v19, v7, v20, v0

  li t2, 0x3da7781c747e529f
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v2, v13, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v13, v12, -10, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v26, v19, v1, v0

  li t2, 0x1fda4ea32753f20d
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v12, v15, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v13, v30, 14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v20, v1, v19, v0

  li t2, 0x00fafa7d358288e4
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v3, v4, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v26, v11, -2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v20, v24, v0

  li t2, 0x42f15ff05cbfc367
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v10, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v14, v16, 0, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v30, v20, v10, v0

  li t2, 0x96e7d6abd0268ced
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v18, v2, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v24, 14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v8, v22, v26, v0

  li t2, 0x0ba01c32928939ae
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v28, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v10, 9, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v16, v24, v20, v0

  li t2, 0xc87b0c7cba12e553
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v4, 8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v4, v6, v24, v0

  li t2, 0x66b36eee643e17bf
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v10, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v28, -3, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v16, v2, v6, v0

  li t2, 0x2ab9bbeaa30bb82b
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v8, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v8, v22, 2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v20, v12, v0

  li t2, 0xf18661b0860a3411
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v6, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v14, 4, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v14, v16, v20, v0

  li t2, 0x936c9632a9f75974
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v4, v26, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v10, v20, -14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v14, v18, v12, v0

  li t2, 0xe3735b675786bbba
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v10, v16, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v18, v12, -5, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v4, v24, v16, v0

  li t2, 0x4e6203668ee9deb3
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v16, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v18, v28, -10, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v24, v30, v12, v0

  li t2, 0xe5ef40d85a29f4f3
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v24, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v14, v4, 14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v2, v30, v26, v0

  li t2, 0x9c7176f4f5e9afab
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v14, v30, -9, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v4, v24, v8, v0

  li t2, 0x619fd808795e5260
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v14, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v26, -10, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v16, v28, v20, v0

  li t2, 0x02ccfd6b1dc6434d
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v10, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v12, -7, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v10, v18, v8, v0

  li t2, 0x76b0af7c037642c8
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v14, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v8, v16, 13, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v14, v22, v10, v0

  li t2, 0x293bb5df6c38dd9a
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v4, v2, 7, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v22, v18, v14, v0

  li t2, 0x8249a0ef0f16ed8a
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v6, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v12, v24, 8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v22, v16, v26, v0

  li t2, 0x83c2f6ff59074093
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v28, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v14, -9, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v14, v28, v0

  li t2, 0xf32cc5b9214038a2
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v28, v2, 5, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v22, v24, v8, v0

  li t2, 0x54ee265ec328d73d
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v10, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v18, v4, -12, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v6, v20, v0

  li t2, 0x7e4898d597e7c668
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v4, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v2, -9, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v20, v26, v2, v0

  li t2, 0xe4c2e7d40395f2e4
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v24, v30, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v22, -5, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v6, v28, v0

  li t2, 0x1e89713aebdc510d
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v12, v30, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v10, v30, -16, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v10, v26, v20, v0

  li t2, 0x3666c2ba13faf30d
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v14, 3, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v8, v18, v0

  li t2, 0x29d0454647cc3867
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v10, v22, -2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v14, v22, v2, v0

  li t2, 0x92d0cad399a1d8c8
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v14, v30, -13, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v4, v6, v22, v0

  li t2, 0xc63a54a3da153ece
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v14, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v14, -13, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v28, v4, v10, v0

  li t2, 0x77897bbe79db4d40
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v22, v8, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v2, v18, 8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v30, v20, v22, v0

  li t2, 0xc2fb0096439d57cb
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v22, v20, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v26, 2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v30, v2, v4, v0

  li t2, 0x4e7b546737467124
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v4, v10, -2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v24, v26, v12, v0

  li t2, 0x0397c1f843a17af7
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v18, v2, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v26, 6, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v16, v22, v10, v0

  li t2, 0x7b461445dab14339
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v24, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v4, v8, -11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v10, v14, v26, v0

  li t2, 0xbbd784c61749a3ea
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v16, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v26, v4, 1, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v20, v8, v26, v0

  li t2, 0x64fa0f1e129f698b
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v14, -4, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v4, v20, v30, v0

  li t2, 0x15778ba9a6dd488f
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v24, 14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v16, v22, v14, v0

  li t2, 0xf30e821b9b09978a
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v14, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v26, v18, -2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v8, v14, v22, v0

  li t2, 0xa00a4788be574b63
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v18, v26, -16, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v16, v2, v0

  li t2, 0x23eeb9d7fcf76049
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v12, v10, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v2, 1, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v22, v2, v30, v0

  li t2, 0xcd686c89ec33240d
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v14, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v10, v30, -13, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v12, v20, v30, v0

  li t2, 0x919f7440220740f2
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v12, 12, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v28, v24, v8, v0

  li t2, 0x696df5e18e5c19a8
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v10, v22, -6, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v8, v2, v24, v0

  li t2, 0x18c6b9cb77e553a2
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v10, v4, 12, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v4, v6, v16, v0

  li t2, 0x682d7d9dfe76ca9a
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v24, -11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v16, v10, v0

  li t2, 0xaa3cbb1e6afe9ea2
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v14, v30, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v8, v4, 14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v2, v26, v20, v0

  li t2, 0xbb8b264638dd34e4
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v26, v28, 11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v30, v24, v0

  li t2, 0x0ccd69f3c70251a5
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v6, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v20, v26, -6, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v20, v24, v4, v0

  li t2, 0x70a35e124bb3b661
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v2, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v14, -7, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v20, v14, v0

  li t2, 0x9569e1dc8a52f7d2
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v24, v30, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v14, v10, -7, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v10, v24, v16, v0

  li t2, 0xf9c7017210a6f46d
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v6, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v10, v8, 7, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v24, v18, v30, v0

  li t2, 0xfe660fa1c4b703db
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v24, v30, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v8, v10, 12, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v30, v6, v20, v0

  li t2, 0x2b6350eebb483cea
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v16, v2, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v12, -5, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v4, v16, v18, v0

  li t2, 0x9853312789bef52f
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v16, v2, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v4, v18, 13, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v14, v16, v24, v0

  li t2, 0x53cf3cf2d7a5f8dd
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v6, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v18, v10, 0, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v10, v18, v8, v0

  li t2, 0xdad70a7c5c72d831
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v14, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v10, 10, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v6, v16, v0

  li t2, 0x27f97f2dd5aebeb0
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v26, v24, -7, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v8, v6, v0

  li t2, 0x28518b7c8c76ed6b
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v18, v2, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v28, 14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v10, v4, v24, v0

  li t2, 0xa0494616018a9e35
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v30, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v28, v10, 8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v12, v20, v14, v0

  li t2, 0x3ba7bd63ebf8fd5b
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v4, v30, 10, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v14, v20, v8, v0

  li t2, 0x3b3de51fcd1a53fb
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v10, v8, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v10, v12, 5, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v12, v28, v22, v0

  li t2, 0x996404031c0f4dbe
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v10, v26, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v2, 9, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v28, v8, v0

  li t2, 0xa8975267e783afe0
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v26, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v14, 14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v2, v6, v10, v0

  li t2, 0x2db0dca35b2ea31f
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v10, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v20, v16, -11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v2, v14, v0

  li t2, 0x409881c0d39c50de
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v18, v24, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v20, v14, -3, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v10, v16, v14, v0

  li t2, 0x16260317c849398e
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v14, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v28, v24, -8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v18, v20, v0

  li t2, 0x0dd7df1505a6a770
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v4, v10, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v20, v28, 14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v4, v30, v0

  li t2, 0x2d29754894ebf6fe
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v10, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v28, v10, -11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v28, v18, v30, v0

  li t2, 0x01a7d04797257fdf
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v24, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v4, v10, 11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v2, v30, v10, v0

  li t2, 0xc0375181c60447f1
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v18, v24, 8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v2, v6, v8, v0

  li t2, 0xdc62f36a0bfd9e9b
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v22, v16, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v20, 15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v22, v26, v30, v0

  li t2, 0x646005304a7eae2f
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v28, v10, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v12, v20, 6, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v2, v4, v16, v0

  li t2, 0xb7a31f7c620d9174
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v8, 15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v22, v26, v6, v0

  li t2, 0x5326c4cdb3b5843f
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v24, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v14, 5, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v20, v14, v0

  li t2, 0x4860c740e6219e9a
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v6, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v20, -11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v24, v10, v16, v0

  li t2, 0x9f06d2a28a073384
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v22, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v2, -15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v12, v14, v0

  li t2, 0x0a097278f1d51423
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v24, v2, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v2, -12, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v30, v2, v26, v0

  li t2, 0xc9cb6b723ccdee40
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v12, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v2, v18, -9, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v28, v16, v18, v0

  li t2, 0x9856068c88bb475d
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v20, -9, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v12, v24, v14, v0

  li t2, 0x231655e57fe3ce48
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v28, 6, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v8, v30, v22, v0

  li t2, 0x070ad17cdd29a373
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v20, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v24, -13, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v20, v18, v30, v0

  li t2, 0xe55e7aa9846a654a
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v18, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v26, -9, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v12, v18, v24, v0

  li t2, 0x309d85f7f5c3ded4
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v22, v14, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v2, v26, 11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v24, v28, v12, v0

  li t2, 0x7cc5e81a2c7347ac
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v14, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v4, -8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v28, v4, v14, v0

  li t2, 0x0f12b5999c8f366a
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v2, v12, 14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v22, v14, v4, v0

  li t2, 0x16e354b12e0ed21c
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v18, v20, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v14, v12, 8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v16, v4, v30, v0

  li t2, 0xf6f2e9b41e59b23e
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v6, v10, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v4, -6, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v12, v18, v16, v0

  li t2, 0x4c5328dfff92c044
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v24, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v12, v4, -16, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v22, v2, v24, v0

  li t2, 0x916d0a857f241b3e
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v20, v26, -3, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v14, v10, v4, v0

  li t2, 0xdca0397ca3729976
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v10, v12, -12, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v10, v26, v30, v0

  li t2, 0x26401eb1a78db0d8
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v4, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v20, -1, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v4, v24, v0

  li t2, 0x46eeffd8641a31b4
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v6, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v10, v28, -9, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v26, v28, v0

  li t2, 0x186831806db86740
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v10, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v26, 15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v4, v16, v0

  li t2, 0x877d984e0b7fea99
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v12, v30, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v24, 3, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xe1ff3b3ceb587d80
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v6, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v20, v22, 1, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v12, v28, v0

  li t2, 0xbabee1955fc7dc2c
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v10, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v12, v20, -3, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v16, v4, v0

  li t2, 0xf44d1f2495a48577
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v6, v14, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v22, -10, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v22, v2, v16, v0

  li t2, 0x4835ac23c2bb0d77
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v6, v14, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v10, v28, -7, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v12, v2, v0

  li t2, 0x6c34e18ecba5a909
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v4, v2, 0, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v26, v14, v0

  li t2, 0x6dcce801c2f0b333
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v14, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v20, v6, 2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v30, v14, v28, v0

  li t2, 0x2a472e6bff9bc5c1
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v18, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v20, 14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v30, v20, v28, v0

  li t2, 0xf35ccd487046990e
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v24, v26, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v6, 14, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v8, v24, v0

  li t2, 0x903cd698ae3bbcd3
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v24, 3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v28, v16, v0

  li t2, 0xd202e0083bf3b9d8
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v12, -13, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v24, v12, v0

  li t2, 0x8ab92a52e4cd9f0a
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v8, 12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v8, v24, v0

  li t2, 0xe7bec813dfd1526b
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v20, 3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v8, v28, v0

  li t2, 0xa1b8399ae892601f
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v8, -3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v24, v4, v0

  li t2, 0xd9954ad329f21c4c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v24, 6, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v4, v28, v0

  li t2, 0xa860bb8ee37c832c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v24, 12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v12, v24, v0

  li t2, 0x8b8d984b1979ef38
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v28, 3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v8, v24, v0

  li t2, 0x6092f6dd8abbf014
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v12, 5, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v12, v24, v0

  li t2, 0xca8bc9ff16cba9be
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v12, 10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v28, v12, v0

  li t2, 0x0491a6c6ff12b763
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v8, 10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v16, v20, v0

  li t2, 0x764e3603f0e00a79
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v20, 9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v4, v16, v0

  li t2, 0xf8e5a756aa6230ac
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v12, -16, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v4, v20, v0

  li t2, 0xf4643d511c182d5e
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v12, -8, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v24, v4, v0

  li t2, 0xf4cad0b120e1f2d3
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v16, -16, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v12, v24, v0

  li t2, 0xbc088d595be89794
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v24, 12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v8, v12, v0

  li t2, 0x41ab025166e5e358
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v28, 5, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v16, v28, v0

  li t2, 0x8d071daaf927ad21
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v20, -10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v20, v24, v0

  li t2, 0x196506889e8f786f
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v28, -9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x368b982086f2bb68
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v8, -9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v8, v12, v0

  li t2, 0x060f263b91e9d09d
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v24, 7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v16, v8, v0

  li t2, 0xaeb3e7af0e939c14
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v12, 8, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v28, v20, v0

  li t2, 0x8b34201fa67c1b65
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v4, -14, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v12, v4, v0

  li t2, 0x0eb17f68ac26a2c3
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v8, 9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v8, v24, v0

  li t2, 0x30203252e33ed94d
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v12, -2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v20, v4, v0

  li t2, 0xaf72856ab0d62df8
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v8, 6, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v24, v12, v0

  li t2, 0x3bb23d35bd95fad3
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v16, -13, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v24, v8, v0

  li t2, 0x2096202b8cfd00c4
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v28, -13, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v28, v12, v0

  li t2, 0x8bc45ad9f6cddf8a
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v4, 3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v20, v8, v0

  li t2, 0xb7deae9ef7db4c80
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v20, -9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v24, v12, v0

  li t2, 0x7942bda60bf9dc1d
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v12, -5, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v12, v28, v0

  li t2, 0x872a8c8f9176460c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v20, 14, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v12, v8, v0

  li t2, 0x4a640ab25a5cd544
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v12, 2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v4, v12, v0

  li t2, 0x37f340ea2b7a8022
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v28, -3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v4, v24, v0

  li t2, 0xb83c157e3cbd551e
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v16, 14, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v16, v12, v0

  li t2, 0x290db4a06ce702f6
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v16, -5, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v4, v24, v0

  li t2, 0x073e5b0d098590fc
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v16, -9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v20, v4, v0

  li t2, 0xe8f92600186aac1c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v12, -11, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v8, v12, v0

  li t2, 0x450f79172870fc99
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v12, -10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v28, v16, v0

  li t2, 0xe0fe649ec723447c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v8, -16, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v16, v28, v0

  li t2, 0xe1bb411867ebded0
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v12, 4, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v20, v12, v0

  li t2, 0x580783ba874a3d37
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v28, 10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v4, v20, v0

  li t2, 0x03225dfab8f1a0ee
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v12, -7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v24, v8, v0

  li t2, 0xe8d74dc7309c522d
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v20, 14, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v12, v24, v0

  li t2, 0x3ce9e6f82efde7a6
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v28, 8, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v4, v28, v0

  li t2, 0xa6ecb496f3753341
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v12, 2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v28, v20, v0

  li t2, 0x4ea52a8525b8e248
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v16, 10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v12, v24, v0

  li t2, 0x3d3c4f11aa34d8f1
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v28, 12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v16, v12, v0

  li t2, 0x884401e279580199
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v8, 11, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v12, v20, v0

  li t2, 0x50b191000c885779
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v28, -10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v8, v28, v0

  li t2, 0xa9a2cc257da3505c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v8, 14, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v8, v24, v0

  li t2, 0x9c12ca412b2d940c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v20, -9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v4, v20, v0

  li t2, 0xe7133b52b652f362
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v8, 14, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v4, v12, v0

  li t2, 0x21f14d4acefc90db
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v20, -11, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v4, v28, v0

  li t2, 0xfb4f61b7db49c781
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v8, 13, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v12, v4, v0

  li t2, 0x9da5b99a850be7e6
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v8, 12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v8, v28, v0

  li t2, 0x25fae48720d6c584
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v16, -7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v20, v4, v0

  li t2, 0x0aaef4387ba154ac
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v16, 7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v8, v28, v0

  li t2, 0xfbba5c718aea7b15
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v12, 0, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v24, v28, v0

  li t2, 0x410e2b79bfa1f93f
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v4, 5, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v16, v24, v0

  li t2, 0x615d9733ec9eef36
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v16, 2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v8, v16, v0

  li t2, 0xacd0939c1867d18a
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v24, 4, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v28, v20, v0

  li t2, 0xb3a164b4c9f15810
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v8, -1, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xedfb7c5c03ad1e3b
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v20, 6, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v4, v28, v0

  li t2, 0x3a53eb271095ebfa
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v28, -12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v8, v16, v0

  li t2, 0x3f0156c1c0cacc33
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v20, -8, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v24, v12, v0

  li t2, 0x908fea2b132707d2
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v24, -11, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v4, v24, v0

  li t2, 0xcec4ebeb56828115
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v8, 6, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v16, v8, v0

  li t2, 0x4032f7a658167298
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v4, -10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v12, v28, v0

  li t2, 0xe494a9d3ccf3d4c9
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v28, 5, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v12, v8, v0

  li t2, 0x00f2d533a74581b8
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v4, -12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v28, v12, v0

  li t2, 0x041aad58b8a25cf6
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v8, 8, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v28, v24, v0

  li t2, 0x458ab11d292f012e
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v4, 7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v8, v20, v0

  li t2, 0x1a47a89fb9843f2a
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v24, 6, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v4, v16, v0

  li t2, 0xbb49e8a8cd50a7e6
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v4, -9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v20, v8, v0

  li t2, 0x88eee33b6fc1c437
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v20, 9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v12, v28, v0

  li t2, 0xdffcc521b5ce73d6
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v28, -1, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v12, v8, v0

  li t2, 0x4de83bca3f28868a
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v20, 15, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v24, v12, v0

  li t2, 0xa51d4ed9170aadad
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v12, 11, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v12, v8, v0

  li t2, 0xb2795637f1c5c112
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v8, 15, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v16, v28, v0

  li t2, 0xc863597087128714
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v8, -4, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v28, v8, v0

  li t2, 0x204c08203a725eeb
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v20, -4, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v12, v24, v0

  li t2, 0xdbb3293c485a0d2c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v4, 1, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v12, v28, v0

  li t2, 0x1d566458d7e7839a
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v20, 9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v20, v12, v0

  li t2, 0xcb86f383470c4880
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v8, -13, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v4, v12, v0

  li t2, 0x67e8789d1cca912a
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v16, -13, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v28, v4, v0

  li t2, 0xf0e255f85db91c6b
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v20, 6, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x0c43daf8373a83f8
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v28, -2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v8, v4, v0

  li t2, 0x8ecbf701d34b5103
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v24, 7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v20, v4, v0

  li t2, 0x9c0af36a6c3623d7
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v16, -15, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v12, v8, v0

  li t2, 0xd1d9d8dcd34f339c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v4, -4, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v20, v12, v0

  li t2, 0x9d2f01641adc79da
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v4, 10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v4, v28, v0

  li t2, 0x12c34e06dce81e23
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v28, 8, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v24, v4, v0

  li t2, 0xc327500f33c4ad68
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v24, 9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v28, v12, v0

  li t2, 0xb38ae55543a743c1
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v4, -14, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v4, v8, v0

  li t2, 0x3450b8dc1e6fa9c5
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v8, -14, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v12, v4, v0

  li t2, 0x8f49fd43ad807cff
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v8, 1, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v8, v4, v0

  li t2, 0x86d2c0476b327b9d
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v20, -13, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v28, v20, v0

  li t2, 0x0cdc3fa71b42b7a1
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v12, -14, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v4, v20, v0

  li t2, 0xa5fb715de84eac25
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v28, -9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x52142ab38b5f4dae
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, 2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x6087a006b4a8bb03
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x7c0c083dc2a8e05a
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, 1, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x50a533c338c8e8b6
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -15, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x1ed0fb2124c45c11
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, 6, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xa8f276a110c0a50e
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, 12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x1444e0cd206b50dd
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, -13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xa6adc0f1ceebbcb3
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -11, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xe8a1583f6a07b674
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, 15, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xd21a3ce93489ae58
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -4, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x2b44f7c79d99abbf
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xdfe237f6a7f5aa35
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x9824871acf3f6179
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, -13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x379cbc328dda9e22
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, 8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xf42d0958450fda0f
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x5f57fb1198115126
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, -5, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xd4d2071b6b1e0881
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -15, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x870172ad72dfa03a
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 7, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xdadd5a196922e7e6
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, -9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xde8ca99a5b64e4a5
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, 1, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x8aa5226632236834
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 11, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xbcb38f752be7c9db
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x772173816f08ed10
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xe691c3f8e0b07d8e
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -16, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x4214b546cd2f71ff
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x74de272552e1b0a0
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, 9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xf02facc5bdb6b778
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, 4, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x3e3c3a7ba851d73c
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 1, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xd1e1384d856858ba
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 15, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x6df2ae00e2dc4d8c
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xbeca048718fcf6e3
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 6, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xaac449e24fd99f54
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -3, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x68d1b7e68fda2cf5
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, 6, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x975314da90c28777
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -5, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xbe26f6b82feeb784
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 7, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xbc610cc245dd42b6
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, 0, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xfeaa0a766124cadb
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 0, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x51c404f524ae2a63
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, 4, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x238c111b6d419df6
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, -7, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xdeeb061f1f647303
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 14, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x4bd1dcdd01e1737f
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -4, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x00d793be87d0d744
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, -1, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xe307aba8da371a2f
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, -12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xb1693de329d3f1a1
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xb0af972d62bd47c6
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, 2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x368ed389194eacc2
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -15, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x7ed54989ee8f5f1f
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xb3501f68196847a3
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xa75726b8da54532d
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 1, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xa0a8acf29cc30b6e
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x7cb91e50e28c32df
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 6, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x4791972b462a68cb
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x9e6551bb711f536c
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xe1acea4fe8f7407b
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, 14, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xdb570ab3a9fae3d8
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xf39986dcc02503f3
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x36a73e1a21d20a60
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, 3, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x5c60d36d74d4849f
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 7, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xa5f1f9c472e360dd
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -15, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xc96a237dbbd90aa1
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x91ea45e567c151b6
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, -12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x75c70439ce7af629
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x046d718279a3e155
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xdcd4a5291086dc9e
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, -13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xc777004e602675bc
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, 2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xebca80e15b5b455f
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -6, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xe5e619897f2b6d35
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -3, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x19490358796b3a1f
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x774d5c09e848895b
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -11, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xf5566f59d29f9cfa
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 6, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xfc9f1bdeb01bb3ce
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 11, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x13009b678743af01
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x8699983e77387e64
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -11, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xb842a1dc564a8495
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, 1, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xef62ecd1ef98534e
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x3d48590ebd6bdd2d
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xe98f29d11848a823
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x90a8403915721bb2
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -6, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x6daad11d62f9e081
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -4, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xa174f4758339c969
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 4, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x84e4cc55ea13fbea
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x970e213b24fa6f03
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 7, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xdaacf47d90551d67
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, 15, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x64ebab143e06463d
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x53011796fa4319ef
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, -6, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xf2eeb3614dc89de9
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x73a45a06a2e888ac
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x332abde7cdd7f0cd
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -15, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xf02aaa053230b1fc
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xc12954b4c14257ef
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 0, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xe4b1cd553fa29d66
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -1, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x558b51b61f119373
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xe4e423d4daabb3c5
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x84aaa295ff54fdf3
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x3eddf0ae354c913a
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 15, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x6fab17e653c64172
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -5, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x0843cff0135c3ac1
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -5, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x0e987155b0f6b609
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, -15, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xe9ff42b126c7ebf0
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -4, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xb56c719b8542432d
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, 9, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v12, v21, v28, v0

  li t2, 0x87194e5c9ecc59fb
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v26, v7, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v11, v18, -11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v6, v14, v20, v0

  li t2, 0xe613849faa9b2b90
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v2, v21, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v5, v28, 5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v24, v21, v10, v0

  li t2, 0x3e149925af1fbc44
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v16, v31, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v15, v28, -9, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v14, v31, v27, v0

  li t2, 0x49e5176ffaf227d7
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v17, v10, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v6, v3, 14, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v26, v13, v3, v0

  li t2, 0x708bb305b85933cd
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v21, v2, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v31, v17, 10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v23, v15, v1, v0

  li t2, 0xbbe4675ac2f73687
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v2, v12, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v11, v27, -5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v23, v18, v30, v0

  li t2, 0x4b8d34ed90520357
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v10, v22, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v3, v16, -7, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v14, v22, v10, v0

  li t2, 0xe2cae101b522469e
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v28, v13, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v1, v29, 12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v17, v19, v8, v0

  li t2, 0x41dcb78b823b017c
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v22, v16, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v6, v27, 11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v17, v31, v26, v0

  li t2, 0xc71ec4e944a63b58
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v28, v9, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v8, v21, 12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v20, v21, v1, v0

  li t2, 0x4170a6fb4b3c132d
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v24, v6, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v13, v1, -15, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v4, v2, v26, v0

  li t2, 0xc5601aa977740d32
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v15, v23, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v15, v20, -14, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v13, v19, v9, v0

  li t2, 0x64440c914cc1e354
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v14, v11, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v9, v20, 0, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v6, v25, v27, v0

  li t2, 0x4521f1be84b632c6
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v14, v13, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v25, v7, 12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v8, v16, v29, v0

  li t2, 0xf17a23bfa3d8659d
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v4, v16, -8, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v30, v24, v20, v0

  li t2, 0x159f4d3f215e44a0
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v22, v8, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v30, v19, 2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v3, v6, v4, v0

  li t2, 0x066deb6f5693405c
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v15, v27, -12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v8, v30, v27, v0

  li t2, 0x850822d813367b00
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v14, v12, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v18, v11, 3, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v11, v25, v2, v0

  li t2, 0xb32f8abe72c7710f
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v6, v28, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v4, v19, 10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v7, v4, v10, v0

  li t2, 0x5f499a61072e063d
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v27, v14, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v24, v27, -6, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v30, v26, v21, v0

  li t2, 0x8d6ac84bdf577427
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v4, v5, 6, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v23, v1, v19, v0

  li t2, 0x54e56966650bc5c4
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v31, v11, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v5, v27, -7, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v28, v23, v19, v0

  li t2, 0x46bf2ecbe9dd9026
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v31, v23, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v31, v13, 0, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v18, v5, v29, v0

  li t2, 0x14b2c6bbcb92ff06
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v2, v29, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v8, v31, 10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v6, v23, v14, v0

  li t2, 0x24ed46eb3d9681a9
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v18, v23, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v20, v29, 14, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v13, v14, v3, v0

  li t2, 0x48aac9ae0e8a4675
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v5, v14, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v23, v28, -1, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v2, v10, v13, v0

  li t2, 0xfe4f3a98a2e1c588
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v20, v30, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v24, v16, -12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v22, v18, v11, v0

  li t2, 0xf82bb1f38be461da
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v3, v1, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v4, v16, -12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v1, v11, v6, v0

  li t2, 0x7276d24840b72a3b
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v11, v9, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v6, v8, 5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v12, v11, v7, v0

  li t2, 0x3a17faed350380d4
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v31, v22, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v1, v24, -8, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v23, v21, v13, v0

  li t2, 0xea47639654b6a4bf
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v21, v30, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v22, v26, 12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v27, v29, v31, v0

  li t2, 0x0c4b0319413b8715
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v17, v6, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v4, v3, -3, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v10, v3, v20, v0

  li t2, 0x9d9019c3d6cd0119
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v2, v30, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v27, v30, 5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v25, v2, v15, v0

  li t2, 0x6f753cdcf034594a
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v19, v8, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v6, v26, 7, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v1, v20, v13, v0

  li t2, 0x9a9d74effa067e3b
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v27, v3, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v12, v13, -9, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v20, v13, v12, v0

  li t2, 0x4ef24e2f13a88f78
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v14, v17, -10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v10, v13, v27, v0

  li t2, 0x44ae7c6e7f0ccd63
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v27, v22, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v17, v20, 3, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v8, v11, v22, v0

  li t2, 0xd0d60872055b998b
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v1, v3, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v11, v16, -11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v30, v24, v23, v0

  li t2, 0xcf7c83e0f9dc6f26
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v30, v18, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v30, v14, -3, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v16, v26, v19, v0

  li t2, 0x58b7fe2e8163d69c
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v21, v25, -8, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v6, v11, v10, v0

  li t2, 0x994e4dc6abdeccea
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v21, v2, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v7, v3, 4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v2, v28, v29, v0

  li t2, 0x4bb1bd097aa8c7c5
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v22, v24, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v5, v6, -3, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v14, v20, v28, v0

  li t2, 0x28405b08b05a16e7
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v6, v29, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v5, v8, -4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v20, v10, v30, v0

  li t2, 0x01f006140dd89778
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v10, v26, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v22, v6, -9, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v4, v7, v15, v0

  li t2, 0x8d2a5535c38ff034
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v5, v20, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v8, v23, -5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v8, v31, v16, v0

  li t2, 0xb8308252f24ca636
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v5, v23, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v23, v1, -16, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v14, v6, v10, v0

  li t2, 0x74e6fd1673c2691c
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v30, v1, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v14, v11, 11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v27, v30, v8, v0

  li t2, 0x9f858bfbc5c20966
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v14, v10, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v25, v15, -10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v18, v3, v2, v0

  li t2, 0x84d747dbd0e01bba
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v27, v9, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v4, v31, -13, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v12, v5, v10, v0

  li t2, 0xbd9f21d8c61c5259
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v1, v31, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v13, v14, 7, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v14, v13, v8, v0

  li t2, 0xb115e89c3b590d2d
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v27, v22, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v5, v26, 10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v16, v12, v3, v0

  li t2, 0x5d7c2444136194e6
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v25, v13, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v30, v29, 7, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v28, v3, v14, v0

  li t2, 0x646db3ab61dfa7a4
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v30, v6, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v31, v4, 4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v27, v15, v5, v0

  li t2, 0x35f1b0c3af053fd4
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v22, v12, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v10, v27, 8, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v23, v31, v24, v0

  li t2, 0x4f28a1bd42c5ec61
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v1, v27, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v7, v22, -15, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v31, v5, v30, v0

  li t2, 0x3ed781253296fd5c
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v17, v4, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v30, v1, -16, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v7, v13, v12, v0

  li t2, 0xb9e129d84a48a8f9
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v30, v16, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v3, v2, -14, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v17, v3, v16, v0

  li t2, 0x95053c5cb468d6b6
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v31, v27, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v29, v31, -13, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v2, v31, v6, v0

  li t2, 0xdc2fc2bf483e0663
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v17, v4, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v3, v10, -4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v24, v6, v30, v0

  li t2, 0x492a05375a940831
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v10, v5, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v28, v20, 4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v24, v7, v29, v0

  li t2, 0xae36a18ebd6a8df2
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v3, v14, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v29, v13, 2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v5, v2, v17, v0

  li t2, 0xd27e80766b0079b6
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v6, v2, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v5, v25, -2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v26, v23, v16, v0

  li t2, 0xaabbb758ddb5a6ff
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v30, v20, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v15, v14, 10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v25, v14, v9, v0

  li t2, 0x89769404bac5b305
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v28, v7, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v28, v14, 9, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v9, v7, v4, v0

  li t2, 0x78381d310b8d2fbd
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v10, v25, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v12, v25, 1, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v25, v2, v14, v0

  li t2, 0x1af6d3eb8ea36507
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v11, v14, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v4, v19, 1, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v13, v9, v15, v0

  li t2, 0x7f88d9a3a2097b03
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v27, v12, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v28, v27, -7, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v2, v1, v13, v0

  li t2, 0xabc7d20cf35a4baf
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v23, v16, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v17, v6, 12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v13, v23, v5, v0

  li t2, 0x46be7083377dd46b
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v25, v5, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v9, v20, 4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v4, v7, v28, v0

  li t2, 0xe6ad0087f9c4a289
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v31, v18, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v26, v2, -2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v5, v6, v24, v0

  li t2, 0x8c7f88dd1593e604
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v25, v9, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v8, v9, -7, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v20, v7, v5, v0

  li t2, 0xd95aab383d10167a
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v26, v21, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v9, v3, 4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v30, v9, v28, v0

  li t2, 0xe3e2fd209ec04c64
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v19, v24, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v22, v25, 9, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v17, v24, v14, v0

  li t2, 0x3e14274910e11709
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v21, v4, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v27, v8, 14, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v31, v30, v26, v0

  li t2, 0x9d1c9d6af2c06faf
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v19, v23, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v29, v18, 9, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v20, v17, v15, v0

  li t2, 0xdc6c106c6e2388bb
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v4, v27, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v16, v22, -15, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v13, v1, v18, v0

  li t2, 0xd714b1d336439dce
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v6, v20, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v1, v18, 15, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v20, v9, v28, v0

  li t2, 0x2f8a59db876f21b7
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v22, v29, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v20, v21, -16, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v27, v15, v6, v0

  li t2, 0xa996959f3b13a553
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v1, v27, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v23, v9, 1, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v31, v9, v14, v0

  li t2, 0x3138eea642a23095
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v7, v28, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v31, v6, -16, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v17, v14, v12, v0

  li t2, 0x138074426e93b25d
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v2, v19, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v26, v31, 12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v10, v27, v20, v0

  li t2, 0x8ceaec16a425f5c2
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v19, v17, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v22, v25, -2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v30, v22, v2, v0

  li t2, 0x3d916fcadc904d54
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v8, v19, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v2, v24, -14, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v31, v14, v3, v0

  li t2, 0xf67f4740d7601b5c
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v17, v21, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v25, v21, 4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v5, v24, v3, v0

  li t2, 0x61cdc82e648fdec7
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v23, v18, -5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v29, v24, v13, v0

  li t2, 0x6633868221fab3ea
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v24, v13, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v29, v17, -5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v17, v7, v10, v0

  li t2, 0x0a36f53a2ddef5bc
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v29, v10, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v14, v20, -14, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v26, v15, v29, v0

  li t2, 0xe5199d39b7eb7dea
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v24, v10, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v18, v19, -13, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v13, v24, v4, v0

  li t2, 0x7671837c784a3e61
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v14, v24, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v23, v8, 5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v2, v29, v7, v0

  li t2, 0x1c6822846b4cf79c
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v25, v15, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v4, v6, 13, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v22, v28, v14, v0

  li t2, 0xb0fbfacd96537e8b
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v9, v19, 13, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v28, v5, v17, v0

  li t2, 0xbe62113bcc268593
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v12, v6, 12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v15, v13, v26, v0

  li t2, 0x9ebaad2367b0638d
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v2, v4, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v24, v14, -8, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v21, v3, v28, v0

  li t2, 0xa754537e25abe882
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v16, v17, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v5, v14, 0, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v20, v1, v5, v0

  li t2, 0x4062a07343ffce02
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v5, v15, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v31, v13, -4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v25, v22, v16, v0

  li t2, 0x85c5c792847c5ec6
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v1, v28, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v12, v20, 14, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v11, v27, v8, v0

  li t2, 0xe257bc0a4a2c1d50
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v30, v1, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v29, v17, 8, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v14, v7, v25, v0

  li t2, 0xb0bde9d2ab2e5599
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v9, v5, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v14, v17, -7, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v10, v13, v2, v0

  li t2, 0x4ffd7f5712a30f28
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v15, v3, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v4, v7, 3, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v8, v27, v28, v0

  li t2, 0xf4ba4c7117f6666e
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v29, v13, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v9, v29, 6, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v14, v30, v0

  li t2, 0x2e1fce9700c36f0d
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v12, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v12, v18, 8, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v4, v8, v6, v0

  li t2, 0x3e1c3dc094e2536f
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v18, v4, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v12, 3, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v10, v20, v0

  li t2, 0xa8599f0af474859b
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v4, v6, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v26, v10, -4, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v2, v20, v18, v0

  li t2, 0xf89be39a19eecf05
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v12, v18, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v20, -10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v4, v28, v20, v0

  li t2, 0x6c08366b8f3fffa9
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v6, v2, 9, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v8, v22, v12, v0

  li t2, 0x29323c469ad51604
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v30, v8, 3, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v2, v12, v20, v0

  li t2, 0x4f1e4d001a9bb1a5
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v30, v6, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v18, 8, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v24, v2, v6, v0

  li t2, 0x93b0cdb23bc70d6f
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v20, v4, 7, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v16, v8, v0

  li t2, 0x95ce8d50e639c497
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v18, v10, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v4, 10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v26, v18, v0

  li t2, 0xf75e8dddd32c9674
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v22, v26, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v28, v16, 5, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v16, v28, v0

  li t2, 0x2e8e5c2666087892
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v12, v26, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v14, v28, 0, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v20, v10, v0

  li t2, 0x6dd7fb90d98a6a1e
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v30, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v10, v20, -12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v4, v16, v0

  li t2, 0xe707e86bbc846b33
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v14, v28, 6, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v18, v10, v28, v0

  li t2, 0xdec35b70221207e9
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v22, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v20, v26, 8, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v20, v24, v16, v0

  li t2, 0x5a320b98025cb245
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v22, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v12, v4, -8, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v6, v20, v10, v0

  li t2, 0xc04bcf6e27953bdf
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v18, v6, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v2, v16, 7, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v6, v14, v4, v0

  li t2, 0xa0161e17061af928
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v18, v6, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v12, v14, -3, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v4, v16, v8, v0

  li t2, 0xccf327adb252c48c
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v30, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v20, v16, -12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v6, v16, v18, v0

  li t2, 0x767cd811ff3a8ee7
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v10, v24, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v14, 15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v20, v24, v0

  li t2, 0xa0c5e049a1bb6732
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v22, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v12, v30, -4, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v22, v2, v12, v0

  li t2, 0x10c2fe825f490c9b
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v30, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v22, -2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v24, v6, v12, v0

  li t2, 0x8064029c2b559230
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v28, v10, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v2, 11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v24, v4, v8, v0

  li t2, 0xb186c3757fe62121
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v10, v12, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v18, 0, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v22, v20, v0

  li t2, 0xb895c172819ab20f
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v22, v10, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v4, 1, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v26, v4, v2, v0

  li t2, 0x14ec0dc768543f10
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v26, v28, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v4, v28, 8, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v6, v20, v0

  li t2, 0xa24a600fe6cc14a8
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v14, v22, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v10, v26, -1, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v28, v10, v0

  li t2, 0x8b718772cb88331f
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v12, v2, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v4, v16, 11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v24, v20, v8, v0

  li t2, 0xf480bebac98f69b8
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v2, 15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v16, v26, v2, v0

  li t2, 0x32e4e610d8aa15e4
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v16, v10, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v22, -5, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v22, v4, v8, v0

  li t2, 0x2e43e6d02ce37246
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v14, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v28, v12, 9, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v30, v26, v28, v0

  li t2, 0xcebd4d276605854a
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v22, v6, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v10, -16, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v24, v4, v14, v0

  li t2, 0x0f8c14bb5bf1d1f9
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v18, v10, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v4, v18, 5, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v8, v28, v6, v0

  li t2, 0xb2cd94abb92c0b6b
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v10, v20, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v12, -7, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v12, v18, v14, v0

  li t2, 0xe793ce01a5ccb411
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v4, v30, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v4, v26, -15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v4, v12, v0

  li t2, 0xebe36cc85a88d322
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v14, v10, 6, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v22, v4, v8, v0

  li t2, 0x1e2af307378b4927
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v22, v4, 7, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v8, v4, v18, v0

  li t2, 0x504ddafe1c1642d9
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v14, v24, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v14, 15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v16, v30, v4, v0

  li t2, 0x3cb6e24f2481d6cd
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v10, v22, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v12, -4, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v22, v8, v12, v0

  li t2, 0x7d64f406ca30e848
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v12, v24, -2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v18, v12, v0

  li t2, 0x87a3366b6a4659a8
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v2, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v30, 8, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v30, v12, v14, v0

  li t2, 0x4375b40685b94847
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v4, 7, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v12, v18, v0

  li t2, 0xe2e0321c0455e637
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v20, v28, -1, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v4, v12, v2, v0

  li t2, 0xcad23bdfc326669d
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v18, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v2, v12, 7, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v6, v26, v16, v0

  li t2, 0x0d74ac2686c620b3
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v12, v22, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v12, v20, -3, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v18, v14, v10, v0

  li t2, 0x2242e19375036ce7
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v20, v24, -7, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v8, v20, v26, v0

  li t2, 0x887d80f23f80b597
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v30, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v14, v4, 8, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v22, v6, v14, v0

  li t2, 0x76d12f042c89b2a6
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v26, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v28, v8, 13, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v20, v28, v24, v0

  li t2, 0xcadcb8e00363f85d
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v18, v24, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v2, -6, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v8, v26, v20, v0

  li t2, 0x208c148556536c5a
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v12, -16, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v8, v18, v16, v0

  li t2, 0xa0fd63d3c9fa8571
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v30, -1, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v26, v24, v6, v0

  li t2, 0xa0b03daa473bac06
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v6, v4, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v22, v6, -8, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v8, v14, v0

  li t2, 0x68f28e492e241c4c
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v28, v2, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v30, -10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v24, v20, v0

  li t2, 0x98765d0d58459ca0
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v16, v6, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v4, v30, -4, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v24, v4, v0

  li t2, 0x848ca0d417f26cb4
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v26, v6, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v6, v14, -2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v20, v30, v26, v0

  li t2, 0x8cb29c5b1bbda720
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v22, v14, 12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v30, v22, v28, v0

  li t2, 0xd76174290db8ee98
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v20, v26, -8, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v12, v6, v0

  li t2, 0x21caf20baf7cd1ed
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v26, v22, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v22, 5, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v22, v12, v2, v0

  li t2, 0x1bd2d0a27aebe3b0
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v22, v18, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v20, -11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v2, v6, v0

  li t2, 0x86b7598b7fe5fadd
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v26, v4, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v20, 11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v20, v4, v16, v0

  li t2, 0xe849e1031c63f19f
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v12, v10, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v20, 15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v8, v28, v0

  li t2, 0xab238cf67a07e04e
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v8, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v12, 7, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v12, v24, v0

  li t2, 0x13534adc8a6f1338
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v22, v10, -8, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v4, v20, v12, v0

  li t2, 0x877764cd619c3c84
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v14, v12, -9, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v22, v6, v2, v0

  li t2, 0xc6b32003dafeb53a
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v6, v12, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v10, v14, 15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v22, v26, v24, v0

  li t2, 0x489cbb123bcaa5b2
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v4, v18, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v14, -10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v8, v10, v2, v0

  li t2, 0x343e397f73b6b879
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v14, v8, 6, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v4, v2, v0

  li t2, 0x855b7ac1f88b7d09
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v16, v18, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v6, v14, 12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v6, v4, v0

  li t2, 0x317dad4427786afc
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v6, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v22, v24, -10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v30, v20, v4, v0

  li t2, 0x143ad7bcdf7d768f
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v20, v18, -12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v30, v16, v10, v0

  li t2, 0x8cfc87e4d170cf5c
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v14, v4, 3, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v26, v12, v0

  li t2, 0x95a74fec124ab615
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v28, v22, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v20, v4, -11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v18, v2, v24, v0

  li t2, 0x3d7c2b0a62231375
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v16, v18, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v20, -10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v22, v18, v24, v0

  li t2, 0xb63df94aa4df7778
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v18, v24, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v30, v8, 14, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v30, v24, v14, v0

  li t2, 0x7f1bb2954628ff71
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v22, v2, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v4, v28, -3, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v30, v2, v0

  li t2, 0x0a0bc72bc09817f3
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v22, v2, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v14, v10, 9, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v18, v8, v0

  li t2, 0xd6d6753b29d3841b
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v14, v2, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v12, v10, 15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v20, v2, v18, v0

  li t2, 0x13a099127886efe9
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v28, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v28, v30, -16, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v26, v18, v10, v0

  li t2, 0xc6f43ebc2b8db9f4
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v4, v16, -11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v26, v14, v6, v0

  li t2, 0xe6773124c4074b5c
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v14, v12, 1, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v2, v8, v24, v0

  li t2, 0xd92ee2bbf1f943f4
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v6, v18, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v20, v4, -11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v12, v2, v4, v0

  li t2, 0xf350f64064ecf98c
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v14, v22, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v6, v16, 14, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v16, v18, v28, v0

  li t2, 0xc239445a2e852cc6
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v6, -11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v4, v22, v8, v0

  li t2, 0xb82a3a30b960b6a5
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v28, v26, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v14, v4, -15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v2, v26, v4, v0

  li t2, 0x48699fd5e035571c
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v10, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v30, 10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v20, v30, v28, v0

  li t2, 0xb5d5970122e41c7f
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v2, v28, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v30, -3, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v18, v24, v0

  li t2, 0xbb2b60703b6cdf9d
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v10, v18, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v14, v2, -13, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v14, v4, v0

  li t2, 0x55cb4e347cc8faf3
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v16, v10, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v12, -10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v6, v26, v4, v0

  li t2, 0xf2718fee35884e96
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v22, 12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v6, v30, v8, v0

  li t2, 0xe94060dc4329b879
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v16, v10, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v6, v20, 2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v4, v12, v24, v0

  li t2, 0xf3f865c6f9aa8727
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v26, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v30, v6, 13, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v30, v10, v26, v0

  li t2, 0xdd5a76d3a0ceecf4
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v14, v6, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v14, 4, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v24, v18, v0

  li t2, 0x85bcaa631d851693
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v26, v20, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v26, v16, -10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v22, v12, v28, v0

  li t2, 0x5256680898cbb196
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v24, v30, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v6, v30, -7, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v20, v8, v12, v0

  li t2, 0xb07833bbdd1e69a3
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v22, v28, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v10, v16, 1, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v18, v6, v0

  li t2, 0xcb12029af9c57e12
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v26, v28, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v24, -15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v24, v18, v4, v0

  li t2, 0x59a9972bdd276968
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v18, 1, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v24, v8, v0

  li t2, 0xfa1ae415789ca635
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v6, v28, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v14, v28, -14, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v30, v12, v6, v0

  li t2, 0x852e9060e924c487
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v2, v12, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v16, -14, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v28, v26, v0

  li t2, 0x0bb8968323cef3c4
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v10, v8, -13, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v24, v30, v6, v0

  li t2, 0xb1135f915acdbf0a
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v26, v2, 7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v8, v28, v0

  li t2, 0x3a75143662916dd1
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v28, 4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v12, v20, v0

  li t2, 0xae0153a965f354cc
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v4, 13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v20, v4, v0

  li t2, 0xeda0f30eb228b0a3
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v12, 11, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v20, v12, v0

  li t2, 0xe74ec6882a370da1
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v4, 4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v12, v4, v0

  li t2, 0xb328eb0e11a17572
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v28, -3, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v4, v16, v0

  li t2, 0xf1a05067a9ed0c5c
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v24, -15, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v8, v28, v0

  li t2, 0xf673a94abd8f19fd
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v20, 9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x83f01f662e02fd2b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v28, 12, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v12, v16, v0

  li t2, 0x857be91f6bdf2183
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v28, 4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v28, v4, v0

  li t2, 0x52853dbd6ad2e550
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v20, -6, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v16, v4, v0

  li t2, 0x7329036ea2a5b209
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v12, 4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v24, v28, v0

  li t2, 0x9c9d27ec635b3b9b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v12, 11, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v20, v28, v0

  li t2, 0x0c59e35d441ce47b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v24, -9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v4, v16, v0

  li t2, 0xfadc9e6500798f97
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v28, 14, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v4, v12, v0

  li t2, 0x3b3246164ae9dda8
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v4, 0, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v4, v16, v0

  li t2, 0x0f2c41905db8353c
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v12, 10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v16, v28, v0

  li t2, 0xf5d743e8583eae1b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v16, 2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v28, v4, v0

  li t2, 0x76ec7e1f6710d1dd
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v16, -3, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v20, v12, v0

  li t2, 0xe21f042c8915e340
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v16, 15, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v24, v20, v0

  li t2, 0x0886ec4201b8ce24
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v20, -4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v8, v4, v0

  li t2, 0x1dc927553f7c6faf
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v12, 1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v24, v16, v0

  li t2, 0x6ab316e7062300a0
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v4, 10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v28, v8, v0

  li t2, 0x404e18fb0b3554b4
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v8, 7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v16, v20, v0

  li t2, 0x7882ae94e858bfe7
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v24, -2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v8, v20, v0

  li t2, 0x7ca553ba22c6fad6
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v4, -13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v8, v16, v0

  li t2, 0xf631fb0ac4fdc882
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v8, -1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v28, v4, v0

  li t2, 0x46cab53731b4d656
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v12, 6, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v28, v12, v0

  li t2, 0xeab99038f5b65ee4
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v24, -16, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v20, v16, v0

  li t2, 0x782c3bc3c7ee1bd6
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v8, 5, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v4, v24, v0

  li t2, 0xf7bf566f96636669
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v24, -4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v24, v20, v0

  li t2, 0x63b4f587a7b9a4d2
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v8, 13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v12, v4, v0

  li t2, 0xde2d95e97b0bfc1e
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v20, 3, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v16, v24, v0

  li t2, 0xf58e667c4c3b7e43
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v8, -15, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v4, v20, v0

  li t2, 0x7323cbbc6ea9ff6a
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v28, 5, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v4, v28, v0

  li t2, 0xaf165006f68f765e
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v4, 9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v4, v8, v0

  li t2, 0xdde0e7dabfe64d2f
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v12, -16, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v20, v8, v0

  li t2, 0xb42c9916b9ce8914
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v24, -5, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v12, v4, v0

  li t2, 0x35bc239c34caee1a
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v28, 11, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v20, v12, v0

  li t2, 0x95365f57fe0edb35
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v24, -1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v8, v12, v0

  li t2, 0x22b15edcb3c46537
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v20, -6, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v24, v8, v0

  li t2, 0xfae68c1ba7c98068
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v8, -13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v12, v16, v0

  li t2, 0xed499a7181f3dab9
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v8, -9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v8, v28, v0

  li t2, 0x3c832d22e2d99035
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v8, 7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v24, v4, v0

  li t2, 0xad6ecd0b1f97b21b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v20, 1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v12, v16, v0

  li t2, 0x87d687ed386f0b45
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v4, -1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v12, v20, v0

  li t2, 0xe8332d42e40a3ca3
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v24, -7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v16, v4, v0

  li t2, 0xfa65399ddd4e5b02
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v4, -4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v12, v4, v0

  li t2, 0x858266c2f9c8e7dd
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v20, -7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v16, v20, v0

  li t2, 0x3aba1714cc750b3e
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v20, 4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v8, v16, v0

  li t2, 0x5f343d0e396db232
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v12, 5, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v28, v20, v0

  li t2, 0x8975dd4f2f40db20
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v4, 9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v8, v28, v0

  li t2, 0xcf7a0e3917488b2f
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v16, 13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v12, v28, v0

  li t2, 0xaddb8d0af55150d1
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v12, -13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v4, v24, v0

  li t2, 0xca5b7f2ded45a405
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v4, 15, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v12, v8, v0

  li t2, 0xe5320dc0b0e459d5
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v16, 6, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v24, v28, v0

  li t2, 0x1cc5ad17eb31f030
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v8, 8, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v28, v20, v0

  li t2, 0xbdf150ca23e72f46
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v12, -9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v28, v8, v0

  li t2, 0xc7690c6d0cc259dd
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v16, 11, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v20, v28, v0

  li t2, 0xafa0942087ea7334
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v12, -12, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v20, v8, v0

  li t2, 0xbf0feb04365bb499
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v4, 11, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v12, v8, v0

  li t2, 0x7d8e8dff6d440af5
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v12, 8, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v16, v8, v0

  li t2, 0xd8351412ee2bc54c
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v20, 11, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v24, v8, v0

  li t2, 0x3ed391949b4aa553
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v12, -15, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v24, v28, v0

  li t2, 0x30332d0328e0c64e
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v4, -6, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v4, v24, v0

  li t2, 0x3bd1bd85b9deb02a
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v12, -5, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xf6f6a4756d01e2fd
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v8, 12, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v28, v20, v0

  li t2, 0x9b4ecdf3cd670c9c
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v20, -13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v28, v8, v0

  li t2, 0x707a54f8efe444af
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v16, -7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v20, v16, v0

  li t2, 0x459aebb2af404a50
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v8, 8, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v28, v20, v0

  li t2, 0x05ea895abe03aee4
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v28, -15, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v8, v28, v0

  li t2, 0xae9d58efe27a4b36
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v12, 10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v28, v24, v0

  li t2, 0xacb2a02fb4a73c58
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v16, -14, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v4, v8, v0

  li t2, 0x651e439f1d4069f3
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v28, -4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v20, v24, v0

  li t2, 0x0d24baee015a9be0
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v8, 14, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v28, v20, v0

  li t2, 0x92005175250becc9
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v20, 10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v20, v24, v0

  li t2, 0x41c9a0b77b752e8a
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v20, -6, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v20, v4, v0

  li t2, 0x3e258169a5c6ef84
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v4, 10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v12, v4, v0

  li t2, 0xeca3763c653be279
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v8, 5, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v12, v28, v0

  li t2, 0x05aa74eeaa74f42c
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v28, 12, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v4, v24, v0

  li t2, 0xb0e26b8652a6390b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v4, 14, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v16, v24, v0

  li t2, 0xdaea2b7d7424081b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v28, -12, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v12, v4, v0

  li t2, 0x08d1c72ed8ec56d9
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v4, 12, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x617ee71e6e739058
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v24, 1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v12, v4, v0

  li t2, 0x3cff5e7d8cf774e7
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v28, -10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v12, v16, v0

  li t2, 0x680bcefea885189c
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v16, 9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v12, v20, v0

  li t2, 0x7037e3f0b3571d89
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v12, -10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v12, v8, v0

  li t2, 0x28b0004ffc78d31f
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v20, 0, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v16, v4, v0

  li t2, 0x5d2296561fee60b8
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v24, -14, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v16, v4, v0

  li t2, 0x1bd2669ccd5f1a7c
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v24, -10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v20, v24, v0

  li t2, 0x4ce0a4aecd50ba48
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v20, -1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v16, v24, v0

  li t2, 0x140917180d87a102
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v8, -12, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v16, v4, v0

  li t2, 0xc7bf472fa6031728
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v20, -13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v8, v20, v0

  li t2, 0x99104181299c8389
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v24, 12, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v16, v20, v0

  li t2, 0x43331a8b46f4794b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v20, -3, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v20, v4, v0

  li t2, 0x7a593cf0fe2639c2
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v16, -10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v4, v28, v0

  li t2, 0x856620361380ce5b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v16, 11, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v12, v4, v0

  li t2, 0xc8c4ca55a0cccf2d
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v12, 14, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v28, v20, v0

  li t2, 0x2244c9b783b8e4a4
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v12, 7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v20, v24, v0

  li t2, 0x979df979d6264e45
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v28, -14, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v28, v16, v0

  li t2, 0xade7ea822e370a94
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v4, 2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xfb48d46f6fd11527
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, -8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x1a39d52812b4a7f7
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x145ebbfc54120656
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 15, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xeae4a6ea1efe3c7b
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, -15, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x0a16ec3f85d11a81
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 0, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xbb77300a398d5d07
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 15, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xe5530ceb4d658904
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 1, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x6387e166cef0b48f
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, -4, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x42c244def3860b75
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 3, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x3998be80b7f7aa66
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 0, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x5779ffeed5c7432e
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x985a8e1138241412
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -3, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x8a6cd2489f089726
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, 11, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x14989d1e1837aab3
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 11, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x48515b95a4268355
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x5b11fa6d6d07651d
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xc7cc31f3f9d4b5b6
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -10, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x20284e0fa9c0c28e
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x1995470864cd73fa
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, -6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x86dffc5fd5f9bbbb
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xefbae6f006763d2f
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x31c3c38a2687a710
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x60eea951f3d823ef
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x4393a376155daa12
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x2b8205ab0e0d09a3
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -12, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xe8c3735fdeeee11d
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, -1, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x0b4a9759df4e38f5
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 1, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xdb8bbc7b0f6872da
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 4, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x10980494ad4fee4a
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 11, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x9c33cc333877ad63
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x9854f5f5c0de6ad8
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -12, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xf1f1c0ef0b68b4db
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, -10, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x7ad43cff5b0177d9
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x5cacf54fb4af55e6
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, 2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x643e113fa2cafb52
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x4a81b6164115e454
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xac3ce168691d3328
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, -4, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x78f71ab5207748a0
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x398630b586deac11
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -13, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xa2cdb2eb89a3680c
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, -12, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x28762b93f5fbd6f8
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, -8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xc19135e01e5238d0
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 11, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xbfb7e6a9bf5b0a2b
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xe96e8985ddd28134
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 13, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xbcf6de02259ab2fa
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xca11d627538cc95e
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 4, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x327202a6687d1682
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, -2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xdfa03abb9347d374
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x3773905b0820736d
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -1, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xea03bdf38ddfdeaa
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 0, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xb0d228edb8c25be0
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x3b213944fca9c93e
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 10, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x6ebecc04b7dc5d3e
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xb9735cfe60b6c6a5
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 3, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x84d3e8cb450cb0ef
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x0a82a70b6d4f7e07
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, -1, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x714c77cf4b6d88d5
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 15, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xdad0416bb8dac85b
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, -12, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x39de6df9c1a81d74
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xc7d3b5ad3e0ae3a3
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, -1, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x302562d9f943c97a
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 0, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xe6bb2178e8734bc6
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, -9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xef5cc7964832b34f
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, -6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xe25fa3d2d7fbb908
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xc85478a2842525e7
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 12, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x5db08b0452f20197
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xa2528dcb4d37ceba
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 15, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x1bdefd2aafd2c45d
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x1baffb62998715ca
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -16, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xf78a96cbe7c7ec7c
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xa192cfda5ebddece
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -12, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x2ba023fc1f788848
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x032628ec3bcbac2e
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 14, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xbb398dce9f290473
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 0, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x668be2f03cdfd57b
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -13, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x8a999498ae8a7151
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 0, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xb76cb57b39b1dbe5
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xe24933d62c53cb4a
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 15, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x3a3bfccced146bd8
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x103a1a538eafa41d
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -12, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x6c26fbe1c4d9a4cb
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 11, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x6f1c6ddcaa48ea84
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x6d52353971f122ce
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, -6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x697c97bfae0c4fcc
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, 12, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x7a34fe9e51f87bcc
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -13, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x5c5381a7e61442e8
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 12, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xb08b9c6fb1a01bd7
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, 4, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x48a2d9abacf4eac8
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x0b6cab301dc9b10a
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, -5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x0ce02934ec92ba4e
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, -13, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x1cfa6d40444e7061
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, 5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x6ba19e4f33d96a85
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x24dfea7923df44ae
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 0, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xe5e46f1e856e26a6
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xfefab5bcfbbc53c1
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, -7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x644321693ad3c9bb
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, -16, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x79a5741793f4bd59
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 13, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xaa308c06b03e14cb
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 12, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x48fd6fc9c431598d
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 13, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xb37c65883b36a7ba
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 7, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v30, v5, v22, v0

  li t2, 0xbc037333bd2d5aa5
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v6, v17, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v22, v9, 13, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v20, v17, v24, v0

  li t2, 0x188935da3345bf72
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v25, v12, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v12, v21, -8, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v20, v24, v13, v0

  li t2, 0x774b562de8d780f8
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v12, v17, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v2, v20, 3, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v11, v18, v28, v0

  li t2, 0xc09357bb5a805036
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v5, v27, -7, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v18, v14, v11, v0

  li t2, 0xe6eb6811d32cac8c
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v23, v7, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v11, v4, 9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v14, v18, v2, v0

  li t2, 0x343fcfe72188a042
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v15, v21, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v25, v17, 11, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v15, v16, v14, v0

  li t2, 0x27172444dfdf021e
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v28, v18, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v11, v5, 14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v31, v9, v17, v0

  li t2, 0xdb803844b4e49e8c
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v30, v28, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v1, v26, -6, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v18, v17, v6, v0

  li t2, 0x275543bcdde49bcc
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v26, v8, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v24, v7, 9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v17, v10, v19, v0

  li t2, 0xf5bb836434b6896a
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v21, v14, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v25, v28, -13, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v20, v26, v17, v0

  li t2, 0x2ab3a179f8403ebb
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v6, v26, -3, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v15, v11, v17, v0

  li t2, 0xe9004d7e5b53c63c
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v19, v8, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v24, v20, -9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v20, v18, v21, v0

  li t2, 0xd9edc0a666aa8502
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v21, v15, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v25, v17, 6, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v12, v25, v15, v0

  li t2, 0x593ca44eb9999b6c
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v9, v15, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v3, v2, -3, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v7, v13, v21, v0

  li t2, 0xa4b7ac0f8ce1d7ba
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v22, v5, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v18, v17, 3, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v2, v3, v22, v0

  li t2, 0xb9daad162cb02841
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v10, v15, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v6, v29, 4, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v28, v27, v22, v0

  li t2, 0x2d578d5b7036ed38
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v13, v22, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v18, v6, -1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v29, v7, v13, v0

  li t2, 0x3c9a4cad044721e6
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v19, v23, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v6, v9, 1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v13, v10, v17, v0

  li t2, 0xfa771baf9b5abc0b
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v10, v29, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v23, v7, -15, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v26, v9, v21, v0

  li t2, 0x0ba82469a3684a89
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v19, v16, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v10, v30, 13, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v13, v16, v2, v0

  li t2, 0x72bfbdfe7f3243dd
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v10, v21, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v22, v27, -16, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v13, v1, v14, v0

  li t2, 0x3778369e242e9705
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v27, v17, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v5, v20, 12, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v25, v1, v5, v0

  li t2, 0xaebc03ee4742d95e
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v5, v26, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v6, v8, -12, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v14, v5, v26, v0

  li t2, 0x707e7b6c56eeaef2
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v26, v29, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v13, v7, 14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v13, v24, v20, v0

  li t2, 0x33cfbcf096bd97f4
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v1, v22, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v11, v30, -5, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v15, v6, v31, v0

  li t2, 0xa49db3a680641591
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v10, v11, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v10, v1, 15, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v31, v16, v17, v0

  li t2, 0xe4f7e3386f287993
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v30, v16, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v24, v27, -9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v16, v3, v10, v0

  li t2, 0x3ab3aa5a3b088cf6
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v13, v30, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v21, v22, -4, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v20, v15, v31, v0

  li t2, 0xc3684892df61f234
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v9, v27, 10, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v9, v28, v6, v0

  li t2, 0x7210d00bd58d4064
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v1, v24, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v19, v2, -7, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v17, v18, v5, v0

  li t2, 0x2b07e8a7525ecdb2
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v15, v8, -7, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v4, v11, v31, v0

  li t2, 0xdc9555fe0a0289b5
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v28, v26, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v26, v16, 5, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v20, v13, v6, v0

  li t2, 0xaf51d0060cc21fd7
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v24, v31, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v1, v26, 12, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v22, v9, v18, v0

  li t2, 0xd614aaa2944db13c
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v15, v25, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v8, v6, -9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v28, v25, v24, v0

  li t2, 0x51cbd704673600fa
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v13, v5, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v23, v15, 0, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v21, v11, v20, v0

  li t2, 0xffb47d88cd13dee7
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v31, v24, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v1, v28, -8, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v15, v19, v8, v0

  li t2, 0x8329d1972a4e8acd
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v3, v11, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v26, v19, 8, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v5, v16, v9, v0

  li t2, 0x87ad0b365a3a989b
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v3, v31, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v1, v19, 1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v16, v14, v17, v0

  li t2, 0xed6fa4c6befde50a
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v10, v29, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v3, v22, 5, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v8, v20, v17, v0

  li t2, 0x78fc64acba200171
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v29, v10, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v25, v9, -5, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v4, v12, v26, v0

  li t2, 0x6eccc914bc97df8e
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v8, v3, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v20, v22, 9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v28, v19, v24, v0

  li t2, 0x9ee5a8ad7b990c02
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v2, v30, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v21, v16, -4, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v1, v6, v27, v0

  li t2, 0x0f5a9987b7e6e7ff
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v14, v30, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v8, v12, -11, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v9, v15, v30, v0

  li t2, 0x6ef4a73cd6ad6754
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v5, v8, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v23, v19, -3, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v22, v26, v19, v0

  li t2, 0xac84cbd882d75149
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v30, v25, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v25, v22, -1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v25, v20, v15, v0

  li t2, 0x4503b2930dcd40e2
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v3, v30, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v10, v3, -10, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v26, v16, v2, v0

  li t2, 0x1e4599aa9249a829
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v28, v29, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v6, v4, 7, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v31, v16, v10, v0

  li t2, 0x909dfedb333bda72
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v7, v31, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v27, v17, -1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v28, v2, v1, v0

  li t2, 0x07ca5e346b19ddbf
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v12, v25, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v5, v14, 1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v18, v31, v25, v0

  li t2, 0xcfb11edd83613ca1
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v11, v3, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v18, v22, 9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v16, v14, v31, v0

  li t2, 0xa6f4037f4feef948
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v29, v30, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v30, v4, 6, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v6, v5, v12, v0

  li t2, 0xf15e6f2da5f3af8f
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v26, v15, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v28, v2, 9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v13, v17, v1, v0

  li t2, 0x3cc4fdd6eeceaf53
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v31, v19, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v16, v25, -3, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v10, v31, v1, v0

  li t2, 0x35e244f4d759919c
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v9, v26, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v21, v18, 14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v18, v30, v15, v0

  li t2, 0xe93ee45edf74dd35
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v16, v14, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v16, v12, -10, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v20, v27, v23, v0

  li t2, 0x3932e7c985f67490
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v17, v23, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v31, v5, 2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v20, v21, v19, v0

  li t2, 0x2f8cfe6ebc736891
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v19, v1, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v8, v9, 9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v15, v23, v26, v0

  li t2, 0xce72de5220c3807e
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v2, v4, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v29, v11, -12, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v15, v26, v4, v0

  li t2, 0xcf242b99723a524f
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v27, v14, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v9, v21, 12, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v20, v11, v7, v0

  li t2, 0x9ca950aec5a52a43
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v13, v22, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v27, v15, 4, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v24, v16, v21, v0

  li t2, 0xbd5ed3eac6cb24a1
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v27, v20, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v27, v30, 9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v15, v23, v12, v0

  li t2, 0x5b8d57f00e069030
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v21, v6, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v17, v14, 2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v27, v25, v19, v0

  li t2, 0xc400bfba244499de
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v24, v31, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v15, v21, -7, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v24, v2, v20, v0

  li t2, 0x01f6373b2d4ef35e
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v5, v14, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v20, v5, -9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v18, v31, v19, v0

  li t2, 0xdcf97141931506ac
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v10, v3, -3, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v22, v5, v27, v0

  li t2, 0xc037a36e3d2cf817
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v12, v22, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v27, v13, 13, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v17, v18, v8, v0

  li t2, 0xbb15f027b93cc70e
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v12, v14, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v18, v25, 1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v21, v10, v25, v0

  li t2, 0x093b75f5d11db718
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v8, v1, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v22, v27, 1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v17, v18, v27, v0

  li t2, 0x262d1a3e0a082803
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v10, v11, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v11, v18, -5, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v19, v18, v14, v0

  li t2, 0x055a3adf02fbcbf3
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v5, v2, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v4, v20, -15, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v13, v18, v4, v0

  li t2, 0x6d515a9da513dbd3
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v11, v2, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v2, v19, -14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v3, v12, v25, v0

  li t2, 0xb7c6600c97233fe7
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v16, v18, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v9, v7, 12, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v25, v3, v29, v0

  li t2, 0xe177a79665264d82
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v31, v3, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v13, v11, 14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v29, v21, v19, v0

  li t2, 0x32891c1455d83311
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v3, v26, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v11, v21, -5, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v10, v23, v8, v0

  li t2, 0xf7f2ea89e3e20ec4
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v22, v1, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v22, v31, -5, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v27, v30, v8, v0

  li t2, 0x298f3d537ece8bf2
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v13, v20, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v24, v27, -11, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v31, v6, v20, v0

  li t2, 0x7a7076dcabf2df56
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v22, v6, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v4, v23, 1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v5, v22, v12, v0

  li t2, 0xdb652761aa582a17
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v5, v12, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v20, v26, 4, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v31, v24, v16, v0

  li t2, 0xf4e3f0842704be7e
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v19, v12, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v4, v10, 7, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v31, v28, v18, v0

  li t2, 0x638257b9ef5414d3
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v2, v7, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v8, v16, -13, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v30, v4, v16, v0

  li t2, 0xcae2f5ca3cbbfb01
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v13, v23, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v10, v25, -2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v23, v17, v27, v0

  li t2, 0xf48366a44a508c75
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v26, v27, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v11, v16, -16, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v7, v11, v25, v0

  li t2, 0x216ad7f5d47daee4
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v29, v28, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v21, v12, -12, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v2, v4, v22, v0

  li t2, 0xcdc525d3b92814dd
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v13, v27, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v25, v28, -6, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v18, v30, v6, v0

  li t2, 0x7688550b6fac1735
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v24, v14, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v16, v14, 6, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v1, v9, v26, v0

  li t2, 0xb68b84e01d5b559b
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v28, v27, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v3, v12, 8, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v3, v22, v20, v0

  li t2, 0x91e07ca900f8b90d
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v28, v23, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v12, v21, -3, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v23, v26, v7, v0

  li t2, 0xc99cc2fc532156c3
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v7, v28, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v11, v1, 14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v21, v16, v29, v0

  li t2, 0xe1a0dcc8e1480057
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v12, v21, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v14, v28, -11, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v22, v6, v24, v0

  li t2, 0xbfe710f37975cd47
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v7, v29, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v22, v2, -1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v6, v2, v4, v0

  li t2, 0x3f56f0d7e2d93ce9
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v19, v31, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v17, v11, 4, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v26, v16, v21, v0

  li t2, 0xb60236c787f4664d
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v30, v18, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v6, v31, 9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v1, v10, v17, v0

  li t2, 0x86c7ddb9d9c8d904
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v14, v16, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v17, v23, -9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v6, v27, v9, v0

  li t2, 0x60e76ab50f00d939
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v2, v22, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v19, v7, 10, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v31, v26, v2, v0

  li t2, 0x84119a4b85a2e15e
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v4, v30, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v7, v28, 4, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v24, v6, v9, v0

  li t2, 0xcb6c4bd50d4cb299
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v4, v1, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v24, v2, 9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v31, v22, v8, v0

  li t2, 0x5a4dbaea5434b303
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v3, v22, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v3, v14, 10, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v28, v17, v15, v0

  li t2, 0x7a7222fb17525c0c
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v26, v22, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v28, v1, -8, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v26, v6, v12, v0

  li t2, 0x0d94038c2992ed20
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v31, v26, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v16, v30, -3, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v14, v22, v2, v0

  li t2, 0xe013f8545e0e88d6
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v13, v18, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v27, v6, -14, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v22, v2, v14, v0

  li t2, 0xceb3ca8595b44c64
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v30, v18, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v26, v12, 0, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v6, v16, v0

  li t2, 0xb5ef7d34d0f11a13
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v10, v6, -13, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v10, v16, v12, v0

  li t2, 0x4f525ece7e03450a
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v14, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v14, -6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v10, v28, v24, v0

  li t2, 0x8b8e48fcbf0a95ab
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v26, v20, 11, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v24, v8, v26, v0

  li t2, 0x0acb8a483233455f
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v4, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v6, v20, 3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v4, v22, v0

  li t2, 0x9987dded60a75d9d
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v22, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v18, v2, 6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v6, v14, v24, v0

  li t2, 0x94782b7d783ecd41
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v26, v12, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v18, v20, -5, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v16, v10, v0

  li t2, 0xa9b6eec84b2890cb
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v26, v16, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v6, v8, 9, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v24, v30, v0

  li t2, 0x8d286b348639ddb9
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v22, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v28, v16, 7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v6, v14, v0

  li t2, 0x61a8aeeb416281d1
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v22, v26, 13, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v4, v20, v0

  li t2, 0x168142f3ec492bf5
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v2, v16, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v2, v22, -8, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v12, v18, v30, v0

  li t2, 0xbdb27fe459e30d28
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v2, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v26, v14, -9, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v24, v16, v0

  li t2, 0xa94e9048d89ce29a
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v26, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v20, -4, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v26, v16, v0

  li t2, 0xe19e0ca7fae155f4
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v30, v8, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v20, v28, -13, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v16, v2, v0

  li t2, 0xccdc99eac88ef354
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v2, v16, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v24, -3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v6, v14, v0

  li t2, 0x92ba06576d5619f4
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v6, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v26, -7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v10, v20, v14, v0

  li t2, 0xec65452436d2f51e
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v2, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v4, v8, -13, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v24, v6, v0

  li t2, 0xcb344fea91ada8e1
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v10, v4, 7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v2, v10, v0

  li t2, 0x4297d4ff069a6f06
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v4, v22, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v20, v26, -3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v28, v14, v0

  li t2, 0x9a28428e9c2fadbb
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v30, v28, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v6, v10, -6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v6, v18, v16, v0

  li t2, 0x1373544752128763
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v10, v20, -3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v20, v16, v0

  li t2, 0x65ca224702cd7a6a
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v10, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v26, v18, -5, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v12, v16, v8, v0

  li t2, 0x9cad78c4adb6e6be
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v22, v14, -13, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v26, v22, v0

  li t2, 0xb05cd44c8d301adc
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v26, v28, 5, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v8, v16, v0

  li t2, 0x3019bd8a6abb7e25
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v30, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v4, 3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v18, v22, v4, v0

  li t2, 0x56e63f620add1335
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v24, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v10, v24, -6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v26, v8, v30, v0

  li t2, 0x14d0a9e07c668983
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v4, -5, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v6, v30, v10, v0

  li t2, 0x3ab432ca2d61546b
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v14, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v14, -16, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v28, v2, v0

  li t2, 0x6fcb7e01e3b13c72
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v22, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v14, 1, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v8, v20, v6, v0

  li t2, 0x41171d1f5a8dae91
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v14, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v2, v10, 4, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v12, v20, v0

  li t2, 0x3fe1e9bc5a9362a3
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v14, v28, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v6, v8, -12, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v28, v20, v2, v0

  li t2, 0x9cdbde024267580e
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v26, v18, 13, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v22, v24, v0

  li t2, 0xc76dec1a324fd213
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v4, v18, -6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v26, v4, v12, v0

  li t2, 0xccf0ee091c5baff5
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v10, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v2, v28, 14, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v16, v30, v12, v0

  li t2, 0xf14b8a0ce9cac749
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v6, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v8, v10, 0, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v28, v18, v0

  li t2, 0x8b342d3084f1a15e
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v26, v22, -16, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v18, v6, v0

  li t2, 0x8e0d8b3541b1805c
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v28, -3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v28, v24, v10, v0

  li t2, 0x6233a38d2a4de979
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v30, -7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v24, v20, v8, v0

  li t2, 0x9643821f3e538bb4
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v2, v24, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v28, v4, 1, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v24, v16, v14, v0

  li t2, 0x6a86999c4478f153
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v2, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v8, v2, -4, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v22, v26, v0

  li t2, 0xa4493d064bde68f0
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v26, v8, 6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v8, v24, v20, v0

  li t2, 0x5acbaa530937c691
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v30, v18, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v20, v18, -12, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v10, v16, v0

  li t2, 0x7a6e2d4212d915b3
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v14, v8, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v6, v30, 15, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v26, v30, v16, v0

  li t2, 0x4c3defa80ff5eb68
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v2, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v8, v24, -12, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v18, v4, v0

  li t2, 0x0ca29de15f5e7660
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v20, -14, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v22, v10, v8, v0

  li t2, 0xc51b972745936166
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v22, v28, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v2, v14, -16, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v10, v14, v0

  li t2, 0x1f49c38bdf95bb86
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v12, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v4, v12, -11, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v22, v30, v20, v0

  li t2, 0x1d038cad22e9d31b
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v8, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v26, v22, -11, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v20, v18, v0

  li t2, 0x1b09d678463e60d5
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v18, v22, -5, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v24, v26, v2, v0

  li t2, 0x1a495c578e8c528c
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v8, v6, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v22, v30, 9, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v18, v12, v0

  li t2, 0xf47a55f5da7efe74
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v12, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v28, v8, 11, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v18, v10, v0

  li t2, 0xe2a335665b02d61f
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v14, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v8, -11, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v22, v30, v10, v0

  li t2, 0x073fce5df1a638ce
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v20, v8, 4, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v24, v6, v30, v0

  li t2, 0x9f41a564858685b6
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v4, v16, 9, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v18, v2, v0

  li t2, 0x5dea6efeea570fc3
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v14, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v6, v14, -6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v24, v16, v0

  li t2, 0x64f3344e80f83f42
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v14, v2, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v10, -14, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v6, v4, v0

  li t2, 0x42dea353f4b3ea72
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v22, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v6, v22, 9, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v14, v22, v0

  li t2, 0x02e75ab50e035bee
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v14, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v4, v30, -13, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v6, v30, v0

  li t2, 0x3632d3765334a69b
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v2, v22, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v18, v24, 1, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v6, v2, v10, v0

  li t2, 0x1faf5101bc960e88
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v26, v30, 6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v16, v6, v0

  li t2, 0x60d6553d7da2c528
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v26, -12, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v4, v16, v0

  li t2, 0xebdaed9faefb6db1
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v24, v18, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v16, v8, 5, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v24, v8, v12, v0

  li t2, 0xf86407ae57c5a466
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v26, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v2, v20, 10, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v16, v28, v0

  li t2, 0x166754fdcae30e4e
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v4, v20, 8, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v28, v18, v10, v0

  li t2, 0xacc4a0e233a141cf
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v2, v24, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v6, 4, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v12, v6, v16, v0

  li t2, 0xab7930a798d50b9f
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v22, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v2, v12, -2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v30, v18, v0

  li t2, 0x7d544d7736e2e234
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v14, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v20, 1, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v10, v22, v2, v0

  li t2, 0xe9ac6170f2882337
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v22, v2, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v8, 13, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v16, v24, v0

  li t2, 0xd84b85310b11947f
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v12, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v30, -9, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v18, v12, v14, v0

  li t2, 0x778d7290667c6d22
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v24, v18, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v22, v14, -15, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v12, v6, v0

  li t2, 0x6b1792ec0eac142b
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v14, 9, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v6, v18, v28, v0

  li t2, 0xff87324881ba358a
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v4, 10, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v28, v24, v26, v0

  li t2, 0xc86da0a1b4d8363c
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v22, v26, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v6, v30, 10, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v30, v18, v0

  li t2, 0x56fe0536442e0c82
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v20, v14, 8, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v16, v20, v14, v0

  li t2, 0xf248d18337c1dae0
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v2, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v18, v8, -9, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v8, v28, v0

  li t2, 0xa8c754f7ae795c7c
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v16, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v4, v28, 12, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v16, v24, v22, v0

  li t2, 0xd2b21589857604b6
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v10, v26, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v8, v12, -2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v24, v18, v0

  li t2, 0xdc209a0722c02b35
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v8, v28, -10, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v30, v14, v0

  li t2, 0x9ac5f13db16fc37e
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v16, v22, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v10, v4, 2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v10, v14, v22, v0

  li t2, 0x44b0ae5bbaa3d82d
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v10, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v14, v2, 0, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v6, v28, v2, v0

  li t2, 0x79c928f3057df3c1
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v8, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v18, -15, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v8, v26, v4, v0

  li t2, 0xfae6eb9367f04ccf
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v22, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v2, -16, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v20, v16, v0

  li t2, 0x1a2a12c3923961c1
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v28, v20, 4, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v28, v20, v14, v0

  li t2, 0xd4b2bc5242271735
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v30, v12, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v2, v10, -11, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v28, v30, v6, v0

  li t2, 0x508fd2c733cb73ae
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v10, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v8, v20, -7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v2, v26, v0

  li t2, 0x020d1a8563cba515
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v28, v18, 12, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v22, v10, v0

  li t2, 0x79a7d1335d382f07
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v12, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v20, 12, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v8, v6, v10, v0

  li t2, 0x7a09f566f236a304
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v22, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v20, v18, -15, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v10, v14, v16, v0

  li t2, 0x7c157a0015ea43cd
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v10, v26, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v28, v4, -4, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v4, v26, v0

  li t2, 0xc1016d6fe78c8173
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v4, v18, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v18, v12, -12, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v16, v28, v0

  li t2, 0xfc417cb7cab0ea79
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v8, v18, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v8, v16, -1, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v6, v20, v12, v0

  li t2, 0xf48c0fa86e038df8
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v10, v2, 8, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v6, v12, v24, v0

  li t2, 0x62cb1e6a7afee72e
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v8, v24, 0, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v6, v4, v24, v0

  li t2, 0x83d4a767e7d95179
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v20, v8, 14, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v12, v20, v26, v0

  li t2, 0x1ac9973b0e25b341
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v28, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v6, -1, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v6, v30, v0

  li t2, 0xa21169158d86dfad
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v26, v16, -2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v14, v6, v0

  li t2, 0x37e92935025f01e1
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v6, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v20, v24, -11, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v28, v8, v0

  li t2, 0xd58a3c7564c69ed2
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v14, v2, -4, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v28, v20, v30, v0

  li t2, 0xa5a0895dd5a82ea3
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v18, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v26, v24, -16, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v12, v20, v14, v0

  li t2, 0x9dbf4f7141339fea
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v26, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v2, -7, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v8, v20, v0

  li t2, 0x4e7368b5ef2e50ac
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v8, -13, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v24, v4, v0

  li t2, 0x57e0362bed1ce0ce
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v16, -14, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v12, v8, v0

  li t2, 0x1f7d58263d047110
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v20, -11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v28, v8, v0

  li t2, 0xaaf94b0265a490cc
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v24, -5, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v4, v24, v0

  li t2, 0xe283ba1a59f4d0ee
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v24, 9, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v24, v12, v0

  li t2, 0x56290f534318b3b6
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v28, 7, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v12, v4, v0

  li t2, 0xc53b455bd59f4f0d
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v12, -10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v4, v24, v0

  li t2, 0xae99bf2479f3fe98
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v28, 13, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v4, v8, v0

  li t2, 0x2aba65d8cbc2ac31
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v4, -4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v28, v4, v0

  li t2, 0x6867bd7e1917e821
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v4, -8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v16, v28, v0

  li t2, 0x711477b137b0b3c5
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v16, 6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v28, v12, v0

  li t2, 0xac5a9ab8d75411aa
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v4, -10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v28, v16, v0

  li t2, 0x2e2ad5c2fb9456d0
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v12, -2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v16, v20, v0

  li t2, 0x1d98b973ce18b089
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v8, -7, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v28, v24, v0

  li t2, 0x26c08dd072b6fb73
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v20, -16, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v8, v28, v0

  li t2, 0x12a9963bc5988c89
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v24, -10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v24, v28, v0

  li t2, 0x0fc1c6d5c6e86946
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v16, -12, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v16, v24, v0

  li t2, 0x9edc760a7f723bf6
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v24, -6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v24, v12, v0

  li t2, 0xd5502a28bc3bd6fb
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v8, 10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v4, v24, v0

  li t2, 0x825a8360d69a529d
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v24, 0, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v4, v16, v0

  li t2, 0xa81172b20d8168bd
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v12, -12, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v28, v4, v0

  li t2, 0x182c1eb7db299fed
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v4, 6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v8, v12, v0

  li t2, 0x1076fce7f32b31e1
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v24, 3, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v20, v28, v0

  li t2, 0x3f05a31e26e192f5
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v28, 4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v16, v8, v0

  li t2, 0xcadd8bfc41ce01c3
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v12, 9, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v8, v24, v0

  li t2, 0x1b25574fca9fe824
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v16, -13, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v24, v12, v0

  li t2, 0x0d9c231980d7b865
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v28, 2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v4, v12, v0

  li t2, 0x011d215bc88c78b8
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v12, -16, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v12, v24, v0

  li t2, 0x03d5fd5640299c37
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v12, 2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x2b1b06a968aeca58
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v24, 1, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v16, v8, v0

  li t2, 0x8cd26b6e4162ca06
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v16, 6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v24, v12, v0

  li t2, 0x15cf323b013b9067
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v4, 10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v4, v24, v0

  li t2, 0xc3abbc36c19c2832
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v24, 2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v24, v8, v0

  li t2, 0x7174a8964cd85c65
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v20, -1, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v28, v16, v0

  li t2, 0x6dc6b56d9d2ac0b6
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v24, -10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v24, v28, v0

  li t2, 0xf188b840712d6afa
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v28, -2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v12, v8, v0

  li t2, 0x890ab95332ded7a0
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v4, 3, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v24, v12, v0

  li t2, 0x25af2b34d8f4700d
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v8, -8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v4, v8, v0

  li t2, 0x79b66d0b2fbde71c
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v12, -6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v24, v12, v0

  li t2, 0x30d789868939a4b8
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v12, -14, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v28, v20, v0

  li t2, 0xa18615cc1cbe1295
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v8, 2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v28, v20, v0

  li t2, 0x916560743430f2e2
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v12, 15, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v8, v16, v0

  li t2, 0x256a1770276bcb1c
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v24, -8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v8, v12, v0

  li t2, 0xd06327d0a5af3014
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v4, -6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v8, v4, v0

  li t2, 0xbc636428ee053eff
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v28, -4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v20, v28, v0

  li t2, 0x67df6b01fb6487fc
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v24, -8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v4, v24, v0

  li t2, 0xfb4c8bf31989b663
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v28, 7, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v20, v8, v0

  li t2, 0x90bb049febff80b6
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v20, -4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v8, v12, v0

  li t2, 0xd32a2e5809d95e79
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v28, 10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v24, v20, v0

  li t2, 0x666acef4fc81bc5a
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v12, 4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v4, v20, v0

  li t2, 0xc3610c44b294ad4f
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v12, -14, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v28, v20, v0

  li t2, 0x60eed19417055466
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v12, -14, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v28, v16, v0

  li t2, 0xc0cfbff1badb6783
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v16, -6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v16, v4, v0

  li t2, 0xb9a6dd733cff004f
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v24, 6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v24, v4, v0

  li t2, 0x49cdf526c0d7dfc6
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v24, 1, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v28, v24, v0

  li t2, 0x1063ec0d468ac67d
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v8, 2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v12, v4, v0

  li t2, 0x8070e5bcea641286
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v16, 12, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v8, v28, v0

  li t2, 0xa51ba0fbaa769b51
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v12, -6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v24, v12, v0

  li t2, 0x55a05366d17469dd
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v28, 14, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v8, v12, v0

  li t2, 0x059ed46d56400f80
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v28, -4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v20, v28, v0

  li t2, 0xa0c10d5b4606376e
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v20, 8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v4, v28, v0

  li t2, 0xb896f7bd8f711190
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v24, -7, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v8, v12, v0

  li t2, 0x81929baca29cfe52
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v12, 0, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v28, v12, v0

  li t2, 0xafe614fad624588e
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v20, 10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v16, v8, v0

  li t2, 0xd1cb6e6619f486d5
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v24, -6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v24, v12, v0

  li t2, 0xc634ff939828b2c2
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v4, -3, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v20, v16, v0

  li t2, 0x524143287d3a7eec
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v20, -8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v4, v20, v0

  li t2, 0x143a502111084426
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v28, 7, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v20, v4, v0

  li t2, 0x56615642405ff909
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v16, -14, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v28, v4, v0

  li t2, 0x9b889d7011f21e24
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v4, 11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v12, v8, v0

  li t2, 0x19785179343989b9
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v4, -11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v16, v4, v0

  li t2, 0x5a631cdb0cb0dd00
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v28, 15, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v16, v4, v0

  li t2, 0xdc19e27bcb72d2dd
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v16, 10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v20, v16, v0

  li t2, 0x4f0a83d961229635
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v20, -16, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v8, v20, v0

  li t2, 0x55d51239a121a585
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v16, 9, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v8, v12, v0

  li t2, 0x9dcaeaa1e0a0fa1d
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v12, -4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v8, v16, v0

  li t2, 0xe287661508ae1247
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v8, -14, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v8, v4, v0

  li t2, 0x99bd4a3cf873542b
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v16, 11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v24, v20, v0

  li t2, 0x2787133d0d710a9d
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v8, -16, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v20, v28, v0

  li t2, 0x3c393911b2c6e98a
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v16, -12, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v4, v12, v0

  li t2, 0x8d8a0031034c8627
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v4, 5, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v4, v16, v0

  li t2, 0xf3a65412c6f59333
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v16, -13, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v12, v24, v0

  li t2, 0x60f2eff8280fafd9
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v16, 2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v20, v24, v0

  li t2, 0x9bd7831f786d8d91
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v4, -2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v20, v8, v0

  li t2, 0xceb49d749133ffb6
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v12, 6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v24, v16, v0

  li t2, 0x6c2e27f524eeba0b
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v4, -6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v16, v4, v0

  li t2, 0xe97fc1ed16386d79
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v4, -14, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v8, v28, v0

  li t2, 0x1686d0ea905427e5
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v12, -11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v8, v28, v0

  li t2, 0xbde312cc949fc254
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v28, -13, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v24, v28, v0

  li t2, 0x3229289b3379aa7d
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v12, -10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v20, v12, v0

  li t2, 0x51e25b879d3b4b1a
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v12, -12, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v28, v16, v0

  li t2, 0x4f31b79b1fb34db2
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v20, 13, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v16, v12, v0

  li t2, 0xb5cef106818926b8
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v4, -2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v20, v12, v0

  li t2, 0xf1b49449ec7184ef
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v28, -6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v16, v28, v0

  li t2, 0x61340482094a90cd
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v8, -1, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v28, v8, v0

  li t2, 0xb80030caad91de90
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v16, 1, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v20, v24, v0

  li t2, 0xb5b886cda293867a
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v20, 7, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v12, v28, v0

  li t2, 0xf88f3fbcb2644202
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v20, 4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v24, v16, v0

  li t2, 0xebc5c8aafdf3467d
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v8, -13, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v12, v8, v0

  li t2, 0xa2e5e1fe93c9bfbf
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v20, 7, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x8a35b8952a60713b
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 8, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x14c959db65dbf5f2
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x0df6bac398a52981
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xd43fee33b4e6f143
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 10, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xc07be9ab02371387
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -14, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x3518f6d236f36b88
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, 3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x1fb88e69832c079e
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xa9b71a174633bd80
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xafb7e14afd0905aa
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -4, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xf4ca5e846a3677e3
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x3e482b89f8a16252
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x8ff982a67ca81990
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xee1a9b85d891f1e4
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, -3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x9edb08b47c2a54bf
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x57c5b84d150adeee
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x202ffb01c9e7abe4
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 0, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x47bd6df8dac20c27
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x489882b928e43627
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x1edf2e35fafebe2b
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -6, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x6264cf304e5ff4da
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -10, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x8758b6255effb14c
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xa9bd0d09934dd83d
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x99ecae5c2c1c723f
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x9b8a1998ba1bc1de
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 9, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xda9538462c3a6974
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, 5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x89e881449181b1ec
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -4, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xbe8d7f36cc554caa
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 10, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xce14446f259573fe
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 8, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x6d80f3821c37caa4
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 6, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xe5c2eaf468ffdeb8
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x18c5349a37cf732a
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 8, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x99b504f348a02515
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 7, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x4f8625904ae43688
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 14, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xca7229a8d88f9a27
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xe8323fe4b83273f9
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x56eff51df98cac00
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x21c9b825761a0e56
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 12, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x2ffd554651ad5847
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, 8, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x7f5f6b2fc31d4ee1
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xc3deaf6d3863e0c3
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x437aefd0903357db
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x037ab41b05b405dc
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 9, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xc80cdf724f9c647c
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x5a3c987e7279706b
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -9, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x2af9d8746c58a183
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, -1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xe4eb4561b3f5cfb7
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -12, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xeb475723cabb03f6
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, -9, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x26db45ca4f57b0ec
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, -5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xaaeeb2e981141d3c
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xc4a64ba98f3a914d
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -10, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x0667d137541ea95a
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xab8e28f213cf84c2
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, -16, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x31fd0752bbc54a5f
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -12, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x47c8cae5822ef076
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, -15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x84dcb3d142347be2
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 10, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xe61de25bccaf6b1e
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 4, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x06ee4fc5d11a83f1
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x4fdad791b6dc2663
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 14, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x84aaecbbe0b1878f
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 9, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x66f496b8cda9634a
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xa88ab3bfdff0890c
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -6, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xef2c5d1e034470d7
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, -9, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xd7ccdb4af942e1af
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 14, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x367d4aac4890d7d6
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x7777d1b52c29b7dd
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -7, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xd77ec155c9311c11
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -4, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x909e5d4aa7cbfc7b
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 12, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xa89849fd11c93197
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, -3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xb4f4cfd65e8de03a
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x2faddbce81c3cb23
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x739a704a28064857
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -6, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x55cfc0c07570e984
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x05d47ad26378151e
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, 1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xa3b4d9f6ccd6b165
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, -14, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x278bdf14f12d8e54
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x8691ec30910ae8db
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x681527741ebcca63
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, -1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x8760c3cd9ef96272
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, -15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x25aed7cf2de83d1e
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xf11dbd54a2538795
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x690a5f16a92022f5
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 7, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x6cb7e7714883aeb3
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -12, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xf5af8d0b2cca8d99
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x6610f5f1ba5df6a7
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -16, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x64b52496b41df98d
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, -11, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x108c20702ba04a18
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -4, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xf485b0b6623a8f6a
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xe248bf1d8fb728ee
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 6, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x6e4d92cc08582942
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, -6, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x0d29f186ff8f191b
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x9904ab174ebca2b6
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, -10, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xfb72ee5fea4167c0
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 6, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x7a2f0df1ed0a50f1
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x7d7c83ea08128001
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -4, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x1c83936ecb2e4b29
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, -2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x6cfa242bd0f61618
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -10, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x661e670fbcb9b59a
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, -4, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x4cef848dc623f1e5
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, -4, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x6d40461ba8325563
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, -12, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x2d4c0799d8d63d72
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 13, v0

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
