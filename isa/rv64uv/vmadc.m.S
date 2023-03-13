#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v13, v1, v21, v0

  li t2, 0x358e94d4fa2220f8
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v23, v13, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v16, v5, -8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v9, v2, v10, v0

  li t2, 0x2d273c3e1dac16fe
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v13, v23, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v13, v16, -14, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v23, v3, v25, v0

  li t2, 0xca886d9e71daeb76
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v28, v31, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v31, v18, 4, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v5, v29, v7, v0

  li t2, 0xcb7c6d67f79a919e
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v16, v6, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v9, v30, 9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v18, v31, v8, v0

  li t2, 0x7fd1e0aa9bbbf762
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v28, v11, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v13, v20, -4, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v17, v6, v21, v0

  li t2, 0x7819ea476d69101d
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v28, v17, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v19, v31, 9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v3, v21, v13, v0

  li t2, 0x1e951aacc1581387
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v7, v17, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v14, v31, 9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v11, v5, v25, v0

  li t2, 0x2bf96db2fe354e6c
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v16, v17, -13, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v2, v8, v11, v0

  li t2, 0x25a94861d530819d
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v19, v18, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v9, v3, -5, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v31, v19, v11, v0

  li t2, 0x1fa0df84242f8581
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v31, v16, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v14, v11, 7, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v19, v8, v27, v0

  li t2, 0xc212360b29f51325
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v19, v28, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v28, v22, 9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v4, v6, v18, v0

  li t2, 0x13f761cdde029199
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v23, v10, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v1, v24, -7, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v8, v2, v22, v0

  li t2, 0x98858711746a6b00
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v18, v15, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v12, v7, -3, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v1, v27, v10, v0

  li t2, 0xb8ec5144b01922dc
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v17, v12, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v15, v28, 4, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v12, v1, v14, v0

  li t2, 0x957bd19a85bba7ea
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v4, v1, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v16, v26, 7, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v30, v3, v22, v0

  li t2, 0x5b84bc5a4d8e5702
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v7, v15, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v17, v9, 2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v6, v25, v8, v0

  li t2, 0xffe84a50dc8aa5c4
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v11, v18, 12, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v21, v24, v3, v0

  li t2, 0x2612ffbb2a3db653
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v15, v19, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v25, v5, 14, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v9, v7, v19, v0

  li t2, 0x19b953ec08a97056
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v13, v9, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v18, v20, 7, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v18, v13, v24, v0

  li t2, 0x461e43dfaa4dc4ff
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v19, v1, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v5, v15, -5, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v13, v12, v30, v0

  li t2, 0x9615729ad88fca31
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v23, v13, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v19, v27, -16, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v26, v25, v24, v0

  li t2, 0x56c6521e2b03ad54
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v11, v14, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v16, v13, -6, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v6, v27, v20, v0

  li t2, 0x17bf2f7aee1ff1d7
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v18, v22, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v14, v21, 14, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v2, v19, v31, v0

  li t2, 0xd95dea444b70eb50
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v24, v27, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v26, v23, 15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v15, v18, v16, v0

  li t2, 0xdd5525a53aa9b7dd
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v1, v24, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v16, v24, -15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v12, v16, v27, v0

  li t2, 0xc3d7621e503b55a1
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v28, v21, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v14, v27, -3, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v30, v13, v25, v0

  li t2, 0x29ac99983f84b500
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v24, v31, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v31, v2, 4, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v16, v18, v28, v0

  li t2, 0x3063873a384bd073
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v1, v28, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v6, v5, -13, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v30, v7, v9, v0

  li t2, 0x9a499bad96d536dd
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v31, v21, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v8, v3, 13, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v28, v20, v6, v0

  li t2, 0x8db0d0f7c6bdbb88
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v22, v12, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v22, v27, -12, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v14, v11, v9, v0

  li t2, 0x46f6905d7e5e1cfc
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v21, v30, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v3, v26, -2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v30, v16, v31, v0

  li t2, 0x61dc6f029f694631
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v28, v27, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v14, v3, -8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v21, v7, v10, v0

  li t2, 0xad59bbeff8abbb78
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v5, v29, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v11, v10, -9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v13, v22, v1, v0

  li t2, 0x81037b0fbdec1d97
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v7, v13, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v23, v1, 6, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v25, v20, v27, v0

  li t2, 0x9bcf6f46fd90283c
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v19, v20, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v3, v13, 15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v2, v31, v25, v0

  li t2, 0xe1c097996e24e97a
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v28, v14, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v28, v10, 1, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v22, v5, v12, v0

  li t2, 0x17d3db04b66b78aa
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v16, v7, 11, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v3, v23, v22, v0

  li t2, 0x6cb279da8c111424
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v19, v31, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v2, v20, 15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v19, v14, v15, v0

  li t2, 0x6b1100995a01c2fc
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v9, v5, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v27, v6, -11, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v2, v4, v11, v0

  li t2, 0x6e485753cf792186
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v7, v30, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v28, v19, -14, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v23, v18, v27, v0

  li t2, 0x1cc9f85b0d46d8ae
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v4, v27, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v20, v9, 7, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v10, v30, v21, v0

  li t2, 0xa7921408d13325a3
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v6, v21, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v16, v20, -10, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v13, v11, v27, v0

  li t2, 0xc86258a6bd660929
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v15, v14, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v21, v25, 12, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v4, v9, v17, v0

  li t2, 0xe30c2cefc8a9a888
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v30, v17, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v14, v11, -11, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v1, v3, v17, v0

  li t2, 0x9d12a104235b52ac
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v12, v31, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v16, v3, -4, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v10, v27, v17, v0

  li t2, 0x04bef6a07a3c8aa1
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v9, v2, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v17, v20, -14, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v1, v15, v8, v0

  li t2, 0x3148bd5a022aa2ea
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v29, v13, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v12, v17, 5, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v19, v2, v13, v0

  li t2, 0x0edade04c6ba8d2f
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v2, v8, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v18, v24, 2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v29, v6, v26, v0

  li t2, 0x67523e87cd21c4c9
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v19, v17, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v25, v5, 0, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v13, v1, v26, v0

  li t2, 0xdebe2cfddfc5d69f
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v3, v1, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v10, v15, -15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v17, v19, v23, v0

  li t2, 0xac9db69b7c58f20e
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v11, v12, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v3, v5, -9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v22, v24, v27, v0

  li t2, 0xe71365864c94d9d1
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v9, v31, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v23, v11, 15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v31, v20, v22, v0

  li t2, 0xd307e0c00f8ae145
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v20, v17, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v31, v8, -7, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v24, v23, v7, v0

  li t2, 0xe89646e4d14cf360
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v9, v26, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v13, v3, 8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v29, v21, v30, v0

  li t2, 0x3fa77e1a1234d342
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v3, v1, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v28, v1, -6, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v10, v28, v8, v0

  li t2, 0x7c6c86106db339b8
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v7, v3, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v5, v12, 9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v28, v29, v8, v0

  li t2, 0xfa0e9fd628fab4c4
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v25, v13, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v27, v26, -5, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v19, v22, v7, v0

  li t2, 0xe96aa672290c9b63
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v6, v14, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v10, v20, -7, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v5, v31, v24, v0

  li t2, 0x7c7dbc1f15907f25
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v16, v18, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v8, v31, 3, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v31, v17, v12, v0

  li t2, 0xdf003d9a01826942
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v1, v6, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v8, v4, 5, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v15, v20, v8, v0

  li t2, 0x5db0d714a7501f53
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v25, v22, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v2, v20, -9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v26, v18, v29, v0

  li t2, 0xcfc68e8f4e40eb4b
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v20, v3, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v5, v11, -6, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v12, v9, v26, v0

  li t2, 0x300710139338c6fb
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v29, v1, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v5, v9, 9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v29, v28, v9, v0

  li t2, 0xca81e2f3b7f84073
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v16, v10, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v10, v21, 8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v20, v1, v10, v0

  li t2, 0x4faf78e70d5f6cef
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v30, v11, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v24, v23, 11, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v16, v19, v20, v0

  li t2, 0xea8ec4f13562fa70
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v1, v6, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v3, v2, -16, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v22, v19, v31, v0

  li t2, 0xfb9d6b34ce0ccbd2
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v26, v23, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v10, v30, 4, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v31, v1, v27, v0

  li t2, 0xab689a6d2e9aa2de
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v29, v17, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v1, v4, -15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v8, v14, v25, v0

  li t2, 0x97ac3eb8f2cccac2
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v2, v28, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v14, v25, 15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v12, v5, v19, v0

  li t2, 0xa7df85e7bccb9792
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v30, v9, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v16, v18, -12, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v6, v15, v24, v0

  li t2, 0x6f7163c061bbb790
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v27, v18, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v23, v18, 8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v7, v2, v5, v0

  li t2, 0x4bf88ba1866984aa
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v24, v6, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v8, v4, 14, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v24, v5, v2, v0

  li t2, 0xf7014cc28ea3bbe6
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v14, v15, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v20, v30, 13, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v28, v5, v20, v0

  li t2, 0x833b43ea207e689a
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v7, v23, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v31, v7, 1, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v5, v26, v6, v0

  li t2, 0x6e9d0a54ccd4bd7c
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v25, v2, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v11, v2, 10, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v27, v11, v23, v0

  li t2, 0xf9082f0f248c9022
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v27, v29, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v14, v27, 10, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v21, v5, v16, v0

  li t2, 0xabd6dd7fa3a78ac5
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v25, v24, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v21, v29, 9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v12, v21, v11, v0

  li t2, 0xed64268008fafbef
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v5, v7, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v19, v10, 14, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v26, v14, v25, v0

  li t2, 0x41aa70d342a3ac91
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v23, v27, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v29, v7, -9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v15, v19, v22, v0

  li t2, 0x11b0426d89f98a74
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v21, v25, -6, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v11, v2, v27, v0

  li t2, 0x2a2441d257ca9a60
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v21, v20, 3, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v18, v26, v6, v0

  li t2, 0x5bcebcb60d6bae48
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v5, v30, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v18, v11, -14, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v17, v9, v22, v0

  li t2, 0x192141548cbcd819
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v5, v1, 5, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v11, v31, v21, v0

  li t2, 0xcecefc8d10b7571c
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v25, v26, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v1, v11, 13, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v10, v14, v20, v0

  li t2, 0xb73eddb9807480b6
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v26, v20, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v3, v7, -9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v26, v5, v31, v0

  li t2, 0x9be862fb86376d6d
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v9, v22, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v25, v17, -1, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v30, v11, v6, v0

  li t2, 0xb2a18fe9408eca47
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v11, v23, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v1, v29, -1, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v8, v4, v1, v0

  li t2, 0x03f863776b48dc47
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v27, v10, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v26, v3, 11, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v16, v12, v28, v0

  li t2, 0xf3d16035401f06bf
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v16, v19, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v5, v8, -11, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v7, v1, v11, v0

  li t2, 0x2877cc8e69450eb2
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v18, v8, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v14, v10, -8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v8, v16, v12, v0

  li t2, 0x77700ac89553ebce
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v20, v2, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v25, v24, 8, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v24, v12, v1, v0

  li t2, 0x82e21040b300e29e
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v13, v27, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v27, v21, -9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v31, v19, v11, v0

  li t2, 0xe2a63ab899f443f6
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v24, v17, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v30, v21, 15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v28, v6, v30, v0

  li t2, 0x7979393f13d09ab0
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v11, v12, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v31, v17, 2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v15, v18, v10, v0

  li t2, 0xfcaa9f16a64d1164
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v10, v8, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v29, v20, -2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v8, v27, v4, v0

  li t2, 0x36cd084889129ef9
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v30, v22, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v10, v17, -7, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v12, v22, v17, v0

  li t2, 0x521c42795670872e
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v19, v2, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v19, v21, 1, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v4, v26, v3, v0

  li t2, 0x3014cfb098e2c203
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v1, v3, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v8, v27, 12, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v9, v25, v22, v0

  li t2, 0x621b53fa4e6272b5
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v28, v7, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v5, v10, -7, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vvm v13, v16, v9, v0

  li t2, 0x92d7a37130bbd8ae
  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vxm v31, v23, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmadc.vim v31, v20, -8, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v14, v26, v0

  li t2, 0x5a90e7d83831126f
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v24, v22, 0, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v14, v12, v8, v0

  li t2, 0x00795f72b1d7939d
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v18, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v20, v18, 6, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v28, v22, v0

  li t2, 0x3f25675a58b2dc8b
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v26, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v22, v2, 4, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v24, v14, v0

  li t2, 0x177d94b46ee4ed96
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v8, v18, 13, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v6, v12, v0

  li t2, 0xafbab0ee672d9d3c
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v22, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v4, 12, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v12, v14, v28, v0

  li t2, 0x962d42e3aeef5a71
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v26, v24, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v24, v26, 3, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v20, v24, v6, v0

  li t2, 0x902cec6ef0b946ee
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v6, v16, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v20, 10, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v10, v24, v12, v0

  li t2, 0x385d4c1366a4a5ca
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v14, v28, -14, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v30, v24, v22, v0

  li t2, 0x27886618e543953f
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v4, 5, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v30, v24, v2, v0

  li t2, 0x3e8aaa73caa81211
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v18, v28, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v14, 0, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v22, v18, v0

  li t2, 0x6236210ea8c0d768
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v6, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v18, -11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v30, v10, v16, v0

  li t2, 0x43a9492c0f41f40e
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v20, v12, -15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v20, v12, v4, v0

  li t2, 0xa9d44b9dc65257e5
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v12, -6, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v10, v16, v0

  li t2, 0xe0358fde22cb2a69
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v8, v24, -3, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v30, v6, v16, v0

  li t2, 0x5b95850284840b74
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v2, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v22, v16, -1, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v30, v10, v8, v0

  li t2, 0x60684163d8e784a5
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v2, v18, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v8, 15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v26, v16, v24, v0

  li t2, 0xea382270e333a9b1
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v16, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v22, v26, -7, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v26, v28, v16, v0

  li t2, 0x3125ae73760b8990
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v8, v26, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v20, -5, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v8, v12, v22, v0

  li t2, 0x4561059ab366828b
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v2, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v2, v26, -16, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v26, v28, v10, v0

  li t2, 0x7c4c7448441a91bb
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v10, v30, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v20, v30, 12, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v10, v12, v18, v0

  li t2, 0xb98b1a0e8d0cdbb2
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v10, v18, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v28, v18, -6, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v4, v12, v8, v0

  li t2, 0x2f40ee00687b1023
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v6, v4, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v28, v2, -12, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v26, v12, v8, v0

  li t2, 0x5d54c403d93435f9
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v20, v30, -7, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v20, v2, v0

  li t2, 0xfeea125ee15b58ec
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v10, -5, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v2, v6, v14, v0

  li t2, 0xaf874fba5d6bd984
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v30, 12, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v22, v8, v10, v0

  li t2, 0x8755ee405cabcde1
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v24, v18, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v10, -5, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v18, v26, v0

  li t2, 0x09a13a8abefb218f
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v8, -8, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v26, v2, v16, v0

  li t2, 0xba009b358d777f07
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v4, v30, -14, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v4, v20, v28, v0

  li t2, 0xc0a1255d01d0e98b
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v12, -7, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v2, v22, v10, v0

  li t2, 0xf333ac84a54a11e8
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v22, v10, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v20, v26, -16, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v14, v18, v0

  li t2, 0xab9eea98c2c5a8c9
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v24, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v4, v30, -14, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v8, v24, v12, v0

  li t2, 0x46121fe8e345f2f5
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v4, v30, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v6, -2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v10, v4, v0

  li t2, 0x8c4ce2df058ac1ee
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v28, v6, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v2, v22, -3, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v10, v24, v4, v0

  li t2, 0xa5f560d14d3815fd
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v22, v10, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v2, 14, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v26, v14, v4, v0

  li t2, 0x854ed4535d67cc5e
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v26, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v22, -5, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v16, v26, v0

  li t2, 0xd95e06b26902f154
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v10, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v6, v30, 14, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v20, v16, v26, v0

  li t2, 0x379b68e53b11be88
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v12, v18, 15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v18, v30, v0

  li t2, 0x2b3c009ffebe7c07
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v22, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v20, -15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v20, v16, v0

  li t2, 0xd78c0cf0652b295d
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v20, v6, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v8, 15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v20, v26, v0

  li t2, 0xbfab5acec76ee331
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v10, v28, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v4, v20, -2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v4, v8, v30, v0

  li t2, 0x06c7782256495c0d
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v28, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v2, v24, -15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v14, v4, v30, v0

  li t2, 0x326d935d76ab0e0f
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v28, v18, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v10, 11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v8, v12, v18, v0

  li t2, 0xc2ae798a381d9e9b
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v20, v6, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v22, v24, -3, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v2, v20, v22, v0

  li t2, 0xb9d5de7ce8bbbf93
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v2, v18, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v28, v2, 9, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v22, v10, v4, v0

  li t2, 0x5362c61e34c4b30c
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v18, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v22, v2, 0, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v2, v6, v0

  li t2, 0xae9eedd4a2a9e23d
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v24, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v14, v12, -4, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v24, v22, v0

  li t2, 0x179cbcfb3064e7bf
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v10, -15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v26, v12, v0

  li t2, 0x9b173da6917107fa
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v18, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v30, -13, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v10, v30, v28, v0

  li t2, 0xd88e7974f55cc8bc
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v24, v4, -5, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v22, v10, v0

  li t2, 0x05863e2d8de248f9
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v18, v16, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v2, -12, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v2, v24, v8, v0

  li t2, 0x6765ddf3cc1d6f8a
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v4, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v28, 4, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v22, v18, v28, v0

  li t2, 0xf4bf8092c5631b6c
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v8, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v20, v24, -1, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v26, v28, v0

  li t2, 0x7ff2f03e36368982
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v22, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v28, v6, -3, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v8, v16, v2, v0

  li t2, 0xf9c4dc9d3bbd7c9c
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v8, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v24, v22, 1, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v12, v14, v2, v0

  li t2, 0xbe26cec6f767da3a
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v8, 0, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v26, v14, v0

  li t2, 0x71f0b03173e8e292
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v22, v30, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v12, v20, -13, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v22, v28, v0

  li t2, 0x7d075cb288ef18e8
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v26, v16, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v28, v10, 8, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v8, v2, v6, v0

  li t2, 0x10fc8a6baaaafb14
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v2, v26, -6, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v22, v26, v20, v0

  li t2, 0xc58610f0811b1235
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v26, v12, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v22, v10, -4, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v14, v16, v24, v0

  li t2, 0x72564a042c9a52c5
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v26, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v8, v22, 3, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v12, v28, v0

  li t2, 0x6be1d9327609fcab
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v22, v12, -7, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v26, v8, v0

  li t2, 0xb3fdc577f77153ad
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v28, v22, -6, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v20, v14, v16, v0

  li t2, 0xb5ad9ab2ff14a0ee
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v6, v8, -1, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v28, v18, v14, v0

  li t2, 0x1aad06bd41ec7677
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v26, v4, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v20, v30, 4, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v30, v2, v14, v0

  li t2, 0xc0dfb928c16e4c9f
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v20, v22, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v12, 9, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v22, v18, v0

  li t2, 0x302706932b529ee8
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v26, v4, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v24, -10, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v14, v26, v0

  li t2, 0x252bd0d502124292
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v12, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v24, v6, 7, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v22, v28, v2, v0

  li t2, 0xe7a5c679efa7c9ef
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v26, v16, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v28, 11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v12, v24, v0

  li t2, 0x2a5edff837273490
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v18, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v2, v16, 0, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v20, v4, v18, v0

  li t2, 0x4eb78a12b8bb5497
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v10, v12, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v24, -8, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v12, v20, v0

  li t2, 0xd2b87f38f2e0afc7
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v10, v24, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v24, v6, 9, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v2, v28, v20, v0

  li t2, 0x897787c179e4fdf2
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v16, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v4, v20, -12, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v10, v24, v14, v0

  li t2, 0xa7a043b82146c230
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v26, v4, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v28, v16, 13, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v8, v20, v0

  li t2, 0xba13bde5766dd19d
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v30, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v24, v2, -5, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v8, v22, v12, v0

  li t2, 0x646764df4c4b6739
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v4, v18, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v4, v8, 6, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v22, v8, v20, v0

  li t2, 0x2f7a1e6bf95d2d06
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v4, v2, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v22, v4, 14, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v4, v18, v20, v0

  li t2, 0x920870289728a23c
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v6, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v10, v6, -1, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v10, v16, v26, v0

  li t2, 0xea1367501ef8ccd4
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v18, v22, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v14, v12, -5, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v8, v20, v0

  li t2, 0xc0ecea154afe9a62
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v8, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v18, 9, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v8, v6, v4, v0

  li t2, 0xf1c9756d01f09088
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v2, v10, 1, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v8, v2, v10, v0

  li t2, 0x4d7e0248104dfb3d
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v24, v30, -2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v14, v2, v8, v0

  li t2, 0xb47ea2e6c6dcaf9b
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v10, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v18, 11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v14, v26, v20, v0

  li t2, 0x54af7f90c188ce6c
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v14, v22, 2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v22, v20, v0

  li t2, 0x801415b0802a6407
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v8, v16, 2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v10, v28, v22, v0

  li t2, 0xcc499e2c2189f567
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v8, v26, 14, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v20, v30, v6, v0

  li t2, 0xd29abd06c2cf3be5
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v26, v4, -15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v26, v2, v0

  li t2, 0xdda87ea61848153d
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v14, -10, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v22, v6, v28, v0

  li t2, 0xb76a998b1e56a51b
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v26, -7, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v26, v6, v0

  li t2, 0xe336a9096de7c25a
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v16, v26, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v24, v6, -2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v8, v2, v4, v0

  li t2, 0x80ee40d9f482feba
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v4, v2, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v10, 5, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v2, v16, v20, v0

  li t2, 0x9ad2dc1cada42f62
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v24, v22, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v6, v12, -6, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v4, v24, v0

  li t2, 0x51a3c93d64b16418
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v12, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v14, v20, -15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v4, v20, v0

  li t2, 0x758a5d5bf5ebf24a
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v22, v16, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v6, v28, 15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v6, v22, v26, v0

  li t2, 0x2795403e7d89174c
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v4, v30, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v2, v8, -5, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v16, v12, v20, v0

  li t2, 0x25829abd59fc02d7
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v8, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v18, v6, -3, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v26, v22, v6, v0

  li t2, 0x5e5162f934e0e912
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v14, v4, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v12, v22, -10, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v24, v4, v12, v0

  li t2, 0x17e143b9b97d8536
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v30, v2, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v12, v10, -12, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v30, v4, v24, v0

  li t2, 0x7e7495299f7db9f1
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v16, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v16, v24, 1, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v22, v6, v20, v0

  li t2, 0x7bd942bcd5675592
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v20, v30, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v2, v24, 2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vvm v18, v6, v30, v0

  li t2, 0xb14f7f578a88f5dc
  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vxm v8, v14, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmadc.vim v30, v24, 4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v24, v20, v0

  li t2, 0x3b519d8837632ba4
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v20, 6, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v20, v28, v0

  li t2, 0x878bd5704248cc5a
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v4, 14, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v16, v8, v0

  li t2, 0xf1e523a1c23b78a4
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v28, 11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v20, v12, v0

  li t2, 0xa73892c2828f49de
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v20, -16, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v20, v8, v0

  li t2, 0xb94a83f3b90af206
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v4, -15, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v8, v20, v0

  li t2, 0x183008bcfb99455a
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v16, -6, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v20, v4, v0

  li t2, 0x96a14b2c406d806f
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v24, 12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v12, v20, v0

  li t2, 0xd8c4ef672c20209e
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v20, -1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v16, v28, v0

  li t2, 0x188aa38cd9499c21
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v12, -4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v28, v20, v0

  li t2, 0x8eac4d234f343a22
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v24, 7, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v20, v12, v0

  li t2, 0x092dd452d429308e
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v4, 6, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v12, v24, v0

  li t2, 0x9fc14b09ec92d5cc
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v4, 13, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v24, v16, v0

  li t2, 0x439a6718b0515ee4
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v8, -14, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v28, v8, v0

  li t2, 0x17a29f46c5663ff0
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v4, -4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v8, v28, v0

  li t2, 0x030b9011bd35ac0d
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v12, 1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v24, v28, v0

  li t2, 0x2d1ff9bcd785fad4
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v16, 4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v12, v16, v0

  li t2, 0x34c5f7ce0e5a8eb7
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v4, 13, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v8, v16, v0

  li t2, 0xdbe8841c011ace45
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v4, -6, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v16, v24, v0

  li t2, 0xe3ad07bd42a571b5
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v12, 9, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v12, v20, v0

  li t2, 0x8934eea17065f7c6
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v28, -7, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v20, v4, v0

  li t2, 0x7a4b3e3761cdfc16
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v20, -2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v4, v8, v0

  li t2, 0xfce0dce5337e8cf4
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v12, -12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v12, v20, v0

  li t2, 0xa0899ad8b77d0f7d
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v16, 12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v16, v28, v0

  li t2, 0x5f003d74f77bf136
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v8, 15, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v28, v16, v0

  li t2, 0x73115ea8636e088b
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v4, -6, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v12, v24, v0

  li t2, 0x232d95267cb9f9a0
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v24, -15, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v4, v20, v0

  li t2, 0x5158cc53109a2533
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v8, 11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v16, v28, v0

  li t2, 0x2d50f235a5e6546c
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v8, 4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v8, v28, v0

  li t2, 0x840f99def0036f6e
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v28, 2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v20, v8, v0

  li t2, 0x3334e2070b160cab
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v20, -1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v20, v16, v0

  li t2, 0x1033eb0457de85ab
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v4, 11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v20, v24, v0

  li t2, 0x28de51cc2cb1e98b
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v20, -1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x79d2312f7a4611d6
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v12, 5, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v12, v4, v0

  li t2, 0x7718e70fa7273ce7
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v4, -9, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v8, v4, v0

  li t2, 0x86a5964d293e8b9e
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v28, 13, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v28, v20, v0

  li t2, 0x22eecdf4fa6ca1e4
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v20, 3, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v28, v4, v0

  li t2, 0x3a20e683f1973e98
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v4, -13, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v24, v16, v0

  li t2, 0xed8b02c4b273f41a
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v20, -13, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v16, v28, v0

  li t2, 0x63faccec0b5548fe
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v20, -6, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v4, v16, v0

  li t2, 0xec5db4df5f2e00a1
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v20, 2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v24, v12, v0

  li t2, 0xd8d8e96da07d8c7d
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v8, 0, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v28, v4, v0

  li t2, 0xd12e17ad86399dc8
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v12, 11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v24, v12, v0

  li t2, 0xb05ae13a1277f5b5
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v12, 11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v4, v28, v0

  li t2, 0xaa2c015f3de03900
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v16, 14, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v16, v20, v0

  li t2, 0x93bc0a665e13ba18
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v28, -5, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v12, v24, v0

  li t2, 0x30ae2f530924722b
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v12, -7, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v12, v20, v0

  li t2, 0x1bc5ee02f9ac1c19
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v12, -7, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v8, v16, v0

  li t2, 0x186c7142254faddc
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v20, 1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v20, v12, v0

  li t2, 0xf0410e046e286c37
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v12, -7, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v8, v12, v0

  li t2, 0xa7af211da5e96676
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v4, 4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v20, v4, v0

  li t2, 0x1ea3d855239b3f5f
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v16, 9, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v16, v24, v0

  li t2, 0x382bcd5832394417
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v24, 0, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v28, v8, v0

  li t2, 0xd698e529c9cf6e55
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v4, -16, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v4, v24, v0

  li t2, 0xc797785026fd4d0b
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v12, 0, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v16, v4, v0

  li t2, 0x7bed63d103fa7137
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v16, -16, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v24, v4, v0

  li t2, 0x3335e707b20d8bc9
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v20, -14, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v24, v4, v0

  li t2, 0x5c7b6731d4418e77
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v28, 8, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v4, v8, v0

  li t2, 0x7aabfcf0f0390e4d
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v4, -5, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v28, v12, v0

  li t2, 0xaee025bd7fd28890
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v24, -2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v4, v24, v0

  li t2, 0xdbd7b5382e0f4551
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v12, 11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v12, v4, v0

  li t2, 0x3793b57c360b01c4
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v12, 8, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v20, v12, v0

  li t2, 0xd4529bb39c889bf1
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v24, -4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v4, v8, v0

  li t2, 0xd095353f5628870e
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v16, 3, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v20, v16, v0

  li t2, 0xee3a01ca864a97fd
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v8, -8, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v12, v28, v0

  li t2, 0x7982b9deecb1f36a
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v20, -6, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v8, v12, v0

  li t2, 0x7e1eb28a62ec3895
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v28, 8, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v20, v16, v0

  li t2, 0x8702ad5d54f3a613
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v16, 10, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v28, v24, v0

  li t2, 0xc514bfcb47b13f25
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v28, 12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v8, v20, v0

  li t2, 0x294bd677fd3e15bc
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v8, -2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v20, v28, v0

  li t2, 0x29ae3c8dfe04b380
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v20, 15, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v28, v20, v0

  li t2, 0xc58041fd86d86a7e
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v20, 9, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xf2b92bb24f7cf204
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v16, -4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v20, v8, v0

  li t2, 0x2c49def2e660cc0e
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v12, 3, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v16, v20, v0

  li t2, 0xd3917b8293cd3885
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v12, 15, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v20, v8, v0

  li t2, 0x0c2a4cc5c5d88b5b
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v16, -1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v12, v16, v0

  li t2, 0x118f740f8ea61cde
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v8, -8, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v24, v28, v0

  li t2, 0x76c11fcad9e23574
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v20, 11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v20, v12, v0

  li t2, 0xbc677ab448480985
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v16, -10, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v28, v20, v0

  li t2, 0x995c84775908f6af
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v8, -7, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v24, v4, v0

  li t2, 0x855c04b87aa39fc0
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v12, 5, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v24, v20, v0

  li t2, 0xdd656d855eecc629
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v12, -5, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v24, v20, v0

  li t2, 0xa99b70ca536a0fcd
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v16, 1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v8, v20, v28, v0

  li t2, 0x3b42ef520c3a371a
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v4, -12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x039bbc3373ee3dce
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v8, 4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v4, v16, v0

  li t2, 0x37193d1efa704aaa
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v8, -9, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v8, v20, v0

  li t2, 0x0cba8d3116e7133f
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v16, v4, -1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v4, v28, v0

  li t2, 0xb3f83ee1ce071de1
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v20, -7, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v4, v20, v0

  li t2, 0xcaff20c3e3261472
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v8, 12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v4, v28, v0

  li t2, 0x753bef97ccf09e08
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v8, -16, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v16, v12, v0

  li t2, 0x616c681a8cf3da88
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v24, -2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v28, v20, v0

  li t2, 0x7e0b2bed8f4fd0f5
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v12, v8, -11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v16, v28, v12, v0

  li t2, 0x0805dbb9e2e4f2c3
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v4, 0, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v16, v8, v0

  li t2, 0xcf57cb3e3a57070a
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v8, v28, 15, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v4, v16, v20, v0

  li t2, 0x47d03c692709abc7
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v4, v8, 5, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v24, v16, v28, v0

  li t2, 0x0ce0dc9db40c4162
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v4, 3, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v20, v8, v28, v0

  li t2, 0x962bcbf6edb946a0
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v8, 4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v4, v24, v0

  li t2, 0x7c2862348ac1c580
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v8, 11, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v12, v28, v8, v0

  li t2, 0xf18f536e0aac8b5c
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v28, v16, -10, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v4, v8, v0

  li t2, 0x45a855918f9f2e9d
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v24, v28, 8, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vvm v28, v24, v20, v0

  li t2, 0xe5130c3967d6bd46
  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmadc.vim v20, v12, 0, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x8b1f45df937e1f46
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 13, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x170068ac618ae9a1
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, -5, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x1f53b621222f018a
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 6, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xa633548f581a0bcf
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -13, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x50dc681c5c797955
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 13, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x77e189d04d50b1b3
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 5, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xbf99be12db5e43f6
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, -9, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x9a20df9803e5bb04
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 0, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x22fc98e526e60d89
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xb1781a587df82938
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, -16, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xbff16bfaccc3e34a
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, 10, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xdc882a2245121bec
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -14, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x5b456b22d27ca1d1
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, 3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xf6d1421b6e5caa08
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -1, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x287329a445a50270
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -10, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x2f6362fb4b1cb60a
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 13, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x6bc419a76e2e89d4
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, 1, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x460d90e285e27db2
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -6, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x89ef62dffb281e15
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xe27fec39bd37c7f4
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, -15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x0fe00c24c058a6ee
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, 14, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x300d67fc939f09f1
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, 0, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x48622372bfe7498c
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xc3e327908d3776fb
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, -9, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xbecac4d920d1e98d
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -8, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xacee00218da926de
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, 11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xf2a36bcee8399262
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, 15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x1eb33a0995d3b7b3
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 0, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x3c49764702525436
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x2a8d6d3350fadfa4
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, 2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x103a5377f36ef24e
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -9, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x3caa12aaebaf94a9
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x4eb4c88a4035a1b5
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -14, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x079dcfbbece99d1c
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 7, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xe4103cbc0b46e276
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, 14, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x47c6ae2557a58128
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, 3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x5f8edd4b6e8ed073
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x55d1472c7e98aeda
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x4bc4d6ba8c23518a
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, 2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xbbfb3d463580e3d4
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x02c85a580dba0614
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 8, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x94bca2b3fa5d13eb
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 6, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x38e2271cba9574f2
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, -10, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x75f7592323440977
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x6b496b1feb0568c6
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, -5, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xd969d40899cb6806
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, 8, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x3dbaee8ffbcbad4b
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -14, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xaa691d6188653ce5
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, 4, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x58acbf3c6fcba2b6
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, -10, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x8955a2fc5917ac70
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xc682f1a667a39caf
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -12, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x5010635ffa03672d
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -4, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x10481c99aa49dd45
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, 0, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xcc9cb51792735b64
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 9, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xc89a2a7c5bf57558
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -4, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x757440976dd93622
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 10, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xbf761adb9c976205
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, -3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xa93b2d1f8d78dcc9
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -7, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x40e005f980d82908
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, -14, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x95660dbec08e524c
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x13d5c2c94ccac3f8
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xbd1aac3476a40cb3
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 6, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x795606580aa14946
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, -9, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x005b96441af6e67e
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 0, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xf647621b99420115
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, 13, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x93d96730db219fca
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -5, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xba8778f47cc9172a
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x6efc9836f3e9cff3
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, 0, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x9e892006688b3d09
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 6, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xfac2b7aaf059b7cb
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xc4fea7627a16f814
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, 5, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x0da1783b930cf952
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, 2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x50ff0226979f632d
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 6, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x47bf521f21c679d0
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 10, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xe0818482834a3521
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, 4, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xf26a341984ae6976
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xe5b116e2eae17da4
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, 2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xc70877305fcdaf5c
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, -13, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x7035781ee38fcd3c
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xa48d3159c68a42d3
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, 15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x2656726bf242a441
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xc60b092ff4f20802
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, -11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xd1ccec3451b1a1f1
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x0a1a8cc8fc84339d
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v24, -1, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xaedc9b38352f27b1
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, 15, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x95dc17bc6a93ec0e
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 12, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xda14753325d395c3
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 13, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xfcf51d5910f26699
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 4, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x0927fa2be71758cf
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 7, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x000bb07d4eb38e1c
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -13, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x4bf603930efe768c
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v16, v8, 9, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x9710898b4e59889f
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 7, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xe840fc068074372f
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, -12, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xc61785425f9db174
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, 13, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xef5c55ec5ff47de9
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v16, 12, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xe414af33fd88dc37
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -9, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xdea4512d506f4602
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v24, -14, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x3ecaabd7a84930a0
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, -6, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xc8ccaa75995ed5f4
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v24, v8, 7, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xc02cae1cbaf43927
  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmadc.vim v8, v16, -16, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v23, v10, v13, v0

  li t2, 0x780e53ae150d8b0a
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v14, v23, 6, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v15, v5, v28, v0

  li t2, 0x8bff675178fe83b8
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v2, v13, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v1, v7, -15, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v16, v7, v21, v0

  li t2, 0x39ab5d53c118b385
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v6, v1, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v16, v2, 10, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v19, v20, v3, v0

  li t2, 0xb578c7a80399b0eb
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v9, v5, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v25, v29, 6, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v18, v4, v3, v0

  li t2, 0x6971b1fe0f1db7d2
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v21, v14, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v1, v12, -10, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v18, v9, v4, v0

  li t2, 0x40a65d6523b09045
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v25, v9, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v28, v16, -12, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v3, v31, v14, v0

  li t2, 0xae670f8870197136
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v11, v2, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v19, v21, 2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v4, v3, v21, v0

  li t2, 0x4ee368345e905695
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v5, v20, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v31, v27, 14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v15, v2, v31, v0

  li t2, 0xb84146a9c1730e27
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v8, v29, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v1, v13, 13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v15, v20, v24, v0

  li t2, 0xfc1718aa72a3d2b2
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v17, v24, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v3, v19, 9, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v9, v22, v11, v0

  li t2, 0x50e7705af23ef9c5
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v16, v23, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v28, v13, -3, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v1, v6, v26, v0

  li t2, 0x7f91af8007f47bb9
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v19, v2, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v5, v6, -14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v16, v20, v2, v0

  li t2, 0x2c91a63ad5828a3b
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v14, v28, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v17, v4, 13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v26, v15, v12, v0

  li t2, 0xd23325a74f24ffda
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v25, v1, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v30, v3, 13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v12, v15, v23, v0

  li t2, 0xf6c6cb35c45ca571
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v20, v17, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v4, v6, 15, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v8, v29, v4, v0

  li t2, 0x283be21c50480f9d
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v5, v23, 9, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v22, v31, v16, v0

  li t2, 0x53f8504f2c398fb7
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v20, v17, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v25, v14, -4, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v25, v6, v28, v0

  li t2, 0xdc05ba0af9925f5a
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v17, v26, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v30, v10, -15, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v26, v11, v25, v0

  li t2, 0x765272d209752e46
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v19, v23, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v26, v9, 8, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v24, v9, v11, v0

  li t2, 0x52e0704844927e54
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v23, v5, 1, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v21, v19, v17, v0

  li t2, 0x6b5469471abf9967
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v17, v22, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v10, v4, 5, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v15, v27, v12, v0

  li t2, 0x432e12e7ed6cd522
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v4, v11, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v27, v10, -14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v27, v1, v30, v0

  li t2, 0x9a6faa5455bd07b3
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v7, v6, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v10, v5, -4, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v20, v22, v11, v0

  li t2, 0x2c8d7db7f375eee4
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v3, v31, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v21, v26, -9, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v21, v19, v17, v0

  li t2, 0x846d4ea935fbc9b1
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v3, v28, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v16, v26, 6, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v1, v23, v14, v0

  li t2, 0x3e3e2ef95e032dad
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v6, v17, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v8, v30, 2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v17, v2, v11, v0

  li t2, 0x4020c3e713c15ed0
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v29, v6, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v13, v3, 6, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v4, v3, v6, v0

  li t2, 0xdf87ce7c504fbd34
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v3, v24, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v16, v18, -11, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v3, v21, v25, v0

  li t2, 0xbf32d2d1478b86f2
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v10, v4, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v30, v14, 4, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v31, v1, v10, v0

  li t2, 0x1564e79de9929e3a
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v2, v27, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v4, v14, 5, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v3, v19, v30, v0

  li t2, 0xf3817168d081ec9b
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v4, v21, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v28, v23, -5, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v15, v10, v30, v0

  li t2, 0xe5c590f7179a239d
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v13, v29, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v10, v26, 1, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v30, v12, v25, v0

  li t2, 0x86feca92df5ab1c7
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v17, v5, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v6, v8, 10, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v17, v1, v6, v0

  li t2, 0x41a11301cd081167
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v6, v9, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v26, v3, -5, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v29, v27, v25, v0

  li t2, 0x6c008da021562842
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v8, v14, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v15, v26, 9, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v31, v3, v27, v0

  li t2, 0x155bfb048665dd82
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v8, v31, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v5, v29, 0, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v5, v1, v19, v0

  li t2, 0x31b51fc19d8fe3ec
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v25, v27, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v20, v2, -11, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v19, v30, v15, v0

  li t2, 0x213548c8f323d7f5
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v15, v4, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v7, v5, 11, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v27, v31, v1, v0

  li t2, 0xb8c3c9f5ea4662b2
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v14, v8, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v7, v13, -15, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v14, v15, v19, v0

  li t2, 0x182548163246a1ed
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v12, v1, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v12, v14, -14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v20, v18, v16, v0

  li t2, 0x4636fff3da125fd9
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v29, v14, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v1, v31, -2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v2, v20, v24, v0

  li t2, 0x8229a3581c89421c
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v18, v21, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v2, v4, 12, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v29, v16, v2, v0

  li t2, 0xbb9da5dbcffe8099
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v17, v16, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v3, v29, -15, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v19, v24, v2, v0

  li t2, 0xfe36f7cd0a7c310b
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v7, v2, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v23, v16, 8, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v19, v22, v10, v0

  li t2, 0x51cdcb7161f5fa1a
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v1, v28, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v2, v24, -14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v30, v17, v24, v0

  li t2, 0xb3c1c51f91d02a72
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v31, v11, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v14, v30, -13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v9, v8, v5, v0

  li t2, 0x2a7e74073e029421
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v2, v9, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v7, v30, 9, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v3, v27, v8, v0

  li t2, 0x488f87d61cef3ca5
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v22, v13, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v13, v7, -11, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v22, v16, v3, v0

  li t2, 0x5bd5fdc73db9d469
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v12, v18, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v12, v30, -9, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v1, v6, v28, v0

  li t2, 0xe8c4cd551a991a58
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v23, v19, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v4, v25, 12, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v28, v19, v26, v0

  li t2, 0x5ff0b142d3186116
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v3, v16, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v3, v28, 0, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v4, v13, v21, v0

  li t2, 0xea8a3a7368614294
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v30, v28, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v26, v28, -1, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v31, v8, v21, v0

  li t2, 0x113f3bdc428987cb
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v5, v17, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v22, v28, -15, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v6, v24, v7, v0

  li t2, 0x9b96f0c8e19bb4ed
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v3, v12, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v1, v26, -14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v6, v24, v26, v0

  li t2, 0x0458d41e7820eb9a
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v11, v4, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v16, v26, -13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v26, v21, v13, v0

  li t2, 0x864d48edafcc320a
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v15, v7, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v10, v26, -11, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v16, v3, v10, v0

  li t2, 0xeecf47d611ee0b0c
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v3, v6, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v20, v13, 0, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v22, v20, v8, v0

  li t2, 0xfbb681f9dcfe3160
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v18, v24, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v3, v2, -3, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v17, v19, v23, v0

  li t2, 0xb84e8ef63134db18
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v26, v3, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v11, v12, -3, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v7, v17, v25, v0

  li t2, 0x4988605e2fcd6a00
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v9, v25, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v15, v2, 10, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v24, v9, v19, v0

  li t2, 0x8de0a386837b7fd2
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v31, v10, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v2, v8, -2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v8, v6, v27, v0

  li t2, 0xa7a1984c67a2d271
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v24, v25, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v4, v3, 13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v18, v20, v10, v0

  li t2, 0x78fdee00ba5d6941
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v28, v13, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v13, v31, -12, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v9, v19, v29, v0

  li t2, 0x7b1ed99895b41158
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v15, v12, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v10, v11, -2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v11, v31, v19, v0

  li t2, 0x067abd0cf13f4854
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v18, v29, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v18, v28, -4, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v6, v21, v7, v0

  li t2, 0x4439452f65e755a6
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v29, v25, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v11, v25, -14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v11, v28, v1, v0

  li t2, 0x267fbc5680a562b4
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v22, v13, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v19, v24, -9, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v26, v30, v23, v0

  li t2, 0x0b50c6454e3d69f0
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v30, v20, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v16, v31, 12, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v26, v31, v24, v0

  li t2, 0xf73e8698a962d00c
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v14, v2, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v23, v8, -13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v10, v19, v12, v0

  li t2, 0x7f1587b905227f92
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v31, v9, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v23, v5, 6, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v8, v19, v2, v0

  li t2, 0xd2c136c44c3c2ede
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v18, v16, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v13, v2, -16, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v6, v24, v26, v0

  li t2, 0x33f21ebd7a312564
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v30, v22, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v24, v10, -11, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v21, v30, v15, v0

  li t2, 0x36ffc6e50d3f3cbf
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v7, v4, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v13, v3, -15, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v2, v27, v25, v0

  li t2, 0x48fa39cefa308f51
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v5, v17, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v23, v15, -14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v16, v7, v6, v0

  li t2, 0xc55b27812b9482da
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v24, v2, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v5, v4, -12, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v18, v22, v9, v0

  li t2, 0x386cb5ab4cce3be3
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v5, v9, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v12, v26, -15, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v21, v7, v10, v0

  li t2, 0x997549d3beff3d6c
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v9, v22, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v11, v2, -14, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v16, v22, v10, v0

  li t2, 0x3da4e70c337db7d9
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v31, v27, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v25, v13, -16, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v24, v2, v11, v0

  li t2, 0x2146f5d0a1d49992
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v19, v11, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v30, v31, -11, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v10, v29, v20, v0

  li t2, 0xe5443699ac53e996
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v8, v29, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v30, v17, 9, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v23, v16, v18, v0

  li t2, 0xef9eb6f7bacbcd35
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v28, v9, -4, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v24, v3, v13, v0

  li t2, 0x6959f616b26c7bf9
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v19, v12, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v27, v20, 4, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v18, v31, v29, v0

  li t2, 0x90ba37cfbc7975f2
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v9, v28, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v26, v10, -13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v31, v23, v4, v0

  li t2, 0xcdf4724fe2d205c2
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v30, v20, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v1, v22, -2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v30, v31, v3, v0

  li t2, 0x6ccfa521b24dd2f8
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v5, v16, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v21, v8, -1, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v28, v20, v10, v0

  li t2, 0xfb1f6db20e590068
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v28, v9, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v8, v29, 13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v3, v29, v28, v0

  li t2, 0xf1da9fa642fee19c
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v25, v26, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v27, v23, -12, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v23, v30, v15, v0

  li t2, 0xe413337dfd587e59
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v11, v17, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v17, v7, -16, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v26, v9, v8, v0

  li t2, 0x7866967a68f93365
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v2, v6, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v26, v1, 8, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v29, v20, v1, v0

  li t2, 0x0242f7dfa89addce
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v22, v3, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v10, v7, -1, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v13, v22, v18, v0

  li t2, 0xbe60d86b97728514
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v20, v27, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v7, v23, -15, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v10, v20, v24, v0

  li t2, 0x15ea36cb35b8ec68
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v1, v21, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v22, v25, -9, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v29, v9, v17, v0

  li t2, 0x62d0def68340f206
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v19, v27, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v4, v9, 5, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v5, v20, v29, v0

  li t2, 0x7f18b047b0b0fbb6
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v17, v15, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v8, v23, -9, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v28, v2, v1, v0

  li t2, 0xdbf9a11ed60edb70
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v4, v27, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v27, v18, 6, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v30, v21, v23, v0

  li t2, 0xcf5a920907cb2f1c
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v7, v28, 15, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v1, v25, v30, v0

  li t2, 0x6d9db8b2342cd851
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v26, v27, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v29, v7, 11, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v24, v27, v5, v0

  li t2, 0xbc1f1e5a1d659738
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v21, v28, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v29, v26, -4, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v10, v23, v5, v0

  li t2, 0x43bc35f36bb97ce9
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v9, v19, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v15, v21, -1, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vvm v9, v3, v31, v0

  li t2, 0xf986581a1123f047
  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vxm v2, v20, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmadc.vim v19, v31, 2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v24, v8, v4, v0

  li t2, 0xf9c6e46c5c9f18a5
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v4, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v8, v20, 1, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v10, v24, v0

  li t2, 0x17b8a2032fd3a6ae
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v22, v14, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v18, v12, -7, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v12, v26, v10, v0

  li t2, 0xe0067a56db8d1852
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v18, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v26, v16, -11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v24, v28, v30, v0

  li t2, 0xa95e82050ec6343a
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v12, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v24, 14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v8, v20, v2, v0

  li t2, 0xec6e2daa37bb9bd7
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v24, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v18, -12, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v10, v28, v24, v0

  li t2, 0x13c819276ce5d8bd
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v14, -11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v28, v22, v26, v0

  li t2, 0xa5a6df944e584a54
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v12, 11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v10, v4, v24, v0

  li t2, 0x359317b208ca563e
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v8, v2, 8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v10, v26, v30, v0

  li t2, 0x6679a737b5777890
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v10, v16, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v14, v26, -16, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v20, v6, v16, v0

  li t2, 0x174011436c243ae1
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v26, v16, -15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v30, v10, v16, v0

  li t2, 0xcc0ffb172258795d
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v28, v30, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v30, 9, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v30, v22, v8, v0

  li t2, 0x34a3d17f0995f657
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v30, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v26, v12, 15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v22, v4, v0

  li t2, 0x5cc3445ed9a8661d
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v2, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v14, v30, -8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v10, v24, v16, v0

  li t2, 0xfa21eb1b3448460e
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v20, 1, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v8, v24, v2, v0

  li t2, 0x6d9f721470e33ff2
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v10, v24, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v4, v8, -5, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v8, v22, v12, v0

  li t2, 0x41205f29fc1615ef
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v18, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v12, 15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v28, v20, v2, v0

  li t2, 0x2efdf04d7e871f98
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v10, v16, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v18, -10, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v24, v22, v0

  li t2, 0x0c9f2e3358dbf80e
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v12, v10, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v20, v8, -8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v24, v16, v0

  li t2, 0x7b5bbe3e85a638f0
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v22, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v26, -15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v30, v2, v6, v0

  li t2, 0xe9b2757ca177e4fa
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v28, 15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v24, v20, v4, v0

  li t2, 0xf95444333e767814
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v18, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v10, 12, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v8, v6, v12, v0

  li t2, 0x4706aafa0d5ca48c
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v20, v4, 5, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v4, v24, v0

  li t2, 0x960016a7e6b944c4
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v4, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v4, v28, -6, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v6, v4, v0

  li t2, 0xea378bfc48547a5d
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v14, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v2, v12, 15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v8, v30, v12, v0

  li t2, 0xfb039f2f96afe923
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v8, v30, -11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v4, v26, v16, v0

  li t2, 0xabd087f6b58c1605
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v2, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v2, 15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v16, v30, v18, v0

  li t2, 0xbd33ceea7e50a6e7
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v26, v8, 4, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v20, v30, v16, v0

  li t2, 0x4a7b7d6081c5d885
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v18, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v28, v12, 14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v16, v18, v0

  li t2, 0x922ec642e41c0071
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v20, v12, 14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v14, v4, v0

  li t2, 0xd5cc11f2b8b6d415
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v12, -2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v8, v4, v30, v0

  li t2, 0xaa4ec3f1f3d7fcc7
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v28, 10, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v14, v10, v20, v0

  li t2, 0x481c013eb056697b
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v28, v4, 2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v22, v6, v24, v0

  li t2, 0xe0c10a0f4f996ed1
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v14, v12, 11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v8, v12, v30, v0

  li t2, 0xb45987ea5c65202a
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v14, 13, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v20, v2, v22, v0

  li t2, 0x6422f36fa6ada75b
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v6, 15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v16, v26, v0

  li t2, 0xe7456addf061ad2d
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v22, v10, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v12, v26, -10, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v22, v2, v28, v0

  li t2, 0x2a3d40253db249ed
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v26, v18, -9, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v14, v22, v4, v0

  li t2, 0xd3fb4f81157e3503
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v4, v18, 2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v14, v10, v16, v0

  li t2, 0xb1c3969976d3c81a
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v10, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v20, 1, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v22, v4, v0

  li t2, 0xf7117f933cc51850
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v12, 11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v20, v30, v8, v0

  li t2, 0x961a55b4a1cf48e1
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v6, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v10, -8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v2, v8, v18, v0

  li t2, 0x240f62bd2b2b3443
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v14, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v2, 9, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v12, v2, v0

  li t2, 0x5ccc7738803ce662
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v10, v20, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v12, v14, 12, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v8, v6, v20, v0

  li t2, 0x297ba54b8871503d
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v24, v26, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v8, v4, -12, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v20, v28, v10, v0

  li t2, 0xa9ed7834269d3219
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v4, v2, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v14, v12, -9, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v22, v30, v0

  li t2, 0xb8226fe8f8dc210b
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v18, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v20, -10, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v28, v22, v14, v0

  li t2, 0x8feb035be0cd27ab
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v14, v24, 11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v14, v4, v24, v0

  li t2, 0x7d2340671acc5a81
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v16, -2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v20, v12, v8, v0

  li t2, 0xe16a95fe71eb4950
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v24, v26, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v18, v2, -13, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v10, v28, v0

  li t2, 0x6003f5c3543783dc
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v14, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v18, v20, -15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v24, v22, v30, v0

  li t2, 0x8e7b5f8f42f11ce6
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v26, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v2, 12, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v20, v26, v30, v0

  li t2, 0xd4a7ecfb4b788dc4
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v18, v24, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v4, v22, 10, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v16, v20, v10, v0

  li t2, 0x7b9fc476471ce7ea
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v8, v6, -5, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v26, v10, v0

  li t2, 0x9825c58ebdf74d73
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v28, v14, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v2, v12, 11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v28, v12, v30, v0

  li t2, 0x9aca1f40c6995249
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v14, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v8, v28, 13, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v8, v26, v10, v0

  li t2, 0xa5b9842e7115e77d
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v8, v18, 13, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v14, v12, v0

  li t2, 0x2d64295777dd4738
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v16, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v12, v26, 12, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v28, v24, v0

  li t2, 0x41f0a09e6851d3a1
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v18, -11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v10, v24, v30, v0

  li t2, 0xcfd3e551d9f9bebc
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v8, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v18, v22, -1, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v22, v10, v4, v0

  li t2, 0x2231e494afd9d438
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v16, v14, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v24, -7, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v4, v2, v10, v0

  li t2, 0x32cf0bb648b42d46
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v20, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v28, -15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v2, v28, v0

  li t2, 0x6b26dadac324f82a
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v20, v6, 7, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v12, v8, v10, v0

  li t2, 0xe00ae549f6a69e6b
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v12, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v8, -4, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v16, v6, v20, v0

  li t2, 0xe3f5193c83a059fd
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v18, v20, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v6, 8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v28, v14, v20, v0

  li t2, 0x425ce307fd6639ef
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v28, v14, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v2, 6, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v16, v2, v4, v0

  li t2, 0xa62eed9317e797ea
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v28, -8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v24, v6, v12, v0

  li t2, 0xdf19219840c30e2b
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v4, v10, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v4, 8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v20, v22, v0

  li t2, 0xc7be4e8eb967fc06
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v4, v26, -5, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v12, v30, v26, v0

  li t2, 0x8a03e2ec2098bfb6
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v14, v24, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v4, v20, -1, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v12, v10, v0

  li t2, 0x2444a18e4edc2273
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v18, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v24, 15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v20, v8, v2, v0

  li t2, 0x118cfabd56aed2b5
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v24, -3, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v28, v30, v0

  li t2, 0x740767b1675bd39b
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v8, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v26, v10, 5, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v30, v26, v4, v0

  li t2, 0x2a415321239b5bea
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v26, v6, -2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v8, v26, v4, v0

  li t2, 0x3a9cbb8b7de3dcb5
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v8, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v24, v8, 15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v6, v8, v0

  li t2, 0xf37d5eb3b300a0f3
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v14, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v4, -16, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v8, v14, v0

  li t2, 0xfae0f19633c175e8
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v22, v2, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v2, v24, -4, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v16, v28, v6, v0

  li t2, 0xa1ccc6d0357b75d5
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v4, 12, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v14, v30, v12, v0

  li t2, 0xc22b4ea75aacb8b3
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v22, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v18, v28, -8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v6, v22, v8, v0

  li t2, 0x2afe95e87f2b96f8
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v30, -11, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v24, v26, v14, v0

  li t2, 0xd4fb668c4514d9e3
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v30, v2, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v18, v28, 6, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v28, v2, v18, v0

  li t2, 0xf952e883e136a1f3
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v6, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v12, v28, -6, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v16, v12, v6, v0

  li t2, 0x539d8476daca23ba
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v10, v4, -8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v28, v24, v12, v0

  li t2, 0xeb9a353fd848e8a7
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v6, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v30, -10, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v16, v8, v28, v0

  li t2, 0xfdf0fc434511b083
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v12, v10, 0, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v4, v8, v6, v0

  li t2, 0x4812044a0dc918c7
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v10, v16, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v12, v30, -8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v10, v16, v0

  li t2, 0x19f52477daa93935
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v30, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v26, v24, 1, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v18, v4, v0

  li t2, 0xf0c2a2b8bfb98b26
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v14, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v8, v10, -12, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v28, v26, v24, v0

  li t2, 0xf50e76e2ed01a80c
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v10, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v18, v8, 3, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v30, v18, v12, v0

  li t2, 0xa25ca669a3b7f749
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v16, v18, -14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v28, v30, v0

  li t2, 0x94d07970b254db68
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v26, v30, -8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v4, v26, v24, v0

  li t2, 0x0b8acd796b09d99e
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v10, v28, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v26, v30, 0, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v4, v24, v14, v0

  li t2, 0xf9fb40b534de45ee
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v10, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v20, v4, -1, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v14, v16, v0

  li t2, 0xd022f7fcd41b4feb
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v26, v10, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v10, v12, 0, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v26, v10, v6, v0

  li t2, 0x5cb308898ee4e1e0
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v6, v18, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v10, v28, -4, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v8, v4, v0

  li t2, 0xb8571370bedc5d22
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v20, v14, 9, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v18, v10, v24, v0

  li t2, 0x6537336543eacb0e
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v28, v10, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v30, v6, 15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v16, v18, v30, v0

  li t2, 0xd42dd637ab03c2c2
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v26, 5, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v10, v20, v12, v0

  li t2, 0xa4a9856baa80b1a3
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v12, v2, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v22, v26, 14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v4, v26, v14, v0

  li t2, 0x99c241e3cd9468cf
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v2, v20, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v8, v10, -15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vvm v28, v18, v4, v0

  li t2, 0xae17511608591dee
  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vxm v4, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmadc.vim v6, v10, 2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v24, v20, v0

  li t2, 0xff5905e84f5accd5
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v28, -16, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v12, v28, v0

  li t2, 0x090fa8acf830b39c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v4, 9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x13ef479905e67a64
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v16, 7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v20, v24, v0

  li t2, 0x64219eb9636f4010
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v4, -16, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v28, v12, v0

  li t2, 0x1f6d437671c9ba74
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v4, 10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v4, v16, v0

  li t2, 0xd7c3a27055dbaef4
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v28, 1, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v24, v12, v0

  li t2, 0xc02ebb6ec6dea214
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v12, -4, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v28, v12, v0

  li t2, 0xa43ec38751341d42
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v24, -11, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v16, v24, v0

  li t2, 0x340fc8d17799969c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v28, 5, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v20, v8, v0

  li t2, 0x47d4ff535b044048
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v24, -3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v12, v4, v0

  li t2, 0xdc332d89e2e43298
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v4, 3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v20, v12, v0

  li t2, 0x1041a05812a96eb7
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v4, -15, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v24, v28, v0

  li t2, 0xcfc80655eec11dfa
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v4, 1, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v16, v8, v0

  li t2, 0x0991a05a97d59b71
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v8, -7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v16, v20, v0

  li t2, 0x3266db15462a6410
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v4, -2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v20, v12, v0

  li t2, 0xc1ed033c0872126c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v12, -14, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v12, v24, v0

  li t2, 0xbdeb5f349e1478d0
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v28, 5, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v12, v8, v0

  li t2, 0x35b38a5ecaddae30
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v12, 3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v12, v8, v0

  li t2, 0x4150ec4f92ebfe18
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v20, -3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v20, v4, v0

  li t2, 0xaffe68c760489aa2
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v20, -1, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v16, v20, v0

  li t2, 0x568ab156e474bd39
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v20, -4, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v8, v4, v0

  li t2, 0x26354da9819c45be
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v24, -8, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v28, v24, v0

  li t2, 0xa482b98ff148d162
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v24, 9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v4, v16, v0

  li t2, 0x07f90d1e496c81d6
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v4, -2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v20, v28, v0

  li t2, 0x92fda37f266df8f6
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v16, 5, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v28, v20, v0

  li t2, 0x9f78b85c2d7d72d5
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v16, -11, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v28, v16, v0

  li t2, 0xb2c2b327a7574e57
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v12, -12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v4, v28, v0

  li t2, 0xb2dee98cac7b4c5c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v24, -9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v20, v4, v0

  li t2, 0x09bb34236274d2e8
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v4, 9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v8, v12, v0

  li t2, 0x1377bac0492824a4
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v16, 12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v8, v4, v0

  li t2, 0x654aa2a146232160
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v20, -3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v24, v12, v0

  li t2, 0x1061110faea8c645
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v20, -11, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v20, v16, v0

  li t2, 0xa482023eb013c736
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v24, 7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v12, v24, v0

  li t2, 0xea3edf83ff018a4d
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v4, 3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v16, v28, v0

  li t2, 0x0277be0bd7a2496d
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v16, 7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v28, v12, v0

  li t2, 0x5f0808213c427ad3
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v4, 6, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v24, v16, v0

  li t2, 0xe8c6b23a4148f35c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v12, -1, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v12, v24, v0

  li t2, 0x0805fd4557c36794
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v20, -8, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v4, v16, v0

  li t2, 0x58b50b7c0372b7c4
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v12, 2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v20, v28, v0

  li t2, 0xd6eae4224f77d9a2
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v20, -8, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v4, v16, v0

  li t2, 0x368d19e80809a432
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v28, 7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v28, v20, v0

  li t2, 0x1def42ebe4a576f9
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v4, -12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v28, v16, v0

  li t2, 0xa9db0a2725a5745c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v4, -12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v20, v24, v0

  li t2, 0x3dd7f8348525d9c3
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v12, 8, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v24, v4, v0

  li t2, 0x2d8c50f4dcca2f08
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v4, -1, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v28, v20, v0

  li t2, 0x4efddc238f65c781
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v12, -15, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v20, v24, v0

  li t2, 0xd90cd44e7031afa3
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v4, -13, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v20, v24, v0

  li t2, 0xc1ad55d57a03d383
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v8, 7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v24, v12, v0

  li t2, 0x6ce53b3a936e37f8
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v8, -6, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v20, v8, v0

  li t2, 0x175f393b11e06294
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v16, 1, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v28, v4, v0

  li t2, 0xe935804d55901db2
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v24, -12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v20, v24, v0

  li t2, 0x94ce685bc78bd937
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v20, 8, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v24, v28, v0

  li t2, 0x9df2db21a4623d44
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v16, -7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v20, v8, v0

  li t2, 0x22e8ac91e4255a32
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v28, 8, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v12, v16, v0

  li t2, 0xbc9173548f9b9b69
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v24, -9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v16, v20, v0

  li t2, 0xf72e5d003b9b27fe
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v16, -1, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v20, v4, v0

  li t2, 0x101f21aaae55ba62
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v16, 1, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v24, v16, v0

  li t2, 0x3c13571deb70d14b
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v20, 3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v12, v24, v0

  li t2, 0x3d9f710149669f6e
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v16, -16, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v28, v20, v0

  li t2, 0x4378768e30e94fe6
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v12, 7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v16, v4, v0

  li t2, 0xad6dd57db6a3c4c1
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v12, -16, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v20, v12, v0

  li t2, 0x3969dc834db01a0f
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v8, -6, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v20, v8, v0

  li t2, 0xefefea7093980486
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v20, -16, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v28, v12, v0

  li t2, 0xa228b7bafcac4738
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v24, 10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v28, v20, v0

  li t2, 0xb7337443096c2e45
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v12, -9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v20, v24, v0

  li t2, 0x78c1bbd7d57f4c0b
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v12, -14, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v24, v8, v0

  li t2, 0x651757f43ea647c4
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v24, 4, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v20, v28, v0

  li t2, 0x61fd95112e8feaa4
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v28, -2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v12, v28, v0

  li t2, 0x49cb4359702ec944
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v8, 7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v12, v28, v0

  li t2, 0xa57b2982b700440c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v24, 10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v24, v28, v0

  li t2, 0xd22809de6cd14746
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v4, -12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v12, v24, v0

  li t2, 0x769001fac661ae6c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v4, 5, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v4, v24, v0

  li t2, 0x8a5197cd1a97448c
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v28, 3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v4, v16, v0

  li t2, 0x17cadaaddabb1661
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v16, 13, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v24, v8, v0

  li t2, 0x9b0a288820db780b
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v16, 14, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v12, v4, v0

  li t2, 0x5206799af79c1377
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v28, 9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v12, v24, v0

  li t2, 0x1753ebc9ff0b716f
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v4, -7, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v16, v4, v0

  li t2, 0x6e140381a47c17da
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v20, 9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v20, v8, v0

  li t2, 0x711b8cb1f52602c8
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v12, -6, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v16, v4, v12, v0

  li t2, 0x366a1451e44cce8b
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v28, 13, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v20, v16, v0

  li t2, 0x89226c7f95e7e754
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v4, 15, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v28, v8, v0

  li t2, 0xdea40f28747a99ef
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v24, -9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v4, v12, v0

  li t2, 0x6849b08425709e7a
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v4, 2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v12, v16, v0

  li t2, 0x79fec1e6f433b194
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v4, 10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v12, v8, v0

  li t2, 0x7484e12499555118
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v4, 2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v28, v24, v0

  li t2, 0x0f7eed58598926b0
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v28, -14, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v4, v16, v0

  li t2, 0x85f4e9f2e9f5cdfd
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v8, -1, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v16, v12, v0

  li t2, 0x5831d15ec943c256
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v16, -4, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v28, v16, v4, v0

  li t2, 0x7bf5f8bba8cc9d5d
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v4, -15, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v8, v16, v0

  li t2, 0xcab4981fd3fd9c94
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v20, 5, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v4, v8, v0

  li t2, 0x24138229761550b6
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v12, -10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v8, v20, v4, v0

  li t2, 0xae57914f0983dbb3
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v8, v20, -12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v20, v24, v0

  li t2, 0x32a8e3891d00326a
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v28, 10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v12, v20, v0

  li t2, 0xd46a2bea10d62ffc
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v20, -9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xd3794fcab9f71057
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v28, v8, 12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v4, v28, v8, v0

  li t2, 0x7d303b4a5da8c8ab
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v12, v24, 13, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v12, v4, v16, v0

  li t2, 0x0f683d099b127a38
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v4, v24, -3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v4, v8, v0

  li t2, 0xd2f67fb3024ccbee
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v16, v8, -3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v8, v12, v0

  li t2, 0x4ecc26de7def550b
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v20, v16, 9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vvm v20, v24, v16, v0

  li t2, 0x8b12e334b22f20da
  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmadc.vim v24, v8, 14, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xe95035005b582766
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -15, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xa1c9a92d4db7c486
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -16, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xe916ff50f143970f
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x84fb713a01eb1e33
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, 10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x8505faa1eb5fe7be
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 6, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x88160a772795969a
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, 13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xc5df2bbb23ad2049
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -4, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x84b0f53dfe636e40
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -6, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xe45ad7cdb48da9aa
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, 2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x7a3d59b315e0e86a
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x6ee3d6b9317d12a3
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 5, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x7617590bd62c8ea5
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, 10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x9cff2b326b08e024
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x81dc1ff6e3ff0b0d
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -11, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xdda374fe10e3fd68
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -11, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xf55ca8cea1978d20
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, -4, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x7d5ef0ef5fea8787
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, -5, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x150d6deccb284445
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x97243ac1aa4be603
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, 13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xb3ddeff13633c3bb
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -4, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x03485bad51bc0509
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 1, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x0083ba1fec182612
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xfba9c2d99ffd0f30
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 5, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xeddb655232fc4a68
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, 15, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x8295f47362367a6e
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, -9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x593fadf18a6ec9a6
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x608bf7aa8a8d133c
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 1, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x234283afcfb18177
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, -4, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x72d4716ef957598d
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xfda8c717fc12251b
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 1, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xb0a1a284c1d7b4eb
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x66265ba4689e233a
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -3, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x7154b361ed3b42d4
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xe84fb12abd94d071
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, -10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x58d88f2c73e6df9b
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, 11, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x365b73686b8f0fcb
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 11, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x071e7e3708375bec
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x19e5d6b457236194
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 3, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xfd12feee66916bed
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, 15, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xd667254cbf3922fd
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, 13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x652205ae146a50cd
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -15, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x95c932a5524a4142
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, 0, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x6d86be5508bef164
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 3, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xf7ea8eb0ad7406d2
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xa91cb1e0c5fdae04
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x36de731bbda66827
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 6, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x6a81c76f217c098b
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xff57d15a8670cc3a
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xba848ebd13ca0667
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -11, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x4649526443948b11
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x4c51c45164d359b2
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, 10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xb78263b5d8509fa5
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, -4, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xfd2d4dfb2411e446
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -6, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x7eac37be545fe7a1
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 11, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x2be88e9f39340a27
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xbadfb33c40cbe945
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, -11, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x96e9e43e8f5339df
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, -12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x646d0abe8cd0280e
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -4, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xacdf493bc4267ea6
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xf07b6e550cf6d9f1
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 11, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x2269a990c4874dc2
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -16, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x35ab996c684f80d0
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, -6, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x3a520ae19c9982b3
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -14, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x00aa5bf2f8fe9026
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -7, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xe253539dabca8113
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, -3, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x6b6a2d108ce524aa
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xaef4a7fdb54328c4
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -7, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x2ebcc803739454e2
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -14, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xd230c148a47ba68d
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -3, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xc178e01791f25bc7
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 4, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x64377edf0655fd14
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -3, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x496b53535693da83
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x9368ac1b2882292b
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, -5, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xb888e5c61c8aa812
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, 14, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xb506af81dd184f66
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, -8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xe201613a00065fa6
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, 9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xaabdaad1879bef3e
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, 13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x9b31c28c1d6856ff
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, -1, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xacd84222b2ab2919
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 0, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x58156bf047b4d596
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, -13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x078642b313e2964e
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, 10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x4f5d367de7bcc018
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -3, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x64a7f808bea719c9
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, 14, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xd347e196bce33fd8
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x3d7b4dacc0afcd19
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, 0, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xfe09846b8ff76412
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, 0, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x2ced0e498ed8aef7
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, -16, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x5a74bc18e8638e90
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v24, 13, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x5cd0d5f18d928183
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 0, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x3ecf3177fe525862
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x080d9ae64c7b1f5b
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v16, -10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x28434a6df8a94ba4
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, -8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x56ea9a46f3843264
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v8, v24, 1, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x21e3b15ebd790533
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v8, 6, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xfb37893537fd10f0
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 15, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xf14de2f9f71ace43
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v24, v16, 8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xbfac865dc0c86168
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, 12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x6ebce4851e336ea3
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, -11, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xf56035535777cf6e
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, 14, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x6632ed0895be69fc
  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmadc.vim v16, v8, 2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v16, v18, v24, v0

  li t2, 0xb11aa5638fcce9aa
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v3, v30, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v19, v11, -6, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v19, v11, v2, v0

  li t2, 0x42ba220a40881e88
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v7, v8, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v21, v23, 5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v16, v14, v29, v0

  li t2, 0x35cd6663978a40a2
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v1, v9, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v23, v19, 10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v10, v12, v23, v0

  li t2, 0x97af62ba6c829d2e
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v12, v29, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v23, v10, 9, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v14, v19, v20, v0

  li t2, 0x0ca587220a3f3bee
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v3, v28, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v12, v18, 8, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v13, v3, v19, v0

  li t2, 0x1ac7f143794fbe40
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v12, v22, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v10, v26, 0, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v20, v30, v10, v0

  li t2, 0x36c933aac1d1ca1d
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v11, v22, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v13, v28, -11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v15, v1, v2, v0

  li t2, 0xbf7a2dbe4782633b
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v9, v3, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v6, v27, -2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v28, v7, v4, v0

  li t2, 0x1886adf071602c3f
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v4, v15, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v10, v20, 6, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v4, v22, v14, v0

  li t2, 0xc8756bfc3ef0b238
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v25, v21, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v20, v10, -11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v21, v13, v12, v0

  li t2, 0xa568bbe4e8c9f42d
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v5, v8, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v30, v9, 11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v25, v18, v3, v0

  li t2, 0x5d31c239b8d94b33
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v19, v9, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v8, v25, -5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v28, v19, v2, v0

  li t2, 0xc730b5ddbb5af95b
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v5, v8, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v14, v24, 2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v10, v24, v4, v0

  li t2, 0x5e0898a2895f0a51
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v10, v16, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v10, v7, 2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v20, v13, v19, v0

  li t2, 0x906707cb7dd5375b
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v26, v5, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v4, v22, -5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v30, v11, v2, v0

  li t2, 0x399054ca0c4d40bd
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v12, v23, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v20, v12, 10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v4, v17, v26, v0

  li t2, 0x7bcbcf47f55538eb
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v24, v26, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v8, v7, 11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v11, v26, v16, v0

  li t2, 0x7ce5ea6bb47f48d3
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v16, v19, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v3, v12, -4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v24, v31, v29, v0

  li t2, 0xe14c30d9afa14a46
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v28, v1, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v28, v26, 7, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v14, v8, v11, v0

  li t2, 0x8c6b825e4690fc1a
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v23, v22, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v5, v13, 0, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v11, v20, v17, v0

  li t2, 0x3daf98e54914023b
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v8, v1, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v4, v13, -2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v29, v17, v20, v0

  li t2, 0xa521d50ab347d4cd
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v17, v7, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v23, v6, 15, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v29, v14, v20, v0

  li t2, 0xfdae5c44848a3584
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v4, v9, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v10, v19, -12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v12, v6, v27, v0

  li t2, 0x5908c61b1549de77
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v1, v15, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v14, v4, 2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v11, v27, v14, v0

  li t2, 0x92f0736220164cae
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v29, v16, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v17, v24, 7, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v30, v28, v26, v0

  li t2, 0x81296d7c231780ec
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v21, v22, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v31, v3, 11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v13, v21, v27, v0

  li t2, 0xa0e27258fb92fc02
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v15, v3, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v3, v2, -13, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v31, v6, v10, v0

  li t2, 0xd12462dce3428721
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v13, v28, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v18, v15, -12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v10, v23, v20, v0

  li t2, 0xa4890685e2d2be6c
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v29, v21, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v7, v2, -1, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v22, v10, v29, v0

  li t2, 0xfd7f6d80a2a97636
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v2, v23, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v11, v8, -12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v15, v11, v8, v0

  li t2, 0xb3f789428633bd1c
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v31, v21, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v13, v27, -10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v27, v22, v14, v0

  li t2, 0xe5b226a136567da6
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v21, v13, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v2, v3, -3, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v25, v2, v20, v0

  li t2, 0x3307ae8c10cf0bb4
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v18, v16, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v27, v25, -12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v30, v3, v16, v0

  li t2, 0x6df5cb602fdeaa22
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v24, v29, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v15, v25, 13, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v2, v18, v16, v0

  li t2, 0x3e1e441e2a62bd2a
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v10, v3, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v28, v10, -14, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v15, v3, v4, v0

  li t2, 0x6476449720185014
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v18, v3, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v13, v24, -4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v14, v3, v26, v0

  li t2, 0xb20bfd6751033900
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v8, v9, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v28, v12, 11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v6, v1, v3, v0

  li t2, 0xda821b6ba2f9b37a
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v25, v8, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v19, v21, -2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v25, v2, v23, v0

  li t2, 0x2c222223b59554d9
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v12, v18, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v30, v24, -2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v28, v4, v9, v0

  li t2, 0xa85091229fcbc961
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v15, v18, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v6, v30, 7, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v14, v23, v18, v0

  li t2, 0x8139ed7cc46dbd45
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v3, v19, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v22, v28, -5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v4, v16, v8, v0

  li t2, 0x3f4f470c5e827291
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v8, v9, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v22, v25, 10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v23, v17, v27, v0

  li t2, 0x0294cd1c5ee7afad
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v15, v16, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v5, v25, -4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v30, v31, v29, v0

  li t2, 0x656ad8ea77d106ec
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v22, v26, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v28, v30, -13, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v11, v25, v21, v0

  li t2, 0x0ceb934db06b016a
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v15, v14, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v9, v13, 11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v23, v9, v15, v0

  li t2, 0x6649640e4d93764d
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v24, v1, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v21, v16, -4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v21, v5, v27, v0

  li t2, 0x93bdf512bd1a9cdb
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v6, v30, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v29, v31, 8, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v8, v7, v15, v0

  li t2, 0xc9cf9ca93881bc38
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v30, v31, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v10, v21, 5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v23, v12, v28, v0

  li t2, 0x409e8836cea2163e
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v6, v28, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v26, v8, 11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v8, v18, v6, v0

  li t2, 0x4885d8d3a0465d23
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v18, v2, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v28, v8, -2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v8, v28, v11, v0

  li t2, 0x774feea071b6cd4f
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v27, v29, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v24, v23, 1, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v19, v30, v28, v0

  li t2, 0xdf18ef2073b3505f
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v7, v13, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v28, v10, -14, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v4, v8, v14, v0

  li t2, 0x036e3b27db37f3d4
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v28, v5, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v1, v31, 14, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v9, v13, v14, v0

  li t2, 0x807656948404f36f
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v22, v20, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v16, v30, -16, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v28, v4, v5, v0

  li t2, 0x8d012d48248890e7
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v17, v6, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v7, v9, -7, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v25, v21, v28, v0

  li t2, 0xe389c138a768ebc9
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v6, v28, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v13, v8, 0, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v27, v25, v6, v0

  li t2, 0x8173433518c45329
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v1, v29, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v4, v13, -5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v8, v22, v25, v0

  li t2, 0xd8c36718d77fa5cf
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v15, v24, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v5, v15, -9, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v18, v15, v5, v0

  li t2, 0x6d3341485a65cec7
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v24, v13, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v5, v31, -12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v2, v11, v19, v0

  li t2, 0x580e54b176fedfed
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v6, v4, -9, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v4, v22, v10, v0

  li t2, 0x60c609367ef14da4
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v3, v4, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v18, v6, -4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v26, v9, v21, v0

  li t2, 0x96548f0fc8a7d815
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v5, v23, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v1, v3, 1, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v6, v11, v2, v0

  li t2, 0x2abf1389f1e23148
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v11, v25, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v26, v21, 5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v17, v25, v31, v0

  li t2, 0xf96a4b66799ec7af
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v18, v17, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v4, v7, -11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v5, v18, v11, v0

  li t2, 0x098b5bc48d815779
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v2, v13, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v2, v3, -15, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v19, v21, v26, v0

  li t2, 0x4da51ad9a81ee5d0
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v8, v9, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v24, v8, 10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v8, v6, v31, v0

  li t2, 0x567c1153b5d8e485
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v7, v3, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v29, v25, -15, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v7, v4, v12, v0

  li t2, 0xfbe07dea1ebf55d9
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v13, v30, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v27, v29, 11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v16, v30, v6, v0

  li t2, 0x11013ddb107e08e7
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v24, v17, -5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v24, v18, v7, v0

  li t2, 0x96dceef7b6142f95
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v10, v2, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v21, v18, 8, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v6, v2, v22, v0

  li t2, 0x780322a663c8bfa0
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v28, v3, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v12, v18, -4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v24, v13, v15, v0

  li t2, 0xf63ed7d4faf708a0
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v22, v4, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v13, v12, -10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v17, v2, v15, v0

  li t2, 0x3e03d0ffc9c39d5d
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v11, v19, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v8, v23, 10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v22, v21, v18, v0

  li t2, 0xe332ecbb2dfcd9ff
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v3, v7, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v20, v26, 9, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v7, v17, v11, v0

  li t2, 0x58dd4ff983095ca7
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v14, v23, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v29, v16, -10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v17, v9, v11, v0

  li t2, 0x891212b1a3e349a0
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v19, v15, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v7, v25, 2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v27, v30, v25, v0

  li t2, 0x107a37c76720321b
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v15, v29, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v14, v17, -1, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v29, v21, v30, v0

  li t2, 0x1241494617f74afd
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v12, v29, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v29, v18, -7, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v25, v11, v6, v0

  li t2, 0xb2a35cd47d086530
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v29, v9, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v14, v29, -16, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v28, v29, v17, v0

  li t2, 0x7fa64cc830fdfaf2
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v14, v9, 15, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v27, v9, v18, v0

  li t2, 0xb12e668509c36b69
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v31, v7, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v5, v18, 13, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v21, v5, v4, v0

  li t2, 0x971c8088fc6329dc
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v6, v19, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v21, v17, 4, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v23, v16, v21, v0

  li t2, 0xa50d7ac160f7d213
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v2, v30, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v29, v2, 2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v10, v11, v26, v0

  li t2, 0x939bce5d8870b5ec
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v11, v30, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v25, v11, 8, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v16, v3, v10, v0

  li t2, 0xac4dcb7b1de5a7d4
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v26, v21, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v23, v30, -12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v30, v4, v11, v0

  li t2, 0x125f91cacd06ed66
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v25, v16, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v9, v12, -12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v27, v28, v23, v0

  li t2, 0x1b9e604aef4fc277
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v21, v9, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v11, v24, 2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v23, v25, v5, v0

  li t2, 0xa9e48adaf8e38c16
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v14, v18, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v15, v7, -8, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v31, v27, v14, v0

  li t2, 0x0c2d90d712a19ece
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v9, v24, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v9, v13, -14, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v14, v20, v27, v0

  li t2, 0x46cecf3980ad52c3
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v16, v21, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v8, v3, -15, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v14, v29, v26, v0

  li t2, 0x48a3d07396587cda
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v5, v26, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v15, v31, -8, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v16, v11, v5, v0

  li t2, 0x94cbeb234a22f2ba
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v6, v19, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v15, v7, -9, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v22, v26, v20, v0

  li t2, 0x75b64d4585162d8b
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v27, v16, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v16, v12, -1, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v31, v8, v20, v0

  li t2, 0x9b45ca41caf81146
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v27, v17, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v2, v10, -9, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v27, v18, v7, v0

  li t2, 0xa217f5aaaf64c68b
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v28, v31, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v29, v11, 5, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v25, v2, v4, v0

  li t2, 0x0178c16212bff7a2
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v23, v3, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v14, v24, 10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v29, v6, v22, v0

  li t2, 0x55c1ebc5941a7657
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v11, v5, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v25, v7, 11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v11, v19, v29, v0

  li t2, 0x74a00fda3d424adf
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v13, v20, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v27, v30, 11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v24, v1, v31, v0

  li t2, 0x0de7abb6f68e3dd0
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v23, v5, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v26, v3, -13, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vvm v21, v19, v27, v0

  li t2, 0x42ec1ea51bcf882b
  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vxm v26, v12, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmadc.vim v26, v30, -6, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v12, v30, v4, v0

  li t2, 0xf9dc83f6cbb37ebd
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v4, v26, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v4, 13, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v16, v8, v0

  li t2, 0x4714c13bc89a8a3d
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v6, v30, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v10, v22, -15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v6, v20, v2, v0

  li t2, 0x69abfa3d34a7c99f
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v2, v20, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v30, v26, 2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v30, v4, v28, v0

  li t2, 0xdc864b1cc345f35e
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v12, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v10, v4, 2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v16, v28, v2, v0

  li t2, 0x51b144741f46b58a
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v10, v24, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v4, v2, -8, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v18, v8, v20, v0

  li t2, 0x4313782df379b3d1
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v10, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v6, -14, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v22, v10, v6, v0

  li t2, 0xa1666176072bebd4
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v2, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v26, v6, 11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v12, v8, v20, v0

  li t2, 0xa67ef68816b93618
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v4, 3, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v24, v16, v0

  li t2, 0xb62f9f39d277a36c
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v4, v6, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v28, v4, 13, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v2, v26, v22, v0

  li t2, 0x73366b4debc1bef8
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v30, v28, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v20, 10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v18, v6, v0

  li t2, 0x790de00934356364
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v2, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v28, v22, -7, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v12, v30, v28, v0

  li t2, 0x09d66ced21df6874
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v18, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v20, v22, -13, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v18, v6, v26, v0

  li t2, 0x2db5eb7702b1cb74
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v8, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v20, 8, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v30, v14, v0

  li t2, 0x390f979cd888c69f
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v12, v22, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v12, v20, 2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v24, v8, v0

  li t2, 0xf10476e5dcf754aa
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v20, v30, 1, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v22, v2, v6, v0

  li t2, 0x7fb5cda1b4a499ff
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v26, v20, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v30, 6, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v12, v4, v22, v0

  li t2, 0x622a764569a979c7
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v26, v12, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v10, 10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v30, v14, v0

  li t2, 0x7748a270f3c2a0d9
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v24, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v14, v18, -13, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v8, v10, v6, v0

  li t2, 0x064c8e56fc91d571
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v26, -13, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v20, v2, v18, v0

  li t2, 0x24940b28bb66ef9d
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v22, v12, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v2, v26, -2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v18, v28, v0

  li t2, 0x460b3edd53119bc4
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v28, v18, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v14, v24, -9, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v26, v10, v14, v0

  li t2, 0xf708832ecf91f0e4
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v26, v30, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v10, -7, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v18, v26, v0

  li t2, 0xb8e844e368f197d9
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v8, v30, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v16, -2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v16, v6, v0

  li t2, 0x9cfdc9259900dfe1
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v4, v2, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v12, 9, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v2, v22, v12, v0

  li t2, 0x74d0160568953b8a
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v8, v6, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v14, v8, -5, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v6, v8, v22, v0

  li t2, 0xd70dd46da567ba03
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v2, v16, 6, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v12, v26, v16, v0

  li t2, 0xbd5550edf2cf552f
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v26, 2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v26, v20, v28, v0

  li t2, 0x65d70100b6118e15
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v10, v22, 7, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v2, v10, v28, v0

  li t2, 0x062a6c696060209f
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v2, v10, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v30, 11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v16, v24, v14, v0

  li t2, 0x7d4f6b281a8f0bce
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v30, v10, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v30, 10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v8, v10, v24, v0

  li t2, 0xa20ebad83da6b66f
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v6, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v22, v30, -12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v14, v8, v0

  li t2, 0x579db83d09ee8196
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v18, v4, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v12, -1, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v6, v10, v22, v0

  li t2, 0xa2f9a1a96735e3b6
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v26, v28, -10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v2, v4, v6, v0

  li t2, 0xc7e1c5213c8e9781
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v16, v22, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v6, v20, 12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v4, v2, v28, v0

  li t2, 0x1d632dbe1b7cb0a3
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v10, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v14, -10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v16, v10, v20, v0

  li t2, 0x3d1d83864be9e328
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v22, v10, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v2, v16, 7, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v26, v6, v30, v0

  li t2, 0x104cd1cfc71f9316
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v18, v20, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v30, 4, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v6, v4, v28, v0

  li t2, 0xcc1dcfaaee139347
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v2, v20, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v26, -9, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v26, v2, v22, v0

  li t2, 0x147009256a9e58cd
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v28, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v12, v6, -15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v30, v6, v10, v0

  li t2, 0xc70a9087a65e3410
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v8, -15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v18, v8, v10, v0

  li t2, 0x7933234df8ceae2a
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v14, v12, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v28, v18, -5, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v18, v20, v0

  li t2, 0xbdb4687a93009006
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v6, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v6, v26, 6, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v20, v14, v2, v0

  li t2, 0xc33bd66d050d26a5
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v28, v22, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v26, 5, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v12, v8, v18, v0

  li t2, 0x81e5fa24c0592a3b
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v18, v26, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v26, v30, 7, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v16, v24, v0

  li t2, 0x56bde1f373d5b535
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v18, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v4, v20, 10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v4, v8, v14, v0

  li t2, 0x993353ff989f2958
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v30, v22, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v24, 12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v4, v8, v10, v0

  li t2, 0x20287e5834874d04
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v2, v4, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v28, 4, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v26, v28, v22, v0

  li t2, 0x0d2cd62ce31b8675
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v6, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v30, v18, -16, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v24, v10, v2, v0

  li t2, 0xa9c454cbdc12dd50
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v14, -1, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v6, v16, v26, v0

  li t2, 0x76ef9c22ea25f8c8
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v30, v8, 3, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v22, v12, v20, v0

  li t2, 0x78873a1be10ba5cd
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v28, v6, -2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v12, v4, v14, v0

  li t2, 0x83722376a2893259
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v14, v24, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v10, v8, 10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v30, v22, v28, v0

  li t2, 0x9410bb95975b7fb2
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v14, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v30, v24, 9, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v8, v10, v0

  li t2, 0x22df37e97f63417c
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v24, v18, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v22, v14, -12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v24, v2, v26, v0

  li t2, 0x98f0db7b287666bb
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v22, v18, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v12, v30, -2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v6, v14, v10, v0

  li t2, 0xb7ced328409dad18
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v26, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v10, v26, -15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v16, v2, v0

  li t2, 0x79cc24d8f0a394c5
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v10, v4, -13, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v8, v2, v0

  li t2, 0x1f7837715233291a
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v4, v30, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v6, v22, -3, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v24, v12, v18, v0

  li t2, 0x96d0b3f7c41f9315
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v22, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v12, v8, -14, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v10, v30, v0

  li t2, 0xc0491c819a842424
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v18, v28, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v28, v6, -6, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v30, v18, v10, v0

  li t2, 0x92fee9a5c6aed413
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v30, v18, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v20, -7, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v6, v14, v22, v0

  li t2, 0x69bf875616fb2cba
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v6, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v2, v24, -13, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v8, v30, v2, v0

  li t2, 0xec6c9c2418f32135
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v24, v18, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v28, v18, -12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v2, v20, v0

  li t2, 0xeca14e5bb5edd3e0
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v30, v28, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v12, v30, 4, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v20, v28, v18, v0

  li t2, 0xc64006200efc33f0
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v2, v12, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v12, v8, 11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v18, v30, v0

  li t2, 0xe13f9a3bcc2684da
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v30, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v6, v30, -12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v18, v12, v30, v0

  li t2, 0xa593795ecf7a3d0f
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v6, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v14, 11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v2, v26, v4, v0

  li t2, 0xc2ef67a76b279214
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v4, v6, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v28, v24, 6, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v22, v26, v24, v0

  li t2, 0x80dfac7200ca736f
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v30, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v16, 12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v12, v26, v10, v0

  li t2, 0x9176556b2254152b
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v4, v10, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v6, -3, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v10, v6, v0

  li t2, 0x4d6cd52b44cf7829
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v8, v10, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v2, v20, -2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v2, v10, v24, v0

  li t2, 0xf73db3364cb58be5
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v26, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v22, v28, 13, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v20, v6, v10, v0

  li t2, 0xb12a4667df02506d
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v2, 3, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v4, v10, v2, v0

  li t2, 0x312040890f046926
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v2, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v28, v14, -6, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v20, v6, v14, v0

  li t2, 0xcea03391fdee918b
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v2, v6, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v2, v14, -16, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v12, v28, v16, v0

  li t2, 0x5bc96c92ab59b6e5
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v10, v28, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v22, v12, -13, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v12, v14, v0

  li t2, 0x28194b84da18b175
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v14, 12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v6, v28, v12, v0

  li t2, 0xb32ca8bf3e831b10
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v8, v22, 15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v16, v10, v26, v0

  li t2, 0x128dc88000d5b260
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v2, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v14, -16, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v18, v8, v22, v0

  li t2, 0xa780fdb90f0da61f
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v2, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v22, v20, 11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v16, v18, v20, v0

  li t2, 0x1a809ffd2edc33ae
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v30, v28, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v30, v28, -13, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v8, v22, v0

  li t2, 0xd8d8f4163521efb6
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v4, v30, 0, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v26, v20, v0

  li t2, 0xb7863591e362b782
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v18, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v18, 1, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v4, v10, v0

  li t2, 0x3833cbee6ce878fa
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v20, v2, -6, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v2, v22, v0

  li t2, 0x647df9575a0a06f9
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v2, v4, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v30, v26, 15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v6, v14, v0

  li t2, 0x000553cd97c6bf61
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v10, v20, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v22, -2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v30, v24, v16, v0

  li t2, 0x2f87bf6f700d299b
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v16, v2, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v10, 0, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v2, v26, v22, v0

  li t2, 0x9d9fa6586e8c051b
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v30, v12, -14, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v8, v20, v28, v0

  li t2, 0xb235e616c2ef0eac
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v6, v30, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v30, v26, -9, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v8, v22, v26, v0

  li t2, 0x94d23bdbba56f22d
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v10, v4, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v26, v20, 5, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v28, v4, v22, v0

  li t2, 0x925de3d604bd02e8
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v6, v30, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v24, v26, -11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v2, v24, v4, v0

  li t2, 0x1ce87e12aa58ace5
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v26, v4, 15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v18, v14, v12, v0

  li t2, 0xf6d79f193af53ade
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v2, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v10, v12, -9, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v26, v6, v4, v0

  li t2, 0x179e6c8e93631aef
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v8, v2, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v12, v22, -11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v20, v14, v6, v0

  li t2, 0xde8fe0f75da36ced
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v10, v18, 15, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v8, v6, v24, v0

  li t2, 0x662d67b1b91f98ac
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v18, v16, -11, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v10, v6, v24, v0

  li t2, 0x25347e2277143686
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v26, v6, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v4, v16, -1, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v6, v28, v22, v0

  li t2, 0x8b3f9ec695ecf3c6
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v22, v10, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v12, v24, 1, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v12, v16, v28, v0

  li t2, 0x939e267f1f57c106
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v16, v24, -12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vvm v14, v8, v6, v0

  li t2, 0x2e3477c5fcdb84c5
  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vxm v30, v20, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmadc.vim v4, v10, -8, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v24, v16, v0

  li t2, 0x6001729c42dfbdfe
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v24, 8, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v28, v24, v0

  li t2, 0x4bd60549c0588816
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v8, 7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v20, v24, v0

  li t2, 0xe2e4f4996edb0e08
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v24, -3, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v8, v20, v0

  li t2, 0xdfcbbfa27f9ecba5
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v8, 7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v8, v24, v0

  li t2, 0xff727c10cf642d09
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v20, -12, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v20, v8, v0

  li t2, 0xefcde82ba9788599
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v28, 0, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v4, v28, v0

  li t2, 0x2e8842196b2df97d
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v20, -11, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v8, v28, v0

  li t2, 0x21ea1df47947b2e3
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v24, -10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v16, v4, v0

  li t2, 0x891d57e8d2b1ce3e
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v28, 1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v12, v24, v0

  li t2, 0x24019d12d7c8315b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v4, 1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v20, v4, v0

  li t2, 0x6a010e5120e39ecc
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v16, 7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v12, v8, v0

  li t2, 0x1441197b3d42e010
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v28, 1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v28, v8, v0

  li t2, 0xaba419d83fcaeba8
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v4, -6, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v28, v4, v0

  li t2, 0x258d8d7fe1f48413
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v4, -13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v28, v16, v0

  li t2, 0xbb1afd72c2f2a033
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v16, -13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v8, v16, v0

  li t2, 0x070cbb96f5ec74e9
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v28, 11, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v24, v4, v0

  li t2, 0x92bca51e39fcdafb
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v20, -7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x2fd31d6525b3d9ac
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v20, 0, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v24, v28, v0

  li t2, 0x4284bcbbce2770e8
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v28, 9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v12, v20, v0

  li t2, 0x52fcb2434b2ecaa7
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v4, 9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v8, v20, v0

  li t2, 0xa8f17b25c7780d65
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v16, 2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v28, v16, v0

  li t2, 0x9fd950f6ab8b2f67
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v28, 7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v12, v16, v0

  li t2, 0x5f8b8cb0e467b70b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v8, -5, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v8, v16, v0

  li t2, 0xb995ff0f5b02aee2
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v20, -9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v8, v16, v0

  li t2, 0xe334f2b20c4bc7ac
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v20, 9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v20, v28, v0

  li t2, 0xb29bda17e7ccc3a3
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v28, 1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v4, v12, v0

  li t2, 0x111c4c5b12689764
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v8, 2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v12, v16, v0

  li t2, 0xdebb70173a4af997
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v20, 4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v4, v16, v0

  li t2, 0x42c0282c033ab330
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v16, 5, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v20, v12, v0

  li t2, 0xaf6b9b591f1afb4c
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v12, 10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v16, v8, v0

  li t2, 0x33437363d3144d2e
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v8, -7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v28, v20, v0

  li t2, 0x7e67570f07ade87b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v20, -5, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v24, v4, v0

  li t2, 0x3ae4ee87b7f4800a
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v20, 2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v4, v16, v0

  li t2, 0x9b71f84853c03edf
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v12, -14, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v8, v24, v0

  li t2, 0x48c90a7d9edde5de
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v16, -5, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v4, v8, v0

  li t2, 0x82906481b265aa53
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v28, -8, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v20, v8, v0

  li t2, 0x0e695a2693a15dc6
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v12, 4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v28, v4, v0

  li t2, 0xc713680a03578d96
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v24, 15, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v16, v28, v0

  li t2, 0x8728ec309170f087
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v24, -15, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v28, v16, v0

  li t2, 0x382c89e43e55a603
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v12, 13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v24, v12, v0

  li t2, 0xda2a8cdaa44c2f39
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v12, -1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v8, v24, v0

  li t2, 0x510b569908638eee
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v12, 8, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v24, v4, v0

  li t2, 0xe4fd481aa2708c93
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v24, -10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v28, v4, v0

  li t2, 0x668e8f20f37badb1
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v4, 3, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v4, v24, v0

  li t2, 0x5743e3410b8a45db
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v12, 2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v20, v16, v0

  li t2, 0x12055868a1587e25
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v20, 11, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v16, v4, v0

  li t2, 0xb1b930fc1d98c8c9
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v8, -9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x3d3add489dd9a05b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v24, 14, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v28, v4, v0

  li t2, 0xbb1e54ac409576cc
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v12, -6, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v16, v4, v0

  li t2, 0x8c278841f288a1df
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v16, -14, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v28, v4, v0

  li t2, 0xee23d92f3f44c4a5
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v24, -4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v20, v12, v0

  li t2, 0x414fdb824cfc6c7d
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v20, -4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v16, v4, v0

  li t2, 0x12a9b9d2513be112
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v8, -3, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v28, v20, v0

  li t2, 0xea3eeb10a1380698
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v16, -1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v24, v12, v0

  li t2, 0x6143dd4d7985694b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v8, 0, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v20, v4, v0

  li t2, 0x1b77c97d43f5acc3
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v28, -2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v12, v20, v0

  li t2, 0xd6de7be18c6ef4f8
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v24, -1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v12, v4, v0

  li t2, 0xecaeaf5d24da2684
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v20, -9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v24, v8, v0

  li t2, 0xb41beab246c1b438
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v20, -15, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x6b47dfaf8e6f692e
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v20, 13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v24, v12, v0

  li t2, 0x10b72211b2bdb66b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v8, -10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v8, v4, v0

  li t2, 0x6d57b44d7026b2f1
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v12, -5, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v24, v16, v0

  li t2, 0x6eb6f6da59737045
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v4, -16, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v12, v28, v0

  li t2, 0x66066fa709d8ad53
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v28, -9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v28, v8, v0

  li t2, 0x60e10325931887c8
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v8, 10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v28, v8, v0

  li t2, 0x9bf16860978fb9d2
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v4, 14, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v4, v12, v0

  li t2, 0x607cf93498c9019e
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v24, 7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v8, v16, v0

  li t2, 0x5c991a66e0b98050
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v20, -9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v16, v4, v0

  li t2, 0xe0d61dc31bd5fd9d
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v8, 9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v24, v20, v0

  li t2, 0x03435992b4557050
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v20, -2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v24, v8, v0

  li t2, 0xdd345e22a4cb35ea
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v24, -8, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v24, v16, v0

  li t2, 0x89979fb891d59ac1
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v4, -6, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v12, v20, v0

  li t2, 0x85ddd2f4ff06e6d3
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v12, 15, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v8, v28, v0

  li t2, 0xc8560c882b8baf0f
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v16, 1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v16, v8, v0

  li t2, 0xa5a241b3f49cc69e
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v24, -7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v28, v16, v0

  li t2, 0xee9bd9a9e3519b31
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v28, -10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v8, v28, v0

  li t2, 0x29d087c14c2e50bb
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v16, 1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x28275973df0b9765
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v28, -16, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v4, v12, v0

  li t2, 0x8e2aa429a1823d6b
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v16, -8, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x6b4fae6ee4f9dcd4
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v20, -4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v12, v8, v0

  li t2, 0x76dfd0576f7b7964
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v24, 10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v28, v8, v20, v0

  li t2, 0x659fe381564358f5
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v4, 8, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v28, v4, v0

  li t2, 0x6f352ba3aefc6fe9
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v16, -7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v28, v24, v0

  li t2, 0xd0e6dfbaefc2f052
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v28, -10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v4, v16, v0

  li t2, 0x2ca706ca4b04f7ec
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v12, 4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v28, v8, v0

  li t2, 0x3b9200990a6ca2d7
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v16, v4, 12, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xd4382253a0faf40f
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v12, -13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v28, v16, v0

  li t2, 0xcf675f399a29d127
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v16, -9, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v16, v28, v0

  li t2, 0x06bf4a64f90a3023
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v24, -10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v24, v12, v0

  li t2, 0x20bc124f44cfaab5
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v16, 11, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v4, v16, v24, v0

  li t2, 0xfbc236109d031a94
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v20, v4, 13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xd7abe240c8be4bd4
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v8, 14, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v8, v20, v24, v0

  li t2, 0xbe67626671385773
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v28, v8, -7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v28, v16, v0

  li t2, 0xf42dce9fe7ab0803
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v24, 10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v20, v4, v0

  li t2, 0x3be45dc6aa4f9b7d
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v20, -8, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v20, v24, v0

  li t2, 0xe6a06308684d19d2
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v16, -8, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v24, v4, v20, v0

  li t2, 0x72949cf8d839022e
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v12, v4, 1, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v16, v20, v8, v0

  li t2, 0x41c180216a4931d7
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v8, v28, -7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v12, v28, v16, v0

  li t2, 0x2c203871a9dcadfd
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v4, v28, -6, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vvm v20, v24, v28, v0

  li t2, 0x09683c414b1dae5d
  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmadc.vim v24, v20, 3, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x97ec5240aafe6568
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x30fb060ed74ffc4c
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xa8906cc4afecd95f
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, -7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x25f8b4d837e9c2f0
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 14, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xeac5846774512c6e
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x2f1714fda7b1f3a6
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 13, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x1487235246ac05b2
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, -9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x05dc732d695ee643
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xe418424a6e8f0829
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, -9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x3493f052e0076a0a
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, 8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x9257afb628105a34
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -16, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xab6df857acb39421
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xd261e1438703b7ac
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, 1, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x8f61f6b89392fd13
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 15, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x73c14e20a10fe31c
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -11, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xe424bd0eb602f132
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x8c3b896ae68a0aff
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, -11, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x17b39fe459571bc2
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -4, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x9f18ebb4b35f990b
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 14, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xa6e4f04f1e44627b
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xd21a84e418c6302d
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 10, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xb845c681f4572f9d
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 15, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x76b04a02caebca93
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 14, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x08ae3cc009f43a9a
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x193c58da50bd278c
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xea56da13325fc348
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -16, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x635df3c0c9e3720a
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x1be590cec6db17e3
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x67a13ca502739f1b
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, 15, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x6d50014502769746
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xdd1e7330a03bc436
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, -4, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xee3ec53736542e5a
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 1, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x823c6fecfe29f47f
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 3, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x82a32250cc3b9384
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x80fc787e83c42c8f
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, -11, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xa33478d143aaf644
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xbf5843701178d358
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x88074957ee5d58fb
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, 15, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x3e51f255ad145c65
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, -5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x4bdf302f3f4b513f
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x966310e19f790a86
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 11, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x9a0c8c539fcafd0d
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, -5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xcd1672ac05487f81
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x53ec44669a652e6e
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, 2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x9ebb18e0ea488d94
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, -13, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x904ecf88d8929c79
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -14, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x4669300712ef072c
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xe6b2b0a38b43f668
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xbc322df3cd2b0870
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 11, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x150eff6d11f1805b
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x30db2f1697d98753
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, 11, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xeb486a9cb0c886b2
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, -7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x5330037edf50a450
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, -3, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x94ec6e6776600219
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -15, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xa9f6288601d9a274
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -1, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xe3900e06ba3472f0
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, -13, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x0f3909dc56d75889
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -1, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xb02d59e797336887
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 12, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x26e9b09cce38c04d
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 10, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xa4b2f143412bf167
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, -12, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x736044c61e2b0e5a
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, -15, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xf519711d9c918a79
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x5a5d902e8a704454
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, -9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x7c98ce477cf0df47
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x9064bc804be49807
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 14, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x47f38a6317384108
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -14, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x3fe47258f258a87d
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 11, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x984f9b13a5972f75
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, -7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x3179284d9b9c25f6
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xb5944d16155e4551
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x3d0859d3f7ba5715
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -14, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x440b481934add4e7
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, 2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x31fb6ad90535609e
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -3, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x4fe06f55a9e0901d
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, 3, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x7ff110f675da4f6e
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, -1, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x256ac5a91bb09369
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 0, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xb790bf0379d47bfb
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 0, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x3433733935e4a46f
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x2b4401f1d948f376
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xb0e64cde5826a619
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, 1, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x4d5c1af3f3d7e5b7
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x04dc754c7e5badfb
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x6d389376e23bcbff
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 7, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x3373c5f8e173011f
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x63be32e71312f993
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, -8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xc44c7f722f49d038
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x8fa9361eba7d3c53
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xe75fceb3e717d07f
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 11, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x95936d5be86160de
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -14, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xb0e1cb9ddc0815dc
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, -6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x1c44d149b264b61a
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -5, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xb326931561c7fb18
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, -12, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x2d3a08795328cff0
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, -6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xaf6ccd4f86b80588
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v24, 10, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x379429f85ef1cc79
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x43b1de6ed578f2bf
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v8, 12, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x6f883853d90438df
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v8, 8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x8ab885436c4ec020
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v16, v24, -4, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xe1d740fa11886aad
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v24, v16, -15, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xd4430c998f522967
  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmadc.vim v8, v16, 13, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v25, v26, v31, v0

  li t2, 0x00e27e80bf70f7b7
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v2, v12, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v10, v7, 14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v24, v4, v30, v0

  li t2, 0xc491ebd071018ee4
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v24, v1, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v1, v22, 11, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v8, v5, v15, v0

  li t2, 0xe595f2d7194875d6
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v13, v29, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v3, v10, -6, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v19, v5, v13, v0

  li t2, 0x6ef2c65d3cacdbfe
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v25, v9, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v24, v18, 7, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v14, v9, v18, v0

  li t2, 0x4587aed264a22c03
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v2, v23, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v23, v6, -16, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v8, v9, v17, v0

  li t2, 0x332c7540f99c5e19
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v16, v17, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v20, v11, -3, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v3, v12, v31, v0

  li t2, 0xbc928ada09decebd
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v7, v14, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v8, v13, -2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v16, v7, v10, v0

  li t2, 0x54cefec03ab8c60c
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v19, v18, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v27, v15, 14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v30, v23, v7, v0

  li t2, 0x1d3736bcf980d070
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v19, v10, -6, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v16, v19, v29, v0

  li t2, 0x1efcc47aa8557387
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v15, v1, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v2, v26, 12, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v5, v31, v26, v0

  li t2, 0xa02db3add6b494b2
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v18, v13, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v12, v26, -8, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v12, v9, v14, v0

  li t2, 0x5d4a833435e7b0df
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v15, v16, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v17, v1, -2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v2, v11, v18, v0

  li t2, 0xeccda4f514b65f6c
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v3, v8, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v17, v31, -1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v17, v22, v16, v0

  li t2, 0xfec30f6637838e5d
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v20, v5, 1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v12, v27, v3, v0

  li t2, 0x87257836a90526e2
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v10, v1, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v29, v13, -4, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v8, v7, v11, v0

  li t2, 0x3ac4eceb6c43229f
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v2, v30, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v15, v10, 8, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v19, v29, v10, v0

  li t2, 0x0e4a49e0a61ab561
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v14, v18, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v31, v6, 10, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v13, v21, v14, v0

  li t2, 0x2d7ab78dba475e64
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v9, v1, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v24, v6, -15, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v21, v22, v17, v0

  li t2, 0x85bbb79bbd508e9a
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v22, v16, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v4, v2, 7, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v6, v17, v13, v0

  li t2, 0x60d6b2ea1611241e
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v10, v9, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v18, v26, -7, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v31, v29, v18, v0

  li t2, 0x2b5440ca2ab2efdc
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v18, v8, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v30, v12, -14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v17, v30, v2, v0

  li t2, 0x7c10b79589c94af3
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v13, v15, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v6, v12, -4, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v17, v20, v5, v0

  li t2, 0x32256f0e7d68de43
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v12, v1, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v14, v30, -1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v8, v1, v22, v0

  li t2, 0x69a71f0ac2920e12
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v19, v29, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v3, v27, 15, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v15, v16, v20, v0

  li t2, 0x04320bc8aa4ec671
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v22, v9, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v2, v28, 0, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v6, v8, v13, v0

  li t2, 0x50cd464722da6ea6
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v4, v22, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v12, v25, 11, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v12, v22, v15, v0

  li t2, 0xb922e7ef63b88d63
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v16, v26, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v15, v13, 10, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v27, v23, v21, v0

  li t2, 0x4a6d536429ec2c46
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v4, v13, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v10, v22, -11, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v5, v17, v1, v0

  li t2, 0x54054f62d2f07484
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v5, v28, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v23, v21, 12, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v4, v14, v22, v0

  li t2, 0x1d263c546d2792c6
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v23, v15, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v9, v19, 12, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v25, v15, v23, v0

  li t2, 0x43afd8dbbc3a2568
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v24, v22, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v20, v24, 0, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v2, v17, v25, v0

  li t2, 0xafc55ab2c6a10772
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v31, v22, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v17, v14, -14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v1, v27, v25, v0

  li t2, 0x7ea12f6e0f9db554
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v26, v7, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v12, v9, 7, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v31, v18, v21, v0

  li t2, 0x19fb7dc5dec080ae
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v10, v3, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v26, v18, 8, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v23, v18, v2, v0

  li t2, 0xcf362df9275da1e9
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v23, v7, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v6, v24, 0, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v14, v15, v3, v0

  li t2, 0xfb8c4ff6b8ca98ee
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v26, v21, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v25, v12, 6, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v9, v18, v24, v0

  li t2, 0xd36eadfc16ee86c8
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v9, v24, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v10, v14, 13, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v31, v18, v12, v0

  li t2, 0x437d2a33e0633440
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v24, v13, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v4, v31, 9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v7, v23, v13, v0

  li t2, 0xba0fab10eb69a443
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v25, v23, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v25, v28, -15, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v1, v9, v11, v0

  li t2, 0x617a8c5190023446
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v11, v18, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v15, v12, -16, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v1, v17, v2, v0

  li t2, 0x6741cbfb15e82c41
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v15, v6, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v8, v14, -9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v22, v25, v27, v0

  li t2, 0x52ed2598484eea48
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v18, v26, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v5, v1, 14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v17, v18, v8, v0

  li t2, 0x5ee4d681343477e6
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v11, v15, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v9, v28, -4, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v29, v26, v22, v0

  li t2, 0x3678ebe290e763fd
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v20, v15, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v24, v5, 1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v10, v1, v7, v0

  li t2, 0x22ca850aa5b2c5d4
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v21, v8, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v9, v26, -10, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v8, v25, v5, v0

  li t2, 0xfd8aa52dc4024807
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v22, v12, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v23, v21, -4, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v16, v17, v7, v0

  li t2, 0x6eb7e258e7019b92
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v28, v9, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v21, v9, -5, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v26, v17, v15, v0

  li t2, 0x4286885836bbc10d
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v16, v11, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v8, v23, 5, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v11, v6, v25, v0

  li t2, 0x5c070b3d457b0a1a
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v29, v22, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v23, v2, -6, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v6, v2, v5, v0

  li t2, 0x6933db6b2c912e00
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v25, v17, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v11, v15, 1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v11, v18, v8, v0

  li t2, 0xf41342d3380d669f
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v11, v4, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v22, v15, 0, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v24, v9, v5, v0

  li t2, 0xab4dc6624380b91f
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v6, v3, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v10, v24, -3, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v14, v22, v23, v0

  li t2, 0xb57c85410bd8602a
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v1, v2, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v29, v12, 0, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v20, v15, v30, v0

  li t2, 0x373dc284e86f47b3
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v3, v30, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v18, v4, 14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v25, v19, v22, v0

  li t2, 0x1e26e5a4f3b26023
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v28, v7, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v14, v17, -8, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v8, v12, v29, v0

  li t2, 0x2eeec4252cf0f865
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v9, v31, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v21, v19, 15, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v12, v5, v29, v0

  li t2, 0x404209fd48eccf46
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v9, v27, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v31, v1, 3, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v10, v12, v29, v0

  li t2, 0xfde6d9d94e45f851
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v24, v1, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v4, v29, 0, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v6, v9, v26, v0

  li t2, 0x185e3c57d6778271
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v17, v14, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v26, v9, 15, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v4, v8, v19, v0

  li t2, 0x88ddb347eed60d91
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v25, v10, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v25, v20, 14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v22, v3, v26, v0

  li t2, 0xa92fa5760848d60c
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v21, v6, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v3, v30, -2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v17, v10, v15, v0

  li t2, 0x2f8e8179a872e132
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v8, v22, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v31, v13, 4, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v13, v3, v7, v0

  li t2, 0xc26b4ef248b19b54
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v22, v30, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v6, v11, 14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v12, v22, v30, v0

  li t2, 0x1a1638156d7bbc6a
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v19, v14, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v30, v7, -6, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v3, v4, v13, v0

  li t2, 0x1ace6a90fc22071a
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v9, v8, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v27, v31, -7, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v16, v7, v1, v0

  li t2, 0xabf2efab5ceb670c
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v25, v30, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v25, v21, 1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v3, v2, v7, v0

  li t2, 0x31c64e003f1fc9c8
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v12, v6, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v28, v15, 10, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v11, v12, v20, v0

  li t2, 0x74d6637d59c6e522
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v29, v25, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v15, v13, -9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v3, v9, v17, v0

  li t2, 0xb1c07d0c1f486a50
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v16, v18, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v18, v26, 10, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v23, v2, v29, v0

  li t2, 0xeedccfd50da07ad7
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v19, v25, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v18, v5, 6, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v13, v10, v8, v0

  li t2, 0x488e6d6c6bf6d3f9
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v3, v19, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v31, v22, -14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v3, v26, v31, v0

  li t2, 0xe49347d154176ca1
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v13, v17, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v27, v18, 9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v12, v27, v3, v0

  li t2, 0x3e7bbbcc34082194
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v27, v1, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v27, v7, 0, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v25, v29, v13, v0

  li t2, 0xd80e8d439ccaf668
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v3, v5, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v25, v19, -4, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v27, v20, v14, v0

  li t2, 0xadb3a6bccb5c472c
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v1, v17, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v24, v30, 8, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v4, v14, v18, v0

  li t2, 0xac232aaa3d7a4c84
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v13, v30, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v7, v18, -15, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v12, v14, v18, v0

  li t2, 0x69e96b7a1da2aa54
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v23, v28, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v26, v29, -5, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v4, v18, v23, v0

  li t2, 0xb6adc0734a190206
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v30, v10, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v7, v14, -3, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v10, v8, v1, v0

  li t2, 0x12185f694aa860e9
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v17, v21, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v29, v26, 13, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v15, v4, v20, v0

  li t2, 0x14c080a957aa24f6
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v29, v13, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v14, v29, 14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v18, v30, v4, v0

  li t2, 0xb93334c5892b0529
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v21, v20, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v31, v13, -10, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v11, v16, v7, v0

  li t2, 0xd8cc50d0885232e3
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v26, v13, -2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v8, v14, v25, v0

  li t2, 0x537d9a2bbd6481b5
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v17, v13, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v3, v14, -2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v19, v16, v26, v0

  li t2, 0xde042eb67e200cf4
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v23, v31, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v6, v7, -3, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v29, v12, v24, v0

  li t2, 0xda1887d1de59c656
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v26, v24, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v5, v2, 10, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v8, v16, v20, v0

  li t2, 0x5edf494aff8c1098
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v18, v16, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v14, v9, -11, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v2, v26, v19, v0

  li t2, 0x7b9eda762c98e7a9
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v24, v30, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v17, v24, -8, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v5, v28, v7, v0

  li t2, 0x551756decb493185
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v5, v31, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v24, v17, 8, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v15, v28, v26, v0

  li t2, 0x2a7819bf4178ea8e
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v31, v6, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v30, v14, 5, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v28, v12, v29, v0

  li t2, 0x25eda7d6ed72803c
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v7, v16, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v29, v4, 15, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v17, v16, v10, v0

  li t2, 0xabf9350dc886684c
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v12, v27, -11, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v15, v24, v22, v0

  li t2, 0x56f658df66b5f5f0
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v25, v23, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v24, v10, 2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v22, v23, v31, v0

  li t2, 0x99d01fe0b0d70f18
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v19, v27, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v4, v14, 14, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v20, v27, v17, v0

  li t2, 0x61b2360cadd1d7ae
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v29, v22, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v8, v21, 1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v13, v14, v6, v0

  li t2, 0xd2857b57487022e4
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v22, v23, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v18, v6, 0, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v13, v23, v7, v0

  li t2, 0xd8667c20a28ce0f9
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v5, v10, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v9, v19, -7, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v15, v4, v10, v0

  li t2, 0x2073dbc8d5e85d8e
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v26, v13, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v21, v10, -2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v7, v11, v31, v0

  li t2, 0x0d3a8355ed112b56
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v24, v17, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v4, v16, 11, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v4, v2, v23, v0

  li t2, 0xdf4bc3f0461b69e0
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v16, v3, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v6, v7, -7, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vvm v20, v17, v18, v0

  li t2, 0xa0c5592eb5e2d06f
  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vxm v6, v29, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmadc.vim v23, v25, 2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v26, v24, v6, v0

  li t2, 0x4332f5d221b910ac
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v16, v2, 8, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v16, v24, v2, v0

  li t2, 0x65a427930af44a80
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v22, v24, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v10, v12, -13, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v8, v18, v22, v0

  li t2, 0xe3f9e10df30b2b90
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v22, 7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v8, v26, v0

  li t2, 0xea18ff2208ca1645
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v8, v22, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v22, -9, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v8, v22, v16, v0

  li t2, 0x2e2fd4af4ec34648
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v30, v6, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v26, -7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v4, v24, v0

  li t2, 0x7ce7e81ae9bb75ec
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v14, v18, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v10, 5, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v10, v8, v2, v0

  li t2, 0x7579c78c82b1620d
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v14, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v16, v30, -2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v18, v24, v28, v0

  li t2, 0x38a0da5bee96504d
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v16, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v6, v28, 6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v12, v10, v24, v0

  li t2, 0x22e1591d885a8a1c
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v10, v16, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v18, -3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v18, v30, v0

  li t2, 0xa5e72a9b69054950
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v8, v18, 14, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v16, v22, v0

  li t2, 0x6d833d200cfdc108
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v12, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v16, v30, 7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v12, v26, v4, v0

  li t2, 0x7441067fb17e047a
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v24, v6, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v2, v28, -15, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v6, v24, v8, v0

  li t2, 0x0ca6b4b07d2cd628
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v2, v26, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v16, v8, 4, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v10, v18, v8, v0

  li t2, 0x6410bda29b9fb72e
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v28, v8, -1, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v4, v28, v0

  li t2, 0xa8f24a824da09729
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v14, v26, -7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v16, v6, v10, v0

  li t2, 0x7dcee0b0ebc4b221
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v14, v18, -15, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v28, v18, v0

  li t2, 0x8607959071dcb414
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v10, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v10, v28, -3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v16, v4, v0

  li t2, 0x3d38ee6b0b0bdf7a
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v6, v18, -7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v10, v22, v0

  li t2, 0x945c241cae9ce00d
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v14, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v6, v2, -11, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v8, v12, v6, v0

  li t2, 0xad255d3675cd4f60
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v6, v20, -13, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v24, v10, v2, v0

  li t2, 0x5a01cc3eac44768b
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v2, v14, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v8, 4, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v2, v26, v0

  li t2, 0xd3804905d87b89d6
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v22, v8, -1, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v8, v22, v10, v0

  li t2, 0x59b839275032decb
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v30, -6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v26, v18, v14, v0

  li t2, 0x4cbe3ace07ea2b1e
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v26, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v8, 7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v18, v16, v14, v0

  li t2, 0x5a99328a13cec00b
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v26, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v18, v12, -3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v2, v28, v0

  li t2, 0x47a06b30d11219ab
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v20, v10, 5, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v22, v30, v0

  li t2, 0x13f7a1cfbdb2e3dd
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v12, v2, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v26, v30, 8, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v6, v12, v0

  li t2, 0x2e2ae96737a4fa66
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v18, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v22, v4, 2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v28, v8, v26, v0

  li t2, 0x3fe1ec1234633798
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v4, v26, -12, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v12, v8, v6, v0

  li t2, 0x48985064c1a666e9
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v22, v10, 6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v26, v12, v0

  li t2, 0x0add22f8b30acc1f
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v12, v2, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v22, v16, 8, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v22, v16, v28, v0

  li t2, 0xd3c822c62e9ea750
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v2, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v14, -10, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v16, v6, v8, v0

  li t2, 0x859cbb0504be71c2
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v26, v12, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v2, v26, -12, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v8, v28, v4, v0

  li t2, 0xb66fa0075b05ce85
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v10, v18, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v14, v30, -6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v24, v2, v30, v0

  li t2, 0x8cfccfa3aac96ebf
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v6, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v22, v18, -6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v8, v14, v28, v0

  li t2, 0x9eae29dd4a6828b5
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v16, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v16, v6, -3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v12, v4, v6, v0

  li t2, 0xaeeedc578a872d19
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v8, v10, 12, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v18, v14, v24, v0

  li t2, 0x2cde118ce66f3d68
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v28, v26, 8, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v16, v26, v2, v0

  li t2, 0x03d32cead04d0fd2
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v14, v24, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v20, -14, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v20, v18, v0

  li t2, 0x0079ab014ae41c92
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v4, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v10, -8, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v24, v14, v18, v0

  li t2, 0xb269af13c2f9349c
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v16, v6, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v16, v26, 1, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v10, v6, v24, v0

  li t2, 0xe3f9c1908c7cf32e
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v18, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v18, v12, -8, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v26, v24, v12, v0

  li t2, 0xcb0da42643a82475
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v26, v16, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v6, 9, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v14, v8, v0

  li t2, 0x58b7ecf2ba35b332
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v22, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v18, 3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v22, v18, v0

  li t2, 0x4de4d9ed2749d331
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v16, v6, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v4, v30, -14, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v24, v8, v10, v0

  li t2, 0xfe0ef58f6998eb31
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v28, v16, 6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v6, v22, v14, v0

  li t2, 0x8fae2c2011e78045
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v2, v28, -13, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v16, v24, v4, v0

  li t2, 0x1daca3f340f7582f
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v22, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v26, 11, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v26, v22, v4, v0

  li t2, 0xa8e6f8d6fd383865
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v22, v6, -12, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v24, v2, v8, v0

  li t2, 0x6bb9221566b3ca02
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v26, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v6, v24, -11, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v18, v10, v30, v0

  li t2, 0xdbecba1104db7a00
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v30, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v2, v20, -5, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v22, v26, v30, v0

  li t2, 0x4e2133704ed3175e
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v26, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v20, v22, 3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v18, v14, v12, v0

  li t2, 0xa4b7a3f141db06de
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v26, v20, 3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v22, v12, v0

  li t2, 0x9c2d85c9037634a5
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v6, v12, 14, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v28, v6, v0

  li t2, 0x55c94d299883d870
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v14, 7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v10, v28, v26, v0

  li t2, 0x7df7a80fea5ac21a
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v26, 6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v6, v16, v30, v0

  li t2, 0x7c92c80333c9662b
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v4, v8, -6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v26, v20, v28, v0

  li t2, 0xe53bb3e2e5dd5b0a
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v2, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v4, v16, -10, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v26, v14, v24, v0

  li t2, 0x08eb73af2294dfe5
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v24, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v10, v8, 7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v2, v16, v0

  li t2, 0x5e843a63b905ab80
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v20, v22, -11, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v6, v14, v10, v0

  li t2, 0x502ed64f0ea6ea80
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v2, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v28, v8, 0, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v28, v10, v18, v0

  li t2, 0x1f77c9ab5f987bbf
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v30, v12, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v28, v12, 5, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v6, v4, v0

  li t2, 0xca728393e3587cd3
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v26, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v16, v4, 9, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v20, v22, v0

  li t2, 0x3eff71d40079e901
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v22, v24, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v10, 3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v22, v28, v26, v0

  li t2, 0xd9221985e4156a16
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v4, v6, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v8, v30, -6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v12, v4, v0

  li t2, 0x7f90bb533a3a6dc0
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v28, v18, -8, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v22, v4, v0

  li t2, 0x409f8eec6759b369
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v16, v2, -4, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v6, v2, v0

  li t2, 0x68fa47764f41cae8
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v14, v24, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v8, v16, 13, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v18, v16, v30, v0

  li t2, 0xf23b33b9b34f1146
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v8, v26, -12, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v16, v30, v14, v0

  li t2, 0xcea54dd26f9a917c
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v22, v26, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v10, 8, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v22, v12, v16, v0

  li t2, 0x1cd49016836a461f
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v22, v6, 10, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v6, v2, v0

  li t2, 0x2ec4168d02c09c1a
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v28, v24, -3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v14, v10, v0

  li t2, 0x2d24ccade6b9dabc
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v16, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v14, v22, -7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v18, v16, v28, v0

  li t2, 0xf252c95af5f4d804
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v30, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v20, v10, -10, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v28, v14, v2, v0

  li t2, 0x2f6c9e9996ef927f
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v22, v28, -6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v14, v10, v0

  li t2, 0xd0bbebd8f8143ced
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v2, v12, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v16, v12, -7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v12, v4, v18, v0

  li t2, 0x81bc0323fc5c4dd5
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v30, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v18, v30, 12, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v8, v22, v6, v0

  li t2, 0x15d9e2a0d7f45126
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v30, v24, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v2, v22, 15, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v6, v18, v20, v0

  li t2, 0x4c94886f0d9c669e
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v30, v2, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v14, -15, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v26, v14, v0

  li t2, 0x8645bb13d315f849
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v14, v18, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v10, v30, -3, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v26, v24, v0

  li t2, 0x7e2088ea3d1ff340
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v26, v12, 10, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v26, v4, v6, v0

  li t2, 0xc04476d859bc456a
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v14, v24, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v16, v14, 5, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v22, v6, v14, v0

  li t2, 0x783d8730735872e1
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v26, v12, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v8, v28, 1, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v4, v12, v0

  li t2, 0xf7a2fa5a14297f84
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v14, v24, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v12, v22, 13, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v24, v22, v0

  li t2, 0xc106a6cbbbf7c768
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v2, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v8, v26, 11, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v20, v30, v10, v0

  li t2, 0x6177f0bee22621c1
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v20, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v10, v24, -6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v16, v12, v0

  li t2, 0x4b94a773e7d7f8d4
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v26, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v10, v14, 14, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v26, v20, v24, v0

  li t2, 0x892ee79630c982f7
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v14, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v24, v4, 2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v2, v26, v4, v0

  li t2, 0x418e717f45b8a6cf
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v4, v10, 15, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v30, v18, v4, v0

  li t2, 0x7e1beb0724ba21eb
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v6, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v16, v28, 0, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v12, v2, v22, v0

  li t2, 0x4534adcacaef1690
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v14, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v16, v22, 5, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v10, v28, v0

  li t2, 0x82ff696b26622c52
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v30, v16, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v2, v18, 0, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v14, v4, v30, v0

  li t2, 0x486173fb3328b4c3
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v4, v26, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v10, v4, -14, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v12, v26, v22, v0

  li t2, 0x4dfa83f08cee6dc2
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v4, v26, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v20, v18, 2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v22, v28, v30, v0

  li t2, 0xef7d86bb24529880
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v14, v18, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v4, v14, -7, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v22, v8, v24, v0

  li t2, 0x884ef5245a372a03
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v18, v28, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v4, v30, 6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v24, v20, v8, v0

  li t2, 0x160e89817e8795eb
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v28, v26, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v22, v20, -14, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v4, v30, v20, v0

  li t2, 0x70238ddd552159fd
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v30, v12, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v24, 6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v26, v6, v20, v0

  li t2, 0x15b8e582baaaf5b0
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v26, v4, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v30, v14, 12, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vvm v10, v4, v24, v0

  li t2, 0xec8199d6cc0564b2
  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vxm v8, v22, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmadc.vim v4, v26, -16, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v12, v28, v0

  li t2, 0xa3b56c84274333c3
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v4, 11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v28, v24, v0

  li t2, 0x397547c124de6f5e
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v12, -15, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v16, v28, v0

  li t2, 0x4f15103b9ecb8816
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v4, -4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v4, v24, v0

  li t2, 0xcc681fb49bbf013e
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v28, -7, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v12, v4, v0

  li t2, 0x67789fe643574edc
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v4, -10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v12, v28, v0

  li t2, 0x57601f4f491ab8d5
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v24, 6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v20, v12, v0

  li t2, 0xc018c4810261d673
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v4, 7, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v16, v24, v0

  li t2, 0x0e93e924f2c48577
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v8, 3, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v4, v20, v0

  li t2, 0x10d423dc207c8d75
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v28, -4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v12, v8, v0

  li t2, 0xe4bb9b36fb5c6200
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v12, -6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v28, v12, v0

  li t2, 0xa183812eb8d7136f
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v20, 1, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v12, v4, v0

  li t2, 0x8ee943c4b8262c2d
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v8, -10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v16, v28, v0

  li t2, 0xb99a9a40fd8ab155
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v28, -8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v12, v8, v0

  li t2, 0x58a67e170e20d6cd
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v12, 13, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v20, v8, v0

  li t2, 0x71f4a586103b0ef6
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v28, 12, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v28, v16, v0

  li t2, 0xc70c034cddbd8bcc
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v4, -3, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v4, v16, v0

  li t2, 0xb804015e9a1423a1
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v12, -14, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v8, v28, v0

  li t2, 0x704afef481c1d99c
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v8, 0, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v24, v12, v0

  li t2, 0xac6828595a2ef83f
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v12, -8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v4, v28, v0

  li t2, 0x04af482b2c5363e8
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v4, 2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v4, v28, v0

  li t2, 0xf9d16aa50157cf78
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v28, 1, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v20, v28, v0

  li t2, 0x97fde6aae85c7482
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v24, -6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v16, v12, v0

  li t2, 0x7cb3c4668c303cae
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v24, -7, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v8, v24, v0

  li t2, 0x93e338656bf4d8d8
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v16, 11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v12, v4, v0

  li t2, 0xfedc9e4dfebf8c72
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v28, -4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v24, v28, v0

  li t2, 0x665d1ce87df2ed3c
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v4, -9, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v16, v20, v0

  li t2, 0xe8f46dd4db15609a
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v12, 7, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xd8e9fc2029fec0be
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v8, -11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v28, v16, v0

  li t2, 0xf61c26e99691ee12
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v4, -1, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v20, v12, v0

  li t2, 0xbdc86a6088e52bb7
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v20, 8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v24, v20, v0

  li t2, 0xd92f13d1fa99afe3
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v16, 3, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v20, v8, v0

  li t2, 0xda41f4a6ee4030d6
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v24, 13, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v16, v24, v0

  li t2, 0x6135524bf3e58c34
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v20, 4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v4, v20, v0

  li t2, 0x7350cac33bfc2158
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v8, 9, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v28, v20, v0

  li t2, 0x87a832dc52abb19b
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v12, -16, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v16, v20, v0

  li t2, 0x3b9aeb0f06172261
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v4, 14, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v16, v24, v0

  li t2, 0x75ac53b98a97edff
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v8, -15, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v20, v4, v0

  li t2, 0x523b2491790e562c
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v28, 7, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v12, v20, v0

  li t2, 0x5efbe9dfc2dec614
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v24, -3, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v20, v28, v0

  li t2, 0x58b37f7b59729343
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v16, 6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v24, v12, v0

  li t2, 0xcd093fe64bcd5c9e
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v28, 4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v4, v24, v0

  li t2, 0x8752d8c79cf84629
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v4, 0, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v4, v12, v0

  li t2, 0x7cbea7fb4e62eebe
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v12, 0, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v4, v28, v0

  li t2, 0x0b26ab4130c47b18
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v20, 6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v28, v12, v0

  li t2, 0x68c166dd80af8a05
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v16, -5, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v20, v28, v0

  li t2, 0xef8ae1f86ee8fa49
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v4, -2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v4, v12, v0

  li t2, 0x1e9911469c849af2
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v4, -2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v4, v28, v0

  li t2, 0x499190b4a506e73c
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v28, 4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v12, v4, v0

  li t2, 0x7aabc2a5411c5db9
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v24, -16, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v20, v12, v0

  li t2, 0x1964a6da4d690530
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v12, 11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v28, v12, v0

  li t2, 0x0642af0188446fc4
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v4, -12, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v28, v4, v0

  li t2, 0x36abfff5acedb262
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v20, 1, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v24, v8, v0

  li t2, 0x59afdb37dc7c6217
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v8, 7, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v16, v4, v0

  li t2, 0xe0be0e65ab802343
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v20, -8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v8, v24, v0

  li t2, 0xe1b4fc2e12e231ca
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v28, 10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v4, v12, v0

  li t2, 0x1ea0b12485c32dcd
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v4, -16, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v8, v12, v0

  li t2, 0x8a6e2665721a39af
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v24, -5, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v24, v28, v0

  li t2, 0x315b6c55a69675e8
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v8, 8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v4, v20, v0

  li t2, 0xafbdcc0669deb2fc
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v8, 9, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v8, v4, v0

  li t2, 0xd9d6758777849d1d
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v16, 3, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v28, v24, v0

  li t2, 0x84813a8e551715d1
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v28, 6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v16, v8, v0

  li t2, 0xb03b8e0d25ddb2d3
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v24, -11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v4, v20, v0

  li t2, 0xc5a80c7e45b2c9f8
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v16, 13, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v16, v4, v0

  li t2, 0x891cf811f84d606f
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v4, -11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v24, v4, v0

  li t2, 0x3e9790473531c07e
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v12, 14, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v28, v20, v0

  li t2, 0x055db8dac3c57f45
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v24, -2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v24, v28, v0

  li t2, 0x0a8c0f93a43b2b25
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v8, 0, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v4, v16, v0

  li t2, 0x9062d036f0bb53dd
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v24, -14, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v12, v20, v0

  li t2, 0x84064b71e1113b92
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v12, -7, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v24, v8, v0

  li t2, 0xf65b3739376d5eeb
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v16, 4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v16, v4, v0

  li t2, 0x58fdcc5f645744b7
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v4, 0, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v24, v4, v0

  li t2, 0xcf6bc72570597fed
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v24, 10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v12, v16, v0

  li t2, 0x0371dbc90269cb6b
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v12, 3, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v16, v8, v0

  li t2, 0x765f49daeed4c001
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v12, -10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v12, v20, v0

  li t2, 0xd3dcc1a6970482ab
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v12, -4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v4, v20, v0

  li t2, 0x90c498c5d66808a5
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v24, -9, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v24, v12, v0

  li t2, 0xdb0c79cf26689ed6
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v12, -11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v12, v28, v0

  li t2, 0xad55a0d7786402e8
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v12, v20, 9, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v16, v4, v0

  li t2, 0xe55ecdfcb4e6f526
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v4, -11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v28, v12, v0

  li t2, 0xcbbd5f52d54b9f0e
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v12, -13, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v16, v28, v0

  li t2, 0xf7eb17808addec93
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v28, 6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v20, v28, v0

  li t2, 0x037184ca1bc43c6a
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v4, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v4, -11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v16, v28, v0

  li t2, 0x79082f3040b17acf
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v8, -16, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v12, v16, v0

  li t2, 0xd2a5a1b8971ce10b
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v20, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v24, v4, -14, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v28, v4, v0

  li t2, 0x9b471b45393d3ce7
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v12, 8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v16, v24, v0

  li t2, 0xe444a4822edbc539
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v8, 4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v12, v8, v0

  li t2, 0xc0611e1081bc65f3
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v16, -3, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v8, v4, v12, v0

  li t2, 0x98a5fa69f7163981
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v16, -11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v12, v24, v0

  li t2, 0x6d5afeedd49e5bbe
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v28, -12, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v12, v16, v8, v0

  li t2, 0x507a9fd86ac24064
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v28, -6, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v28, v12, v0

  li t2, 0x27473010342c2dfd
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v12, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v20, 9, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v20, v8, v0

  li t2, 0x5a14c44e177c14ef
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v24, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v20, -11, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v20, v4, v8, v0

  li t2, 0x42581d6a8de856dc
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v8, v28, -8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v4, v24, v0

  li t2, 0x9fb9cc4bf886bd17
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v16, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v24, -9, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v16, v28, v0

  li t2, 0xd1ae9aee59cea542
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v4, v20, -8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v28, v4, v0

  li t2, 0xf75753953d440a82
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v16, v24, 13, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v4, v16, v24, v0

  li t2, 0x1d940c940a0affca
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v28, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v20, v8, 13, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v16, v20, v4, v0

  li t2, 0xec2001182aa896f0
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v12, v8, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v12, -4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v24, v8, v20, v0

  li t2, 0xe125e3231d4a793c
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v24, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v20, -14, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vvm v28, v8, v24, v0

  li t2, 0x9fdca242e02ef558
  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vxm v4, v28, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmadc.vim v28, v24, 15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xcfff6795949f4ab0
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 11, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x9ed2ad777269dcc5
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 11, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x10679cff936c1680
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 11, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x5ba50ac8492bf274
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xbff4f1353b6d2d74
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -16, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xfa912752dc8215f2
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x29331c8289a82e74
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 9, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x5bc8149b0b44ffc2
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 8, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x61cdd5ecdc44d8dd
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, -13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x2297de4c79f832dd
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, -3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xb270f6ad4ec61581
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x9f53210dbdce95ae
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x0054122a8b145938
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x11ff5c12f635b84c
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -12, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x99e15aecaab5a91e
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 7, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xe406993a30e08c0b
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, 14, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xeba04805bf4b25d5
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, -3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x1eee8d64bb2b0f69
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x6a1cfd311bc74944
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 4, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xad876b5e00608133
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 10, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xa25a0747862a1995
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xab7dc3a437ef31da
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x888c0f821275bf9f
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -9, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x6be26508cacad9b1
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, -3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xc092859b795e279d
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 10, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xd96cd09abf021fb2
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 6, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x584d05c85a8c0f47
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xc8d802b3fc57cd06
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 11, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xfa5f4678309a11df
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x640da3f489ea37e5
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, -9, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x63f73f4bc4219e25
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x533fb29c8f89d6aa
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xfcd667c7a35615af
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xd1aada9cbcee470a
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xb4365f8e0b498ee2
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, -14, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x6d879b618f9fefbc
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 12, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x967451b025cbaaa9
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 6, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x9bc594c8a11234e8
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 4, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x8709883216af7af8
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, -13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xd0b3612226e3dc6c
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -11, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x6e2c1c0329b4f18c
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 8, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xade3c3176075f019
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xffa8a0d2eedcb4e4
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -7, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xbb353c9fda454e52
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -6, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x0102916fc424bd23
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, -14, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x5f5b02bde64376e5
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x6078e4a5bae79916
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -4, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xa80ba9ce887815c1
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xa25bb5964d195fd3
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xe9c4a635984f1354
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, -13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x39f20c0c11f569cb
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 14, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xd8c0f429782a1a59
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 11, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xabe319d9e2b5bafa
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x01a69d1b2d98e458
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x911922ca0f330206
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -6, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xb01e27f94c918d72
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xf029dbb8fddeffa2
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x65f58f1c37e9a92b
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, -1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xe7a4ec5ba35ee258
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, -8, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x7a6c4bee592faeb6
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x6bbff1eae9a3c319
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -6, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x11d3032d0b3a795f
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xecedcd86b464f886
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, 13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xd4169ed3ddd2efd4
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 8, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x9765aa339ded3927
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, -3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x1a22f669d5e5c26f
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, -11, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x7b09d7368cbb6292
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -11, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x696188a7af612031
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x656f78397cca175a
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, 15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x6d36554e07539a93
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, -6, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x84d079932e0a13b5
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, -12, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x2973b24228626d58
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -7, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xa1d7e6ea69eea2ab
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, -2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x2ace974925074516
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -8, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x9c36ca94034d2882
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, -8, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x462bc8b07ac31542
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x3de9089b260f62bf
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, -13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x9bdc5b23d4a7db55
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 6, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0xe7848393aeec62fb
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, -7, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xcbd00aa4fcf31e11
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 8, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0x2774f9e93f89b196
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 12, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x272b8cb3c001b07c
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 7, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x940ba17bd7762289
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0x0ebf7ba3cc75a53c
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 11, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x248539e7d474c2eb
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, -5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xa60b764b2f3db548
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, 5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0xf9f8073a9ee98fd6
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xaaaec3d17b518793
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v16, v24, v0

  li t2, 0xd4848eef0e3c7d50
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 10, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x39602e95b589a2b6
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, 13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0x17bf708efa9c5ef0
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xaba64ea122456cd5
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v16, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, 13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x693b3d36021d0cd8
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v8, -9, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v8, v24, v0

  li t2, 0xabd27257f34b6395
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v24, -14, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x6b48c32f9d9c9093
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v24, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v24, v16, -7, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v16, v8, v0

  li t2, 0xede3ba999416fb95
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v8, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v24, 2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v24, v8, v16, v0

  li t2, 0x4c8ae6914094b3ed
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v8, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v8, v16, 5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v16, v24, v8, v0

  li t2, 0x02936015bb05027e
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, 14, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0xbb8fee830e01a3a0
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, -2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vvm v8, v24, v16, v0

  li t2, 0x2dc05524532d8d6e
  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vxm v24, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmadc.vim v16, v8, -2, v0

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
