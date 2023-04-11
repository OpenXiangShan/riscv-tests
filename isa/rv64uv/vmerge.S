#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vvm v7, v7, v25, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vvm v22, v22, v11, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vvm v13, v13, v30, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vvm v13, v13, v1, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vvm v4, v4, v17, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vvm v16, v16, v19, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vvm v15, v15, v24, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vvm v27, v27, v15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vvm v19, v19, v1, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vvm v10, v10, v23, v0

  li t2, 0x55e6981fe4e23722
  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vxm v11, v11, t2, v0

  li t2, 0x24d7a740f56f1da5
  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vxm v23, v23, t2, v0

  li t2, 0xe8435af2d33d4d16
  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vxm v4, v4, t2, v0

  li t2, 0x6dabaf996e6283c2
  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vxm v29, v29, t2, v0

  li t2, 0x306827c206a400fd
  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vxm v9, v9, t2, v0

  li t2, 0x86915080ed508267
  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vxm v19, v19, t2, v0

  li t2, 0xe9ed1afc9d9794a2
  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vxm v2, v2, t2, v0

  li t2, 0xe1b0b5441920a1a4
  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vxm v14, v14, t2, v0

  li t2, 0xf35f11ae46f10da1
  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vxm v1, v1, t2, v0

  li t2, 0xfc00fdb60ef0149c
  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vxm v29, v29, t2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vim v12, v12, 15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vim v27, v27, 9, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vim v27, v27, 3, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vim v27, v27, -5, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vim v4, v4, -6, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vim v28, v28, 10, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vim v1, v1, 12, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vim v3, v3, 2, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vim v24, v24, 15, v0

  vsetvli t1, t0, e8, m1, ta, ma
  vmerge.vim v20, v20, 12, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vvm v24, v24, v16, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vvm v28, v28, v22, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vvm v4, v4, v20, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vvm v28, v28, v2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vvm v12, v12, v24, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vvm v6, v6, v10, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vvm v12, v12, v2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vvm v10, v10, v24, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vvm v4, v4, v8, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vvm v16, v16, v14, v0

  li t2, 0xb0b85b2bd6bf8ee6
  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vxm v6, v6, t2, v0

  li t2, 0xdbffa08999f05a36
  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vxm v2, v2, t2, v0

  li t2, 0x4ec345a31d04eedc
  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vxm v2, v2, t2, v0

  li t2, 0xa45f7763823b08d6
  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vxm v10, v10, t2, v0

  li t2, 0xa35ec8c024ca698e
  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0xbef972f40e6d647c
  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vxm v14, v14, t2, v0

  li t2, 0xa96e5e0879cf0dfb
  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vxm v22, v22, t2, v0

  li t2, 0x24a04109a3bb668b
  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vxm v2, v2, t2, v0

  li t2, 0x7c57a9fa3bcf7236
  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vxm v4, v4, t2, v0

  li t2, 0xf5066b7a2cc9582c
  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vxm v28, v28, t2, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vim v8, v8, 15, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vim v20, v20, -3, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vim v6, v6, 9, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vim v28, v28, -8, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vim v10, v10, -16, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vim v12, v12, 11, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vim v14, v14, 13, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vim v24, v24, 4, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vim v24, v24, 1, v0

  vsetvli t1, t0, e8, m2, ta, ma
  vmerge.vim v18, v18, -14, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vvm v12, v12, v8, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vvm v24, v24, v12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vvm v16, v16, v24, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vvm v4, v4, v24, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vvm v12, v12, v4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vvm v20, v20, v4, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vvm v24, v24, v12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vvm v20, v20, v12, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vvm v8, v8, v28, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vvm v4, v4, v12, v0

  li t2, 0x5295b7b553e3f44e
  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vxm v28, v28, t2, v0

  li t2, 0xcaf52ced1ae8be12
  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0x9587c2c0faacd18b
  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vxm v28, v28, t2, v0

  li t2, 0x39ed4cb76d4d6f56
  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vxm v28, v28, t2, v0

  li t2, 0x2bc82328ce7b42b5
  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vxm v4, v4, t2, v0

  li t2, 0x7046d48032fcaef6
  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vxm v28, v28, t2, v0

  li t2, 0xa345cf4cd1612eae
  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vxm v12, v12, t2, v0

  li t2, 0x99dfb63caab8e4bf
  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0xf43764ce40892752
  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0xd4bea8eb5e8f7542
  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vxm v4, v4, t2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vim v28, v28, -2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vim v28, v28, -10, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vim v24, v24, -1, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vim v20, v20, -2, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vim v12, v12, -16, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vim v20, v20, -7, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vim v8, v8, -3, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vim v20, v20, 3, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vim v12, v12, 0, v0

  vsetvli t1, t0, e8, m4, ta, ma
  vmerge.vim v20, v20, 12, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vvm v8, v8, v24, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vvm v24, v24, v8, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vvm v16, v16, v24, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vvm v16, v16, v8, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vvm v8, v8, v16, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vvm v8, v8, v24, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vvm v16, v16, v8, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vvm v8, v8, v24, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vvm v24, v24, v16, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vvm v16, v16, v8, v0

  li t2, 0x6511a9424cfa01e5
  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0xaae2dd5fcfda9362
  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0x25e956be15f2b740
  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0x48c3c1ee6acbec18
  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0x77af52540627601e
  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0x0604a6886f86695d
  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0x57447f06ba8f71fe
  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0x1a8588dca5b2f10a
  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0xe27f28079c88011f
  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0x28cf80dd5fef788a
  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vim v16, v16, -14, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vim v16, v16, 8, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vim v16, v16, 13, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vim v16, v16, -11, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vim v8, v8, 10, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vim v16, v16, -8, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vim v16, v16, 3, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vim v16, v16, 14, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vim v24, v24, -7, v0

  vsetvli t1, t0, e8, m8, ta, ma
  vmerge.vim v24, v24, 0, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vvm v27, v27, v7, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vvm v6, v6, v28, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vvm v22, v22, v31, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vvm v31, v31, v25, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vvm v3, v3, v17, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vvm v19, v19, v12, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vvm v26, v26, v25, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vvm v27, v27, v25, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vvm v9, v9, v27, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vvm v26, v26, v23, v0

  li t2, 0x995d9941482496d7
  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vxm v22, v22, t2, v0

  li t2, 0x969874133b4e94dd
  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vxm v13, v13, t2, v0

  li t2, 0x3d742695b801bc91
  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vxm v15, v15, t2, v0

  li t2, 0xa714ee1c64a5e85c
  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vxm v5, v5, t2, v0

  li t2, 0x10c31d7a1eab1a34
  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vxm v14, v14, t2, v0

  li t2, 0x1a87dbb883fc29c1
  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vxm v13, v13, t2, v0

  li t2, 0x67777bd412e49251
  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vxm v25, v25, t2, v0

  li t2, 0xd1daf6711fbe4163
  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vxm v31, v31, t2, v0

  li t2, 0x7e0e4f9b375ea80d
  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vxm v27, v27, t2, v0

  li t2, 0xf27727a26a93eb1a
  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vxm v8, v8, t2, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vim v7, v7, 12, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vim v13, v13, 12, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vim v6, v6, 13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vim v9, v9, -5, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vim v31, v31, 12, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vim v10, v10, 8, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vim v19, v19, -7, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vim v25, v25, 13, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vim v25, v25, -16, v0

  vsetvli t1, t0, e16, m1, ta, ma
  vmerge.vim v3, v3, 5, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vvm v2, v2, v12, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vvm v30, v30, v16, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vvm v28, v28, v14, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vvm v10, v10, v6, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vvm v16, v16, v18, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vvm v10, v10, v6, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vvm v18, v18, v16, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vvm v14, v14, v20, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vvm v2, v2, v4, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vvm v26, v26, v18, v0

  li t2, 0x7c658085a634e44b
  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vxm v10, v10, t2, v0

  li t2, 0x57b20cbc9297ec49
  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vxm v26, v26, t2, v0

  li t2, 0x15b345e74a30b27d
  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vxm v6, v6, t2, v0

  li t2, 0xeb52375a1e2e77a1
  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vxm v6, v6, t2, v0

  li t2, 0x01daf87a6ecd7c28
  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vxm v26, v26, t2, v0

  li t2, 0x291354cd9cdd9bb9
  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vxm v20, v20, t2, v0

  li t2, 0xbfdb1caab806498f
  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vxm v6, v6, t2, v0

  li t2, 0x2828c8066ce5496d
  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vxm v12, v12, t2, v0

  li t2, 0xe477a3455a624d4a
  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vxm v12, v12, t2, v0

  li t2, 0x53c57b1d30d219cb
  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vxm v6, v6, t2, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vim v12, v12, -3, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vim v14, v14, 5, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vim v8, v8, -4, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vim v24, v24, -13, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vim v20, v20, 8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vim v18, v18, 8, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vim v18, v18, -15, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vim v30, v30, -7, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vim v26, v26, -10, v0

  vsetvli t1, t0, e16, m2, ta, ma
  vmerge.vim v2, v2, -3, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vvm v24, v24, v4, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vvm v24, v24, v4, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vvm v4, v4, v28, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vvm v16, v16, v4, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vvm v20, v20, v24, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vvm v24, v24, v28, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vvm v12, v12, v20, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vvm v4, v4, v12, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vvm v4, v4, v24, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vvm v24, v24, v16, v0

  li t2, 0xbb223c75a412ad97
  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vxm v20, v20, t2, v0

  li t2, 0x89a6cac2bfe39645
  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0xf10f7f5158583d5c
  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vxm v4, v4, t2, v0

  li t2, 0x3c2c407d820aa898
  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vxm v4, v4, t2, v0

  li t2, 0x8201580350888130
  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0x6a6f94534ff08bd7
  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0xa96e83223f376c77
  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0xf21a83ee663697de
  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0xec661afe389cfd21
  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0x5cc6425b7054327b
  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vxm v20, v20, t2, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vim v4, v4, 9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vim v8, v8, -13, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vim v4, v4, -5, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vim v8, v8, -1, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vim v24, v24, -10, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vim v28, v28, 15, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vim v4, v4, 11, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vim v16, v16, -14, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vim v20, v20, -9, v0

  vsetvli t1, t0, e16, m4, ta, ma
  vmerge.vim v28, v28, 7, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vvm v16, v16, v8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vvm v16, v16, v8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vvm v24, v24, v8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vvm v24, v24, v16, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vvm v24, v24, v8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vvm v16, v16, v8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vvm v24, v24, v16, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vvm v16, v16, v24, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vvm v16, v16, v24, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vvm v8, v8, v24, v0

  li t2, 0xde12903d1e282be1
  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0x25b5a5d2a4d2e065
  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0x5d5b659542931058
  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0xa9a43a7ecbd74469
  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0x3c2626f4be16159f
  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0x9de4c649c94f78de
  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0x255d4f487b9eba1b
  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0x2b19b02d43c7d989
  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0x8425c8aaa41aad70
  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0x7e369bc254f62217
  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vxm v8, v8, t2, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vim v8, v8, 12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vim v24, v24, -12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vim v8, v8, -4, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vim v16, v16, 9, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vim v24, v24, 8, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vim v24, v24, 12, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vim v24, v24, 10, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vim v16, v16, 6, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vim v8, v8, 3, v0

  vsetvli t1, t0, e16, m8, ta, ma
  vmerge.vim v24, v24, -12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vvm v11, v11, v19, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vvm v5, v5, v1, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vvm v7, v7, v17, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vvm v25, v25, v23, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vvm v18, v18, v7, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vvm v2, v2, v16, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vvm v12, v12, v14, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vvm v4, v4, v21, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vvm v26, v26, v25, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vvm v2, v2, v26, v0

  li t2, 0x33397a1e995d7643
  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vxm v6, v6, t2, v0

  li t2, 0x817dddc4ade71f67
  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vxm v19, v19, t2, v0

  li t2, 0x2d700f95288089f0
  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vxm v15, v15, t2, v0

  li t2, 0xd31edfc3afab9d56
  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vxm v25, v25, t2, v0

  li t2, 0x843551584cd897fb
  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vxm v31, v31, t2, v0

  li t2, 0xda83ab5e6401ebb0
  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vxm v21, v21, t2, v0

  li t2, 0x44e1b0f455e0e0c5
  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vxm v3, v3, t2, v0

  li t2, 0x47f0df0c92f110ff
  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0xc5ab74c5eb33b963
  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0x4d7435b1de62417c
  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vxm v15, v15, t2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vim v17, v17, 10, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vim v25, v25, -12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vim v15, v15, -2, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vim v14, v14, 9, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vim v29, v29, 12, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vim v5, v5, 11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vim v1, v1, -11, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vim v21, v21, -3, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vim v26, v26, 6, v0

  vsetvli t1, t0, e32, m1, ta, ma
  vmerge.vim v10, v10, 12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vvm v28, v28, v24, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vvm v8, v8, v26, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vvm v16, v16, v22, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vvm v18, v18, v16, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vvm v18, v18, v12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vvm v14, v14, v10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vvm v2, v2, v16, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vvm v30, v30, v18, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vvm v20, v20, v18, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vvm v8, v8, v24, v0

  li t2, 0x85af66712c364d45
  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0xcf5d49be0d0757f9
  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0x17a46c3286786424
  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vxm v4, v4, t2, v0

  li t2, 0x3dcf261e18c2451f
  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vxm v4, v4, t2, v0

  li t2, 0x2b3ec6c23838e3aa
  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vxm v14, v14, t2, v0

  li t2, 0x6587505849cd4297
  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vxm v2, v2, t2, v0

  li t2, 0xf202a7a44f52fa4d
  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vxm v10, v10, t2, v0

  li t2, 0x9f475f901f8a6ef7
  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vxm v28, v28, t2, v0

  li t2, 0x9b48433de4e457dd
  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vxm v4, v4, t2, v0

  li t2, 0xa483b0e6342798c1
  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vxm v14, v14, t2, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vim v18, v18, -14, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vim v14, v14, -10, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vim v26, v26, -6, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vim v16, v16, 0, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vim v22, v22, -4, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vim v14, v14, -4, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vim v26, v26, 12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vim v24, v24, -6, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vim v20, v20, -12, v0

  vsetvli t1, t0, e32, m2, ta, ma
  vmerge.vim v26, v26, -3, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vvm v24, v24, v16, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vvm v28, v28, v8, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vvm v8, v8, v20, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vvm v28, v28, v8, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vvm v28, v28, v16, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vvm v24, v24, v20, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vvm v20, v20, v12, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vvm v12, v12, v4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vvm v4, v4, v12, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vvm v28, v28, v24, v0

  li t2, 0x10dd1bdeaf544dd2
  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vxm v28, v28, t2, v0

  li t2, 0x6b060347bdf00a8a
  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vxm v28, v28, t2, v0

  li t2, 0xa2bd80b2b4ac200a
  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vxm v4, v4, t2, v0

  li t2, 0x2fce8587278f6b3e
  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vxm v20, v20, t2, v0

  li t2, 0x5f3b4eb1a5500e3a
  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0x20663d8bc219767a
  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vxm v4, v4, t2, v0

  li t2, 0xd4869dfa4d10bc3a
  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vxm v4, v4, t2, v0

  li t2, 0x9f658a37b46ddefc
  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vxm v28, v28, t2, v0

  li t2, 0xf8152da7e7dd0621
  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0x129b5d1d92ece3c5
  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vxm v8, v8, t2, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vim v16, v16, 14, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vim v20, v20, -13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vim v20, v20, 0, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vim v8, v8, 13, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vim v8, v8, 15, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vim v16, v16, -7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vim v16, v16, 10, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vim v16, v16, -7, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vim v16, v16, 4, v0

  vsetvli t1, t0, e32, m4, ta, ma
  vmerge.vim v24, v24, 13, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vvm v16, v16, v24, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vvm v8, v8, v24, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vvm v8, v8, v24, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vvm v8, v8, v16, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vvm v24, v24, v8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vvm v16, v16, v24, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vvm v8, v8, v24, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vvm v24, v24, v8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vvm v16, v16, v8, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vvm v24, v24, v8, v0

  li t2, 0x09c8761b650a8fdb
  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0xf6a64d520a5a9a01
  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0xce76be531438a4d6
  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0x2bdc5410ec9b994e
  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0x627910e30291ecb0
  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0x946e95b6945ce991
  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0x108f9d5f0f301c61
  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0x697b3feab2686e4d
  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0x1f57fbbc123e1153
  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0xf72d6e53134d204f
  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vxm v16, v16, t2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vim v16, v16, -15, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vim v16, v16, -6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vim v16, v16, -6, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vim v8, v8, -9, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vim v24, v24, -10, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vim v24, v24, -10, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vim v16, v16, 4, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vim v24, v24, 15, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vim v8, v8, -2, v0

  vsetvli t1, t0, e32, m8, ta, ma
  vmerge.vim v8, v8, -9, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vvm v7, v7, v3, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vvm v6, v6, v12, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vvm v27, v27, v20, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vvm v20, v20, v8, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vvm v28, v28, v1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vvm v17, v17, v5, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vvm v18, v18, v6, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vvm v3, v3, v13, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vvm v21, v21, v22, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vvm v28, v28, v18, v0

  li t2, 0x8a1b09cbf41971a9
  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vxm v9, v9, t2, v0

  li t2, 0x9d5a3e68e55a71b0
  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0x5a5b936ef9eead61
  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vxm v2, v2, t2, v0

  li t2, 0x9fd5a5362f01ca9d
  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0x3b060fc4a6e569dc
  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vxm v17, v17, t2, v0

  li t2, 0xc74f4b208b52304f
  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vxm v28, v28, t2, v0

  li t2, 0x2101370bc88757e8
  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vxm v23, v23, t2, v0

  li t2, 0x66690eea8a0f2296
  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vxm v7, v7, t2, v0

  li t2, 0x530feda37656b161
  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vxm v29, v29, t2, v0

  li t2, 0xfdfce5500cd2f482
  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vxm v7, v7, t2, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vim v26, v26, 6, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vim v12, v12, 4, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vim v25, v25, 10, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vim v14, v14, 1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vim v21, v21, -1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vim v12, v12, -1, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vim v6, v6, -11, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vim v29, v29, 15, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vim v15, v15, -6, v0

  vsetvli t1, t0, e64, m1, ta, ma
  vmerge.vim v7, v7, -4, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vvm v6, v6, v10, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vvm v24, v24, v4, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vvm v6, v6, v10, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vvm v8, v8, v14, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vvm v28, v28, v10, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vvm v22, v22, v6, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vvm v12, v12, v14, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vvm v2, v2, v4, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vvm v10, v10, v26, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vvm v14, v14, v6, v0

  li t2, 0x56222270af7ba9b8
  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vxm v30, v30, t2, v0

  li t2, 0x307a7db72955e1da
  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vxm v12, v12, t2, v0

  li t2, 0xd35a8c83a11c902b
  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vxm v22, v22, t2, v0

  li t2, 0x5d2bc7101203fc0f
  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vxm v20, v20, t2, v0

  li t2, 0xf7b4f104ba359eb4
  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vxm v18, v18, t2, v0

  li t2, 0x8811ed9745ee4c46
  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vxm v30, v30, t2, v0

  li t2, 0xdebfc8a6a8753dd3
  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vxm v4, v4, t2, v0

  li t2, 0xefd1058649126e81
  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0xb71d718e2b4f84b3
  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0x7f1555c3281776c3
  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vxm v10, v10, t2, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vim v18, v18, -11, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vim v24, v24, 0, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vim v16, v16, -4, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vim v2, v2, -9, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vim v28, v28, -1, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vim v24, v24, 5, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vim v30, v30, 8, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vim v10, v10, -15, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vim v6, v6, 8, v0

  vsetvli t1, t0, e64, m2, ta, ma
  vmerge.vim v6, v6, 4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vvm v12, v12, v8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vvm v20, v20, v4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vvm v4, v4, v12, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vvm v16, v16, v28, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vvm v12, v12, v20, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vvm v4, v4, v12, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vvm v28, v28, v24, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vvm v16, v16, v8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vvm v20, v20, v4, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vvm v20, v20, v12, v0

  li t2, 0xbb19500fc639c8d3
  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vxm v20, v20, t2, v0

  li t2, 0xa227718fcd170d29
  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vxm v12, v12, t2, v0

  li t2, 0x5a608feeba18fa36
  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vxm v12, v12, t2, v0

  li t2, 0x8f3263dba0c11fc2
  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vxm v20, v20, t2, v0

  li t2, 0x621396c1da6ee8da
  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0xa01a485413d2fbc5
  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vxm v20, v20, t2, v0

  li t2, 0x8c778a75c89d25ce
  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0x479e985ba1a3fbb8
  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0x807f43ce15c7ba38
  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0x9df7076c8862e9a7
  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vxm v20, v20, t2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vim v4, v4, -9, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vim v28, v28, -2, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vim v4, v4, 15, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vim v20, v20, 10, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vim v20, v20, 8, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vim v16, v16, -9, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vim v28, v28, -15, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vim v24, v24, -9, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vim v8, v8, 7, v0

  vsetvli t1, t0, e64, m4, ta, ma
  vmerge.vim v16, v16, -5, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vvm v16, v16, v8, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vvm v16, v16, v24, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vvm v8, v8, v24, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vvm v16, v16, v8, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vvm v16, v16, v8, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vvm v24, v24, v16, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vvm v24, v24, v16, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vvm v24, v24, v16, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vvm v24, v24, v8, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vvm v8, v8, v24, v0

  li t2, 0x13af9e5349420cbd
  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0x90157c599ea15e18
  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0xbb8112396e2a462e
  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0x7734cacb070c26b5
  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0xb6a2b491cbecfa7d
  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vxm v8, v8, t2, v0

  li t2, 0x6f7d5dad1a045cc0
  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0x7513f3ad1b970493
  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0x68f93118f78255d1
  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vxm v16, v16, t2, v0

  li t2, 0x8de8c11db75f400d
  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vxm v24, v24, t2, v0

  li t2, 0xd1a04a78e8e427be
  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vxm v16, v16, t2, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vim v24, v24, -15, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vim v8, v8, -3, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vim v16, v16, -13, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vim v8, v8, 11, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vim v8, v8, -9, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vim v8, v8, -6, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vim v16, v16, 14, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vim v16, v16, -12, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vim v24, v24, -1, v0

  vsetvli t1, t0, e64, m8, ta, ma
  vmerge.vim v16, v16, -12, v0

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
