#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  li t2, 0xd0edf5a31910558f
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v17, v1, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v11, v1, 15, v0.t

  li t2, 0x7b744911db50547f
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v10, v31, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v21, v23, 8, v0.t

  li t2, 0x54f9d4df8df3108c
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v6, v23, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v3, v12, 25, v0.t

  li t2, 0xc3ec1ddea6d0c365
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v30, v27, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v5, v23, 7, v0.t

  li t2, 0x3d48268877953863
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v23, v18, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v30, v15, 10, v0.t

  li t2, 0x62e354791ed943bf
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v1, v27, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v8, v3, 22, v0.t

  li t2, 0xe13f02c6cb58a0e4
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v26, v11, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v6, v30, 16, v0.t

  li t2, 0x23f427e86ba70fbd
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v8, v14, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v2, v27, 25, v0.t

  li t2, 0xa85a72f25140d8a1
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v21, v28, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v3, v1, 16, v0.t

  li t2, 0x78428ba8b1f45594
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v3, v4, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v8, v14, 22, v0.t

  li t2, 0x5aecb04e3da74340
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v22, v26, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v18, v12, 16, v0.t

  li t2, 0xc248c8b9c3c45a56
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v28, v9, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v25, v11, 16, v0.t

  li t2, 0x63442925c9358598
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v19, v7, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v4, v20, 15, v0.t

  li t2, 0x21754ab46bd25229
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v4, v5, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v12, v3, 24, v0.t

  li t2, 0x4be8dded39880290
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v18, v26, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v20, v14, 15, v0.t

  li t2, 0xbef765a9b033a274
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v2, v10, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v10, v5, 22, v0.t

  li t2, 0xe4cbdc2aa8ef758c
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v26, v16, 14, v0.t

  li t2, 0x12409204ce6f18ea
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v25, v11, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v15, v28, 11, v0.t

  li t2, 0x466d0ee3fbb03dd9
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v26, v15, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v30, v12, 16, v0.t

  li t2, 0x522f615964a27ef8
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v11, v14, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v17, v5, 19, v0.t

  li t2, 0xa4c9f6a143e3f228
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v13, v6, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v6, v4, 23, v0.t

  li t2, 0x2012189d1720e90e
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v10, v27, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v15, v29, 21, v0.t

  li t2, 0xca97320f6068fe45
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v12, v19, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v12, v13, 28, v0.t

  li t2, 0x161bc2b94c5a7165
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v2, v31, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v26, v14, 23, v0.t

  li t2, 0x6d745d14bdb8bc6a
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v8, v4, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v31, v3, 8, v0.t

  li t2, 0x299a1f2cc44eba54
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v29, v18, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v21, v18, 14, v0.t

  li t2, 0x82f4da41df817979
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v23, v14, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v21, v14, 7, v0.t

  li t2, 0x00bd38f62d471474
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v10, v9, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v16, v2, 10, v0.t

  li t2, 0x57941e720c71b060
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v9, v12, 29, v0.t

  li t2, 0x604f7bf44a034d64
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v20, v13, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v7, v23, 1, v0.t

  li t2, 0x7dca0317551e95f2
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v10, v27, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v5, v23, 29, v0.t

  li t2, 0x75090855125c668b
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v1, v19, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v6, v2, 9, v0.t

  li t2, 0xd593800a023cf3a6
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v25, v5, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v26, v18, 15, v0.t

  li t2, 0xbe04e80e9754567f
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v16, v25, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v3, v12, 7, v0.t

  li t2, 0x7986237b001ec057
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v5, v28, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v9, v12, 2, v0.t

  li t2, 0x896b81919c3b977e
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v27, v16, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v21, v3, 9, v0.t

  li t2, 0x54af5cbdc5e1e769
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v18, v2, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v6, v4, 17, v0.t

  li t2, 0x7523e75704f4fb52
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v7, v11, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v28, v7, 31, v0.t

  li t2, 0x2823cc0b3bfe88c2
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v12, v1, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v12, v23, 6, v0.t

  li t2, 0x2e9e4d1a8aef7e7d
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v8, v30, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v28, v5, 19, v0.t

  li t2, 0x9aa8114d02ccbedc
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v21, v30, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v27, v14, 20, v0.t

  li t2, 0x5774f34a53b95366
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v30, v14, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v25, v23, 6, v0.t

  li t2, 0x27a2a1936da7e0e1
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v16, v27, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v16, v29, 30, v0.t

  li t2, 0x6591b2a6ec9c7da1
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v22, v9, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v10, v24, 25, v0.t

  li t2, 0x4283be12f051a01a
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v10, v24, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v23, v26, 19, v0.t

  li t2, 0xe7bef2d0f8307bba
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v11, v6, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v21, v15, 29, v0.t

  li t2, 0xe90629f243885b14
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v31, v21, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v24, v5, 16, v0.t

  li t2, 0x8798245cb1217311
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v19, v28, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v11, v14, 10, v0.t

  li t2, 0x76d4c28994ed22c8
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v30, v28, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v13, v8, 9, v0.t

  li t2, 0x757bcc60166b4173
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v11, v3, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v14, v21, 6, v0.t

  li t2, 0x661f56bb0ef8b830
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v4, v8, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v7, v27, 4, v0.t

  li t2, 0x9ff7205e340ac1a7
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v6, v3, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v3, v14, 7, v0.t

  li t2, 0x1a803c5058ddc85f
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v29, v20, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v25, v31, 2, v0.t

  li t2, 0x877b8778c99bb539
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v10, v16, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v2, v24, 4, v0.t

  li t2, 0x7d2732c2b7ab68b7
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v13, v11, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v25, v28, 9, v0.t

  li t2, 0x5c664a53af8a033b
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v12, v23, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v3, v22, 25, v0.t

  li t2, 0x6c0fc29e2a1fb86b
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v12, v26, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v25, v1, 26, v0.t

  li t2, 0x45ffbd0d51e81fec
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v22, v2, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v26, v25, 21, v0.t

  li t2, 0x5e8abfbfab64f89e
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v20, v25, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v1, v9, 28, v0.t

  li t2, 0xc9d744e5be7a7129
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v21, v27, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v26, v29, 26, v0.t

  li t2, 0x0ec1382f42f387a5
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v31, v16, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v5, v18, 0, v0.t

  li t2, 0xde8aaf68c195dbb9
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v9, v12, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v5, v27, 23, v0.t

  li t2, 0x7b38d353bc4e87ff
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v25, v6, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v7, v3, 24, v0.t

  li t2, 0x0751e6ab92b8e3ad
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v15, v24, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v25, v10, 7, v0.t

  li t2, 0xe2239ecbbee16eb3
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v27, v28, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v11, v31, 6, v0.t

  li t2, 0x24c3b8a9c9b356cc
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v17, v29, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v31, v2, 25, v0.t

  li t2, 0xac11f2eb51538fbc
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v3, v8, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v2, v24, 5, v0.t

  li t2, 0x947d41036d2a2b14
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v17, v14, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v22, v12, 11, v0.t

  li t2, 0x3bee3cabc696d63b
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v21, v17, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v11, v29, 11, v0.t

  li t2, 0xe5a58f6ae268a8fd
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v18, v28, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v2, v1, 14, v0.t

  li t2, 0x7e3bd27a9e9e85e0
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v31, v27, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v7, v20, 5, v0.t

  li t2, 0x0287b100a6b87e44
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v27, v7, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v9, v12, 19, v0.t

  li t2, 0x7959cf219af5932e
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v23, v28, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v8, v20, 9, v0.t

  li t2, 0xeadd1d2ec9997065
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v5, v10, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v18, v26, 27, v0.t

  li t2, 0x245abb70724cb87f
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v1, v13, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v16, v8, 12, v0.t

  li t2, 0x327ad1156d6d6c97
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v25, v29, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v28, v16, 11, v0.t

  li t2, 0x9597904c6f0828cf
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v14, v21, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v28, v11, 14, v0.t

  li t2, 0x68e475f8700dbe99
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v10, v8, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v1, v25, 17, v0.t

  li t2, 0x47b9bebc90f953f6
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v7, v6, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v6, v22, 10, v0.t

  li t2, 0xb9b77803b1659568
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v31, v16, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v10, v3, 28, v0.t

  li t2, 0x738e356190f51919
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v9, v22, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v24, v20, 3, v0.t

  li t2, 0xedca179baf48c635
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v21, v16, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v7, v4, 31, v0.t

  li t2, 0x7d5202e6a5c7bb81
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v17, v21, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v10, v13, 18, v0.t

  li t2, 0xcbc4d7cdbba768e1
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v23, v13, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v13, v2, 25, v0.t

  li t2, 0xcfd9e1c791cd53ae
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v5, v9, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v10, v30, 20, v0.t

  li t2, 0x3bd58a1178357b5a
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v20, v28, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v8, v23, 17, v0.t

  li t2, 0x10d6e3f4236599a3
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v5, v8, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v23, v2, 18, v0.t

  li t2, 0x3b81ab19e7eda02a
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v9, v12, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v9, v6, 3, v0.t

  li t2, 0xbaf2b34f50397b62
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v15, v4, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v3, v5, 22, v0.t

  li t2, 0x94ea1846864f5127
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v14, v12, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v21, v29, 13, v0.t

  li t2, 0xd51e88446807b0d6
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v16, v9, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v24, v3, 31, v0.t

  li t2, 0xd37d9701e952a49c
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v8, v18, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v17, v24, 16, v0.t

  li t2, 0x42fb6cef4bad5761
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v9, v8, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v29, v17, 23, v0.t

  li t2, 0x82dd1a488a6d1213
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v21, v26, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v1, v24, 4, v0.t

  li t2, 0x5c1f5a4350d2837e
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v19, v21, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v9, v17, 8, v0.t

  li t2, 0xce4c1498d8cc83c0
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v24, v27, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v14, v30, 18, v0.t

  li t2, 0x2e640c250c01d8a4
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v13, v2, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v8, v16, 21, v0.t

  li t2, 0x1a064836a1a02017
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v24, v26, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v25, v18, 25, v0.t

  li t2, 0x1dffab7064b9ad60
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v17, v8, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v2, v29, 15, v0.t

  li t2, 0x5a6b1c9779316953
  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vx v3, v13, t2, v0.t

  vsetvli t1, t0, e32, m1, ta, ma
  vslideup.vi v21, v10, 23, v0.t

  li t2, 0x24b4f2b029c7df92
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v4, v24, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v24, v26, 12, v0.t

  li t2, 0x1ac9bf3d0850a643
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v2, v24, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v20, v22, 18, v0.t

  li t2, 0x431def1e2a350cbf
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v10, v22, 20, v0.t

  li t2, 0x40390a790a5205d4
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v24, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v6, v16, 25, v0.t

  li t2, 0x18eaa4955ee7dfe5
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v10, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v16, v24, 22, v0.t

  li t2, 0xf6be34ece163886d
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v16, v30, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v12, v26, 6, v0.t

  li t2, 0x26b70bd78a4dfad9
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v6, v12, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v16, v18, 24, v0.t

  li t2, 0x27750f7aef48ed2a
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v22, v2, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v22, v18, 11, v0.t

  li t2, 0xa70064f595c222b3
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v2, v8, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v16, v8, 3, v0.t

  li t2, 0x1edc81fb8b22e750
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v10, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v28, v22, 30, v0.t

  li t2, 0x161abc0e0a358fb8
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v12, v18, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v24, v2, 16, v0.t

  li t2, 0x7dc1572d5d3cc110
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v18, v10, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v18, v22, 8, v0.t

  li t2, 0x8d79f0133595d5cd
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v2, v26, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v22, v30, 17, v0.t

  li t2, 0xaca86acaadeebac5
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v12, v14, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v2, v14, 13, v0.t

  li t2, 0xeca6d393777b1555
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v30, v16, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v26, v22, 31, v0.t

  li t2, 0xa0876a25d56ae081
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v18, v2, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v30, v12, 8, v0.t

  li t2, 0x97ef10d6dd6a7da8
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v30, v24, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v24, v4, 13, v0.t

  li t2, 0x190e8156fde5a54d
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v30, v24, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v6, v30, 6, v0.t

  li t2, 0x4350e07a592382c7
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v6, v20, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v2, v26, 5, v0.t

  li t2, 0x75bea85366433093
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v14, v8, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v14, v12, 11, v0.t

  li t2, 0x6a55d7614472da32
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v12, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v28, v12, 30, v0.t

  li t2, 0xddb9ea4b70729265
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v30, v20, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v26, v16, 8, v0.t

  li t2, 0x00b865899e5d646b
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v8, v20, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v2, v14, 2, v0.t

  li t2, 0xfedf4f3b78398c98
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v14, v10, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v20, v26, 28, v0.t

  li t2, 0x9b977be3bbc8c36c
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v2, v10, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v8, v2, 13, v0.t

  li t2, 0x84b8ab9759b3087f
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v10, v4, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v24, v16, 15, v0.t

  li t2, 0x4328c9d3b0a2829c
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v28, v16, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v14, v10, 0, v0.t

  li t2, 0xd506b6b57d18cc6d
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v28, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v12, v28, 7, v0.t

  li t2, 0xb19428af4aac48df
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v30, v18, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v30, v22, 29, v0.t

  li t2, 0xe43b4f29fb557241
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v16, v30, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v14, v6, 1, v0.t

  li t2, 0x90ad67ad5f77c09b
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v30, v4, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v10, v16, 23, v0.t

  li t2, 0x144e481db9386206
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v24, v8, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v4, v20, 20, v0.t

  li t2, 0x6ef78765ca4ed378
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v16, v2, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v16, v8, 27, v0.t

  li t2, 0x6fc3ca9f80bc2fdc
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v14, v16, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v22, v26, 7, v0.t

  li t2, 0x277e9d51e7731574
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v30, v12, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v18, v12, 28, v0.t

  li t2, 0x383610bb6323f327
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v10, v14, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v14, v30, 20, v0.t

  li t2, 0xf9e253557c4d4c2d
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v12, v24, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v10, v12, 6, v0.t

  li t2, 0x5a21bd66cada5e0e
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v30, v6, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v18, v6, 24, v0.t

  li t2, 0x77ca3a3ba3dbe4fd
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v18, v12, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v16, v4, 5, v0.t

  li t2, 0x8b30a06a6178a419
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v18, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v10, v14, 22, v0.t

  li t2, 0x2a91adff8176e5c5
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v12, v14, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v24, v10, 22, v0.t

  li t2, 0xfb2487acf872e452
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v4, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v18, v16, 12, v0.t

  li t2, 0xcabe08bb5418ac80
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v22, v8, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v24, v18, 19, v0.t

  li t2, 0x630c57d3269abab7
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v14, v12, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v26, v20, 20, v0.t

  li t2, 0xd3e37a37238ae8d6
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v16, v2, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v4, v24, 26, v0.t

  li t2, 0xa33c01089014b432
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v28, v2, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v10, v30, 25, v0.t

  li t2, 0x73a6794a75f0e961
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v16, v30, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v30, v4, 29, v0.t

  li t2, 0x388a1439b0fab460
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v30, v4, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v14, v12, 8, v0.t

  li t2, 0x2685efd24f246741
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v12, v10, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v14, v6, 4, v0.t

  li t2, 0x898541c56a5b0394
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v6, v10, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v24, v12, 21, v0.t

  li t2, 0xaddd197f8dc6117a
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v22, v20, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v16, v2, 10, v0.t

  li t2, 0xf52dbba7641f6c89
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v22, v24, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v14, v16, 11, v0.t

  li t2, 0xe6e3b8550cf9526a
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v30, v8, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v26, v16, 3, v0.t

  li t2, 0x126cc5d1636bef96
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v28, v10, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v12, v16, 10, v0.t

  li t2, 0x56518994a94e9f38
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v6, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v12, v2, 27, v0.t

  li t2, 0xe5da7e42e1a648ab
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v14, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v12, v24, 6, v0.t

  li t2, 0x9fee1542cc570b6e
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v14, v2, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v12, v6, 16, v0.t

  li t2, 0x7fb5557cdfad0fe7
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v6, v8, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v16, v26, 23, v0.t

  li t2, 0x755303a89fa7eb0b
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v22, v4, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v6, v16, 31, v0.t

  li t2, 0x3981c094978d00da
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v24, v18, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v26, v14, 3, v0.t

  li t2, 0x01c8a1e898e7e42d
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v14, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v12, v26, 29, v0.t

  li t2, 0x17943f9394d4af22
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v22, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v10, v4, 15, v0.t

  li t2, 0x64d5a31e104d61e7
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v12, v20, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v14, v20, 15, v0.t

  li t2, 0x5b617e5e6d0c542c
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v16, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v18, v6, 6, v0.t

  li t2, 0xd23925941509f253
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v2, v10, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v10, v30, 21, v0.t

  li t2, 0x96bbf277aeec9b90
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v28, v26, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v20, v18, 19, v0.t

  li t2, 0x9a633cb576a36da2
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v16, v12, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v10, v12, 8, v0.t

  li t2, 0x65c8b83cf53f1559
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v12, v26, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v28, v22, 14, v0.t

  li t2, 0x23fca387f360b0f4
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v4, v30, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v8, v4, 27, v0.t

  li t2, 0x475f47f70d80f627
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v2, v10, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v24, v22, 14, v0.t

  li t2, 0x823c88e29a07494e
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v22, v18, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v10, v18, 23, v0.t

  li t2, 0x99838d2187edc159
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v24, v26, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v6, v16, 27, v0.t

  li t2, 0xc419d9cf113de2ae
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v6, v10, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v18, v22, 20, v0.t

  li t2, 0x6c11ce1235f9da70
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v8, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v10, v4, 31, v0.t

  li t2, 0xa9a4ff90b8b57c0d
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v2, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v22, v6, 13, v0.t

  li t2, 0xdf1ad99037d6cb60
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v20, v24, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v2, v30, 30, v0.t

  li t2, 0x1658bc43012b4486
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v10, v24, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v14, v24, 12, v0.t

  li t2, 0x117b3d5f5263e0eb
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v28, v26, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v2, v12, 21, v0.t

  li t2, 0x4a462f1c8ebc596a
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v6, v20, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v8, v20, 2, v0.t

  li t2, 0xb61606d659ba0e45
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v22, v4, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v10, v20, 26, v0.t

  li t2, 0xdb4677f13b2311db
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v22, v18, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v26, v2, 30, v0.t

  li t2, 0x3e14a64009388a76
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v12, v16, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v10, v20, 24, v0.t

  li t2, 0x9d481342106a3f73
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v18, v8, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v18, v4, 1, v0.t

  li t2, 0xbd2d1fe6ddafa20e
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v20, v14, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v22, v4, 1, v0.t

  li t2, 0x4ce50506bb786ab8
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v8, v18, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v8, v22, 3, v0.t

  li t2, 0xeb86c6c26d3932d3
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v12, v2, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v12, v4, 23, v0.t

  li t2, 0xbb7e697ec6a4e3eb
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v20, v30, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v14, v26, 22, v0.t

  li t2, 0x4c53dbb77ae2af81
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v18, v20, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v4, v20, 27, v0.t

  li t2, 0xa9dc70c5c1c4fcba
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v8, v24, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v6, v10, 9, v0.t

  li t2, 0x6ad01317f8d29010
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v4, v26, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v8, v22, 7, v0.t

  li t2, 0x57b2746de3986672
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v24, v2, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v4, v18, 18, v0.t

  li t2, 0x08d55b8442d33cf5
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v20, v30, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v16, v6, 4, v0.t

  li t2, 0x248bc043b77460c4
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v16, v18, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v14, v4, 21, v0.t

  li t2, 0x25db5e4225494600
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v6, v8, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v14, v22, 19, v0.t

  li t2, 0xcbc4a74998a279e1
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v26, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v30, v14, 19, v0.t

  li t2, 0xca447125357e9ed0
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v14, v28, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v2, v20, 27, v0.t

  li t2, 0xc175abb2fa17a31b
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v2, v18, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v2, v14, 16, v0.t

  li t2, 0x8f0268a13431d439
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v4, v22, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v4, v26, 23, v0.t

  li t2, 0xe87d93ac7f4c872b
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v30, v24, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v6, v22, 19, v0.t

  li t2, 0xbabec40f8154256e
  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e32, m2, ta, ma
  vslideup.vi v28, v18, 5, v0.t

  li t2, 0x259abc3fb2243140
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v6, v1, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v3, v25, 16, v0.t

  li t2, 0xc211fab01b8b3e21
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v25, v27, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v30, v29, 1, v0.t

  li t2, 0x41b1ceb969006c37
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v8, v17, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v22, v19, 24, v0.t

  li t2, 0x737c8e1f073bd090
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v20, v9, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v8, v1, 3, v0.t

  li t2, 0x514441bf2afa89aa
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v22, v3, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v25, v3, 6, v0.t

  li t2, 0x41f22307cbe47832
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v18, v10, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v30, v22, 5, v0.t

  li t2, 0xbaf0dd9515da499f
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v26, v25, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v30, v18, 11, v0.t

  li t2, 0xc16b3efcfc482441
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v4, v23, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v15, v11, 5, v0.t

  li t2, 0x0ebfa481ff9727bf
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v25, v17, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v6, v11, 11, v0.t

  li t2, 0x117c7bf2055094b2
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v19, v21, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v17, v29, 14, v0.t

  li t2, 0x7958a6a31287d060
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v28, v8, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v27, v24, 11, v0.t

  li t2, 0x2857da667382297c
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v15, v3, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v8, v22, 12, v0.t

  li t2, 0xb30f501eb818ed1e
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v23, v9, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v16, v30, 2, v0.t

  li t2, 0x1afc106d02514f47
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v1, v10, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v3, v6, 12, v0.t

  li t2, 0xac93a0f28517114e
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v3, v29, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v11, v31, 26, v0.t

  li t2, 0xe0ff143294a4829b
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v1, v8, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v7, v25, 9, v0.t

  li t2, 0xe1981dd817bb05b3
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v1, v3, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v3, v18, 29, v0.t

  li t2, 0xf194f032de930d69
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v9, v16, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v2, v26, 0, v0.t

  li t2, 0xdbd4193778969d5e
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v5, v1, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v13, v15, 28, v0.t

  li t2, 0xb978ea59cd075d80
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v23, v11, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v24, v21, 26, v0.t

  li t2, 0x5b1a8461caafbc98
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v12, v26, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v13, v7, 29, v0.t

  li t2, 0x2374bb1f17fee8aa
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v1, v13, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v1, v19, 30, v0.t

  li t2, 0x41912672cb55c30d
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v11, v29, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v30, v23, 7, v0.t

  li t2, 0x42c6f7a3bf29738e
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v14, v11, 28, v0.t

  li t2, 0xc311b79f56b86d53
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v25, v23, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v24, v8, 28, v0.t

  li t2, 0x515860b109040518
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v24, v22, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v3, v16, 4, v0.t

  li t2, 0x9f06e8ddffa635b1
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v21, v9, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v6, v31, 21, v0.t

  li t2, 0xdf6fa0d088fe3ae7
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v19, v5, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v8, v6, 19, v0.t

  li t2, 0xe742600dcdc61085
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v30, v21, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v8, v25, 27, v0.t

  li t2, 0x7f5f67db6fabad4c
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v24, v19, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v8, v27, 19, v0.t

  li t2, 0xd062abbed69b63f6
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v10, v14, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v17, v14, 16, v0.t

  li t2, 0x86b1d66480adcb77
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v14, v12, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v31, v3, 26, v0.t

  li t2, 0x344b4cd2f57b1d37
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v25, v9, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v16, v2, 0, v0.t

  li t2, 0x6910b2f2b8a85548
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v25, v14, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v28, v7, 27, v0.t

  li t2, 0x970aef6b52a8c3b9
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v17, v14, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v22, v2, 13, v0.t

  li t2, 0x9f7d565b6e41cb4f
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v23, v17, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v29, v5, 13, v0.t

  li t2, 0xd7bf2396d795064e
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v19, v8, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v28, v23, 17, v0.t

  li t2, 0x75dd496ad489d189
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v7, v10, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v1, v24, 27, v0.t

  li t2, 0x98079a7ba5674d4c
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v6, v17, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v6, v24, 6, v0.t

  li t2, 0x990352d291ed3af1
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v30, v24, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v5, v22, 31, v0.t

  li t2, 0xcbeb808333c74cd4
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v3, v30, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v5, v9, 15, v0.t

  li t2, 0x6d5652b440e8fc64
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v22, v15, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v31, v27, 23, v0.t

  li t2, 0xdd2c6a3024f852df
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v26, v11, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v27, v24, 3, v0.t

  li t2, 0x40d57bb028c94076
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v18, v9, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v7, v31, 10, v0.t

  li t2, 0xebefc6e50f2b6779
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v10, v5, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v10, v9, 21, v0.t

  li t2, 0x3818b134429d73db
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v3, v16, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v3, v8, 5, v0.t

  li t2, 0xe19db31d658a5d9c
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v10, v14, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v20, v6, 2, v0.t

  li t2, 0x59bd13b1b8229cbf
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v10, v8, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v29, v6, 10, v0.t

  li t2, 0x6accb9b8801fc20b
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v15, v6, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v25, v11, 18, v0.t

  li t2, 0xdb4f6723f1f7ce23
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v25, v7, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v9, v10, 17, v0.t

  li t2, 0x0a08e9bc3f2c622a
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v30, v5, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v4, v11, 24, v0.t

  li t2, 0x704f2781e541f8dd
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v15, v24, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v30, v12, 8, v0.t

  li t2, 0x903b7da51ea2a300
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v19, v6, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v22, v6, 15, v0.t

  li t2, 0xbbc343075fc2d2ca
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v3, v23, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v11, v2, 3, v0.t

  li t2, 0x5031b2214fde8636
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v23, v16, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v14, v11, 5, v0.t

  li t2, 0xe16357a59ef8f957
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v23, v7, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v14, v13, 0, v0.t

  li t2, 0x7223f056f43bd8d2
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v31, v26, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v26, v7, 9, v0.t

  li t2, 0x2824a16f10b0baa6
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v17, v31, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v9, v24, 14, v0.t

  li t2, 0x8d2d3cd76efd7b3c
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v21, v14, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v20, v6, 15, v0.t

  li t2, 0x87f2f87d6bf8ee0b
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v27, v3, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v25, v6, 0, v0.t

  li t2, 0x86e6dedc072c0e07
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v14, v9, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v28, v29, 24, v0.t

  li t2, 0x7713f4bf16bbd45e
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v1, v15, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v27, v26, 31, v0.t

  li t2, 0x92f22ac155d6f47e
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v14, v2, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v2, v8, 31, v0.t

  li t2, 0x138f9ae11f6da756
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v10, v9, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v18, v23, 0, v0.t

  li t2, 0x9a9f8bef555a8a48
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v2, v1, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v22, v5, 20, v0.t

  li t2, 0xd97438052ac6c992
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v30, v6, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v3, v24, 30, v0.t

  li t2, 0x73283eacc07de737
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v13, v2, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v8, v30, 15, v0.t

  li t2, 0xe34739c663ebb3f5
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v30, v1, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v2, v7, 4, v0.t

  li t2, 0x55746b28ba5118aa
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v14, v2, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v6, v27, 25, v0.t

  li t2, 0x5b377c8936f893fe
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v22, v18, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v31, v9, 16, v0.t

  li t2, 0xa3181d5224912b47
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v14, v24, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v2, v23, 19, v0.t

  li t2, 0xe1cc12716dd29aee
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v29, v11, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v8, v31, 14, v0.t

  li t2, 0x861c12887efb830c
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v29, v24, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v2, v1, 26, v0.t

  li t2, 0x810eefa2461e2afb
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v24, v11, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v20, v18, 7, v0.t

  li t2, 0x460e081b479ac7b5
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v3, v21, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v14, v9, 20, v0.t

  li t2, 0x287d0e1251a3f017
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v28, v5, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v17, v2, 17, v0.t

  li t2, 0x059a00932d8b7676
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v11, v10, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v22, v20, 7, v0.t

  li t2, 0xa33d01e04d7ef0e3
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v2, v9, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v29, v25, 21, v0.t

  li t2, 0x34f2fe698a6ef29c
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v3, v22, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v10, v20, 22, v0.t

  li t2, 0xeff0ba1da25e0682
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v16, v20, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v8, v4, 6, v0.t

  li t2, 0xb18248d5a4a03f39
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v2, v1, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v23, v31, 4, v0.t

  li t2, 0xadc45aef3712e3e4
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v3, v9, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v8, v14, 13, v0.t

  li t2, 0x9eb591c6e3731d72
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v6, v31, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v11, v24, 29, v0.t

  li t2, 0xab9ba4531177d7c7
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v3, v15, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v16, v13, 26, v0.t

  li t2, 0x7dc2523932bcce75
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v30, v3, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v23, v17, 5, v0.t

  li t2, 0xc591f3be041fbdab
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v6, v30, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v30, v31, 1, v0.t

  li t2, 0x9edb89bb31035b45
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v31, v17, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v7, v8, 29, v0.t

  li t2, 0xd6df61d99b7b5462
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v19, v22, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v7, v25, 28, v0.t

  li t2, 0x90d34da2ac638c12
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v21, v9, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v11, v10, 3, v0.t

  li t2, 0xc55ca54f76f0f213
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v25, v2, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v16, v30, 1, v0.t

  li t2, 0xb7829b3123a04d27
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v22, v9, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v25, v24, 10, v0.t

  li t2, 0x953d2ff71d361e54
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v9, v22, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v24, v30, 5, v0.t

  li t2, 0x7187f3d37b9f1697
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v21, v16, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v29, v28, 21, v0.t

  li t2, 0x6fa82362bc350cee
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v12, v13, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v4, v18, 0, v0.t

  li t2, 0x6ed0fbdff69f7e6e
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v16, v30, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v16, v10, 12, v0.t

  li t2, 0xf00290bd6da20a40
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v17, v28, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v22, v15, 22, v0.t

  li t2, 0x5836540321d9e523
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v19, v11, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v11, v4, 23, v0.t

  li t2, 0xbc87b34549c91f0e
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v4, v18, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v19, v11, 21, v0.t

  li t2, 0xfce6e71a7d067702
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v7, v21, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v30, v6, 27, v0.t

  li t2, 0xa1713dc37ab0880d
  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vx v30, v10, t2, v0.t

  vsetvli t1, t0, e64, m1, ta, ma
  vslideup.vi v27, v30, 10, v0.t

  li t2, 0xb6b69e7b2b36f6db
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v20, v12, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v8, v30, 21, v0.t

  li t2, 0x078a88020cbb4c96
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v10, v4, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v30, v22, 14, v0.t

  li t2, 0x463419bcaeeacfa1
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v24, v18, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v28, v2, 9, v0.t

  li t2, 0xdfb9d1a3df7328da
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v4, v16, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v20, v2, 7, v0.t

  li t2, 0x88b9bbd3f4239b6a
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v14, v6, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v8, v10, 4, v0.t

  li t2, 0x66906e9996052b75
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v2, v4, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v30, v18, 19, v0.t

  li t2, 0xece60a90cdcda253
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v30, v18, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v20, v4, 4, v0.t

  li t2, 0x3834dfdfc12fed06
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v8, v4, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v30, v26, 13, v0.t

  li t2, 0x703a24fcba32eec8
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v16, v2, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v24, v20, 23, v0.t

  li t2, 0x4051166f4f22c4cc
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v18, v6, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v26, v2, 27, v0.t

  li t2, 0x5a235dd1e0196234
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v16, v26, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v28, v14, 13, v0.t

  li t2, 0x1bfce72597a78158
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v24, v2, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v10, v18, 22, v0.t

  li t2, 0xcd0b56b7fd534889
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v16, v30, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v10, v12, 19, v0.t

  li t2, 0x73a074adb22862cc
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v12, v16, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v6, v10, 30, v0.t

  li t2, 0x17bb5f9441a7bf60
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v16, v28, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v30, v28, 14, v0.t

  li t2, 0x66931428d528b4a3
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v8, v6, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v2, v28, 8, v0.t

  li t2, 0x1e06bd417c3dba62
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v18, v4, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v16, v14, 16, v0.t

  li t2, 0x93d6e614cfad0c9f
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v26, v24, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v4, v28, 10, v0.t

  li t2, 0x099ee1099eb51efa
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v26, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v16, v2, 5, v0.t

  li t2, 0x5fc487260ab4c7f8
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v2, v12, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v12, v6, 15, v0.t

  li t2, 0xfa1c05948b051db5
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v6, v8, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v30, v12, 17, v0.t

  li t2, 0x414432498a71ed5e
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v18, v2, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v22, v26, 23, v0.t

  li t2, 0xb37ca5f59cd01184
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v8, v6, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v28, v2, 26, v0.t

  li t2, 0x6c7c6f83cf74b2b0
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v12, v24, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v6, v8, 21, v0.t

  li t2, 0x127ce3b4c063ae88
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v24, v16, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v2, v12, 8, v0.t

  li t2, 0xc106cbb148e97237
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v26, v20, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v20, v16, 23, v0.t

  li t2, 0xf93d18169f00f10f
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v12, v24, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v14, v30, 0, v0.t

  li t2, 0x5e5eeee6e4620a19
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v12, v30, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v28, v12, 20, v0.t

  li t2, 0xee810f067f278494
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v28, v6, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v20, v30, 29, v0.t

  li t2, 0xb8d01194b1e9e361
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v14, v8, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v30, v12, 11, v0.t

  li t2, 0x448a0deb88fca49f
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v28, v4, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v12, v16, 0, v0.t

  li t2, 0xae5473b2f97def11
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v2, v28, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v10, v26, 4, v0.t

  li t2, 0x417b2dde23bad36d
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v24, v6, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v24, v18, 25, v0.t

  li t2, 0x9a4058757b1ebd89
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v14, v2, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v4, v28, 30, v0.t

  li t2, 0x69b9c189f717616a
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v26, v8, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v20, v10, 0, v0.t

  li t2, 0x47025123ae217600
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v26, v18, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v30, v14, 29, v0.t

  li t2, 0x7963cdcf7583c6e0
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v10, v26, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v2, v24, 17, v0.t

  li t2, 0xa49be0632e585abc
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v18, v24, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v28, v10, 10, v0.t

  li t2, 0x04934bcff26371f8
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v16, v24, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v26, v16, 31, v0.t

  li t2, 0x78dfa75b03556d98
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v12, v22, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v10, v30, 12, v0.t

  li t2, 0x6cb334170de8bf25
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v24, v20, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v12, v20, 10, v0.t

  li t2, 0x7399fe1386c55ebe
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v28, v24, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v6, v16, 12, v0.t

  li t2, 0xfd8e4284b674858c
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v18, v12, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v16, v22, 14, v0.t

  li t2, 0xa847c7678e813eae
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v4, v6, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v22, v6, 15, v0.t

  li t2, 0xfcb8b86ccc20caf1
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v8, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v2, v16, 29, v0.t

  li t2, 0x0f0d73070e40ac7b
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v4, v8, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v6, v20, 2, v0.t

  li t2, 0xd23cb5f829ce495a
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v14, v8, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v26, v24, 18, v0.t

  li t2, 0x36371407366a26c1
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v24, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v18, v20, 4, v0.t

  li t2, 0xba2d0edbb343c97f
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v6, v12, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v26, v8, 15, v0.t

  li t2, 0xa1b3fda5e12dd9a9
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v20, v16, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v8, v20, 22, v0.t

  li t2, 0x4688d686d2150e26
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v26, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v12, v20, 29, v0.t

  li t2, 0xcfd63ea9acad6149
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v26, v16, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v14, v26, 29, v0.t

  li t2, 0x0a7968e23af13b21
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v16, v4, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v26, v8, 14, v0.t

  li t2, 0x0144974a351d557c
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v6, v20, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v2, v4, 18, v0.t

  li t2, 0x41246e38803cfc3c
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v12, v26, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v6, v12, 11, v0.t

  li t2, 0xe568e74b06a04b8a
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v26, v8, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v10, v22, 5, v0.t

  li t2, 0xe274a11c8a11a34b
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v26, v30, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v30, v12, 5, v0.t

  li t2, 0xace32417175eba4b
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v8, v22, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v6, v30, 6, v0.t

  li t2, 0xd13ab95b760b5a95
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v26, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v2, v28, 6, v0.t

  li t2, 0xfdd0de2ef87136ef
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v10, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v6, v22, 7, v0.t

  li t2, 0xb09a3246be00dc02
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v14, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v24, v4, 17, v0.t

  li t2, 0x3984119e578cb4b8
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v4, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v16, v28, 25, v0.t

  li t2, 0x9ef37ee5a4b785a8
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v4, v28, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v16, v8, 5, v0.t

  li t2, 0x69df5133103fd9fb
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v12, v18, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v26, v12, 8, v0.t

  li t2, 0xc043a8f30bdd7804
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v30, v26, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v8, v12, 27, v0.t

  li t2, 0x4cecbf8171a22bee
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v18, v20, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v26, v2, 23, v0.t

  li t2, 0x76f2d2bfda88ba7f
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v14, v22, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v8, v18, 12, v0.t

  li t2, 0xaefe401b681c53bb
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v16, v26, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v6, v8, 10, v0.t

  li t2, 0x8b89a5a8077f3f92
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v10, v30, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v18, v22, 15, v0.t

  li t2, 0x02f5fe2b8ece0b1d
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v10, v4, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v22, v8, 15, v0.t

  li t2, 0x3ddce607b59619b0
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v8, v30, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v22, v26, 27, v0.t

  li t2, 0xbf5df1256ad13597
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v4, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v14, v18, 6, v0.t

  li t2, 0x67d13208fbfb3de7
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v24, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v18, v28, 30, v0.t

  li t2, 0x8c9235308d24d322
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v30, v16, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v14, v28, 19, v0.t

  li t2, 0xc810155b9690acef
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v22, v30, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v18, v2, 16, v0.t

  li t2, 0x243cc04e90854801
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v28, v22, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v2, v20, 26, v0.t

  li t2, 0xa3df394745d156af
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v10, v24, 13, v0.t

  li t2, 0x7b3dd294e3515c78
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v30, v26, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v6, v2, 3, v0.t

  li t2, 0xc65ec483504f2add
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v8, v16, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v24, v2, 31, v0.t

  li t2, 0x66262c425da6804b
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v12, v28, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v16, v8, 23, v0.t

  li t2, 0x3f72318a1d249fb3
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v20, v8, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v10, v18, 27, v0.t

  li t2, 0xaba2236655ebc9bf
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v8, v14, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v2, v24, 31, v0.t

  li t2, 0xac6ce88a2b93ca56
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v6, v22, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v28, v16, 5, v0.t

  li t2, 0xde31510838f0f610
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v14, v18, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v2, v28, 18, v0.t

  li t2, 0x9b6c05c6ac293ac4
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v18, v12, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v24, v14, 25, v0.t

  li t2, 0x95e061430f39ae76
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v8, v30, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v10, v18, 13, v0.t

  li t2, 0xe63705ce1d85c9c3
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v18, v22, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v10, v12, 25, v0.t

  li t2, 0x103f4dcfb239016c
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v24, v22, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v22, v28, 9, v0.t

  li t2, 0x7cfbf9b753372cb9
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v4, v18, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v26, v22, 23, v0.t

  li t2, 0x8c4aec51564a599b
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v4, v16, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v26, v18, 0, v0.t

  li t2, 0x6101840ecb60ed11
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v12, v28, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v14, v4, 1, v0.t

  li t2, 0xe3f1eac186d627d1
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v2, v22, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v30, v2, 31, v0.t

  li t2, 0x5e538593a447b6f0
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v28, v8, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v14, v26, 16, v0.t

  li t2, 0x38c34173838f7798
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v2, v22, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v26, v6, 1, v0.t

  li t2, 0x83172dfe2ffc9e46
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v12, v22, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v14, v26, 19, v0.t

  li t2, 0x8627c155c50c6001
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v16, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v24, v20, 11, v0.t

  li t2, 0x5a3f692351565dd8
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v10, v18, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v28, v26, 26, v0.t

  li t2, 0x1a85a5c25ce11b38
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v4, v10, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v4, v6, 3, v0.t

  li t2, 0xc16ac37b0f4127dd
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v28, v4, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v22, v16, 17, v0.t

  li t2, 0x8103de1fa994486b
  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vx v14, v12, t2, v0.t

  vsetvli t1, t0, e64, m2, ta, ma
  vslideup.vi v6, v12, 0, v0.t

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
