#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  li t2, 0x29e6b09d27c40b05
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v12, v6, t2

  li t2, 0x97a6db77a82b1883
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v5, v10, t2

  li t2, 0xb16c28aa1eb66460
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v31, v18, t2

  li t2, 0x69dac203648612e5
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v23, v20, t2

  li t2, 0xb62351421b4ba033
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v25, v3, t2

  li t2, 0xedcfe10e08f8a3ea
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v3, v4, t2

  li t2, 0x468db0da44f6348c
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v19, v21, t2

  li t2, 0x01cd860641748dfb
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v1, v8, t2

  li t2, 0xdb8e81c5ab630c2f
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v25, v28, t2

  li t2, 0x8670a1de359f0f9f
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v13, v5, t2

  li t2, 0xd99c96edcda3e033
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v20, v22, t2

  li t2, 0xbda19f0fb701fe63
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v12, v10, t2

  li t2, 0x9d638a50d16612f6
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v26, v12, t2

  li t2, 0xe4730f6878b53d4f
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v4, v2, t2

  li t2, 0x7a053cf9160be1a0
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v24, v14, t2

  li t2, 0xe757b5ffedfb109a
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v22, v12, t2

  li t2, 0xc429b51c3583732f
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v26, v8, t2

  li t2, 0x873d980c6d04add2
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v2, v14, t2

  li t2, 0xe054c17ba7a2ae06
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v26, v16, t2

  li t2, 0x65d64e89f5e928ba
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v10, v24, t2

  li t2, 0x1a7627deca527d04
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v28, t2

  li t2, 0x9a2fbba3bfa64d2a
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v12, v8, t2

  li t2, 0x9edcb7b20b169e46
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v4, v12, t2

  li t2, 0xffcfb112409c0735
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v8, v4, t2

  li t2, 0x77192455817bdb2d
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v28, t2

  li t2, 0xe55944bf4d69a46c
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v24, t2

  li t2, 0x3a756b39ed8385c3
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v12, v20, t2

  li t2, 0x2264e75d4d087118
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v8, t2

  li t2, 0xb7844b16a58299da
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v12, v8, t2

  li t2, 0x60b43082a4d048df
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v24, t2

  li t2, 0x74cca4c3689e83d5
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  li t2, 0x240b1fbb6fa44566
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v24, t2

  li t2, 0x506749900b2454a5
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  li t2, 0x89226462c0c035ad
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  li t2, 0x411814fe0ec7e32c
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  li t2, 0xe2102397c3aa7cc6
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  li t2, 0x8f703a1c833c8320
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  li t2, 0x9727f26adf1bcbe6
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  li t2, 0x6819c443de44985a
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  li t2, 0x7dcc4ffdc682ece7
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  li t2, 0xbc55b775d4fc7bc6
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v26, v16, t2

  li t2, 0xaa2f95babebeaae0
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v13, v18, t2

  li t2, 0x82921d68341afd62
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v21, v24, t2

  li t2, 0x85741851bd5d6b06
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v18, v9, t2

  li t2, 0x95f4851c41f40873
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v18, v31, t2

  li t2, 0x2350fea022b52951
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v14, v24, t2

  li t2, 0xfd7e122bcbf27f9c
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v29, v8, t2

  li t2, 0xfa1d538219ce0914
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v9, v21, t2

  li t2, 0xe71ff7dc7272b018
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v13, v11, t2

  li t2, 0x1ac8583f0430c902
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v22, v8, t2

  li t2, 0x745855516e6f6e88
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v4, v20, t2

  li t2, 0x45382c2194164e5d
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v14, v10, t2

  li t2, 0x4b25a6281a5026a3
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v16, v18, t2

  li t2, 0xcca9b93cd383d517
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v12, v10, t2

  li t2, 0xf8137b68ca7592bd
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v22, v16, t2

  li t2, 0x724566a311ab3ca6
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v26, v20, t2

  li t2, 0x8a651004f431c4e9
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v2, v8, t2

  li t2, 0x813f74b8794ef3a7
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v20, v10, t2

  li t2, 0x59bd7a1b59a352ac
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v2, v6, t2

  li t2, 0xc9cec8850696bc5a
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v16, v30, t2

  li t2, 0x703a7416e3514d22
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v20, v8, t2

  li t2, 0xddf28aaf77178771
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v8, t2

  li t2, 0xbf7babc8bc6807f2
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v16, t2

  li t2, 0xbd77319b57c37b91
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v24, t2

  li t2, 0xd0d554973ce7ca6f
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v20, v28, t2

  li t2, 0xd9120f9c7af49ded
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v16, t2

  li t2, 0xeaabc22348892ff5
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v28, v16, t2

  li t2, 0x14e9e914f71ad13b
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v12, t2

  li t2, 0x9ae245752b1dfb10
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v8, v12, t2

  li t2, 0xd5ac27c1f599611b
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v16, t2

  li t2, 0x99c03bbac3932e41
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v8, t2

  li t2, 0xe6aba3cc910b881f
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  li t2, 0x3b6b93d132e22b11
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  li t2, 0x4d8136c0b9477c86
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  li t2, 0xe5028cf7bd18f53b
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v24, t2

  li t2, 0xba58eb7028ecac6a
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  li t2, 0xd1c915430f717f08
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  li t2, 0x38468befc5d9d16e
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  li t2, 0x445a29025046633f
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  li t2, 0x10552ed7ed290d43
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  li t2, 0x15390c8952157560
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v16, v9, t2

  li t2, 0x6ab66ded401084a4
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v8, v17, t2

  li t2, 0x2fa4536ea6bd7ff9
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v1, v3, t2

  li t2, 0xc143167622312705
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v23, v7, t2

  li t2, 0xee64ecfa4488c0b6
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v23, v19, t2

  li t2, 0xcef59bf1eeadb974
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v5, v26, t2

  li t2, 0x66b8d9d41173579a
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v22, v24, t2

  li t2, 0xdfeca7065ca8d8df
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v13, v28, t2

  li t2, 0xc63d0f4eb9a1b825
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v16, v2, t2

  li t2, 0xd9a7de1cd27e8fb5
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v15, v14, t2

  li t2, 0xa181cb0a5c9d5152
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v14, v8, t2

  li t2, 0x09db0e45d3060395
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v16, v8, t2

  li t2, 0x299786b8f3048c22
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v14, v6, t2

  li t2, 0x7ca0aa30a2d17b2a
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v24, v10, t2

  li t2, 0x57f0289a782c0ca1
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v30, v18, t2

  li t2, 0xb1f2b7a94f133a25
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v8, v10, t2

  li t2, 0xc1cb7237e73a5652
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v4, v24, t2

  li t2, 0xfea2cc204ddbb52e
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v16, v18, t2

  li t2, 0xdf60bfd3e01ee8ac
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v24, v6, t2

  li t2, 0x86f75c12b7337156
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v8, v16, t2

  li t2, 0xe9991dd85d2753d0
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v28, v8, t2

  li t2, 0xc34110e9eea45e1a
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v16, t2

  li t2, 0xd12e0fc9a503b707
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v8, t2

  li t2, 0x7d0dc50dc077d93b
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v20, v16, t2

  li t2, 0x7e00bd0effb3e7d6
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v16, t2

  li t2, 0xc66556c6ed492b0b
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v20, t2

  li t2, 0xdd68e302a735a0a2
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v4, t2

  li t2, 0x27d85e2ae1241a80
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v28, v16, t2

  li t2, 0xbec2bfbf11147d1b
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v16, v8, t2

  li t2, 0x976f239c0a3fcdff
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v20, v4, t2

  li t2, 0x05c7608d2a07158d
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  li t2, 0x2ca46ac7edc16832
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  li t2, 0x5f89753afff10b9b
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  li t2, 0x035591cc5b1519a4
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  li t2, 0x8d52e0de41a61221
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  li t2, 0x3f98b09dd45195d6
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  li t2, 0xfa2eb8809c4b5784
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  li t2, 0xaddb77da37ea46f4
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  li t2, 0xe8de710f0fe9b95d
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  li t2, 0xc93bae052bb243c1
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  li t2, 0x71c8a8fbb650728a
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v12, v26, t2

  li t2, 0x78a7157b2d994332
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v16, v6, t2

  li t2, 0x5ea1c1025500c1dd
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v27, v16, t2

  li t2, 0x77374973d995e0fc
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v20, v15, t2

  li t2, 0x55d082dfa00e14df
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v19, v15, t2

  li t2, 0x01f4b2896b8cd972
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v14, v3, t2

  li t2, 0x1a3371467b15c7f9
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v2, v14, t2

  li t2, 0xbf6d4e51acd819a3
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v30, v16, t2

  li t2, 0xde4c2db392a6604d
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v20, v15, t2

  li t2, 0x85895f14217efd58
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v12, v10, t2

  li t2, 0x506065fad782b86e
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v14, v6, t2

  li t2, 0x95ce9c51c0930788
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v22, v26, t2

  li t2, 0x6302880ab1ba031f
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v6, v4, t2

  li t2, 0x1611531c34b9ab61
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v4, v6, t2

  li t2, 0x3ac17501509ddef1
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v26, v6, t2

  li t2, 0xa27ea73a168fd3fe
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v8, v14, t2

  li t2, 0xed874cc4c5d7433e
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v30, v20, t2

  li t2, 0xb995a00a2607207d
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v12, v22, t2

  li t2, 0x001195e8f56adaff
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v2, v4, t2

  li t2, 0xf7874c20cc4edff9
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v22, v6, t2

  li t2, 0x87060adaa19f7a98
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v16, t2

  li t2, 0x283dd1eb45f3b21c
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v12, t2

  li t2, 0xb489cd98fe342bb7
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v12, t2

  li t2, 0x132e25afdda13192
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v8, v4, t2

  li t2, 0x9894db726f961c5c
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v8, v24, t2

  li t2, 0x10b3ce1301c2bb13
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v28, t2

  li t2, 0x7e3385febf9515bf
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v8, t2

  li t2, 0x1bb384fba23a0c9e
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v28, t2

  li t2, 0x77b4a4f3d41728ac
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v16, t2

  li t2, 0x46bee6c8ad4b5b19
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v16, t2

  li t2, 0xba049cd08b333d36
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  li t2, 0x0cd2f108894219ab
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  li t2, 0x73bf5292c26271de
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v24, t2

  li t2, 0x9b04174cbc04b783
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  li t2, 0xc56b485cbf8fbf3d
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  li t2, 0x95f5dd75b60ce283
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  li t2, 0x0056495c4c36b504
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v24, t2

  li t2, 0x905a082816179f50
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  li t2, 0x18f660252ec60108
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  li t2, 0x28935bf399568837
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v24, v19, -9

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v22, v15, 12

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v6, v31, 8

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v29, v11, 4

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v5, v11, 4

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v3, v19, 9

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v21, v18, 9

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v5, v4, 1

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v2, v1, 0

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v23, v27, -9

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v4, v18, 10

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v2, v8, -9

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v14, v10, 7

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v28, v6, -1

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v18, v28, 9

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v16, v18, -1

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v8, v10, -9

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v4, v28, 0

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v6, v8, -7

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v18, v6, -8

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v12, v20, -14

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v8, 2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v16, -4

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v12, v24, 14

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v4, 4

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v16, 7

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v28, -7

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v12, -4

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v12, 8

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v4, v16, -8

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v16, -5

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, 4

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v24, 14

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v24, 14

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, 4

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, -9

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, -3

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -12

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, -14

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, 8

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v14, v31, -16

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v27, v14, 14

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v23, v26, 14

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v24, v13, -6

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v24, v10, -8

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v12, v6, -4

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v1, v12, 2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v1, v25, 5

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v14, v18, 14

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v21, v1, -1

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v20, v14, -5

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v20, v18, 12

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v12, v10, -9

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v26, v20, -12

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v20, v10, -15

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v16, v24, -16

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v24, v30, 9

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v8, v18, -11

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v20, v2, 13

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v26, v28, 6

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v12, 11

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v12, 14

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v20, -8

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v28, v24, 5

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v28, -9

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v28, v16, 5

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v28, 1

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v12, v8, -8

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v20, 7

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v28, v16, -4

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, 5

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, -6

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, -10

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v8, -9

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, 1

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, -6

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, 5

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, -13

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v8, -16

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v8, 5

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v30, v24, -4

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v10, v13, 3

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v8, v30, 2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v13, v23, 11

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v21, v7, 8

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v29, v20, 13

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v25, v1, 10

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v26, v5, -7

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v16, v27, -15

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v6, v19, -10

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v26, v18, 4

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v8, v30, -2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v30, v10, -15

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v14, v10, -10

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v18, v20, 13

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v22, v4, -7

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v20, v6, -3

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v28, v6, 11

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v18, v22, 12

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v12, v4, 9

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v24, v28, 14

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v28, v24, 13

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v16, -9

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v8, 7

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v4, v20, 14

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v28, v20, -15

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v28, v12, -8

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v28, 6

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v24, 12

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v24, v4, 15

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, -12

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, 5

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, 8

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, 13

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, -3

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, 1

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, 5

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, -9

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, 3

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, -6

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v24, v23, 0

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v1, v10, -6

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v17, v11, -4

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v5, v23, 15

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v4, v8, -16

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v6, v19, -7

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v25, v16, 4

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v8, v24, -11

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v21, v9, 0

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v11, v1, -13

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v22, v14, 6

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v14, v22, -3

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v4, v14, 12

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v6, v10, -6

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v10, v12, 6

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v20, v12, -5

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v12, v6, 13

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v24, v12, 9

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v20, v4, -11

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v22, v26, -7

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v28, 3

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v8, -13

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v16, -11

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v12, -7

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v4, 4

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v24, v8, 1

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v28, v24, 3

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v20, 15

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v16, v28, 15

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v28, -4

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, 9

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, 8

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, 10

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, -16

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, 6

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, 4

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, -13

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, -1

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, -1

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, 3

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
