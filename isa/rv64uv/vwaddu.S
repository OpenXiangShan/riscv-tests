#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x93c6239b9041b8b4
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x0a6f516b3fe55927
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xe35bcd8c1a7e86ab
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x70a4903df9fe6824
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x744648d15c2e2a83
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xa1d640d9259443d0
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x673c0e70992f0785
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x6320ed9ab4d130d6
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x5c64defb6bf6a1ce
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xae994c1e19f6c611
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xa782ac6b5c4fdbbc
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xe859a2da123e83a3
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x25bb28aa557a4115
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x2994f4d46bcad8c9
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xdc501f23f482daa0
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x37b725a81d9e9d7c
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xc3b59d8cefb04710
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xe9010b8fbf9240d6
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x46da464c9e641617
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xcb91887c2a4670e4
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x80143c544d850e24
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x06e25fb9a32dda35
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xa1cb7d5258c79bc7
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x7b95ad979c42030d
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x1eedd465b9a4103c
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x826e9d2a76d7b672
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xc7deab3ff0642bf8
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x22b64e323c187502
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x37283ea4275c6525
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x0974ebd7bceb2655
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x21992162d7e5ce4e
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xee2afb5dff812b18
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xc6a74f99a81235c6
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9b9c753117c018cd
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x305ea1d6f03368b7
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x7836bde2135706d4
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xbb35d7440c4c7f35
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xd59ee0acffdd712f
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x04c3b85ac5e9eedb
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xee396607ea38314a
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x74d804c6b2d47915
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x7151a3106963bef9
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xb0d21123b30cd342
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x5ba94bfc4bc9a30b
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xf8c1fba812db49ac
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x5b0841c208b875a8
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xb10c9794e686a143
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xca285813f7d724d7
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xb6024da1c6863519
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x6dab00e6da5c9362
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x6b741c9f24f51f19
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xdb40ffa16fdfd470
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x60efd4ab777b7bad
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xc4b395cfa658f5b7
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x972e1cd46a3cff78
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x316e4d6903c3b810
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x55ddba907c1d4f3d
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x748832a5d1aedc88
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xf29ca1cb615be404
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x0d7581fbd75f1d67
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xdb8a54ecb7613f89
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xbb7feb5b07254ee1
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xfe47ec15670e99de
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xed94df75c51432bc
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x8ecc0dd81eb34566
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xda3e306e2062bb96
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x8d0916d4c58f89ad
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x8a7b25435878a7cc
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x1db53a125ec75bb0
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x2b63e8945251cc1b
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xb16219f93921e24d
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9a01b6a05b54fc8f
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9731c6ede54fea16
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xb506534b0a000efc
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x5d126f0619b3b914
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x2495de632adcea15
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x507c2ed953f98474
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xa43f613050e9acc2
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x27f6ec36b501463c
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x5968d0dc94bfaaba
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xcff268ec8abec8c4
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9c519c48862ada82
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x4b009a8c1449e0e4
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xee4cc69b1aa1dcb8
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x188c48325cf3fa3b
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9656549a5ccb46bd
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xa56eb6e5b3687d34
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x57832344127299a8
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x5a06e0b77285e354
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xb0680cac73fd3e93
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9e9b5d5ba53da3ff
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x98aeb5a2405ae252
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x95f652d5118380d7
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x2cc778fe53bc14f9
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x3babae746676644a
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xf362f907b4c24966
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x71227ba5816f92bf
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xd8293fb6e6984e4e
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xc5b4b136f64cf55d
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x48134ae9ddc181d6
  vsetvli t1, t0, e8, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x46b64fd90d96a08c
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x11e86c314cd689c9
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x7382f5d0458e917d
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xca01b9af90a210c0
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x669f815c3f546e6d
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xaf9989bb8da8a813
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x4638db50fcbbde4e
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x506a7783f960df99
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xcba71d5fb9c20fd1
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x299a57b315a59021
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x0322f92f60d7273e
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x17f6e4ec419a8f19
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x6752ef60c1751981
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x866e5b76b261a21c
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x70ac68a72419bdba
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xb1da0cf9a5c01be0
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x71c640c116a9548e
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x9c36681c15a13dc5
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x1ba3cb3f7db022e3
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xddaf8d965c222bbc
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x6f4fd625e3820992
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x730a86984a672283
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x660e5575ed6bb3ae
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xfd8ad06699c94e70
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x042726c7bbfc1260
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x8f7cbda2f12e48dc
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x0d4cd9dc26c0612b
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xd2e298b178731385
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xb808e05ef438a76f
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x44989a46916250d9
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xd1df2ce269c8f7e5
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x9afb4c3af3244408
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x18e2e407d5dada86
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x181ef4acf4e07036
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x3e90cd09e92ec93c
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xe573437a53a67fbc
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x927310597674ee53
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x9ca98585c0223d46
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xd19bda7b27f6d3c1
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xa847dab0c5e8e229
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xb5502830140c87a9
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x2c00eeec17f2c8dc
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x7ddd62c921fe35ed
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xcfcbf73c40992efa
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xd928d5d9eda9f9c1
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x4bf28b9363b8531b
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x3d5e674092548961
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xa736da4eda152f9d
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xb7dbb126f1d97a2d
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x12a1facfdd3b38b2
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x81555e743ea04216
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x2a19b596eed92463
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x0fff816be840729f
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xfc1a83337c746563
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x13eb92fbd023a503
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xf902fa2972e10637
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xe99ba29389714f03
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xd02a191fafafa908
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x40196f51c3a5cce6
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xe6feeb007b221ba6
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x516c7bce4a0446fc
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x8dbfb3c9e7646817
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xb03d9045ccd1c93b
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x40f6b9194362d953
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x338ece137f8eebda
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x7c76eef2aea6763e
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xdbebf5d75c758fc3
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xc79a4d4398d5fcd9
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x6a868cf56b2f409a
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x2453b0ec0cae648e
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x6fae082fa5c5e45a
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xf9ac30a25c92c38e
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x3ec25edce0c4866f
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x80562a874222bf2b
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xa374c369ba58850f
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x9ceec330c3fa4df0
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x2433db613f5f4fdf
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xfd330bc9016cae13
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xb3770d1d125d46e3
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x74d75a0ef08df919
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xc62e7aeec8b42714
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x8baa8a5818cd5fc3
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x898542985ac6eaf4
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x2bd62adb919aab4b
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x35044362349e11da
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x3b7ee61b3b2ac467
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xb86053fc1dd30042
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x462e48aaa78938ec
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xc2c2c0e5a0e02b3f
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x1de4fc82a3006c82
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x48c60b0a2f2a0f6a
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xfdaf8ca0bd060c57
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xb3dde3c8e2baac92
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xdc09811c16eb0b22
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x74898c1182a13a0d
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xa762aae2c2c3eaf0
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xd98b19833c04c446
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x3e0766a12d5bb234
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x99c388a31285beb0
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x17fa72e520736ae3
  vsetvli t1, t0, e8, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x47b5e78b3306cd9f
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x89ccc25b178b52a1
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x5da71a3ce7e2217c
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x291a4195278646fb
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x5f18925c8490dab2
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x0532805c3502a43b
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x5b1e693746da1a14
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x56326e8d63afb351
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xdd0853c5ffba2b5c
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x49ca77709e68770d
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe9d9a8a06c233d31
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x5e8fa84560510d82
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xba9943500b165ec0
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x4434374d0e6b16cf
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x5d4ac964cca2c0d7
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x79640dc356f51309
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd2e84bc7264e52b8
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x53945b028db47e9a
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x5ecae4b93a8418d6
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x5479b45841204e5c
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x7017fd6c5b6a42fe
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xcea7f8b5ff4d5178
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x8bb2797a6170adc1
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd12e86703e6ffe63
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe0aa5e5cb23175d7
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x6dacc4025cedf88c
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xc6b0950deec1485f
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xf30a5294755b8c1e
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x66f5e012e84802ca
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xaa57500a3113ce5f
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe0b3ef359aebadf1
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x5d54ad6de1776ca7
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x16b529bf181bb540
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x1af3aaa4fea1255c
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe01483ecb4f58f8e
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x13de3c2e93758206
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xac7e46483ee19295
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xf737fa97ff63d3e8
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xdde0a4d16a2f0ccb
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x339145664c4ed5a2
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x709d4b3356cc101e
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x767a5191e7201915
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xab3686da95e95c79
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x34a56eb7fbb7e307
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x047e416bda702676
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x6e5c4cb61e978d36
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x1ab019ece303e37d
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xdb7f34c123115fa9
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xbdb74e8f9b8cce72
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x415181b87e15f27d
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x3e147dd8c355e038
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x1cf42092a3ca137d
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x532b78709ccfbbc3
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x01ffe0ddee1f772c
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xf81650b43451c343
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x6ea0ed01c70fe18a
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x550630192f38eb43
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x7adac99de1560656
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x8f24b23cadd4b0cc
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x26b43e42723b9fb2
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x1a33ab7032c5a6ef
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xc88669aaa93b3eae
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x470f07d1ac3ad807
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x53d57be765da7e55
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xba1f440bca5b8afa
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x53041dbf7961de68
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x9f040ffcab48b0e3
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x12b4a202eeccfb2d
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x321002fba7549ed0
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xf9924b8261faf274
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x1a5e3f434332c644
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x51cab0b39a50081d
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x4af43dcc62a9193c
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xc8b8017c6d7b9be3
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x2fb8c4a82d8f3e15
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd460c99e7467aa52
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xf1c5544bd1a48c7b
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xae9260b5db6d7b89
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x2fcf8999f7c5df8c
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe246f5a3eec65df6
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x2a12df44a1383630
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x63bdc35a256a3e50
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x4008354fc30b08a4
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x23df4844e2d354c1
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x7a2c105205c591d4
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x0846fce3d0ffb978
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd7a8f269da9c9429
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x3abda24f992c6c79
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x2b29b76d9155e0b1
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd5e4e6ae791d69fe
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xf461f9717b8029c3
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x411f2d47d52088c6
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x5632e714cd2beafd
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe0511af5672ad3c0
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x791bd8de4ddad9ae
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x5b5964d539757cc0
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x145655f0771ca1b8
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x17cc35d6561edebd
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xabc3f81efaaf5e68
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x0573bfc4dc3a782b
  vsetvli t1, t0, e8, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9d7b62f61cbfb246
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x3a3db19b05b7fea7
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x0ba315d87469f6e1
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x740eae86a361b449
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x64d471a3382a0e19
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x0fa37c402dc77983
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x2ccbe36d239bc7b1
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x7154399b6041dd4e
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x6e70296b29f3e831
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x34f6e6dfeda081eb
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xca40dc2dbe50d1be
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xdaea5dd591bb4aad
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x130941d8d55ebdcd
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xad24383258f08b52
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x39518f33c8a8dc5b
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x70ab65eac938536c
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xaacaaff4186ece99
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x75276656a34c8efa
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xe6d6d11d2196b50a
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x5851665a64fca5dd
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xfe1e9e4e42b5dff7
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xeea0c63e5469ce72
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x26b9d991838b0255
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xb3ca785a46bb0127
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x291afbc914c33076
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xb52515fd955302f2
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x51ed4c42821d591c
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x89c9a9ad90a8d21c
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9658983c5bb673b0
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x3a27be79d82c4847
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9d98af8d2f63773a
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xa166604127cee4d0
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xea225be892d1f4af
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x7daca9be4690fc90
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x5263c8270c10e060
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xfe6961ce2d450d37
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x77c8ec03afeebd56
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x5a87df1465137610
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x179003c9ebbcc499
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xfa2736f5cf8edf5c
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xa693f151ae45385d
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x29e70b38cc7f9410
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x1fdfb4df27b1c402
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x6af47898088efc28
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x945dcc30b7727ec8
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xd4606d7c905f74e7
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x393a9de7b1969e0b
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x2f865b5f3b9a4a01
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x058ed5f357bf21dd
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x868bd2af591651be
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x5f4fe5148f9a04e1
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xe287d0d8ee235093
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xa60635a50ea0e4c0
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x918267bc78a9a947
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xf6bc8f899de8012a
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x3c0af19d265d19f8
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x388cbb5be2bd7a7e
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x2c930355a8194d75
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x0766c78302c512c1
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xef734537c5501440
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xe987ca1debd93d82
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x6cb119517b9c7b0b
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xe301a9e2f2160e49
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x48760c506aa4bf74
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xfccf93059962500c
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9b5570e206683fc8
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xd7a7b8465a1b7e0e
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xce5b923559f3ed00
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x51b523f27c8461d9
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x04ba5789b9060fbd
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x42a5a5dac85f579b
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x3a3a7d972cb4ae5a
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x04ddfc696f013d74
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x609e5fa23aa42ef4
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x832f16aa3cd920b4
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x6a133e2ee1a5f32e
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x44b53ae3892b638a
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x02f55e4cb04ce3a6
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xd7b1098175b4a395
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x443b1adcde57c336
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xa9485435173d468a
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x4905c069239502a9
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xe8634661515fdf0e
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x807dbd3e594c7ba5
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x5374f02d46244f55
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x4ee8193c848ab46c
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x4bcdbbe2cd55ab14
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9ba86b2b0b327cfe
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xf3d247b055087473
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xfdf9098728143e0d
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x743a8396e20e0179
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x656dd9481f865c2d
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9b17a0a09baeb660
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x977497b9d1e2b4e0
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x0f84b788d6d02a3a
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xea390bc4442120a9
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x7db46375be53200c
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xcdfa7612ccbaad11
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x12582aeef17f3570
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x56fbee4fb9f3774b
  vsetvli t1, t0, e16, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x1cb33bb254438790
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xbfd2c4f582f3b575
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xf079a45deb0729bb
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x499c00bd4a4e3ac5
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xe490a18e767776fd
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x013297db08356b2f
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xd174c8d3e6f2ba2b
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xe0348283efe5884c
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x1958770797d234cb
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x6c94b4a899f4140e
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xc6c39e14f70a80e7
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xff143e5fab26d47d
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x9abc88c6749fa503
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5ee99f10758b3fdf
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xa9a5f4c52378a0ba
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x803f6e54eeab107f
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x9497a7592c4bf07b
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x7c145438dbe437a7
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x8b25a3e327e205a9
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xfb5be61c6cf56e90
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x8d8aa95236991f1f
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xea66f25bae7402b7
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x4cac67b1c1de399f
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5f836e4f72e2fff1
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x960a2fcff2eb58f1
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x4921442b204890e2
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5a6e37925bb37f75
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x36a0b64cf645a86f
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x8c6f734770887987
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xfcd76a0ed3efa6ee
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xa63dd7cdcb3ac53f
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x7b9a589478226673
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5190b9cc3d089187
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x64dc773ef3fcfe53
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xcbc6409d0a4221e7
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xf1b453d7b64ff488
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xafef7797f2cad215
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x8a2b02dcb19ec4c7
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x7577f56d06a4679e
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x17db68dbfb616272
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x1beff7edee184265
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x45d0a9e8ab03fa43
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x82b8f212f8066357
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xdfe2b5b88e4dd1e7
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x12e36cac36432364
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x07c67833bb417f2f
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xacc01f275de2e200
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x44b934f600706c72
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x05af807c8de4538d
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xfd6c0bd9610a1e88
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x9ea95197f1ef005b
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x9c2eba7850dbf3b1
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xd027ac608a973812
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x04e483ae72c44cc9
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xe901163403762f59
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x8189e82bcd2280c1
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xde24964ecd5af804
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xd86522263889de4e
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x62f22650ee64718a
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x00fe608c38ed5061
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x587e5e52aacf716f
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5d9641f2274aec50
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x7b3e80bf84ca43ec
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x108935bceb8cc913
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x1f582e3fdd5ee9eb
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xf34ce16b9f29882b
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x6b45f1e5855f5074
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xa9abfb5aabd55025
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5947bb4930109db4
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x6bb58bbc873cb5b0
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xf8442cba47ec4605
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x201f853a23ef195f
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xa76fff27761238bb
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5edda2fa22a2124f
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5023e83ef6615906
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5425d688540969df
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5ad3baf375e64146
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xfd56d2f71f9d550a
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x24fe2ea8c5de7223
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xe8d10aaaeb4ba522
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x216d1ccfbc6ec911
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xbf131a242d7591d5
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xcd6d627ad2c37f16
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xa7fe1ba89daf047a
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xb747107a3e0d7a9d
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xcb046d9caa70157f
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xa3cd3cb63bf0f971
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xc72e6dd70fb0eab9
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5241e64631e345bf
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x6da4e1fef6de4bec
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xac6fde4aa57f0281
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x4969248b5cf012ea
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x346a45d4fd9f253f
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xf9ffa56caf9ec1a9
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x95db543e04c7cb26
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xede712d9462b6a72
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x81c2bc6fd614ce60
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x290e3540821511a0
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xd768a7d3c2e463b8
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x9557385cb8da85a5
  vsetvli t1, t0, e16, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xc773295b3e0c2464
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x8545ae3c2c5f6bb3
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x18a934812354535c
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x4dbe5bf36d181e63
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xa334de0f4de1724e
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xeeabe26222807b8b
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe38a1d58c16cef78
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x6ff4eb7bae5f125a
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x4dd579fdaa5f1f27
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x5bf1936695b00284
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x4137904ba08a4c98
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x3b15d8490f8ba464
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xb6b66867a48f504e
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xbbca75608d7b8e12
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x34323766d70240c2
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x8e83f0f57aece666
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe403242c72e68706
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x95bc044188599d88
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xada4ff88d780b1fc
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xfa46d4a8f14825c1
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x202399b38671ab21
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x925aa2b949866a24
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xffe136a69e51cf0f
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x98b33bfaf476b0bb
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x577c70ccd4cc7265
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xde7dcc62c25e87ab
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x77da327b457878e7
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x39898548bb9d2cac
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x80cb554034721dbf
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x7c9bea81e1d82046
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x57ce5f7ef03adbdc
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe458224d6cb27809
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x92c3faa959139c76
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xb523c22fca31f0fa
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x09433ff68be1597f
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xb732d803a5c0fc4d
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe337e95d5ff1130a
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd7c86adb65674a46
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xc1793de11aba0218
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x8a422a34b92d17c7
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xee76ac39208e96be
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xa0305dd5d9652b96
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd8ae81514855d0e6
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xc8944122fbef2d89
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x74309289969e3d3d
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x826ae359b66c0702
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x32f555c1e2437b34
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x9206d0b9ec19279c
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x99014f24bb1a358b
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xddcd05662d71e9f6
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x58bf5f30cf4d407f
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x6b91a50379243e58
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x45e137d18593b4c6
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x1e3b84f640c7f15e
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x2fd45463b351cb2a
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xb3fec29117a3f3e5
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x47707d68209160c5
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x4bd831b81013bb3b
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x5aa1739ab960a2db
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd51252f29b1547eb
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x535e73f39daadce1
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x324a6240e47e0bad
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe01f81d60aeacf82
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x89f5a92d12cadcbb
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x5c413190c1021ad7
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x2ecdb4bf3ba16ce0
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xbd9740461622e82c
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x91469dec286b8470
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x25abec054b9de6a8
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x55b1be865a7571cf
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x0f88cb62f35b9da0
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xfa8d873eb647a1f8
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xce2841d201a87e0f
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x2a5ca33ba018fb01
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xa88536ee2f22983c
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x09735a6832c98851
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xdad2a6d4f16e5246
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x6d54ee2e010b095c
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x8dab3009fc1f6eaa
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe1b09ce954b851aa
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xb877eceb29b483bc
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x766b07184a5f1095
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x85a7bd742760d871
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xbd64156a6761dc8c
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x8de52e2e588fef55
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x3a8c10bd1947ccb3
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x051fd9cf6a2fd37c
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x441f367365f50e54
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x4ef552f44c8f734a
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xc0e38b47117e3b6e
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd8a7862184e3efde
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xf9447b67483b2b17
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x56d69a92829da192
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x5139978ea7eb8fcd
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x01252ebdc7284651
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xb5c4ef93980a8697
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x69ab0876e01678da
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xc549ce726f4b24e1
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xcbbeb6b3f66cd584
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x6adb07636c8381a2
  vsetvli t1, t0, e16, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xc99b9664488ed0dc
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x602abe62ffedd963
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x33c6f7d1984fb997
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xc8cf09da33b4035a
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x7c37855b0040cf93
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xdd0a3e7434481190
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x1421b2d4ec930a05
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xcfba5838b6d8121f
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xc813646fdd377460
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x6897a943d6e702d6
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x3e73932216995263
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x05147a9b51098753
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x8e6d69e55f2a251f
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x8880115c23acf2f0
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xc94dbf27e78086e6
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x41c8b5a931b27d32
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xca5880c62562a9e8
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xdd72cf725fc8b5ad
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xc78ed00c2ecf88f9
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x7b3af1f70fcd1446
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xfed52bae27b3a796
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xa4d01beb6f6c3f41
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xade8838f590293c4
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x3b9b8e48bcb23b4a
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xed7d2729a2e9c470
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xb06f619df247b9f8
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x04b6032266da60b6
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xe6331ea771aa8876
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xab57a9a6a2b8c1df
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x51e73502873c162e
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x4dee6cb52092cd40
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x5bb2ec3474b086ba
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x8d2922be9187d365
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x6b243b3d2396867e
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9be2ab047e1e48a5
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x589512741f336ad2
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x711389a16a1b13c6
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xff427f92807a1ce6
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x2f4aed50d42c3a0c
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x0699806c93dd81fc
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xce0256137040639e
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x21ab79a9911e6ecd
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x43d243ad543271ce
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xde10917efab54865
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xe95360513cce9601
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xc2ac0175507ce04f
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x85164aa037061146
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x5775838eb7160120
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x8405a607fdb7c2fc
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x4262fb8721940e60
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x98af3c25983f62d6
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x3e3b515fdd8d6507
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xb8a1d4d6b0895aa6
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xa2276ecc55047eaa
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x7c4e12cc10fbf8a8
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x7a51983b0495c252
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xd8a719f4a2b745ff
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xbad4f7c67f3e8569
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x7162aa5fbe4f9dec
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x5391efff2c04550f
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x2be1087136d95bcc
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x0deea85d96bdc21e
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xd9b42686f5a94360
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x21ee68621692ca4b
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x3b68076ef192f66a
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x918493674f132f24
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x352dc46c307652cf
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x34e2fed677f51d02
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xcc04c6742a7551ec
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9798858f2167a534
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x213390576e1b6591
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xebe6be21b50fbfa8
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x53ef53a4793daa6c
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x2f73a51a88c6c470
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x4cd3d2c3b3bc605a
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x57dcd760aed06b04
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x6babb0897dc592bf
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x21442d8cad9b63ec
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xcfec5f84b783957f
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x14dd7d8d9fc997c3
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xf9412d1d9e9bd9eb
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x01474d8cf3f34acd
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x71f14b318849ebfc
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x8f63f9eb06f95dc2
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x8e599d52abe8bf7d
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x882429f7bd4a71e6
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x3b76066cde7f1fda
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x26426fd28051dfb5
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xa5b61ed393f98d7b
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xaaaa7c767a7eda08
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9cbc71ce95096dc9
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xdcc273290fb0bf51
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x74a8a0454e6823ce
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0xf88399dc13ee23d3
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x5dfe68c7bc31ff9b
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x13fb369f97735dd9
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x55d809c081072556
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x096811550bd1b31b
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x9dcb227f0a7cce4d
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vv v2, v4, v6

  li t2, 0x6e53f797b7f55d39
  vsetvli t1, t0, e32, m1, ta, ma
  vwaddu.vx v2, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x333a8e51df09de5b
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xb628ddc6ef7eb494
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xf57cd920db32bfd3
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xe338f1799f90e1e5
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x64e1fb53707e2c1b
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xea6e3d20102ce2e6
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x23d751493a12cee3
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x699de92b281f35c5
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x1110cab18a4d6e3f
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xbd4c7d09d2844a21
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x27617f9210e2a80a
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xe7dfb2382dde08a8
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xcbcebeee64a25ae8
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xe38136c4fd9891a7
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x59c4e64c40eb8ce5
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x6a1fe1426a6e34c4
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xa6886ab3bd7f63ba
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5ad8ef04abcc78af
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x803e92a2415fad77
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xf617f8e11866ae63
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x4d7a0627ccdb952b
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x3738f8fda13b1c86
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x0017b3e7938c3069
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x81614b6907b153b6
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x6dd95676d95fee57
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x1f678e5f3fa1d96f
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xe0a1f0df348b666a
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xae555b765dbe90d0
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x1355b14e69b5373c
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x6e75aaca4c072712
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xa1c2884d3fb455bb
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x594e9d60840ba9e2
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x3c4ed949e964afcc
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xea5656a83cf50173
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x9fcff888e3952991
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x7362a99811a26f8a
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x4459f43474eba747
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xfa745bc430253a4b
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xa6dc172e694ec7a6
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xbdbfbf24bc4aec3f
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x28103561a9d3c2e4
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x7a2ac15a81413ecf
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x740e36c2f7dcfd9f
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x30b71794ad73b4a4
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x3ccfd4e9c3821791
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xc394de84335675b2
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x7e8809f11afdd8d3
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x325fe4476d065b20
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x6f5bdfbca41ab459
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xcea36c5af0f0267a
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x99f4d15f400c24c8
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5fff29937e1d77ad
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x88dc794e2856ae8d
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xdb8efd732b5425a6
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x8da86f3225bf56e9
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x81b615751e73e0eb
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xe50150bbcb8c67ca
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x230c5b32e45d25d5
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x4625987c6dd711c8
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x247dc51fa1e55f60
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x3cc547af2e4580c5
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xdb64caf2e9fdcdf3
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xea7e145766ddea56
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x7a01635180cc1a72
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x14eb2ea1cae6f470
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x84df742eec900df7
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x03fc97b4a13e0a77
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xea19e13af44daa23
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xc020c192775603ae
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x1303d504ac8ec496
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x17ea3ce342a477ed
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x025f1729015e6d3e
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x07017b8e7a141622
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xfd8ab48aa439b4b8
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x6ba4ffd20ad2e4f5
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xdb0fde9faa56dbef
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xbdde361fe23f330f
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x9789080d02e76811
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x66011ee2d6ad0074
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x6405e4260cd4291e
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x06322784c627d088
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x80036c72ab3139e1
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5b5cf1749bb5bfa4
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x83cc415df82972fe
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5341ab9d497912d9
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xff7f2d5eb29f510a
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xd243c370c2e70c13
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5d3536feeec5e195
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xda304768c629bfae
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xb4a43c27892bafb7
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x02a216e7279c4082
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x6ee225f5fc346890
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x7e8beb082efcfa62
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0xdd919b8ed9d86b9e
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x9a88812cbd1d7ef3
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x0a25b6bfb0fd8311
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x5fb98c0a850a6a27
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x4f2dd37c3bf96c67
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x59ecf26089c1aa67
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vv v4, v8, v12

  li t2, 0x225bbbc5a07b9f26
  vsetvli t1, t0, e32, m2, ta, ma
  vwaddu.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x408de338ba9d94ee
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xbba8007ef89d81ff
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xbb8dd0ce553f5415
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x0a5dcfeafeb625fa
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xc7312a685a7bbd95
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xf498b39d2f1c5f15
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x9f8d3f357a42eb34
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd01c1ac2781faf0d
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x6d64bb82d5e864aa
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x68f6ac6047a7377b
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x4314037c0c276562
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x1f63ceba1cf7c4f5
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x88fffad5b8e02cd0
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x66d63311030ae789
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe801a84d72036df8
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xb657e6fadde9bedd
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe05226cd8151638a
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x84828ca366dff96a
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x4825d77c0ff501fa
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x94ce820c97b492e5
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x9175af02e7d97ed6
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x992876cf9fb33d56
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xfb19f8d4450d62ec
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x516570b5684d1752
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xb5dc76e6b62e1418
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x7e029b035f058387
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x31f26881f52334b6
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd87ef0d77f93d0d9
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xa50966abb232181b
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd40fe48dcb7811e6
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xc123afef2e183e49
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x766ffe243c8311dd
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xba00152776e42773
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd051745eb8a3b0ef
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe955414f1d4de055
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xfb6589e786cf28bb
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x4b741419eaef18af
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x6df9f40f9d899e18
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xfb085019a9a76571
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x05e7a71c1b048086
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xcad9420cc60ad938
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x846db87ddb3bf334
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xc65ee8f86f4a1618
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xf61656a6a3aad056
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x98630d250180678d
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd93598b380659dbc
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x3a03b44ab0242389
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xcbd23e643f279878
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xac061b54aeecbcfc
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x9f8f6de49a91adc2
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd959e977589e3230
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x638e29ac7c6cb3dd
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd5798dc0c128188e
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xbc33e1692d7188fa
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x1852d94fb3c5ae91
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xcc8efa2875185108
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x7b9a6a358259e888
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x7e29bc50d7af54e1
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xcb11cb9a91f444f6
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x12881afc461aecf7
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xb1b5b4f6c6c9c047
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x37e80fef593ac607
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x204b3b20a7b7ffe8
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xea65aa60249e21cb
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xecd0d1953ea72178
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xf5dc567e60a61c10
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xf3e43d6dd6c17678
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x334461bd21f73d43
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x9fad4617d6f64e82
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x7cd0c91feb30ffd5
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x70c68a01d8752ca7
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x666c1c2c2b16e345
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x40d6a810d56ab5d5
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd5a880fb3fa618b5
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xa9cf9d7c28c2d4c8
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x49c7b71f5a412b30
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd9aedcc503e25c30
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x2b2c4156794801bd
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x0ec7e88401fc6a9f
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x98beaac4a8eccf73
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x9e3032c36f61009f
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x9476c7097401b8b9
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x50785ca5ed239fc2
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xca49f2731aa7cfd2
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x7645758646bafc37
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x03c8b93173dbb620
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xc3e46fbbd1d08c38
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x9e6b399ce4dc0e65
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x2f106ac46d4b6ec0
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xe9c55eb3585b9223
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x9285ada0d5feb42c
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x91ff16d0e212ab3e
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x430ed709cc99358d
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x4eab2822db24cc73
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x6c853907fb657aea
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xd4e6f6fc61b6879f
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x58b9e163f4e61b1c
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0x1a49f021d140bbe5
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xf377f589b9fcc642
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vv v8, v16, v24

  li t2, 0xf99235a6472e0e4c
  vsetvli t1, t0, e32, m4, ta, ma
  vwaddu.vx v8, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
