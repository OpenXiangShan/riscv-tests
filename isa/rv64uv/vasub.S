#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vv v7, v1, v3

  li t2, 0x3ed41304c3d9b252
  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vx v12, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vv v14, v28, v11

  li t2, 0x2b730c88b73823d0
  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vx v26, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vv v10, v14, v8

  li t2, 0xdb6def1bc4e03a47
  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vx v12, v23, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vv v11, v3, v21

  li t2, 0x67cd007858f36550
  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vx v20, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vv v28, v22, v8

  li t2, 0x6eb294efae07d812
  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vx v22, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vv v13, v14, v9

  li t2, 0x750d8d148b0d22bc
  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vx v9, v24, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vv v16, v24, v30

  li t2, 0x6627559c86c047f2
  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vx v5, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vv v1, v28, v19

  li t2, 0x9a6682ac40697381
  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vx v12, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vv v14, v31, v26

  li t2, 0x57c8f7444a35cb32
  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vx v15, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vv v2, v19, v28

  li t2, 0xf4b1379eb0e19f78
  vsetvli t1, t0, e8, m1, ta, ma
  vasub.vx v3, v31, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vv v10, v6, v22

  li t2, 0x9e5a0a18a8a65e9d
  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vx v2, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vv v8, v24, v22

  li t2, 0x0e5b99e1a7f8f7bd
  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vx v8, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vv v26, v28, v8

  li t2, 0xd17337e282c2e386
  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vx v16, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vv v24, v22, v28

  li t2, 0x6a24178146843436
  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vx v6, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vv v12, v4, v14

  li t2, 0x23d9e8d71076460e
  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vx v4, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vv v24, v14, v6

  li t2, 0xf7cb10a969def91d
  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vx v12, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vv v26, v28, v14

  li t2, 0xc4364d495c6feffb
  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vx v24, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vv v18, v14, v16

  li t2, 0x2030e27cfc5d6101
  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vx v14, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vv v12, v18, v24

  li t2, 0xff52aba2f86f5ff7
  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vx v8, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vv v6, v28, v12

  li t2, 0xfc2919bd7e278c3a
  vsetvli t1, t0, e8, m2, ta, ma
  vasub.vx v22, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vv v20, v28, v4

  li t2, 0xd4e039b17998d336
  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vx v4, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vv v4, v20, v16

  li t2, 0x5c01e4f59b7b031f
  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vx v28, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vv v28, v8, v4

  li t2, 0x55a9e02b1cf41470
  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vx v4, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vv v24, v8, v12

  li t2, 0x52fb99cb3524a2a7
  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vx v8, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vv v16, v20, v28

  li t2, 0x24d281f9000803ea
  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vx v20, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vv v16, v12, v28

  li t2, 0x968ac6021886f995
  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vx v4, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vv v20, v24, v16

  li t2, 0x25a0a548c90d60fc
  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vx v28, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vv v12, v28, v16

  li t2, 0x53261daeb7641c9e
  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vx v4, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vv v8, v28, v24

  li t2, 0xdbfb9634ef8f77c9
  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vx v4, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vv v8, v24, v12

  li t2, 0xf2f240f3583c47fc
  vsetvli t1, t0, e8, m4, ta, ma
  vasub.vx v16, v4, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vv v24, v16, v8

  li t2, 0x8e0f87371e83e7b1
  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vv v8, v16, v24

  li t2, 0x8412e607747959d4
  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vv v24, v8, v16

  li t2, 0x32b14961e312094e
  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vv v24, v16, v8

  li t2, 0x0bb0f5769688de4d
  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vv v8, v24, v16

  li t2, 0x0820f20f59a2e9f9
  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vv v16, v24, v8

  li t2, 0xf9872a2ec78078f9
  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vv v16, v24, v8

  li t2, 0xb5fd53cc8e07a5fd
  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vv v24, v8, v16

  li t2, 0x61fda04b4f2ef981
  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vv v16, v8, v24

  li t2, 0xbd68b7e1903e736a
  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vv v16, v24, v8

  li t2, 0x672f04a8af52aae2
  vsetvli t1, t0, e8, m8, ta, ma
  vasub.vx v24, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vv v22, v14, v13

  li t2, 0x2cc1c38dadb398f0
  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vx v14, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vv v11, v30, v7

  li t2, 0xfe8a0d9b0d43b550
  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vx v26, v31, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vv v18, v1, v19

  li t2, 0x265ebfc6d9b7d2b6
  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vx v3, v29, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vv v24, v29, v7

  li t2, 0xdd125344c29a7ef2
  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vx v25, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vv v16, v25, v24

  li t2, 0xd076d2b6c5a58c6b
  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vx v2, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vv v29, v19, v24

  li t2, 0xc36314abd4ac653d
  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vx v23, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vv v5, v3, v11

  li t2, 0xb7f30bb1b24433d4
  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vx v20, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vv v17, v21, v28

  li t2, 0xdcc766bf42e4a4f8
  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vx v19, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vv v1, v28, v10

  li t2, 0xf1ab00de285b8d47
  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vx v4, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vv v19, v5, v11

  li t2, 0x7e385484622deb19
  vsetvli t1, t0, e16, m1, ta, ma
  vasub.vx v29, v19, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vv v20, v2, v18

  li t2, 0x2211624ea9114d35
  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vx v10, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vv v24, v4, v8

  li t2, 0xb1b79ca3b2552e68
  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vx v26, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vv v12, v8, v30

  li t2, 0x370d02b513b1a73e
  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vx v12, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vv v22, v28, v14

  li t2, 0xbfee5e61ba362dc4
  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vx v4, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vv v16, v20, v24

  li t2, 0xe7992c4ae3833aea
  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vx v26, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vv v24, v30, v4

  li t2, 0xde2ae5c5257ccba6
  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vx v6, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vv v24, v30, v28

  li t2, 0xd62c158db36befad
  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vx v18, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vv v26, v8, v28

  li t2, 0xb243f17b20f17ade
  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vx v28, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vv v20, v6, v30

  li t2, 0xd7dae5690de0544e
  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vx v22, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vv v26, v22, v6

  li t2, 0xfbdab9d76f2686c9
  vsetvli t1, t0, e16, m2, ta, ma
  vasub.vx v22, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vv v12, v8, v28

  li t2, 0x0162e5e74826f3b4
  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vx v12, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vv v24, v8, v12

  li t2, 0xf2ea2eb24db77386
  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vx v28, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vv v20, v8, v16

  li t2, 0x98958341d3e7c50b
  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vv v12, v28, v24

  li t2, 0x99b2a41c0f478bfc
  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vv v8, v4, v12

  li t2, 0x7c2b1b7fa177b3c1
  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vx v4, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vv v28, v16, v8

  li t2, 0xa667fdaec77cf1ca
  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vx v20, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vv v28, v12, v20

  li t2, 0x80289b712d72958f
  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vx v16, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vv v28, v20, v16

  li t2, 0x91d8abbeae32d39c
  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vv v8, v16, v24

  li t2, 0xec328543e367e2cb
  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vx v16, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vv v12, v4, v16

  li t2, 0x3125750951732152
  vsetvli t1, t0, e16, m4, ta, ma
  vasub.vx v16, v12, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vv v24, v8, v16

  li t2, 0x52acf14a281484ca
  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vv v24, v16, v8

  li t2, 0xc63f391de29479b4
  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vv v24, v16, v8

  li t2, 0xad72199b91099d8b
  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vv v16, v24, v8

  li t2, 0x49cd484fd2bf6cdf
  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vv v16, v8, v24

  li t2, 0x3214acc066877c9b
  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vv v16, v24, v8

  li t2, 0xd67e7666478ac2e8
  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vv v24, v8, v16

  li t2, 0x47d9df64237a81db
  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vv v8, v16, v24

  li t2, 0xdaf954e585f6bf00
  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vv v16, v24, v8

  li t2, 0xcb86f1eda0926b71
  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vv v24, v16, v8

  li t2, 0x1b64e4cde154a8a1
  vsetvli t1, t0, e16, m8, ta, ma
  vasub.vx v24, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vv v16, v14, v26

  li t2, 0xfd5d757469ea1361
  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vx v14, v23, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vv v8, v24, v2

  li t2, 0x62eb2248aff1242e
  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vx v25, v11, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vv v6, v21, v28

  li t2, 0xcac351c4bb193f75
  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vx v31, v17, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vv v1, v10, v17

  li t2, 0x35bcbc247b09c7f3
  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vx v9, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vv v21, v2, v31

  li t2, 0xdb070a5bc2807708
  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vx v31, v11, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vv v15, v10, v18

  li t2, 0x50e967aeaa4ef983
  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vx v13, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vv v29, v10, v1

  li t2, 0xa68c0b1e5bddbfff
  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vx v13, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vv v21, v2, v29

  li t2, 0xdf8241e09bfc3868
  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vx v24, v17, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vv v22, v13, v31

  li t2, 0xa80805d50a5b31e7
  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vx v18, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vv v8, v4, v26

  li t2, 0x283b9b705262138b
  vsetvli t1, t0, e32, m1, ta, ma
  vasub.vx v24, v29, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vv v22, v24, v10

  li t2, 0xa9b53fbdaaf14260
  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vx v20, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vv v24, v20, v10

  li t2, 0x76ea1c2cb820af9d
  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vx v30, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vv v8, v28, v20

  li t2, 0x403c891432844fc9
  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vx v14, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vv v30, v16, v2

  li t2, 0x69759b930ebd5cbe
  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vx v24, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vv v22, v12, v16

  li t2, 0x1dae2a3e66804247
  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vx v8, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vv v6, v18, v10

  li t2, 0x58c73fe251975b46
  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vx v6, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vv v14, v28, v24

  li t2, 0x42c025673401a09c
  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vx v2, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vv v14, v6, v20

  li t2, 0xb2c954e851541114
  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vx v6, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vv v10, v22, v8

  li t2, 0xaf0f44c0ab215951
  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vx v6, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vv v6, v26, v8

  li t2, 0xa083cd8a4b1db676
  vsetvli t1, t0, e32, m2, ta, ma
  vasub.vx v8, v22, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vv v24, v8, v20

  li t2, 0xcfe7f837c7617d7b
  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vx v8, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vv v20, v4, v24

  li t2, 0x661f5179288ab497
  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vx v12, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vv v24, v28, v12

  li t2, 0xeacaa349587df557
  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vx v12, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vv v12, v20, v16

  li t2, 0x47c348fe87d47c05
  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vx v8, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vv v8, v24, v20

  li t2, 0xcc684bb499f72dc1
  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vx v20, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vv v28, v16, v4

  li t2, 0xcb4ac7e33a7271a6
  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vx v12, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vv v12, v24, v4

  li t2, 0xfa31733f85e8cd0b
  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vx v16, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vv v20, v16, v8

  li t2, 0xbfdd25fc2a4c78c8
  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vx v28, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vv v24, v4, v16

  li t2, 0x1365269523b77509
  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vx v24, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vv v12, v20, v24

  li t2, 0xe5fcdb62242d0b64
  vsetvli t1, t0, e32, m4, ta, ma
  vasub.vx v16, v28, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vv v24, v16, v8

  li t2, 0xa3ae1413bc7ee2f7
  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vv v16, v8, v24

  li t2, 0xbbe5ee1fdcbcf913
  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vv v8, v24, v16

  li t2, 0x91e3fa88b35b4168
  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vv v8, v24, v16

  li t2, 0x34b9379cc3fe5aae
  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vv v16, v24, v8

  li t2, 0x2e046088e59d5410
  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vv v24, v8, v16

  li t2, 0xb3f5da50d8c43226
  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vv v16, v24, v8

  li t2, 0xc5f8db80200c7769
  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vv v24, v16, v8

  li t2, 0xa02a8b0195ca968a
  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vv v8, v24, v16

  li t2, 0x99df310429092a53
  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vv v24, v8, v16

  li t2, 0xb3703c1747322015
  vsetvli t1, t0, e32, m8, ta, ma
  vasub.vx v24, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vv v2, v12, v4

  li t2, 0xc9cd0bf02fd5d45f
  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vx v8, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vv v16, v9, v7

  li t2, 0x7518a61d766124b2
  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vx v17, v13, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vv v11, v16, v4

  li t2, 0xf86a0c24118f746b
  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vx v13, v2, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vv v20, v25, v14

  li t2, 0x695e08a8bd7a5d86
  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vx v7, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vv v18, v5, v1

  li t2, 0xc27d4603bd16c9e2
  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vx v17, v26, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vv v21, v16, v13

  li t2, 0x3d2624427a8729a2
  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vx v7, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vv v18, v1, v12

  li t2, 0xcf6194b3e8acc112
  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vx v5, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vv v29, v10, v5

  li t2, 0xb70acabf4f8288a6
  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vx v27, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vv v5, v13, v29

  li t2, 0x50c1373058279894
  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vx v22, v3, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vv v8, v20, v13

  li t2, 0xc7674ff413b9ba54
  vsetvli t1, t0, e64, m1, ta, ma
  vasub.vx v2, v1, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vv v4, v12, v10

  li t2, 0xa34742be340a3c41
  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vx v8, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vv v24, v30, v8

  li t2, 0xe1fb519f64c286b3
  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vx v20, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vv v22, v8, v24

  li t2, 0xdc8ff5365a48711e
  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vx v14, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vv v8, v4, v26

  li t2, 0x75df1ff435c008de
  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vx v10, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vv v6, v20, v16

  li t2, 0xdaba222bcacac9ec
  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vx v4, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vv v6, v28, v8

  li t2, 0xcd44b834ae7c121f
  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vx v10, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vv v30, v14, v22

  li t2, 0x492540690ddd0384
  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vx v10, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vv v16, v28, v22

  li t2, 0x2de28e79c0529fac
  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vx v26, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vv v6, v10, v8

  li t2, 0xe7da8395efe6fbe2
  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vx v28, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vv v28, v10, v6

  li t2, 0xde8baf60f9055a8d
  vsetvli t1, t0, e64, m2, ta, ma
  vasub.vx v14, v2, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vv v28, v20, v8

  li t2, 0x409946af074d196a
  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vx v28, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vv v20, v28, v24

  li t2, 0x042ee4a5ca7e614f
  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vx v4, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vv v12, v28, v4

  li t2, 0x55d2fa31a4163ee7
  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vx v28, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vv v24, v4, v20

  li t2, 0x54b4fdeda2c00a00
  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vx v20, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vv v28, v4, v24

  li t2, 0x3a4be6aeaf163a14
  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vx v28, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vv v20, v8, v4

  li t2, 0xf1d8ed6922279c1b
  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vv v4, v20, v12

  li t2, 0x340ef2d31b149e7f
  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vx v20, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vv v24, v8, v16

  li t2, 0xc89102c1ce2d3948
  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vx v12, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vv v16, v28, v4

  li t2, 0x767ea608280723bf
  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vv v28, v16, v8

  li t2, 0xb2dc1c3236ab2df0
  vsetvli t1, t0, e64, m4, ta, ma
  vasub.vx v12, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vv v16, v24, v8

  li t2, 0x23be042e04f8bb06
  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vv v24, v16, v8

  li t2, 0xf853714fd70f2f68
  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vv v8, v16, v24

  li t2, 0xfccfae20549c9d8c
  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vv v24, v8, v16

  li t2, 0xbda507a398956314
  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vv v24, v16, v8

  li t2, 0xd6523e674bd3cd9c
  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vv v16, v24, v8

  li t2, 0xd018ef10a9626746
  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vv v16, v8, v24

  li t2, 0x2271857c8c24024d
  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vv v24, v16, v8

  li t2, 0x22e6ad5b1c498432
  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vv v24, v16, v8

  li t2, 0x3ad6f5e08ae9b81f
  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vv v24, v8, v16

  li t2, 0xa9402865d20873e0
  vsetvli t1, t0, e64, m8, ta, ma
  vasub.vx v24, v8, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
