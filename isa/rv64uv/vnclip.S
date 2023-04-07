#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wv v18, v28, v26

  li t2, 0xed2d75e537a349ad
  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wx v2, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wi v6, v28, 10

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wv v30, v26, v14

  li t2, 0x42c6e62adc9f15d5
  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wx v8, v2, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wi v12, v22, 24

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wv v20, v10, v30

  li t2, 0xc127182e3393d2aa
  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wx v22, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wi v6, v18, 22

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wv v4, v30, v24

  li t2, 0x0f3f4b451af0a100
  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wx v28, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wi v4, v12, 15

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wv v22, v4, v6

  li t2, 0x9185b5f5fccf476d
  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wx v22, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wi v20, v14, 15

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wv v14, v28, v30

  li t2, 0x259b973dfb355504
  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wx v16, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wi v8, v14, 27

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wv v28, v14, v8

  li t2, 0x64106cc57a74dd48
  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wx v6, v30, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wi v14, v2, 7

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wv v26, v30, v14

  li t2, 0x3497f547a53164f2
  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wx v10, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wi v18, v8, 25

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wv v12, v18, v20

  li t2, 0x117c8c0534878390
  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wx v14, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wi v2, v16, 28

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wv v2, v6, v10

  li t2, 0x9f85fae0429ee449
  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wx v30, v24, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vnclip.wi v16, v12, 29

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wv v8, v20, v12

  li t2, 0x155c1fb50592827b
  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wx v20, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wi v16, v8, 22

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wv v28, v16, v20

  li t2, 0xc5f0c54056c021c5
  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wx v28, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wi v24, v12, 0

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wv v8, v4, v28

  li t2, 0x3b068694957d66ca
  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wx v4, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wi v20, v12, 17

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wv v16, v28, v24

  li t2, 0x39d4f0c38cc74a92
  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wx v28, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wi v20, v12, 24

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wv v20, v4, v8

  li t2, 0xb3506523b05c94b5
  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wx v16, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wi v8, v28, 0

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wv v4, v20, v28

  li t2, 0xb096d213a129ed85
  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wx v4, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wi v4, v24, 17

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wv v16, v20, v24

  li t2, 0x4275edaf8a651908
  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wx v4, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wi v8, v16, 23

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wv v16, v24, v4

  li t2, 0x5419f693875758a3
  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wx v28, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wi v20, v8, 18

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wv v16, v12, v24

  li t2, 0x4125881f72a57372
  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wx v20, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wi v24, v20, 2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wv v8, v20, v24

  li t2, 0x3587e1735956e13c
  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wx v28, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vnclip.wi v20, v8, 5

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wv v16, v8, v24

  li t2, 0xb1351f50a131f1ce
  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wi v16, v24, 4

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wv v24, v8, v16

  li t2, 0x16d0709c1994b8a1
  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wi v8, v16, 5

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wv v16, v8, v24

  li t2, 0x42fd0bb4c2d6948a
  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wx v16, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wi v8, v16, 21

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wv v16, v8, v24

  li t2, 0x40bb95372823bae6
  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wi v8, v16, 18

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wv v8, v16, v24

  li t2, 0x8aec96353d5c1f56
  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wi v16, v24, 28

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wv v16, v8, v24

  li t2, 0x1f17404316a4266c
  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wi v16, v24, 4

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wv v8, v24, v16

  li t2, 0xb9e99a9c5eadab7f
  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wx v24, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wi v8, v24, 8

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wv v24, v16, v8

  li t2, 0xd1494a636e6a7908
  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wi v16, v24, 12

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wv v8, v24, v16

  li t2, 0xe0464e33b532cad1
  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wi v24, v16, 17

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wv v16, v8, v24

  li t2, 0x1c9a505734fa64a9
  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wx v24, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vnclip.wi v16, v8, 19

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wv v4, v30, v26

  li t2, 0x493bcf512addfedd
  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wx v6, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wi v10, v22, 12

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wv v24, v4, v14

  li t2, 0x37706b8b4947a3ad
  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wx v18, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wi v22, v26, 3

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wv v8, v4, v30

  li t2, 0x18a7a7502855e9a6
  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wx v8, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wi v20, v28, 9

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wv v2, v26, v24

  li t2, 0xe431cbee60d0d41c
  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wx v26, v30, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wi v26, v18, 23

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wv v30, v10, v24

  li t2, 0xc8a4770d093712c3
  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wx v6, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wi v26, v8, 12

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wv v22, v8, v30

  li t2, 0x4eb456c5a64e92a7
  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wx v10, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wi v26, v6, 1

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wv v12, v6, v30

  li t2, 0x992253f7f1450e36
  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wx v10, v14, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wi v16, v14, 18

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wv v28, v30, v16

  li t2, 0xc55b607770eafafc
  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wx v10, v18, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wi v6, v18, 9

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wv v6, v22, v14

  li t2, 0xc74c9b5d430690d1
  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wx v20, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wi v28, v26, 20

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wv v22, v6, v12

  li t2, 0x9a930b45ba7c4317
  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wx v22, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vnclip.wi v12, v4, 29

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wv v16, v8, v24

  li t2, 0xe65a295b94a2a02d
  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wx v24, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wi v28, v4, 2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wv v12, v8, v4

  li t2, 0xe96cab2538fdd061
  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wx v4, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wi v8, v20, 24

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wv v16, v20, v12

  li t2, 0x54f8b99199b4feaa
  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wx v28, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wi v28, v16, 26

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wv v20, v4, v16

  li t2, 0xb52bac1de9bacf26
  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wx v8, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wi v28, v20, 20

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wv v8, v24, v16

  li t2, 0x5b20a8b4c1efc5f6
  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wx v12, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wi v20, v4, 28

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wv v28, v20, v24

  li t2, 0xf6de77aad96edad8
  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wx v4, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wi v8, v20, 29

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wv v28, v4, v20

  li t2, 0xa3bf22a0190f2d3d
  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wx v12, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wi v12, v20, 29

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wv v28, v24, v4

  li t2, 0xdfc3f334bd826618
  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wx v24, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wi v4, v24, 12

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wv v20, v4, v28

  li t2, 0xd7dc41ffc5876f00
  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wx v28, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wi v12, v24, 19

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wv v4, v20, v24

  li t2, 0x46b871eb2484a81e
  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wx v24, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vnclip.wi v20, v24, 21

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wv v16, v24, v8

  li t2, 0x315d23a22ea538e4
  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wx v24, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wi v16, v8, 6

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wv v8, v24, v16

  li t2, 0xee9a5a9fe8b6db3a
  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wx v24, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wi v8, v24, 4

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wv v8, v16, v24

  li t2, 0x819ee8955a0fc10a
  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wx v8, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wi v8, v16, 7

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wv v24, v8, v16

  li t2, 0x6f80625a2615dadc
  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wi v8, v16, 0

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wv v8, v16, v24

  li t2, 0xa109091f3c9c9eb6
  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wi v16, v8, 15

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wv v16, v24, v8

  li t2, 0x091d8d99d1d7b4b1
  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wx v24, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wi v24, v8, 27

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wv v8, v16, v24

  li t2, 0xf083ccbf716260d9
  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wx v24, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wi v16, v24, 11

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wv v16, v8, v24

  li t2, 0x622190fdfef3e394
  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wi v16, v8, 28

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wv v8, v16, v24

  li t2, 0x74bffe3e30544407
  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wi v16, v24, 1

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wv v8, v16, v24

  li t2, 0xb05efc07ac04b244
  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vnclip.wi v24, v16, 15

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wv v24, v20, v8

  li t2, 0x8e204105e117febe
  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wx v4, v28, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wi v16, v22, 14

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wv v26, v18, v8

  li t2, 0xdd509e945f07d3b3
  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wx v16, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wi v8, v6, 8

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wv v24, v22, v8

  li t2, 0xbbbb511fc8b7a559
  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wx v26, v28, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wi v10, v28, 18

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wv v28, v18, v16

  li t2, 0xfedb79f9671c95c0
  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wx v6, v2, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wi v22, v16, 8

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wv v30, v4, v8

  li t2, 0x067d7184fc31505e
  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wx v24, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wi v16, v26, 2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wv v18, v2, v16

  li t2, 0x9cee94f9a9b6aba5
  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wx v12, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wi v28, v18, 26

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wv v14, v26, v2

  li t2, 0x6dbc1cfa4ec82691
  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wx v2, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wi v8, v30, 31

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wv v12, v30, v24

  li t2, 0xcd11a3398d59b0b8
  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wx v10, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wi v26, v28, 0

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wv v12, v22, v2

  li t2, 0x87b63135cb679401
  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wx v2, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wi v10, v24, 13

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wv v26, v6, v14

  li t2, 0x0c2bca7119105709
  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wx v8, v26, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vnclip.wi v20, v12, 5

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wv v8, v28, v4

  li t2, 0xd59f7fa8f5736c70
  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wx v8, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wi v20, v28, 22

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wv v12, v28, v20

  li t2, 0xecdc9bdc84c79a88
  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wx v28, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wi v16, v4, 23

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wv v24, v12, v20

  li t2, 0x11b20549137ce7c2
  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wx v24, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wi v12, v4, 24

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wv v8, v12, v28

  li t2, 0xbd022dd1a2be5f82
  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wx v4, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wi v8, v12, 1

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wv v24, v8, v28

  li t2, 0x5d12d80bd7a6b6c1
  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wx v16, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wi v28, v20, 27

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wv v24, v8, v16

  li t2, 0x42330dacb11af8a8
  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wx v8, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wi v12, v28, 24

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wv v8, v16, v20

  li t2, 0x7abbbd4f915ea946
  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wx v16, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wi v8, v16, 10

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wv v24, v8, v4

  li t2, 0x16282583f65a09d5
  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wx v28, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wi v20, v24, 17

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wv v12, v4, v20

  li t2, 0xda1b1d20e754f652
  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wx v12, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wi v4, v12, 29

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wv v16, v12, v24

  li t2, 0x65e3ad603fe91bb2
  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wx v4, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vnclip.wi v28, v8, 19

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wv v16, v24, v8

  li t2, 0x49e6ff989ef08eee
  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wi v24, v8, 4

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wv v16, v24, v8

  li t2, 0x6c24e937ff5db340
  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wi v8, v16, 18

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wv v16, v8, v24

  li t2, 0x04bee35fbabe2478
  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wi v24, v8, 30

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wv v16, v24, v8

  li t2, 0x4c3ee8c3f8c1de4d
  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wi v8, v16, 26

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wv v8, v16, v24

  li t2, 0x24c32884c0ded0e3
  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wx v16, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wi v8, v16, 27

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wv v16, v8, v24

  li t2, 0x8ac52d5cd81b7af2
  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wi v24, v8, 31

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wv v16, v8, v24

  li t2, 0x340a329fe367a0c4
  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wi v24, v8, 12

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wv v16, v24, v8

  li t2, 0x50982b54ac7a2a6e
  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wx v8, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wi v16, v8, 13

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wv v8, v24, v16

  li t2, 0x56816bd6046da932
  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wi v16, v24, 22

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wv v24, v16, v8

  li t2, 0x59e2cfb7317a84f5
  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vnclip.wi v16, v24, 11

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
