#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vv v27, v24, v8

  li t2, 0x8e20638cd33c8595
  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vx v14, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vv v13, v30, v17

  li t2, 0x28a7b4ed7a1d416e
  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vx v21, v15, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vv v13, v29, v20

  li t2, 0x397b63dc26d3a87a
  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vx v24, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vv v31, v23, v1

  li t2, 0xc1dd49aadc563f14
  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vx v28, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vv v12, v25, v7

  li t2, 0xb011014605f69ed7
  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vx v16, v23, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vv v21, v8, v28

  li t2, 0x6bb663b1188105c0
  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vx v27, v24, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vv v23, v15, v11

  li t2, 0x1dd4d1366374bba9
  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vx v4, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vv v3, v25, v18

  li t2, 0x9da25e122856a583
  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vx v13, v26, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vv v18, v27, v5

  li t2, 0xb3d54d2711a127ea
  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vx v4, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vv v8, v9, v1

  li t2, 0xeaa54a08dea64bcb
  vsetvli t1, t0, e8, m1, ta, ma
  vssubu.vx v1, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vv v28, v6, v16

  li t2, 0x915d53c719288a1d
  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vx v26, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vv v24, v30, v12

  li t2, 0x3e2b29f88e71eeab
  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vx v6, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vv v4, v30, v26

  li t2, 0x57b6443d07616425
  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vx v18, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vv v4, v12, v6

  li t2, 0x37c3907eeb8c9ef3
  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vx v28, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vv v12, v28, v18

  li t2, 0xeb015fcc10cb3fa5
  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vx v30, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vv v20, v26, v12

  li t2, 0xcce0f03476175690
  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vx v8, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vv v18, v30, v24

  li t2, 0xe0a687a656ddeab2
  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vx v30, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vv v14, v22, v6

  li t2, 0xb6b5b8bafe85de86
  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vx v4, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vv v30, v2, v14

  li t2, 0x73620b603ae08270
  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vx v6, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vv v2, v12, v14

  li t2, 0x085d1006be67d0dc
  vsetvli t1, t0, e8, m2, ta, ma
  vssubu.vx v10, v22, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vv v20, v24, v28

  li t2, 0x869787ef6131ff45
  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vx v4, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vv v28, v8, v12

  li t2, 0x1fef803e0f4d96b7
  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vx v20, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vv v24, v28, v8

  li t2, 0x958459d440bba7bf
  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vx v16, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vv v16, v20, v24

  li t2, 0x8a60e430177dc72e
  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vx v24, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vv v4, v16, v12

  li t2, 0xb32a03eabfa41788
  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vv v24, v8, v28

  li t2, 0x5c7175d845ee3ff0
  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vx v12, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vv v20, v24, v28

  li t2, 0x45905ac076aa4d41
  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vx v4, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vv v20, v4, v16

  li t2, 0x3d2a48a6809c2ebf
  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vx v24, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vv v12, v24, v28

  li t2, 0x7578cfafaa4476c3
  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vx v4, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vv v20, v28, v16

  li t2, 0x5a29058402305dec
  vsetvli t1, t0, e8, m4, ta, ma
  vssubu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vv v24, v8, v16

  li t2, 0x33f807dfe488bce6
  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vv v16, v24, v8

  li t2, 0x650fee65d12426bc
  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vv v16, v8, v24

  li t2, 0x28d0db3a810797af
  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vv v8, v24, v16

  li t2, 0xf4b07bc04a76413b
  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vv v16, v8, v24

  li t2, 0x1ee10b0b9b248b44
  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vv v16, v8, v24

  li t2, 0x42407eb5321b159d
  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vv v16, v24, v8

  li t2, 0x647f78c40ec2c78f
  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vv v16, v24, v8

  li t2, 0xc673dfe186b8ebde
  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vv v24, v8, v16

  li t2, 0x987b83afe6c496b7
  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vv v16, v8, v24

  li t2, 0xcf774b1c023658f9
  vsetvli t1, t0, e8, m8, ta, ma
  vssubu.vx v24, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vv v16, v28, v25

  li t2, 0xd88b72a45eb5271e
  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vx v14, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vv v8, v18, v6

  li t2, 0x4e992a23cc828f47
  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vx v10, v7, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vv v17, v31, v27

  li t2, 0xf5fee1c078646cd1
  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vx v9, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vv v28, v4, v9

  li t2, 0xaf85acc8eb6f2c7d
  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vx v24, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vv v2, v27, v18

  li t2, 0x3363c84ef6ef5bb3
  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vx v9, v1, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vv v29, v12, v3

  li t2, 0x428e2797c407ff23
  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vx v16, v1, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vv v5, v12, v17

  li t2, 0x2e9f5eaef46ae8ab
  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vx v8, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vv v10, v23, v30

  li t2, 0x8c428541a3402368
  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vx v6, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vv v19, v21, v7

  li t2, 0xe17dd320a8f18e6c
  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vx v11, v17, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vv v23, v9, v6

  li t2, 0x2861ddb25836c28f
  vsetvli t1, t0, e16, m1, ta, ma
  vssubu.vx v22, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vv v18, v4, v16

  li t2, 0x42d8bfbbbb3f1ac5
  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vx v2, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vv v28, v14, v12

  li t2, 0xc5a05a7ccd652795
  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vx v12, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vv v20, v10, v22

  li t2, 0x221fc6f4d124fe13
  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vx v6, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vv v4, v16, v24

  li t2, 0xe7d3e8aa0c562c64
  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vx v28, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vv v16, v6, v26

  li t2, 0x01484a7561df5ce8
  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vx v22, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vv v8, v30, v6

  li t2, 0x528032aa19ed8da3
  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vx v2, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vv v8, v28, v6

  li t2, 0x6a22905fb53f76ec
  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vx v10, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vv v2, v10, v28

  li t2, 0x85dc80a330e62d41
  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vx v28, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vv v2, v28, v26

  li t2, 0x49b61a781b17d1f5
  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vx v24, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vv v16, v2, v30

  li t2, 0x401316ac70796823
  vsetvli t1, t0, e16, m2, ta, ma
  vssubu.vx v18, v30, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vv v8, v28, v24

  li t2, 0xf3f690bd80112581
  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vx v4, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vv v12, v28, v8

  li t2, 0xbc66674c7f93b825
  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vx v24, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vv v24, v8, v28

  li t2, 0xadac5a228c212c8e
  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vx v16, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vv v20, v8, v24

  li t2, 0x11a4020435bb70dc
  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vv v4, v20, v12

  li t2, 0xdb69fb2f32273797
  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vx v24, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vv v28, v24, v16

  li t2, 0x5ca8036c32a3c33e
  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vx v20, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vv v4, v12, v8

  li t2, 0x244b86f8666b1133
  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vv v28, v24, v16

  li t2, 0xc5223ac30a128c8c
  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vx v16, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vv v12, v24, v8

  li t2, 0x773c31eca5240727
  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vx v16, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vv v20, v24, v4

  li t2, 0xa67ca8fbb16d4a53
  vsetvli t1, t0, e16, m4, ta, ma
  vssubu.vx v12, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vv v8, v24, v16

  li t2, 0x2bfd5955efe05c4d
  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vv v24, v8, v16

  li t2, 0x25410f82dc593fc7
  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vv v24, v16, v8

  li t2, 0x6698bab9551db06c
  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vv v16, v24, v8

  li t2, 0x88a97f1330ec7232
  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vv v8, v24, v16

  li t2, 0x0db0b59983f4aabd
  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vv v8, v24, v16

  li t2, 0xae49f814a54585cf
  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vv v8, v16, v24

  li t2, 0x000c7a4ac5d82796
  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vv v16, v24, v8

  li t2, 0x1b16bd219e6b6038
  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vv v24, v16, v8

  li t2, 0x2bc197d57b65ed61
  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vv v16, v8, v24

  li t2, 0xcfa09e5ef9335fae
  vsetvli t1, t0, e16, m8, ta, ma
  vssubu.vx v16, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vv v16, v3, v7

  li t2, 0x7e5d701da27fea21
  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vx v9, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vv v2, v18, v31

  li t2, 0x4bcbe5af5274f42c
  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vx v26, v23, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vv v5, v4, v28

  li t2, 0x38d597aa4c76367e
  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vx v31, v15, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vv v11, v6, v27

  li t2, 0x6a30b800b8b37363
  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vx v29, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vv v12, v18, v27

  li t2, 0xf1115528a5bab6a1
  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vx v1, v29, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vv v10, v22, v18

  li t2, 0xca5fbfb9200404c4
  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vx v24, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vv v3, v19, v5

  li t2, 0x3245ffbdf3608499
  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vx v25, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vv v9, v14, v31

  li t2, 0xe89a948e20b47e06
  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vx v2, v22, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vv v18, v29, v4

  li t2, 0x43ad41edc62773b9
  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vx v29, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vv v23, v15, v13

  li t2, 0xa768854f8decfce8
  vsetvli t1, t0, e32, m1, ta, ma
  vssubu.vx v18, v25, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vv v26, v20, v4

  li t2, 0x2ac382e19b7dc9bd
  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vx v12, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vv v4, v10, v18

  li t2, 0x04bf38df8e80ad4c
  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vx v4, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vv v24, v26, v14

  li t2, 0x0642820720600dc1
  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vx v4, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vv v28, v18, v6

  li t2, 0x5ce8fe0d400a7e6c
  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vx v22, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vv v4, v30, v8

  li t2, 0xe72cb20b98a82b9b
  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vx v24, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vv v28, v12, v4

  li t2, 0x72dcb7a04259d941
  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vx v12, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vv v24, v18, v30

  li t2, 0x487c2f033a63e838
  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vx v6, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vv v24, v18, v14

  li t2, 0x9a4ded6b1b33562c
  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vx v4, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vv v28, v6, v2

  li t2, 0x5628431df9c9fb6e
  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vx v24, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vv v30, v12, v10

  li t2, 0x946cb43251c04ca4
  vsetvli t1, t0, e32, m2, ta, ma
  vssubu.vx v12, v6, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vv v12, v4, v28

  li t2, 0xa108d954765eea7f
  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vx v16, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vv v4, v20, v8

  li t2, 0x5741670c85966583
  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vv v24, v4, v12

  li t2, 0x2e6f2c95a1ad3092
  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vx v8, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vv v16, v12, v28

  li t2, 0xff3a8e2ea5bdb61e
  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vx v24, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vv v20, v28, v16

  li t2, 0x266005e8226aef78
  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vx v16, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vv v16, v8, v24

  li t2, 0xaf707aa0cf68228a
  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vx v24, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vv v12, v16, v28

  li t2, 0x88e18c8619df2feb
  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vx v20, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vv v16, v28, v4

  li t2, 0xa24de92b180afbf3
  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vx v4, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vv v16, v20, v4

  li t2, 0xaaef983017a5febd
  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vx v4, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vv v28, v4, v24

  li t2, 0x208fb62ecf248056
  vsetvli t1, t0, e32, m4, ta, ma
  vssubu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vv v16, v8, v24

  li t2, 0x6382f96b0610ce7d
  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vv v24, v8, v16

  li t2, 0x3beabc994c033d72
  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vv v8, v24, v16

  li t2, 0x1625ec58345e3517
  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vv v8, v16, v24

  li t2, 0xd570d463da33947d
  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vv v8, v24, v16

  li t2, 0x7af225a05a53dcd4
  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vv v16, v8, v24

  li t2, 0x22869d1b92a12000
  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vv v24, v8, v16

  li t2, 0x736ac4c17ac35223
  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vv v8, v16, v24

  li t2, 0x63406f6c33dbfb09
  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vv v24, v8, v16

  li t2, 0x698f1534cb879a53
  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vv v16, v24, v8

  li t2, 0x436f3501c4fbe006
  vsetvli t1, t0, e32, m8, ta, ma
  vssubu.vx v24, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vv v21, v5, v24

  li t2, 0x9b9b81c5e162a054
  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vx v20, v11, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vv v17, v5, v21

  li t2, 0x76c4b11f74491dc2
  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vx v5, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vv v8, v31, v19

  li t2, 0x82791b5a7837f507
  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vx v30, v11, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vv v19, v28, v17

  li t2, 0xece40ddeaec9c680
  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vx v1, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vv v25, v6, v8

  li t2, 0x0383a23d142a3d26
  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vx v16, v7, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vv v7, v28, v27

  li t2, 0xd44cb101621b6b9e
  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vx v14, v22, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vv v30, v9, v2

  li t2, 0xae53558a2e1ad0a8
  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vx v10, v15, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vv v21, v19, v4

  li t2, 0x245645f2dc7d6774
  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vx v25, v17, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vv v24, v25, v3

  li t2, 0x05b49a011f2065fd
  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vx v17, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vv v24, v15, v16

  li t2, 0x22b2744c878f7420
  vsetvli t1, t0, e64, m1, ta, ma
  vssubu.vx v1, v19, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vv v8, v6, v26

  li t2, 0x3ed9f944fb429898
  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vx v18, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vv v2, v22, v18

  li t2, 0xdf3b05f03201a1bb
  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vx v8, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vv v26, v4, v10

  li t2, 0x7245ec1135690a73
  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vx v22, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vv v18, v16, v2

  li t2, 0x117bd61e0eff944f
  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vx v20, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vv v8, v4, v2

  li t2, 0x5cd8074cf573e77f
  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vx v16, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vv v18, v8, v20

  li t2, 0xdde22d902adf266e
  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vx v20, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vv v26, v4, v14

  li t2, 0x50c9e6a7c2b6d13f
  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vx v8, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vv v4, v22, v30

  li t2, 0x0560b01c94d2152d
  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vx v12, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vv v18, v28, v26

  li t2, 0xce7547e653b7c404
  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vx v2, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vv v26, v8, v10

  li t2, 0x7626cec89becf8c4
  vsetvli t1, t0, e64, m2, ta, ma
  vssubu.vx v18, v30, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vv v16, v4, v8

  li t2, 0x886826284f925a6b
  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vx v12, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vv v28, v16, v24

  li t2, 0x53e220bdc8e7e39a
  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vx v4, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vv v24, v20, v8

  li t2, 0x7f7bef9dada324fe
  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vx v28, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vv v12, v28, v4

  li t2, 0xf4d8a03bec325d33
  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vv v24, v4, v20

  li t2, 0xfc496c74548c65da
  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vv v4, v24, v28

  li t2, 0x4d56a1dc58971853
  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vv v12, v8, v20

  li t2, 0xcdb9ccd7639cf9fb
  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vv v24, v16, v20

  li t2, 0xc617b7d75337ca39
  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vx v28, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vv v16, v12, v28

  li t2, 0x6fefcadf09cc06f6
  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vx v8, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vv v24, v4, v12

  li t2, 0x2eb8cfc2977f5a1b
  vsetvli t1, t0, e64, m4, ta, ma
  vssubu.vx v12, v4, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vv v16, v24, v8

  li t2, 0x35cc1a1e5d39e350
  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vv v24, v8, v16

  li t2, 0x3adf25fe51378446
  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vv v16, v8, v24

  li t2, 0x4fd533df64d7939a
  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vv v16, v24, v8

  li t2, 0x19aaffd0e48893c6
  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vv v24, v8, v16

  li t2, 0x9f4025888b326ee3
  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vv v16, v24, v8

  li t2, 0xf34eff098e5add22
  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vv v8, v16, v24

  li t2, 0x87a0c29454424933
  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vv v24, v16, v8

  li t2, 0x5e2ec1d659c06a06
  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vv v24, v8, v16

  li t2, 0x18955328d68a439f
  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vv v24, v8, v16

  li t2, 0xca47e2b3f7349702
  vsetvli t1, t0, e64, m8, ta, ma
  vssubu.vx v8, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
