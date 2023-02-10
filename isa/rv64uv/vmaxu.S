#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vv v24, v3, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vv v25, v24, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vv v25, v29, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vv v23, v17, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vv v16, v3, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vv v25, v7, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vv v8, v2, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vv v2, v10, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vv v1, v7, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vv v9, v5, v19

  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vv v2, v28, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vv v10, v12, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vv v6, v22, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vv v12, v8, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vv v18, v28, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vv v4, v16, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vv v14, v26, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vv v8, v14, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vv v18, v22, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vv v6, v14, v2

  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vv v28, v8, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vv v4, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vv v20, v28, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vv v12, v20, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vv v24, v20, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vv v8, v28, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vv v12, v8, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vv v28, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vv v4, v12, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vv v12, v24, v20

  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vv v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vv v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vv v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vv v16, v24, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vv v2, v21, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vv v9, v24, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vv v15, v17, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vv v3, v23, v27

  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vv v8, v4, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vv v17, v31, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vv v13, v25, v9

  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vv v1, v27, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vv v26, v2, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vv v25, v4, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vv v18, v24, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vv v30, v24, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vv v26, v30, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vv v16, v18, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vv v16, v6, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vv v22, v16, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vv v14, v12, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vv v4, v28, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vv v20, v4, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vv v18, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vv v24, v20, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vv v28, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vv v12, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vv v20, v16, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vv v12, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vv v16, v12, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vv v16, v28, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vv v28, v24, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vv v8, v20, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vv v16, v24, v12

  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vv v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vv v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vv v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vv v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vv v8, v16, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vv v7, v11, v31

  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vv v15, v11, v31

  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vv v28, v10, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vv v13, v6, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vv v7, v2, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vv v14, v29, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vv v7, v4, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vv v18, v27, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vv v29, v11, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vv v4, v9, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vv v18, v16, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vv v16, v22, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vv v10, v24, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vv v14, v6, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vv v26, v14, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vv v22, v6, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vv v12, v18, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vv v30, v24, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vv v26, v24, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vv v26, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vv v8, v4, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vv v20, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vv v20, v28, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vv v24, v20, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vv v12, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vv v4, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vv v8, v24, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vv v28, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vv v16, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vv v20, v28, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vv v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vv v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vv v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vv v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vv v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vv v16, v8, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vv v5, v15, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vv v27, v24, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vv v20, v22, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vv v21, v28, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vv v25, v22, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vv v27, v31, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vv v9, v2, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vv v13, v20, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vv v3, v21, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vv v14, v17, v21

  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vv v16, v20, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vv v4, v30, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vv v22, v18, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vv v2, v10, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vv v18, v20, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vv v30, v12, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vv v30, v14, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vv v24, v26, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vv v28, v16, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vv v18, v10, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vv v4, v28, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vv v8, v20, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vv v4, v24, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vv v24, v28, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vv v12, v28, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vv v20, v16, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vv v16, v28, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vv v12, v20, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vv v12, v16, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vv v28, v12, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vv v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vv v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vv v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vv v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vv v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vv v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vv v24, v8, v16

  li t2, 0xe9124589350ff573
  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vx v4, v29, t2

  li t2, 0x40caaa1e05eba060
  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vx v6, v14, t2

  li t2, 0x6c3af28fe3058fba
  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vx v15, v12, t2

  li t2, 0x951a1be3dbec8443
  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vx v26, v10, t2

  li t2, 0x5f839e027d1869f1
  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vx v11, v5, t2

  li t2, 0x9c65fc908e468e55
  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vx v23, v22, t2

  li t2, 0x1e85d3b53ffcf08a
  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vx v27, v12, t2

  li t2, 0xee1ea41503cb5c9c
  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vx v31, v1, t2

  li t2, 0xd80681f456c52b02
  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vx v31, v8, t2

  li t2, 0x0697f8eba4fc069b
  vsetvli t1, t0, e8, m1, ta, ma
  vmaxu.vx v15, v25, t2

  li t2, 0x6e76eba8a21ace73
  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vx v10, v2, t2

  li t2, 0x7db2890237dd2f5e
  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vx v8, v14, t2

  li t2, 0x7c41d842ab539117
  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vx v10, v12, t2

  li t2, 0x0bddf116b4faf9cd
  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vx v20, v6, t2

  li t2, 0x3bc265626ef89fce
  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vx v6, v8, t2

  li t2, 0x9610871979550245
  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vx v24, v6, t2

  li t2, 0xed65d92d31758677
  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vx v10, v18, t2

  li t2, 0xcf66fc0b1abc74ff
  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vx v12, v16, t2

  li t2, 0xd30ba45affeaddff
  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vx v8, v14, t2

  li t2, 0x771416fd063adcf7
  vsetvli t1, t0, e8, m2, ta, ma
  vmaxu.vx v10, v26, t2

  li t2, 0xba51205f15854e99
  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vx v4, v12, t2

  li t2, 0x66cdf2d5f5f9cb2e
  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vx v12, v28, t2

  li t2, 0xf27fd3067fff8f54
  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vx v12, v20, t2

  li t2, 0xa50eadb832d97f71
  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vx v20, v12, t2

  li t2, 0x976d78e2cb1405ec
  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vx v16, v28, t2

  li t2, 0xadaa9f102f3f8881
  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vx v20, v4, t2

  li t2, 0x5bfc359448c668f0
  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vx v16, v12, t2

  li t2, 0xa851f6678a33df26
  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vx v20, v12, t2

  li t2, 0x8396037f3277c4c9
  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vx v20, v28, t2

  li t2, 0x5dd0f418ee3fd64a
  vsetvli t1, t0, e8, m4, ta, ma
  vmaxu.vx v16, v28, t2

  li t2, 0xfff0298214d1a953
  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vx v16, v8, t2

  li t2, 0x4fe4e92ae6330569
  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vx v8, v16, t2

  li t2, 0x844d38577a6b077b
  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vx v8, v16, t2

  li t2, 0x520f49a70c8ea3b9
  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vx v24, v8, t2

  li t2, 0xca1092475bc1b771
  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vx v16, v8, t2

  li t2, 0x89677795e3a90440
  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vx v16, v8, t2

  li t2, 0xbd53b2f90c5c3a29
  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vx v8, v24, t2

  li t2, 0xfbb401921b878484
  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vx v24, v8, t2

  li t2, 0x2f07277cb7a0f6aa
  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vx v8, v24, t2

  li t2, 0x475838e30ce65f92
  vsetvli t1, t0, e8, m8, ta, ma
  vmaxu.vx v8, v24, t2

  li t2, 0x1bf631c11d81bb88
  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vx v22, v30, t2

  li t2, 0x03dfb246f5d45da0
  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vx v12, v24, t2

  li t2, 0xbd8ea88e070d4a56
  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vx v24, v11, t2

  li t2, 0x1349f9f063919cee
  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vx v17, v20, t2

  li t2, 0xe48d677dff513202
  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vx v22, v26, t2

  li t2, 0x3286dce07762d8d7
  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vx v4, v20, t2

  li t2, 0x36065b4c19eec4ea
  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vx v1, v2, t2

  li t2, 0xc1b0d9d4542b3fb4
  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vx v2, v30, t2

  li t2, 0xc784d926ea747acf
  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vx v18, v22, t2

  li t2, 0xdd035f837e302f83
  vsetvli t1, t0, e16, m1, ta, ma
  vmaxu.vx v16, v28, t2

  li t2, 0xa68c84a5585027a3
  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vx v16, v4, t2

  li t2, 0xe7376cdd6e0977fe
  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vx v6, v22, t2

  li t2, 0x85ded037cdd3c62b
  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vx v16, v12, t2

  li t2, 0x8a4256227484f273
  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vx v16, v28, t2

  li t2, 0x047fb3c0ed359fcf
  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vx v16, v6, t2

  li t2, 0x8e3c4ef8b9d22223
  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vx v26, v28, t2

  li t2, 0xd6c712fc8a4a1a07
  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vx v16, v2, t2

  li t2, 0x71ad24b842c5fb62
  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vx v12, v2, t2

  li t2, 0xaf7088ba1f4572f2
  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vx v22, v16, t2

  li t2, 0xd7846d771f61d1d9
  vsetvli t1, t0, e16, m2, ta, ma
  vmaxu.vx v2, v18, t2

  li t2, 0x6e18c1141c77040e
  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vx v8, v16, t2

  li t2, 0xabe9837e50e36b41
  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vx v4, v24, t2

  li t2, 0x3c223e1e81c362a4
  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vx v4, v12, t2

  li t2, 0x76b1f0d66fdcbd17
  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vx v24, v8, t2

  li t2, 0x3f523be43f366c96
  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vx v20, v28, t2

  li t2, 0xbeeda9a259c5d707
  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vx v8, v28, t2

  li t2, 0xba01f983b43831a9
  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vx v16, v12, t2

  li t2, 0xc149a2d13924cf5c
  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vx v12, v20, t2

  li t2, 0x3b98febfb55df853
  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vx v12, v16, t2

  li t2, 0x8712ed3e0d956e0a
  vsetvli t1, t0, e16, m4, ta, ma
  vmaxu.vx v4, v24, t2

  li t2, 0x755e1d537db84bdf
  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vx v16, v8, t2

  li t2, 0x6dae9934dbcb71d6
  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vx v8, v24, t2

  li t2, 0xeff1adb271baa459
  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vx v24, v16, t2

  li t2, 0x4139df1d9aebc056
  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vx v8, v24, t2

  li t2, 0xb394ad73c9029534
  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vx v16, v24, t2

  li t2, 0xea6229ddde207b7d
  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vx v8, v24, t2

  li t2, 0xedcf3f840e52b86b
  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vx v8, v24, t2

  li t2, 0x518e281c22e908c1
  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vx v16, v8, t2

  li t2, 0xe39a8a85d88a0f66
  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vx v24, v8, t2

  li t2, 0x29f5dccadf89f5b4
  vsetvli t1, t0, e16, m8, ta, ma
  vmaxu.vx v8, v24, t2

  li t2, 0xac262e93331bfbdc
  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vx v16, v17, t2

  li t2, 0x8228cfd3b8c6e31c
  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vx v21, v17, t2

  li t2, 0xd6b438e356385fb6
  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vx v26, v5, t2

  li t2, 0x0ccf78e41f5f0c1e
  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vx v18, v6, t2

  li t2, 0xc099c8ee9a3ebda4
  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vx v15, v24, t2

  li t2, 0xfd49399bc2817b47
  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vx v30, v27, t2

  li t2, 0x432cd5e0d62228dd
  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vx v15, v27, t2

  li t2, 0x72797f37dcb6824c
  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vx v7, v3, t2

  li t2, 0x17675e63302270c8
  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vx v22, v13, t2

  li t2, 0x68e642cadb2467e3
  vsetvli t1, t0, e32, m1, ta, ma
  vmaxu.vx v2, v25, t2

  li t2, 0x6c9e513cf97fd630
  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vx v10, v16, t2

  li t2, 0x7d514adefde87aa3
  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vx v24, v4, t2

  li t2, 0xbffae8f4ab8e0759
  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vx v26, v20, t2

  li t2, 0xd96d0c5b5390d1e5
  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vx v2, v12, t2

  li t2, 0x19f58e60b1d1b3c8
  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vx v16, v4, t2

  li t2, 0x8f8fd0847dc6d81c
  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vx v18, v12, t2

  li t2, 0x261e167d48dc59f0
  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vx v2, v8, t2

  li t2, 0x66a9e1d625d8c4ea
  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vx v2, v22, t2

  li t2, 0x3bf16d3989bc0e47
  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vx v30, v4, t2

  li t2, 0x2282dfa4e53d60d1
  vsetvli t1, t0, e32, m2, ta, ma
  vmaxu.vx v30, v22, t2

  li t2, 0x12ed079a29de2308
  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vx v20, v12, t2

  li t2, 0x911be1430ea29277
  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vx v24, v8, t2

  li t2, 0xf76d6549c8088f55
  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vx v16, v4, t2

  li t2, 0x71c405257492d7e8
  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vx v4, v28, t2

  li t2, 0xa43f166c92fccd26
  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vx v20, v28, t2

  li t2, 0x3b3be0bd6d64d60f
  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vx v4, v8, t2

  li t2, 0x7ba2243ebe457c1f
  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vx v12, v20, t2

  li t2, 0x190b38a9422a27d5
  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vx v20, v16, t2

  li t2, 0x391d6e59e14944f1
  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vx v8, v24, t2

  li t2, 0x54bc452206ccd7a8
  vsetvli t1, t0, e32, m4, ta, ma
  vmaxu.vx v28, v8, t2

  li t2, 0xae5e9632060ef50a
  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vx v8, v24, t2

  li t2, 0xeda0c9999bb3107f
  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vx v24, v8, t2

  li t2, 0x7d61ffd317607631
  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vx v24, v16, t2

  li t2, 0xb9cbf2a041e222f2
  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vx v16, v24, t2

  li t2, 0x3978519e42de3927
  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vx v8, v24, t2

  li t2, 0x000e4b39d84a4c1b
  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vx v24, v16, t2

  li t2, 0x758a7dd0e73c768b
  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vx v16, v8, t2

  li t2, 0x5c7f25f3de879a1b
  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vx v8, v16, t2

  li t2, 0x9442bed219697d32
  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vx v24, v16, t2

  li t2, 0x355cb13239775340
  vsetvli t1, t0, e32, m8, ta, ma
  vmaxu.vx v16, v8, t2

  li t2, 0x2702765fa83307af
  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vx v29, v7, t2

  li t2, 0x1028c5cff501929e
  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vx v4, v9, t2

  li t2, 0x51a7c14198b60fff
  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vx v1, v7, t2

  li t2, 0xb857c05cdd3b24ed
  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vx v27, v16, t2

  li t2, 0x51285424d11f662c
  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vx v14, v9, t2

  li t2, 0x57707bafe4cbf10d
  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vx v23, v14, t2

  li t2, 0xa07c271a3652ef5d
  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vx v4, v2, t2

  li t2, 0x57c0fa1d0dbcc802
  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vx v6, v7, t2

  li t2, 0x35563c3e3e97a766
  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vx v10, v1, t2

  li t2, 0x8888f83dc25636b1
  vsetvli t1, t0, e64, m1, ta, ma
  vmaxu.vx v19, v15, t2

  li t2, 0x695b1ef1d73e7191
  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vx v14, v10, t2

  li t2, 0x94af4d57df833800
  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vx v4, v16, t2

  li t2, 0x6e91f77106fbcc59
  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vx v2, v24, t2

  li t2, 0x08749eeb81fa3f94
  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vx v18, v16, t2

  li t2, 0x06ca694bdb117b6e
  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vx v30, v24, t2

  li t2, 0x6b1cd7e4e7d5a88d
  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vx v6, v24, t2

  li t2, 0x311d4bf43cd09b43
  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vx v28, v20, t2

  li t2, 0x1337339231630567
  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vx v28, v22, t2

  li t2, 0xee7384a67d13f0b8
  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vx v18, v24, t2

  li t2, 0x1ce6dbe2d5009738
  vsetvli t1, t0, e64, m2, ta, ma
  vmaxu.vx v28, v14, t2

  li t2, 0x0f934b3e01caf457
  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vx v4, v20, t2

  li t2, 0x2d2746f257a0e37f
  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vx v4, v28, t2

  li t2, 0x13cf9579159a399b
  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vx v16, v8, t2

  li t2, 0x92d222c7475b29a8
  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vx v16, v12, t2

  li t2, 0x1371149303bfe9e9
  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vx v8, v28, t2

  li t2, 0xb35818501308acba
  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vx v16, v20, t2

  li t2, 0x32f45c47e37567d2
  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vx v12, v20, t2

  li t2, 0xde8ccb7d5df068aa
  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vx v24, v12, t2

  li t2, 0xd56a7e4732553be7
  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vx v24, v12, t2

  li t2, 0xb5d131a4ec014dd5
  vsetvli t1, t0, e64, m4, ta, ma
  vmaxu.vx v28, v8, t2

  li t2, 0xf0096775f7bd6ea1
  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vx v24, v8, t2

  li t2, 0xb4f6861b53217517
  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vx v8, v16, t2

  li t2, 0xc2d7c9d0cf4e5246
  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vx v8, v24, t2

  li t2, 0xc4c20129894a6795
  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vx v24, v16, t2

  li t2, 0x651d884ad527ad51
  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vx v8, v16, t2

  li t2, 0xbdc168cc246304ff
  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vx v8, v16, t2

  li t2, 0x121a672284728b6b
  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vx v16, v24, t2

  li t2, 0x68c6db301f48f594
  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vx v24, v8, t2

  li t2, 0x31b3ef074820115f
  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vx v16, v24, t2

  li t2, 0x94c10f230a7d847e
  vsetvli t1, t0, e64, m8, ta, ma
  vmaxu.vx v8, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
