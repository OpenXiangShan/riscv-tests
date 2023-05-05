#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v12, v24, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v26, v20, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v24, v4, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v14, v26, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v8, v26, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v28, v10, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v10, v16, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v2, v8, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v8, v16, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v6, v14, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v4, v22, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v22, v8, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v16, v28, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v16, v12, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v18, v20, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v22, v6, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v18, v2, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v10, v12, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v30, v16, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v30, v8, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v6, v12, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v2, v10, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v12, v18, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v26, v16, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v16, v6, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v20, v6, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v26, v16, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v26, v18, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v12, v26, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v10, v4, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v8, v20, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v26, v10, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v30, v18, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v6, v16, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v28, v24, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v30, v10, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v28, v8, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v10, v28, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v30, v28, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v30, v28, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v2, v6, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v28, v10, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v6, v24, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v28, v26, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v20, v12, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v4, v22, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v6, v24, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v16, v14, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v28, v2, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v4, v26, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v2, v20, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v8, v30, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v24, v14, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v16, v2, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v18, v12, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v20, v14, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v4, v2, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v30, v14, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v30, v20, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v6, v12, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v20, v14, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v6, v22, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v6, v2, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v20, v22, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v18, v6, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v16, v30, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v22, v24, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v10, v26, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v28, v14, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v26, v30, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v8, v18, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v14, v4, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v24, v26, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v18, v12, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v8, v2, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v28, v20, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v12, v30, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v18, v28, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v4, v8, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v4, v24, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v10, v18, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v2, v30, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v6, v26, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v10, v12, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v28, v12, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v26, v24, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v8, v2, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v26, v14, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v8, v6, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v22, v8, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v18, v26, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v20, v4, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v6, v8, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v28, v6, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v28, v6, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v26, v22, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v12, v26, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v30, v14, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vv v8, v16, v24

  li t2, 0xcfe69577c4fedd98
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v28, t2, v8

  li t2, 0xab9ae5342a4412e7
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v24, t2, v12

  li t2, 0x6a67423f22305753
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v4, t2, v2

  li t2, 0x1a74b78123054c77
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v14, t2, v16

  li t2, 0xc65cfca357af2ced
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v16, t2, v30

  li t2, 0xcf503602973b147d
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v10, t2, v24

  li t2, 0x4fbf1c4d28e039aa
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v8, t2, v26

  li t2, 0x9781e75e811f1052
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v2, t2, v24

  li t2, 0x4bed3acacd2a777d
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v4, t2, v10

  li t2, 0xaf6fe17a30ccd499
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v4, t2, v22

  li t2, 0xf688c7c5bcf22c70
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v20, t2, v16

  li t2, 0xc18c744af1656a41
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v4, t2, v24

  li t2, 0xd7bc928dcb2d2289
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v24, t2, v22

  li t2, 0x8639eb5973984806
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v28, t2, v20

  li t2, 0x8a9f121606ca0f2e
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v12, t2, v26

  li t2, 0xab039650f2c38a6c
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v6, t2, v8

  li t2, 0x0e699b1ba511ae1b
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v2, t2, v22

  li t2, 0x6669792f9711ffec
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v28, t2, v2

  li t2, 0x7b69cc4cd1ba4ce5
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v18, t2, v2

  li t2, 0xb67d6604cde2d345
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x2c001f5e1d4c19a1
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v8, t2, v26

  li t2, 0xcc0650ebdaaa6623
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v16, t2, v22

  li t2, 0xdce7a4023d3ddf10
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v10, t2, v22

  li t2, 0x49d15c4d5ce3388f
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v14, t2, v16

  li t2, 0x3e0fe4e22cac524f
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v28, t2, v24

  li t2, 0x7ce637987b106c32
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v30, t2, v20

  li t2, 0x726076f6500ac411
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v6, t2, v10

  li t2, 0x9036d2778c58970f
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v28, t2, v30

  li t2, 0x29f094b2643b1a55
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v28, t2, v20

  li t2, 0x5be210cdc5ba2766
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v2, t2, v16

  li t2, 0xd02f86026accdb04
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v16, t2, v2

  li t2, 0x98d58340312b1196
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v10, t2, v26

  li t2, 0xe41f5fb3f34d1d23
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v28, t2, v12

  li t2, 0x4e810dad38baa29f
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v22, t2, v6

  li t2, 0x9c1822645e7fc579
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v2, t2, v18

  li t2, 0x607803d91e1e26cf
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v24, t2, v30

  li t2, 0x10bafef29bd822fe
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v18, t2, v24

  li t2, 0x467b9cde3889bdd7
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v12, t2, v2

  li t2, 0xd0ec3c98627fc051
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v8, t2, v22

  li t2, 0xcc22347f624c881b
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v10, t2, v24

  li t2, 0x6d1c8f0bcf07f0ff
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v6, t2, v26

  li t2, 0xac649420dc8f500f
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v6, t2, v20

  li t2, 0x3811875c81364d13
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v10, t2, v12

  li t2, 0x62ca1c07549da5a7
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v12, t2, v8

  li t2, 0xf0bae19c1c3bf4e4
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v10, t2, v8

  li t2, 0xc6ec01b54abad6e8
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v4, t2, v8

  li t2, 0x42778340c13886eb
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v12, t2, v4

  li t2, 0x42266179e26e3d6f
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v4, t2, v12

  li t2, 0xab2c4ec8bd10587a
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v14, t2, v4

  li t2, 0xd5ac595d0ad18dc7
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v8, t2, v18

  li t2, 0xc3919ab9bf0df114
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v14, t2, v18

  li t2, 0x0049c563cc6febf7
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v4, t2, v8

  li t2, 0x798a44b32677443b
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v28, t2, v12

  li t2, 0x70b4ed450f738a8e
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v12, t2, v8

  li t2, 0x7636d389f1c31566
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v6, t2, v2

  li t2, 0x25640aeaddfba688
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v6, t2, v30

  li t2, 0xead01e00f322596b
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v2, t2, v4

  li t2, 0xd9d848f5190f3429
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x32729418625fef78
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v2, t2, v8

  li t2, 0x5ec51d37630bbb8a
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v28, t2, v10

  li t2, 0xf93c849531c90bfe
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v28, t2, v18

  li t2, 0x5e3e57761abf59bb
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v10, t2, v30

  li t2, 0x30560e1697b55a9d
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v28, t2, v8

  li t2, 0xc227697be36ead84
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v14, t2, v28

  li t2, 0xffc9dc83e56dd660
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v18, t2, v14

  li t2, 0x9257f16097c1f146
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v30, t2, v16

  li t2, 0xc8b17531ef84eaf0
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v6, t2, v30

  li t2, 0x86e3bd26681fa2d5
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v22, t2, v8

  li t2, 0x66a514fe857228bd
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v30, t2, v4

  li t2, 0xcbcb9d01c149623a
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v24, t2, v26

  li t2, 0x16c629557cc61b15
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v16, t2, v6

  li t2, 0xafa1da90f6e2632a
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v30, t2, v26

  li t2, 0x0c639d7c6cbb1841
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v18, t2, v10

  li t2, 0x8b681dc7e9bb0477
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v22, t2, v10

  li t2, 0x311115485510d049
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v24, t2, v4

  li t2, 0x698bbc02679a2fdc
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v28, t2, v16

  li t2, 0x3cc0d6d526a6f9f5
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v6, t2, v14

  li t2, 0x1741a30441c87dd8
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v8, t2, v2

  li t2, 0x17bfc4d5f747fcba
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v12, t2, v14

  li t2, 0x9d6b8067e05863c8
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v18, t2, v14

  li t2, 0xd7439c7063440d9a
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v28, t2, v20

  li t2, 0x996cf4ceaa75ae1c
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v2, t2, v8

  li t2, 0x08f8345d838541ab
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v30, t2, v4

  li t2, 0xf6eaab1d9c74ec03
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v18, t2, v12

  li t2, 0x069f836a2b976623
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v4, t2, v2

  li t2, 0x096e5de597f04ba1
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v28, t2, v26

  li t2, 0x6abf518527603986
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v6, t2, v26

  li t2, 0x227883e354742eae
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v18, t2, v24

  li t2, 0xacf351577e23a813
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v2, t2, v6

  li t2, 0xb4249f3c57247634
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v10, t2, v20

  li t2, 0xfeaf88a78a1173de
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xdc736aef79224fc4
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v2, t2, v12

  li t2, 0xa277412954f26455
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v6, t2, v26

  li t2, 0x2d93343f0e15e131
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v2, t2, v8

  li t2, 0x0f3dbccf2fa6eefe
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v28, t2, v2

  li t2, 0x0971dfe6a43dd1f0
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v26, t2, v30

  li t2, 0xc0ebf21cae212b9f
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v14, t2, v4

  li t2, 0x46ba89a0e132cbd8
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v22, t2, v26

  li t2, 0x875166a51e9bcc5d
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v22, t2, v2

  li t2, 0x25c070dc4d42db07
  vsetvli t1, t0, e8, m1, ta, ma
  vwmacc.vx v12, t2, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v4, v8, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v20, v12, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v4, v8, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v28, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v20, v28, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v12, v4, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v4, v24, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v12, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v16, v12, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v16, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v28, v8, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v28, v20, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v4, v12, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v16, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v20, v28, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v20, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v20, v16, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v12, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v20, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v8, v4, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v4, v24, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v4, v20, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v20, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v8, v4, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v16, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v16, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v8, v28, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v16, v12, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v16, v20, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v28, v12, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v4, v28, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v28, v16, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v4, v8, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v8, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v4, v8, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v8, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v16, v24, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v16, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v8, v16, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v28, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v4, v8, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v20, v28, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v12, v20, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v28, v8, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v20, v24, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v12, v24, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v8, v12, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v12, v8, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v20, v12, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v4, v28, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v16, v24, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v8, v12, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v12, v24, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v16, v20, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v8, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v20, v4, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v8, v28, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v12, v20, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v20, v4, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v12, v24, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v28, v20, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v16, v24, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v12, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v12, v28, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v28, v8, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v20, v16, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v28, v24, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v16, v4, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v12, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v8, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v20, v8, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v28, v12, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v16, v24, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v12, v28, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v28, v24, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v8, v12, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v12, v20, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v16, v12, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v20, v8, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v12, v20, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v4, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v4, v24, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v8, v4, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v28, v16, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v4, v28, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v20, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v12, v16, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v28, v8, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v8, v20, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v28, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v12, v16, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v4, v28, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v16, v12, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v12, v28, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v12, v16, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v16, v28, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v16, v8, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vv v24, v28, v4

  li t2, 0xd4ed0986ab2e7f24
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x4ae2c0e50b955de6
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v4

  li t2, 0x379dea519255f3ab
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v12

  li t2, 0xe4e5d7ccb88180ab
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v16

  li t2, 0xc53b2a0db9aa6182
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v16, t2, v28

  li t2, 0x84a49760dbab12f7
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x65914589e5329220
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v28, t2, v20

  li t2, 0x7b66da64290a28a5
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v8, t2, v4

  li t2, 0x886d275e63feb9fe
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v4, t2, v12

  li t2, 0x03d0c09907ef488b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v12

  li t2, 0x0cc56e04d626784d
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v4

  li t2, 0xd4b1014e0bdd8508
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v8, t2, v12

  li t2, 0x0156beff08b32282
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v4, t2, v24

  li t2, 0xb226e9fd1b362a70
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v4

  li t2, 0x52167854fb42298b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v28

  li t2, 0xb5c8c056bf043d61
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v8, t2, v20

  li t2, 0x31ad3a72a9fd1056
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v24

  li t2, 0x55f3644846fa6e90
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v28, t2, v16

  li t2, 0x96dba132925b3824
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v24

  li t2, 0x61bd84ff3eef3095
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v28

  li t2, 0x8d4a134f5ae3b9c3
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v12

  li t2, 0x84989cef744bcf13
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v16

  li t2, 0xb6720e41273f2d99
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v8

  li t2, 0x7f11b5e7814e0ffd
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v8, t2, v4

  li t2, 0xb8e027d05ed9c161
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v24

  li t2, 0xa297a26d5c38f2dc
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v28, t2, v12

  li t2, 0x9418f038e0fe5b27
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xe506770d002cbb5e
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v28

  li t2, 0x6e18346dec780f57
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v4

  li t2, 0xbb031c9627748f41
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v4, t2, v20

  li t2, 0x72cfac4b5a1c09ec
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v24

  li t2, 0x53246005fe75eb43
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v4, t2, v28

  li t2, 0xb73401b9be15764b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v8, t2, v28

  li t2, 0xe28a27225adc9406
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v24

  li t2, 0x1dcea1c3f20dbc3a
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v16, t2, v4

  li t2, 0x9a9903e4a6a7f5c3
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x1c874376df4eb2c2
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x0033c47bc2b68b28
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x79c1a4b60a198eed
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v4, t2, v20

  li t2, 0xf2e921cb20ad8520
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x4ec5a283a4f5fd84
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v8

  li t2, 0xa5bfe1326940aec4
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v4

  li t2, 0xbf586e5618bf91c9
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v16, t2, v20

  li t2, 0xa2da46ad467e3aa1
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v4

  li t2, 0x71f29fc4ab208a0a
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v4

  li t2, 0x3a76e028c114cce6
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v4

  li t2, 0xa1b1fbdf9c2ef92a
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v28, t2, v20

  li t2, 0x5a284f2f5e179223
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v28, t2, v16

  li t2, 0x514517f32d85cf8c
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v28, t2, v20

  li t2, 0x440af624a27a9447
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v4

  li t2, 0xd455a7b0b32d1b6b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xf34027bdde18609e
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v12

  li t2, 0x4d07c19028a8308a
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v16, t2, v28

  li t2, 0xb166d444c64147e9
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x588a7713c335cbda
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v28, t2, v12

  li t2, 0x589646f0f80af04b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v4

  li t2, 0x5a20f36a27e87adb
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v4, t2, v28

  li t2, 0x041930c6edb3b739
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v28

  li t2, 0x00799f13c5e8d96a
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v28

  li t2, 0x8dbefba36a1aa966
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v28, t2, v16

  li t2, 0x4691a44aee393044
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v8, t2, v12

  li t2, 0xfb52d8dc625a1e62
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v20

  li t2, 0xb258b6d5f65bb794
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v28

  li t2, 0x67038c5b7badab8e
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v28, t2, v12

  li t2, 0xb88bb63cdd0aad2b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v20

  li t2, 0xa52ee10778bc1811
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v8, t2, v4

  li t2, 0x3c8288c3c570b20d
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v28

  li t2, 0x025cb992366a6390
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v4, t2, v24

  li t2, 0xf48629be1cc52ee0
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x56a80b03be5140bc
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x12c381537241977d
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v28

  li t2, 0xdfafd318dbbbcf85
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v4, t2, v8

  li t2, 0xef3ba7147fd88f6d
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v8

  li t2, 0x31b4c3459f9f0ec0
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x29fb22895c13c86c
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v28, t2, v4

  li t2, 0xc89f488d99ddbf68
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x06429278a8b4b840
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v4

  li t2, 0x8b18e8ee01cfe2da
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x5d9f115bd02f80ca
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v28, t2, v12

  li t2, 0x07e8615b8c768700
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v24

  li t2, 0xcd92ee411b6641bd
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v28, t2, v8

  li t2, 0x413512dd51b6f44a
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x35156ae35f769991
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v4

  li t2, 0x170c6943896a2747
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v8, t2, v4

  li t2, 0xc4f27a8168105921
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v16

  li t2, 0x5732bb671bdcfee4
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v24

  li t2, 0x0a3226a21749a332
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v4, t2, v24

  li t2, 0xb8fa288c246264e1
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v4, t2, v16

  li t2, 0x4470881f0e233d04
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v4, t2, v28

  li t2, 0xb204693acd3e9914
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v28, t2, v4

  li t2, 0xe3f31015b4770070
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v4

  li t2, 0x2cf48962fde75d4b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xda5a79775c911a11
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v4

  li t2, 0x8e11082972074f02
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xd56d486266f9608b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v4, t2, v8

  li t2, 0x3b59941400e67671
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v20, t2, v12

  li t2, 0xd91cdc4407dc5d91
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v24, t2, v20

  li t2, 0x50e71d3b07cb5736
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v4, t2, v28

  li t2, 0xcb077bc43b248e62
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v8, t2, v4

  li t2, 0xc39d226506b324b6
  vsetvli t1, t0, e8, m2, ta, ma
  vwmacc.vx v12, t2, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vv v8, v16, v24

  li t2, 0xc973cb636d173fb6
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x0f6d24a256e5eb0a
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x9eeb5bfc9576108b
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x06fd63708752e5bd
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x5ed7f1d7850c1992
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x71c24e9ad07615c3
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x35dd1f65660aa109
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xbca3115599704b12
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x99e45c878ec21743
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x76b361e8f049a540
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x7d5b3c956af2ef29
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x0eb8c9a4c6d97a69
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x1498a64ebf2be44a
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x6804ab19458035fa
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xe8a5f0a324bba945
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x1326c66f010bc6bb
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x17c06f16b4a85a08
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xfaf533e4418a8939
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xd490ff93057659b7
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x26db1a2065c0698a
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xd7c6417106d8e78a
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xd055bb5e4fe377c5
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x47121be8c33871fd
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xddcdbaf40a82830c
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xd5e25bca5fd8bda5
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xa4574ed9f8761c52
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x87461d8fd0013d91
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x7abb72aaba35187c
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x2438166902feedbf
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x6b83de6985f0aa39
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x3d5fcbb86f207e87
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x8f71fb20507c9857
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xa63d5755c0bffe33
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x7e2f8cbe708e8a79
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x3a6a62cadbd85077
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x3f63e87588102410
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x621833da080ecaba
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xc5b422bca55802d0
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x3c220896ca05c625
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x490faeb245a8ec1f
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x9f8c8859e49b3942
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x7b166ef3bc895782
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x8f99a5d30f4e50c8
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xfc64b929546bd98c
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x41e3d2ed78f96092
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x2f2f50b636f024ee
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x7966f6c230069d41
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x57dd2b26d78ee5c1
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xf8355520a6705f25
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x6e9be5c72b85a21d
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x0676d13e4b4b9c2e
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x270062dcb4c5add0
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x2bc930760383a6fb
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xbafb8c43f7099cfc
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xfe017172be796821
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xfac45c3c4af31bcd
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xd911df8e1ec4c0c2
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xec72c6cdad050a1c
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xe19dcd3397c216a8
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x4f2b89b768720ec4
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xc57b7a0e1307ff4f
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x2f30451c2845cdaf
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xeac5b4cd9c6fffed
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xa3bf3906503919b5
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x124c005313f903d9
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xa913be961ababc39
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xfa6d4f645394a719
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xcdf3517a5ea96036
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xb760c43d021adccb
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xd02432cd095502f0
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xfa237b2c1a252929
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x58b7aa2b9c850272
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xe7c6ac4a40aad717
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x0d9d2fccf358b435
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x1255221ffd6de97b
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x63d4f9656710eaee
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x11df51aacf67bcf3
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x20983176c9cabad6
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x6bd01ba20561cbe4
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xdce07fd67fb3f106
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xf1497b1ac9c729c3
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xab35e9906c2167a8
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xc8385f37cc3dcf23
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x971949cbdb7aa7fd
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x4af6ad6e7c0671c7
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x8cc1ad10bb3c4998
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x30b3b1757768dd48
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x4a1420d59db7f754
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x86b002e9f80b9518
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x59878c708e81da76
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x4ce341be626648e9
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xc2d1ef606aa7765f
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x06d29f1672346efb
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xbbe4f849b0894ddb
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xdba6de2b1c9150b2
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xdb7704bee6b30b4d
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x6198555dda6fa9ce
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xe94d260ede7c40bc
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x9342cab5c58af83b
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x22f1236d2c9974f0
  vsetvli t1, t0, e8, m4, ta, ma
  vwmacc.vx v24, t2, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v22, v4, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v12, v10, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v6, v28, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v14, v4, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v6, v28, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v10, v6, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v20, v18, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v8, v30, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v30, v18, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v30, v24, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v22, v18, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v22, v28, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v16, v6, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v10, v18, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v6, v14, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v24, v10, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v10, v18, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v18, v8, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v6, v4, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v22, v10, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v14, v24, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v14, v24, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v22, v14, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v12, v6, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v2, v30, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v4, v16, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v2, v4, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v4, v18, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v20, v18, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v2, v30, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v30, v4, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v20, v6, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v24, v10, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v6, v4, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v6, v14, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v4, v22, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v4, v18, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v2, v22, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v28, v8, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v24, v4, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v20, v24, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v18, v30, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v4, v10, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v6, v26, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v10, v8, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v26, v4, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v12, v22, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v8, v18, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v26, v28, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v28, v8, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v28, v2, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v28, v16, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v16, v24, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v22, v28, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v24, v4, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v26, v22, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v22, v26, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v28, v22, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v8, v14, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v20, v22, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v16, v26, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v4, v10, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v2, v26, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v2, v12, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v20, v4, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v6, v4, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v20, v26, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v20, v4, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v14, v18, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v2, v4, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v2, v18, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v30, v12, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v24, v10, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v22, v2, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v30, v14, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v8, v14, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v8, v10, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v20, v4, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v2, v28, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v18, v4, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v8, v14, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v28, v20, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v26, v24, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v8, v20, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v22, v20, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v2, v18, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v16, v20, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v12, v28, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v16, v2, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v2, v10, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v16, v4, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v18, v28, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v24, v22, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v28, v10, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v24, v22, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v22, v6, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v12, v18, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v20, v16, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v8, v18, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vv v14, v30, v16

  li t2, 0xe9f883db9db3c014
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v30, t2, v6

  li t2, 0x7b1ec59dc17b9c8e
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v4, t2, v12

  li t2, 0xc66f7d741e308ffa
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v18, t2, v8

  li t2, 0x3d7764294f3ab2ef
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v18, t2, v6

  li t2, 0x24fafcf9edff937d
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x74e38e3dc4498418
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v10, t2, v4

  li t2, 0x6f3a0feaa99ac942
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v24, t2, v6

  li t2, 0x2fd6c3b2121908fc
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v4, t2, v18

  li t2, 0xbe0723712e72b292
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v26, t2, v28

  li t2, 0x335c883c144e54b7
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v16, t2, v6

  li t2, 0x77a72de3782712fc
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v28, t2, v12

  li t2, 0x1445a181be63060a
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v22, t2, v2

  li t2, 0x41411c3ee5419712
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v24, t2, v10

  li t2, 0xe1c450696057992b
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v30, t2, v18

  li t2, 0xd10c615f966032c1
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v4, t2, v6

  li t2, 0x78710165cefcd676
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v4, t2, v10

  li t2, 0xb5d57e12790dda7f
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v30, t2, v22

  li t2, 0xfae11d47c539f441
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v22, t2, v6

  li t2, 0x6cacfe08207e0964
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v4, t2, v20

  li t2, 0xd88f83599c48a980
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v16, t2, v2

  li t2, 0x83c1a11e9e420241
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v18, t2, v12

  li t2, 0xe701bed2ffe1c51e
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v30, t2, v8

  li t2, 0xb7ef3307f669af9a
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v30, t2, v26

  li t2, 0xde4a1b9d2d407881
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v18, t2, v14

  li t2, 0x6ca8d5955c33910f
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v22, t2, v26

  li t2, 0xf82052f32f2af635
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v26, t2, v4

  li t2, 0x5097b0598cb400ae
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v10, t2, v20

  li t2, 0xde7377ceff25ecc9
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v6, t2, v14

  li t2, 0xef7e1db8b91c30ec
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v14, t2, v2

  li t2, 0x14280c217cb2f720
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v18, t2, v8

  li t2, 0x935d6d426907f954
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v16, t2, v2

  li t2, 0x8b3f7f9f04848d7a
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v6, t2, v22

  li t2, 0x89ab8cad9582f3fa
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v8, t2, v4

  li t2, 0x9ce471220f79eaa4
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v12, t2, v18

  li t2, 0x379c3cd8b7aa17d7
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v6, t2, v26

  li t2, 0x3b3a53401023c04e
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v14, t2, v22

  li t2, 0x0b9a2e829c371cae
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v14, t2, v26

  li t2, 0x4bcd0178d6317d96
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v20, t2, v14

  li t2, 0x49d584b46956600e
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v26, t2, v2

  li t2, 0x8f87b9e1cc197c05
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v22, t2, v16

  li t2, 0xeb17c6c580096bea
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v4, t2, v2

  li t2, 0xaf11afca2e73bccf
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v14, t2, v28

  li t2, 0xe92a52add210f934
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v18, t2, v16

  li t2, 0xc9e6ccde21e45724
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v30, t2, v12

  li t2, 0x8cec0580045124e7
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v18, t2, v30

  li t2, 0x24f5e02a89cc83ca
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v8, t2, v14

  li t2, 0x8d278286b3424c1d
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v2, t2, v22

  li t2, 0xd18c07eabfcc63a9
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v20, t2, v30

  li t2, 0x245e50f778dec072
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v20, t2, v2

  li t2, 0xf61b9d18bf9d61e6
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v26, t2, v30

  li t2, 0x36e464e58338202a
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v10, t2, v12

  li t2, 0x1dd078aa38667163
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v8, t2, v14

  li t2, 0xaba8913d039de71d
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v18, t2, v10

  li t2, 0x111fae4bdf106923
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v30, t2, v4

  li t2, 0x1ab373d9150f43b0
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v14, t2, v22

  li t2, 0x5bad6b3e66782150
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v24, t2, v26

  li t2, 0x3094c085c5c08908
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v22, t2, v28

  li t2, 0x665766c420f27204
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v12, t2, v10

  li t2, 0x90012422d16e07fc
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v16, t2, v6

  li t2, 0x30e6cd2706909026
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v16, t2, v26

  li t2, 0x5cd43c9b473d9edc
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v6, t2, v18

  li t2, 0xb33a19a50683b9a2
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v6, t2, v10

  li t2, 0x239a8236b3526fd3
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v8, t2, v22

  li t2, 0xb70256dbd342677f
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v20, t2, v24

  li t2, 0x3711a805ec3677cd
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v12, t2, v14

  li t2, 0x47a25641901d7132
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v18, t2, v28

  li t2, 0x4e5adc604c704d12
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v8, t2, v22

  li t2, 0x889e97bb56f36b9e
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v14, t2, v16

  li t2, 0x065aa3452063db27
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v14, t2, v8

  li t2, 0x9d48faceb6d9dc86
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v26, t2, v12

  li t2, 0x65fdcefa5b0b2775
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v16, t2, v2

  li t2, 0xf01b6dc867df2830
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v30, t2, v22

  li t2, 0xf4f056dd90e795e6
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v16, t2, v18

  li t2, 0x33d56a699ba999be
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v2, t2, v10

  li t2, 0x92e2726aba630bf9
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v6, t2, v20

  li t2, 0xd007d4e9b4ab26ee
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v20, t2, v26

  li t2, 0x1db5decd613fe877
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v26, t2, v4

  li t2, 0x84be6927d3663c53
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v16, t2, v4

  li t2, 0x6151d0645bd03c4f
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v20, t2, v6

  li t2, 0xb50a753ecec817d7
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v8, t2, v14

  li t2, 0x51e73b43cf0bf320
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v26, t2, v10

  li t2, 0x27cc4a12769b4ff0
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xfc83bff63454fa5b
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v22, t2, v6

  li t2, 0x271bc407184c2fe0
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v12, t2, v24

  li t2, 0xaae63a78a66f9178
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v24, t2, v28

  li t2, 0x85e7f80960364dd0
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v24, t2, v18

  li t2, 0xcd2b5739b0e26a3c
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v18, t2, v20

  li t2, 0xe0bb5d68a017cee7
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v4, t2, v6

  li t2, 0x57e227161d90cd63
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v6, t2, v2

  li t2, 0xdcb201588fd42ca6
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v20, t2, v28

  li t2, 0x0f0e52aa7f47a259
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v28, t2, v2

  li t2, 0xd76720740d647d1a
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v22, t2, v20

  li t2, 0x0e9169b23c38af77
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v6, t2, v10

  li t2, 0x9533c5412746989c
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v16, t2, v18

  li t2, 0xf07ec1e584f94d97
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v2, t2, v16

  li t2, 0xb05dac3880d4dfa9
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v30, t2, v24

  li t2, 0xaf6526860d6223f7
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v8, t2, v28

  li t2, 0xe08bb5396170521d
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v26, t2, v12

  li t2, 0x30f604941b32a678
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v6, t2, v26

  li t2, 0xf2bf2dfbf9278233
  vsetvli t1, t0, e16, m1, ta, ma
  vwmacc.vx v14, t2, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v24, v8, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v4, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v24, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v16, v8, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v24, v4, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v16, v4, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v24, v4, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v8, v12, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v12, v4, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v12, v16, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v24, v20, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v16, v4, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v8, v12, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v4, v16, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v8, v4, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v4, v12, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v8, v24, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v4, v8, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v4, v16, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v12, v20, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v24, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v28, v4, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v28, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v28, v16, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v16, v24, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v24, v16, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v16, v24, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v8, v28, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v12, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v28, v20, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v8, v20, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v4, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v4, v24, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v28, v8, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v8, v16, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v12, v8, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v12, v16, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v24, v4, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v12, v28, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v12, v4, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v28, v8, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v28, v20, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v24, v8, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v4, v28, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v8, v20, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v24, v12, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v28, v20, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v24, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v28, v12, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v24, v8, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v16, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v4, v16, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v24, v28, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v4, v12, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v24, v12, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v12, v28, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v28, v16, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v24, v16, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v24, v8, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v28, v20, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v4, v12, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v8, v24, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v16, v12, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v4, v8, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v4, v12, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v16, v12, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v12, v20, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v4, v12, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v12, v28, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v28, v8, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v28, v20, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v4, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v8, v16, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v8, v4, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v8, v12, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v8, v28, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v28, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v12, v4, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v16, v24, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v16, v4, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v28, v16, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v12, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v28, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v8, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v4, v8, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v4, v28, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v16, v20, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v8, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v8, v28, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v12, v20, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v12, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v4, v28, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v24, v4, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v28, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v20, v12, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v12, v28, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v24, v28, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vv v28, v16, v12

  li t2, 0xb78db6c5c6c00c61
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v16, t2, v28

  li t2, 0x67c68fd9878ae063
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v20, t2, v4

  li t2, 0x680d0ab4d625fc98
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v20

  li t2, 0x7eb9b51c7f0e041d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v12

  li t2, 0xcad1103db7478b24
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v4, t2, v20

  li t2, 0x1f24d78e5cbeb26a
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v24, t2, v4

  li t2, 0xc8fe20d23d18f9fb
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v4

  li t2, 0x9067f56c5f3d78de
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x9f537581f9ef3a2d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v12, t2, v4

  li t2, 0x15371161c2b9ce1e
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v12

  li t2, 0x636f9af134a87666
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v20, t2, v4

  li t2, 0x7dc0064ffa553bf3
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v20

  li t2, 0x1220e5191aca81d5
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v12, t2, v20

  li t2, 0xba6dd814a5215f12
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xddad24196ec4a529
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x3399d45d301dad8a
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v4, t2, v8

  li t2, 0x646fe5e88ce345be
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v20

  li t2, 0xf49a1d6e6a090c54
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v16, t2, v12

  li t2, 0xd11b44d24e04a7df
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v24

  li t2, 0x29e2eb6b5b261c1e
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v4, t2, v12

  li t2, 0x564d15b1acab2a7a
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v20, t2, v8

  li t2, 0x5844ac7ac6dae11a
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v12, t2, v4

  li t2, 0x6d18ac0ba3549499
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v4, t2, v28

  li t2, 0x8693ad0ce800b7e7
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v12, t2, v28

  li t2, 0xf6d32e199d74b72e
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v24, t2, v12

  li t2, 0x7735b45d932b4e93
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xe00f866208fff0ea
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v4, t2, v16

  li t2, 0xb05d1d82c8e5a9bb
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v20, t2, v4

  li t2, 0x9914523b4e85143d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v24, t2, v4

  li t2, 0x46a4977edae7c496
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v24, t2, v20

  li t2, 0x2534ac79a0b82b29
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v16

  li t2, 0x325a23f445a49c51
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v12

  li t2, 0x3f1595f689bd5294
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v8

  li t2, 0xa90ea1208bb3cab3
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x754aebff6dd0e4b5
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x7a6b54e608cb5e39
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v24, t2, v12

  li t2, 0x636c345f6fa47bfd
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v20, t2, v16

  li t2, 0x57a28f684d117865
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v16, t2, v4

  li t2, 0x2149ec3e9dbc41fa
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v4, t2, v20

  li t2, 0x9e64e2a19c806171
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v20, t2, v4

  li t2, 0x19a501bfb5cfcc13
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v16, t2, v4

  li t2, 0x1ed53b0b7dcc38c2
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v20, t2, v4

  li t2, 0x20cc067c63527896
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v12, t2, v20

  li t2, 0x8340b67090649a9c
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v20, t2, v8

  li t2, 0x0d4b9ee9fb76d227
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v24, t2, v28

  li t2, 0x2c5ae111fc4e7202
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v20, t2, v24

  li t2, 0x8077084ab168857b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v16

  li t2, 0xbb532d94383a7d5f
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v12, t2, v16

  li t2, 0xc14d129bc7ab5751
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x41aab51c196300d3
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v20

  li t2, 0x7fa28206c7c5bb7f
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v16

  li t2, 0xdbac58896af73a91
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v20, t2, v8

  li t2, 0x9b2f3e9909314199
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v28

  li t2, 0x50391e41a259d48d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v12, t2, v8

  li t2, 0x342f6df59c9a6161
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v16, t2, v12

  li t2, 0x98add0fe6ccd711b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v20, t2, v16

  li t2, 0xf314f76b55101db4
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v4, t2, v16

  li t2, 0xde41baf101dc342f
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v24, t2, v12

  li t2, 0xd95e9964ad3c9ccd
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x43909f8e262e208e
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v20

  li t2, 0x60769aaea3cfb6c2
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v24, t2, v12

  li t2, 0x9c5b0d154ee027a5
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v16

  li t2, 0x0c7ff05745b24299
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v20

  li t2, 0xd53218122b7efcbd
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v12

  li t2, 0xb9f9138d68547726
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v8

  li t2, 0x98f1fc124681e4e0
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v12

  li t2, 0x7fe439448f291c67
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v16, t2, v20

  li t2, 0x1bcf18f5598f6b61
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v4, t2, v28

  li t2, 0x1a0682cbb20d6d5b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x3a34370bc486c18e
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v4, t2, v8

  li t2, 0x2b00643028d40567
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v12, t2, v4

  li t2, 0x48e9a0ed3d4a680e
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v16, t2, v4

  li t2, 0x566ebda4a0f02add
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v12, t2, v4

  li t2, 0x96fab154c36f77bd
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v4, t2, v16

  li t2, 0x5835740a9de65df3
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xd043ebf25ab416eb
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v16, t2, v4

  li t2, 0x246c2a77faab204b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v12, t2, v28

  li t2, 0x78418fa37f66d95b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x45988645b4a4382b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v4

  li t2, 0x66cf561a3415bf52
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v20, t2, v24

  li t2, 0xece3e8e498676af1
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xfce4090ea420a7aa
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v24, t2, v4

  li t2, 0xf827b206cc3d6a8a
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v20, t2, v12

  li t2, 0xfe1db90db761eaf7
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v20, t2, v8

  li t2, 0x254b7af8ab5bc7f0
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x7038ad679a905524
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v8

  li t2, 0xea7501568ddcc0c1
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v24, t2, v4

  li t2, 0xace2bbbc9c15e24a
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v24, t2, v20

  li t2, 0x783343c754e34e23
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xa670b202c1ead414
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v24, t2, v4

  li t2, 0x77b171fe2d2d6965
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v28, t2, v16

  li t2, 0x5e939e3aa82eb861
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v4

  li t2, 0x5d743192b5a17bf9
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v12, t2, v8

  li t2, 0x7104e96d9b8cd931
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v8, t2, v4

  li t2, 0x9fbfe6f3bdd7e4f7
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v12, t2, v24

  li t2, 0x2b738831a0391e88
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x584f60bc3be08dc3
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v20, t2, v28

  li t2, 0x56474c65296668c9
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v24, t2, v4

  li t2, 0x4c63b01f6de62418
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v16, t2, v20

  li t2, 0x0e45dd4a58a4cc02
  vsetvli t1, t0, e16, m2, ta, ma
  vwmacc.vx v12, t2, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vv v16, v8, v24

  li t2, 0x8d68cd25efe623a0
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x1104ee0d4b4a2800
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x3a49560899612042
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xf9cd0458677a3e29
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x092f2b81630406e2
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xe98a9cf098a20040
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x114ac93f681cc5ee
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x3e7f915b56dcf97b
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x979f8e34dc066e0a
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xa78fa21478e94ba0
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x53fd1abca4b5b7a7
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xd87ccdcd658394fe
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x797e74c3548422a2
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xda21e8ab42d63908
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xadd0626e405cfd15
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x11c0936e43c5de35
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x87366561849c5cbb
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xdd693d0507aafe08
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x761db9db8494017d
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xf00af0358b566cef
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x50484632992951ef
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xd0b70cf554ecd4cc
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xe1d2efc0f39a9049
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xd66c6be6574fa250
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xf5db0abd590c90cc
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xf70ced1a05772dbf
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xcfefa82c1f24f435
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x788380ab202f9699
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x1177d8e98179ada7
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x2e2feb74a36e6343
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x1f09f4145a818957
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xd192252a723b30eb
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xdb011cb35d50762f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x6b3636249c5bd217
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xfc6e41e32f9def1a
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x13e492e4bce97f78
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xedc7d683c0e33d56
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x40b7363044c20400
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x410341fb194c99eb
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x2ca566d6599bd2c9
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xc8f82a6ceb42c714
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x177faf02c8bef053
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x57e5bcd9b0ffffe2
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xd207c6be7d5fbda6
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xbfbf36152eb46d67
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xca4043e07c82d068
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x7689ab51e70be9c1
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x8cf92525086e3212
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xf56de1c9a3f67d55
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xb1d8ee6b00ec7710
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x872498cd5b6d399b
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xad5acf57cdcde6e8
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xd16eaf302cb7fbea
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x01f4e2df17238996
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x1e8923de7bacf63a
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x93ab48a9000bf16b
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xf760605fa0f8a7f7
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x4d32d5c2319016ab
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x5ce9aa3714f6bc3f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x469a8d4fe6156aa6
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x56db2964bb5a485d
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xbcddccade887492b
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x897d0d9594712ffb
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x20c86fc20cb2ac44
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xb4a74aeef8eaf5f6
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xdbf8ccf0f5751288
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x736447c4200b859f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xfee75c0773d9c74c
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x33af0da1776d070c
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xdadf277e114b868a
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xff2429899ffefa76
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x202faa137246fb52
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x852cf55e05fb12bf
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xa2aaf8f776a94d66
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x83f02f1fad93db99
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x1a46c45b1d80d07c
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x7301afe1ed4a474f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x13a66e5a03a7c00c
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x5d680d9ed7503a64
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xa6793257e9373e90
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xf34de244ca6cef4b
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xdb32cad911b676c7
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xa237cf839c39bbeb
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x6f76c224d9684c97
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x554a78a2790dcbda
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x96ebfee5c042d6ce
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x08238bfd7fb06252
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xd2081bf79b4eaa18
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x14076e2bff4dd9e1
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x4bedd3dad6ae72e2
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xf5cbe569ea0aaf11
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x2a1e3948f2ccc3a7
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x520b3dd3773b2eb9
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x5ccaf1c0f91c8e12
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x6f604ac70cec67ab
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x6b7240b18a43d2e0
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xccfc7c333bd9f744
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x73de2214235224c9
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x54baf9aa0d166bd3
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x9f095b5be0e0154b
  vsetvli t1, t0, e16, m4, ta, ma
  vwmacc.vx v16, t2, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v24, v18, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v2, v22, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v14, v18, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v28, v4, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v30, v14, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v22, v4, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v30, v10, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v30, v4, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v24, v30, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v12, v30, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v16, v30, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v14, v22, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v30, v24, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v24, v18, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v2, v10, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v30, v14, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v20, v30, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v4, v30, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v24, v6, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v8, v26, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v6, v2, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v18, v10, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v30, v10, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v2, v28, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v26, v28, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v14, v6, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v28, v4, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v30, v26, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v30, v2, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v12, v24, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v2, v10, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v24, v30, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v28, v18, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v18, v6, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v26, v16, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v10, v26, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v18, v16, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v12, v18, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v2, v8, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v24, v12, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v4, v12, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v14, v4, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v10, v24, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v22, v2, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v14, v10, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v26, v6, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v12, v24, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v12, v22, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v8, v30, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v4, v20, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v26, v22, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v10, v30, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v2, v8, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v22, v20, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v18, v24, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v8, v26, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v16, v12, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v6, v2, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v20, v10, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v22, v8, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v8, v14, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v6, v18, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v2, v4, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v8, v22, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v18, v10, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v24, v14, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v20, v16, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v22, v18, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v4, v24, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v6, v14, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v14, v24, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v30, v6, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v6, v8, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v4, v16, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v10, v4, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v14, v6, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v4, v2, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v30, v26, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v6, v26, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v14, v22, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v2, v28, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v10, v6, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v16, v28, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v24, v10, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v22, v2, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v14, v2, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v14, v6, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v28, v8, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v2, v10, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v6, v30, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v26, v28, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v24, v28, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v10, v16, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v10, v30, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v24, v20, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v6, v8, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v20, v26, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v6, v14, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v10, v22, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vv v14, v24, v18

  li t2, 0x6c337ea32332fe27
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v8, t2, v14

  li t2, 0xe280b04f3f07b6a9
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v30, t2, v10

  li t2, 0x5c637d8b8ec01514
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v16, t2, v18

  li t2, 0x4ff92b28ef81d845
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xc82367b530bb22ef
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v30, t2, v6

  li t2, 0xb60fa4be43f02af5
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v18, t2, v20

  li t2, 0x1b037f21458720b4
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v20, t2, v28

  li t2, 0x8fe0109f8040eac6
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v6, t2, v22

  li t2, 0xb0da84690e47c700
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v10, t2, v8

  li t2, 0xf0caec673cab5dcf
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v14, t2, v16

  li t2, 0x582d105d5e407330
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v4, t2, v24

  li t2, 0xa85d9ca80d858ac1
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v12, t2, v2

  li t2, 0x39c025e38bfbf592
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v22, t2, v18

  li t2, 0x02250431807ebf3a
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v22, t2, v30

  li t2, 0x5659d952f32af69b
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v18, t2, v16

  li t2, 0x184f6886d2031d23
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v18, t2, v16

  li t2, 0x6a22356dcd0975aa
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v12, t2, v26

  li t2, 0x576990fbce037987
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v16, t2, v22

  li t2, 0xac04284f7ad65a76
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v12, t2, v30

  li t2, 0x971561edb766a7ca
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v24, t2, v4

  li t2, 0x4ee8b0513cfd5060
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v24, t2, v4

  li t2, 0x29e2cd6bada2fcf3
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xc71264fa3d931a20
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v28, t2, v4

  li t2, 0x67eff507a12cfd97
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v2, t2, v18

  li t2, 0xb9c1e3986bee59e2
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v20, t2, v4

  li t2, 0xb4cc2bedb5f43802
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v18, t2, v12

  li t2, 0x097344ca53787a29
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v10, t2, v16

  li t2, 0xb7b7fdd55134d879
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v20, t2, v6

  li t2, 0x0c0ae04efc1843ba
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v4, t2, v26

  li t2, 0x43d0bfe6174392d1
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v28, t2, v8

  li t2, 0xe8f964c9fbd562b4
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v10, t2, v26

  li t2, 0x859850cb1d2a9d49
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v6, t2, v16

  li t2, 0xed69bba275b62742
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v10, t2, v6

  li t2, 0x52a413b5229c1103
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v30, t2, v14

  li t2, 0xdcd99259fe8c7074
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v22, t2, v28

  li t2, 0xdcc0d49a280f481c
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v16, t2, v12

  li t2, 0xa432d422daac55a3
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v20, t2, v6

  li t2, 0x636edb9cc0792f10
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v16, t2, v28

  li t2, 0x3018b8c5df05f6cf
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v8, t2, v4

  li t2, 0x27e11183c177123e
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v28, t2, v6

  li t2, 0x9f94dda062353df0
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v4, t2, v16

  li t2, 0x28e56acbb3013561
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v10, t2, v22

  li t2, 0x6e0abb8deab6308a
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v28, t2, v4

  li t2, 0x8b56809b4f760cd1
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v28, t2, v20

  li t2, 0xc7d3a34455a28d8a
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v20, t2, v22

  li t2, 0xeee2d4cc0272380d
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v2, t2, v30

  li t2, 0x541e85c3e07eccf1
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v22, t2, v18

  li t2, 0x5ef77dd35272b30d
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v12, t2, v22

  li t2, 0xb644fa2bf7726cad
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v20, t2, v22

  li t2, 0x2fd52970a6307457
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v26, t2, v10

  li t2, 0xf713c923344322a8
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v16, t2, v6

  li t2, 0x07360e5ada29eacc
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v2, t2, v8

  li t2, 0xb1172cfaef8a6c37
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v2, t2, v14

  li t2, 0x70fca70b3e126fa4
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v4, t2, v14

  li t2, 0x7cd2af8fe4a2b050
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v30, t2, v2

  li t2, 0xf26ef3badee5c7f2
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v26, t2, v16

  li t2, 0x6d44f5687f825f60
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v18, t2, v30

  li t2, 0x239269565e245bd8
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v16, t2, v2

  li t2, 0x356e06c0d3b7ba2b
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v6, t2, v8

  li t2, 0x1f8338be69a36947
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v28, t2, v18

  li t2, 0x77e509b2e9738157
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v18, t2, v6

  li t2, 0x71ab360833f60dc2
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v18, t2, v12

  li t2, 0x3d15d692c4446aab
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v24, t2, v30

  li t2, 0x3e0c9ce7d8effe87
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v2, t2, v16

  li t2, 0x8fef666c6f285224
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v2, t2, v16

  li t2, 0xd6dffdaffb241adb
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v30, t2, v8

  li t2, 0xaff590d0e53bd8ad
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v14, t2, v28

  li t2, 0xd17111ad90cc1181
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v8, t2, v6

  li t2, 0x218b516b08579482
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xdfca0ed22eb0bc22
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v22, t2, v28

  li t2, 0xb6e3c796f7fce81c
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v12, t2, v28

  li t2, 0xd74d28553f6f3363
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v2, t2, v8

  li t2, 0xcd8a06d3430dab29
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v26, t2, v4

  li t2, 0x28517d9734a79d0f
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v6, t2, v28

  li t2, 0x0e5b26851a70511a
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v4, t2, v10

  li t2, 0x4465af1ba16ee805
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v28, t2, v18

  li t2, 0x99fc555e8c463d44
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v10, t2, v12

  li t2, 0xf18fa0e49cefddb6
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v8, t2, v22

  li t2, 0x72e8b204ef9ff23a
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v10, t2, v8

  li t2, 0x44c1a8ff380f6a38
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v30, t2, v24

  li t2, 0x072e39787d6bcd69
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v18, t2, v20

  li t2, 0xd9e7a7a14f876ea7
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v4, t2, v8

  li t2, 0x3dc73e5284846779
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v16, t2, v10

  li t2, 0x42786bd8ea6bcca1
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v10, t2, v26

  li t2, 0x9c78ad9d636d409f
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v2, t2, v28

  li t2, 0x8fd9d0d8f4747494
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v28, t2, v14

  li t2, 0x4ecbe3fda583856a
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v14, t2, v12

  li t2, 0x8b6733ebb3e069af
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v16, t2, v12

  li t2, 0xd30e97ef1ce2e4fb
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v20, t2, v26

  li t2, 0x3b51a46da43d6bdc
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v6, t2, v30

  li t2, 0x31b897baef74ac59
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x3eea4a42e47cf546
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v10, t2, v16

  li t2, 0x2af608e711d712d1
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v6, t2, v10

  li t2, 0xad2a9b0f0ba82cdd
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v28, t2, v10

  li t2, 0xdbaec7cdf77c0126
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v10, t2, v18

  li t2, 0x8d08d1bc23294f5e
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v18, t2, v10

  li t2, 0x1763aade92d941d1
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v12, t2, v2

  li t2, 0x9c6acddba176e1a5
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v2, t2, v8

  li t2, 0x7e3700de26bc10d2
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v10, t2, v16

  li t2, 0xe38c4e117800d54c
  vsetvli t1, t0, e32, m1, ta, ma
  vwmacc.vx v10, t2, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v24, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v12, v4, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v24, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v16, v12, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v24, v12, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v20, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v4, v8, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v20, v8, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v8, v12, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v24, v28, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v8, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v12, v16, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v16, v8, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v20, v8, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v12, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v16, v24, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v12, v28, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v20, v12, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v20, v4, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v4, v8, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v8, v20, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v4, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v24, v4, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v16, v24, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v20, v8, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v24, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v20, v24, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v4, v16, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v16, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v16, v28, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v12, v16, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v4, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v8, v16, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v12, v24, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v20, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v24, v28, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v24, v28, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v8, v4, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v24, v20, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v20, v16, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v20, v28, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v24, v8, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v24, v28, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v8, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v4, v24, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v12, v8, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v4, v20, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v4, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v4, v12, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v20, v8, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v4, v16, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v20, v8, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v8, v24, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v20, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v12, v8, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v8, v20, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v8, v24, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v12, v28, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v4, v12, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v24, v4, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v24, v8, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v20, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v16, v20, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v20, v24, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v4, v8, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v8, v20, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v24, v20, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v4, v20, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v12, v8, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v16, v28, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v16, v24, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v8, v4, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v16, v24, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v4, v28, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v16, v28, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v8, v20, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v4, v12, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v12, v4, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v24, v28, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v4, v24, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v12, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v12, v8, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v8, v20, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v12, v24, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v24, v28, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v8, v24, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v12, v20, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v8, v16, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v16, v12, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v20, v8, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v20, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v20, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v4, v20, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v28, v4, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v12, v28, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v12, v16, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vv v4, v16, v12

  li t2, 0x689884cb65c200cf
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v20, t2, v28

  li t2, 0x737990d0d4adf46f
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v8, t2, v4

  li t2, 0x87da5a55768b4d41
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v20, t2, v24

  li t2, 0xaa3c3193701ae422
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v8

  li t2, 0x796bb02873209d99
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v24

  li t2, 0x4fd96e278b06cfcc
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v20, t2, v16

  li t2, 0xa86ebd45e3b112d7
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v12

  li t2, 0x77e8c586ec8993eb
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v8

  li t2, 0x6fee03b5ef04e087
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xdb3b192fc2ddfaa7
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v12

  li t2, 0x36f63fc7137d9243
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v20, t2, v24

  li t2, 0x8a827c21362dc08b
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v8

  li t2, 0x63e9f8f65e7e61ca
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v28

  li t2, 0xe53b312cbc218438
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v24, t2, v4

  li t2, 0x6159ebf4ff94e461
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v4

  li t2, 0xf158cb93b3c01eef
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x7c69e54db0017086
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v8, t2, v20

  li t2, 0xd477e87b30e2f1ff
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v8

  li t2, 0x7d201cefe8c1f959
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v28

  li t2, 0xba0073e37dbf074c
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v20

  li t2, 0x2e07b46c8eba4d6d
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v16, t2, v4

  li t2, 0xe421231c0fb7981f
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v24

  li t2, 0x0d7af3a48516fada
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v16

  li t2, 0xc979c89fb52d67ee
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v16, t2, v28

  li t2, 0x9a774a05405fdbdc
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x2a16add289b75c8c
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v28, t2, v4

  li t2, 0xe5745b0f7b8d6fd7
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v8

  li t2, 0xa4387fca76009a0e
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v16, t2, v4

  li t2, 0xbef3e09c15fcfb18
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v16, t2, v12

  li t2, 0xdf07436571ecf913
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v8

  li t2, 0xa6e4f01678e4dc7f
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v16, t2, v28

  li t2, 0x911ae3b45e3393e3
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v8

  li t2, 0xcaa52602d80a8a69
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v8

  li t2, 0x467e407a1a890e70
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v4

  li t2, 0x50570f5b5e97193a
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v8, t2, v28

  li t2, 0xcdefdae469171b4d
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v24, t2, v20

  li t2, 0x9e8f5958d2d3d903
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v24

  li t2, 0x37f30e4094add6a0
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v8

  li t2, 0xef63fea902cc6af0
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v16, t2, v28

  li t2, 0x92e0b4aae419f3d8
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v28

  li t2, 0x1baf4d866c3a3b08
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x24fdab61d4882421
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v8, t2, v28

  li t2, 0x27918884c51f5f99
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v16, t2, v20

  li t2, 0xd85f1c588b072fb3
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v8, t2, v20

  li t2, 0x4d575e481fdb4498
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v20, t2, v28

  li t2, 0x9f7f375d7897f699
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v16

  li t2, 0x25b07ccf02660a5e
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v16

  li t2, 0x7aa6fe28c30e5ae7
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v16, t2, v20

  li t2, 0x261733105587164f
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v20, t2, v4

  li t2, 0x7c96fd3c7c6372e0
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v28, t2, v12

  li t2, 0x926f306cc590bbf1
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v28, t2, v4

  li t2, 0x8d9ff106ebe8857c
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v28, t2, v4

  li t2, 0x1454e9aeb70df684
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v24, t2, v28

  li t2, 0xef4748cee8bdfca3
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v8, t2, v12

  li t2, 0x1500efbcc22dac8c
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v20, t2, v16

  li t2, 0xbd1660aef7836bd6
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v28, t2, v20

  li t2, 0x627620c588b5fd2f
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v16, t2, v20

  li t2, 0x9fae07a3f8cd5fa1
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v8, t2, v12

  li t2, 0xfc068bbf70fec75e
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v24, t2, v20

  li t2, 0x5136fc87f977d2c5
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v8

  li t2, 0xd89fca70a298d87f
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v24, t2, v12

  li t2, 0x2dcd75587b41ad79
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v4

  li t2, 0x535fa4da625b3ecd
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v28, t2, v8

  li t2, 0xd5223ad10dee938e
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v24, t2, v4

  li t2, 0xdcf3f2b0536affeb
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v8, t2, v20

  li t2, 0x2f3b91cb04181b50
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v20

  li t2, 0xcb8caa8c2c550c44
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v28

  li t2, 0x5a1860280256dd65
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v20, t2, v28

  li t2, 0xc4e77e69da3eb793
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v28

  li t2, 0x9975d4dbd17e98eb
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v12

  li t2, 0x7f610d2954627629
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v8, t2, v12

  li t2, 0xed24962fc86215fb
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v28, t2, v12

  li t2, 0xa0f22b41ec516384
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v28, t2, v16

  li t2, 0xc00c7afd6e76bf33
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v8, t2, v20

  li t2, 0xa066ad05b14ad2cd
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v16, t2, v12

  li t2, 0x57050b61cdfab311
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v20

  li t2, 0x41251cc97f6a5277
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v16, t2, v20

  li t2, 0x01be15f049bb47ec
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v8, t2, v20

  li t2, 0xe09830e899ec897a
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xeb80675d083c1f54
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v28, t2, v4

  li t2, 0x3db4b8debfd515b0
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v24, t2, v20

  li t2, 0xda20131a185678fb
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v16, t2, v20

  li t2, 0x40aa0c807033a342
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v20, t2, v16

  li t2, 0x1f85dd5c877a89a4
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xe115196706de1a74
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v12

  li t2, 0x0cad7187f3bb5c35
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v24

  li t2, 0x8857c56ca9184072
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v24, t2, v28

  li t2, 0xfc7844563d690413
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v24, t2, v12

  li t2, 0xa3b062c249d5f212
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v20, t2, v16

  li t2, 0x8b8e9c49bf450993
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v20

  li t2, 0xd90360a8443aacfe
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v4, t2, v20

  li t2, 0xda760819922dc1ec
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v24, t2, v28

  li t2, 0xd14dc037b5eca385
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v20, t2, v4

  li t2, 0xa3d6b284835e4fbd
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v20, t2, v16

  li t2, 0x1b3109247a9e63cd
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v24, t2, v12

  li t2, 0x9967fc8163fc0496
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v28, t2, v20

  li t2, 0x6da92ab42adb6342
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x062ef05ed887a67e
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v16, t2, v4

  li t2, 0x7d127c216ebd0fdf
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v20, t2, v28

  li t2, 0xc051abc8314d941d
  vsetvli t1, t0, e32, m2, ta, ma
  vwmacc.vx v12, t2, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vv v16, v8, v24

  li t2, 0x409ad81462580b98
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x4f96e8493ce97804
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x965782c770a700e3
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x635c02cbbc195932
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x9162618d22c6b50d
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x1873653424ce4cda
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xd0c4e19e2d891b66
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xed69eae0058dde3a
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x7f070e89c0dc4406
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xd822facfca2c6968
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x68631a5816b28117
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x9c1f1a952ca58c9d
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x7267650ae85dfb5e
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xa676608f9d3d94ce
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xdfa221423abd28e1
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xc1df2b62430b47ad
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x345514c62e12dc49
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xf39a5b496950a0f2
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x48a68279eae53435
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x20f1e1d6abdf8f8c
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x0bb8a419844e04bd
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x9a8010648d750944
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x74062ce8bd856544
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x85b212c79220e6bb
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x9358ce157208904f
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x709e8df5406d445f
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x74c141961e9c3568
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x960052478dd069e3
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x368b62d7f80909e2
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xef0c15879c76f9a6
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xcd55cfeae10da94b
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0x5a175b78805a2639
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x09bb63b22b8586f8
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xa61e5f9c1be179a5
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x09f7d54513ae0bfc
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x93546b9b31c8879e
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xe3ad7a3da4bedaf1
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xea361cee8ffe8ff3
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x5976f4bb6dfde527
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x9caadfaa178a3f7c
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x5b36630dfeeb144b
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xe9b150ba6cf3ac67
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x20fe069d4b1ae38a
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x085fcdbdcf5b87a4
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x154b3daeef074ae1
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x188e338ea4813eea
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x54d363afb364a816
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xdeb083fca8242fea
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x96e387f4d06799a3
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xa302aa68a897f4ba
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x84d1d41cb18f1da3
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x530576b03823e225
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xaf9a07f504246d10
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x7f075adc645732fb
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x9019026b94309678
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xc3e8cfb394c93ce4
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xafca21ea2ef3b903
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xd9c5f406898157cc
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xf9102e3043b50f20
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xbcfa67b8bfa54a2d
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xdbbbb50f0bebed20
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x51ed2a3014653c0d
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xfe63a6d16a95a239
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x9165b870a9be09f0
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xdd7605ddf720fc3c
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xe6f25450b4370d00
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xd82386c90dc0ba98
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xbdbd9f815a8e6a9f
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xe3562be378b4dd9b
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x79718ae18a988d39
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x57e7aab80e873145
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xb0546f1596b17615
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x5d6c2fb82cdf7e23
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x2cc92f718c9c29e7
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0xa96b71e306cfb46d
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xd2644bafe70fe9c0
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x5bdf6c7482ff44c9
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x1933b1ac07e87c95
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x35f38c7449200366
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x17f8814e251c0275
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0xaf58bfc8ed7b4930
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xc1db3bf3c673a6d7
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v8

  li t2, 0xcebe7155b2d72dfd
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0xf48c33c3738d1825
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v8

  li t2, 0x9ff43bc745e2087c
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0xa19642a3d46668e1
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x049312dfc5546d6f
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xd1e30454ef77202b
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x19ab237a282fe761
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x50c8e08196d7c76a
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x0dbf4b107f3a5621
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x299d67c8d559e158
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x5be3fdf1c952cd4f
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0xbd96ba9b45f1bbc4
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x752efc1c213dd010
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x3ed0e8efa64b88de
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v16

  li t2, 0x5b192e437690e9d3
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v8, t2, v24

  li t2, 0x3f3a5b103a53f85d
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  li t2, 0x4109a96e1e2da9f9
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v16, t2, v24

  li t2, 0x09850635d3c8c2d6
  vsetvli t1, t0, e32, m4, ta, ma
  vwmacc.vx v24, t2, v16

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
