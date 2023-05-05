#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v4, v20, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v24, v16, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v2, v10, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v10, v18, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v22, v2, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v6, v24, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v2, v16, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v24, v30, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v6, v2, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v24, v6, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v18, v22, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v24, v8, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v22, v16, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v12, v20, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v10, v6, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v20, v30, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v12, v26, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v20, v16, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v20, v14, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v12, v22, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v26, v8, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v18, v2, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v26, v22, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v4, v22, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v6, v22, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v20, v30, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v20, v30, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v20, v24, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v20, v30, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v24, v18, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v12, v20, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v22, v28, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v2, v16, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v20, v26, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v8, v14, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v8, v2, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v2, v10, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v14, v26, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v22, v6, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v28, v6, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v10, v20, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v10, v6, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v22, v4, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v16, v12, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v6, v20, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v4, v26, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v24, v14, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v26, v10, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v4, v8, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v6, v16, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v6, v28, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v22, v10, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v18, v2, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v30, v8, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v4, v22, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v16, v6, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v26, v28, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v6, v18, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v16, v2, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v2, v30, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v22, v30, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v14, v2, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v24, v4, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v26, v10, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v14, v6, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v28, v8, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v8, v10, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v4, v22, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v26, v18, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v28, v22, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v18, v30, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v14, v30, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v28, v8, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v12, v24, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v6, v22, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v2, v6, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v30, v10, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v12, v16, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v12, v30, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v4, v8, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v28, v4, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v4, v8, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v8, v2, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v26, v2, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v14, v28, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v14, v10, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v6, v2, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v26, v4, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v10, v26, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v10, v22, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v4, v14, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v22, v24, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v4, v2, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v14, v12, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v18, v10, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v28, v8, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v4, v12, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v14, v20, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v12, v16, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vv v12, v16, v28

  li t2, 0x043c7fcebb67b3c7
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v10, t2, v22

  li t2, 0xba49e7d94565f4ea
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v30, t2, v22

  li t2, 0x559de70f38f22533
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xf01d492d7c9f85c1
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v26, t2, v6

  li t2, 0xbc027d4062f77f0d
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v2, t2, v4

  li t2, 0x322394e69bda4baa
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v2, t2, v16

  li t2, 0xb45b3c1981f06fc4
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v24, t2, v10

  li t2, 0xe65ebc7155d8f023
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v18, t2, v12

  li t2, 0xac13e3563bf23386
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v6, t2, v30

  li t2, 0xc2c9fc653b0bd054
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v26, t2, v12

  li t2, 0xbcc09581b4c42d08
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v14, t2, v6

  li t2, 0xa3485f27bc86bcfa
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v26, t2, v18

  li t2, 0xfe1f015ad7a1321a
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x1cd7d60f0c28c2c7
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v10, t2, v26

  li t2, 0xfffdcbf3d5092bd7
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v20, t2, v24

  li t2, 0xd078f848f7d7d4da
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v6, t2, v2

  li t2, 0x91cc479af473bff4
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v22, t2, v6

  li t2, 0x067eb4d75f0ac48f
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v30, t2, v12

  li t2, 0xdc3b8c7c31c8ec9f
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v8, t2, v20

  li t2, 0xec73cf5b6a5aef63
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v22, t2, v2

  li t2, 0x8c771a300cc040a8
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v2, t2, v28

  li t2, 0x97b7a1b11e78eaea
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v2, t2, v24

  li t2, 0xb8530a9ada20af4e
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v2, t2, v4

  li t2, 0xff8c11d35370f5bc
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v28, t2, v10

  li t2, 0xd0f1307d813bc0c8
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v10, t2, v2

  li t2, 0xcd87f8e5035d0303
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v10, t2, v8

  li t2, 0x51d7064e7a024baa
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v28, t2, v30

  li t2, 0x1e48bcecb9d9cfeb
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v4, t2, v14

  li t2, 0xec1a2b32405b46ee
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v28, t2, v10

  li t2, 0xd86fabc73635d718
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v12, t2, v6

  li t2, 0x819425b95df0e245
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v20, t2, v4

  li t2, 0x2548f747df5904d1
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v24, t2, v20

  li t2, 0x9d4348bdea44ec69
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v28, t2, v6

  li t2, 0xfde6d204b5e63b8f
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v10, t2, v14

  li t2, 0x0501874f1b4cc07e
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v20, t2, v6

  li t2, 0xbdba4b8a88ecd38b
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v26, t2, v14

  li t2, 0xbd3cf6345022a84a
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v6, t2, v2

  li t2, 0x1b3455373e778881
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v6, t2, v22

  li t2, 0x5bb54c1c3dc39b80
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v12, t2, v6

  li t2, 0x5fadbf6c9f900a83
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v6, t2, v16

  li t2, 0xa4e2083843782dc0
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v14, t2, v6

  li t2, 0xeeb11a1166048fc8
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v12, t2, v8

  li t2, 0x2068d6ba6446f1bf
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v4, t2, v10

  li t2, 0xb7024fa4d5d283e7
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v30, t2, v2

  li t2, 0x9d8ab4c7b731e096
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v2, t2, v14

  li t2, 0xf7038f150fa0d958
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v12, t2, v2

  li t2, 0xf636e0e696068ef8
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v14, t2, v18

  li t2, 0xf7a7dc95edfac5f5
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v20, t2, v10

  li t2, 0xe5c3d3f8c90e02d3
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v26, t2, v8

  li t2, 0x21bd0d9f608da068
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v18, t2, v16

  li t2, 0x551191b6b0031548
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v2, t2, v16

  li t2, 0x7f8d6139a777ce9e
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v28, t2, v30

  li t2, 0xa9e4f2016d236317
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v2, t2, v10

  li t2, 0x59102da9ab36452b
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v26, t2, v2

  li t2, 0xb794b70b5e71dfb4
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v16, t2, v10

  li t2, 0x0f513fafbac8c260
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v18, t2, v26

  li t2, 0xfc880abdd950f517
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v20, t2, v22

  li t2, 0x12cd2c01e93c975b
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v20, t2, v4

  li t2, 0xf17b7e073fe6ab42
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v20, t2, v16

  li t2, 0x98bd264192bea87f
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v22, t2, v26

  li t2, 0x5d0e021c7c4373fc
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v20, t2, v8

  li t2, 0x392c55ee1af6cc28
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v16, t2, v2

  li t2, 0xe1e8ac8cfa91962d
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v30, t2, v10

  li t2, 0xeeead408688021d9
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v22, t2, v18

  li t2, 0xba152251950078b3
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v4, t2, v18

  li t2, 0xd88d864d19a4ea2b
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v4, t2, v24

  li t2, 0x6a37ac5192c125d8
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v14, t2, v30

  li t2, 0x2bdbc9d7d2f7befa
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v24, t2, v4

  li t2, 0x744943a25285a8e8
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v12, t2, v26

  li t2, 0x211d05154650121a
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v16, t2, v20

  li t2, 0x15e57c009f2ced84
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v12, t2, v22

  li t2, 0xdcfca7340a370382
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v12, t2, v24

  li t2, 0xf4c59aea8e976778
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x08be4ee2abf16dce
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v16, t2, v10

  li t2, 0xe91a3a3e29cd6f34
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v20, t2, v14

  li t2, 0xfac1eae526a8681d
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v6, t2, v26

  li t2, 0x414a005c2458f307
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v30, t2, v8

  li t2, 0xdb6032b8093c0ceb
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v20, t2, v18

  li t2, 0xe63221b37a18776d
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v20, t2, v14

  li t2, 0x0e14c99832980e82
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v10, t2, v2

  li t2, 0xc61f5d93864e11a0
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v2, t2, v12

  li t2, 0xf7484bdb04dae8f5
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v26, t2, v20

  li t2, 0xd9b328fdae4e15b8
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v30, t2, v22

  li t2, 0x616cdbef3ed1fc74
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v20, t2, v14

  li t2, 0xf8acb7badbba4602
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v30, t2, v24

  li t2, 0xc6853f7f076588a6
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v6, t2, v24

  li t2, 0x63de875b79feb581
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v26, t2, v16

  li t2, 0xa0cbde19cde81e06
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v12, t2, v22

  li t2, 0x27c85b5adf3d537c
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v22, t2, v14

  li t2, 0x893700ce16f3a675
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v30, t2, v24

  li t2, 0xb113ace2fcb93c87
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v8, t2, v26

  li t2, 0xdeb8e2119c3b4aac
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v14, t2, v22

  li t2, 0x6a956458f8280e4c
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v18, t2, v24

  li t2, 0xc73e6f8f6d494d46
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v12, t2, v26

  li t2, 0x9f73d2312a85eabf
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v20, t2, v30

  li t2, 0x5c40798f29dde362
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v20, t2, v10

  li t2, 0xfcef1dd2123a6f73
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v20, t2, v14

  li t2, 0x8c8878cb093d69ad
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v18, t2, v4

  li t2, 0x749bc56a5e5cbd62
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v30, t2, v28

  li t2, 0x94c70c1a1cfc1490
  vsetvli t1, t0, e8, m1, ta, ma
  vwmaccu.vx v12, t2, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v24, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v16, v20, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v4, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v12, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v28, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v8, v4, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v24, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v24, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v8, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v28, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v20, v8, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v4, v16, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v12, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v28, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v8, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v8, v28, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v8, v4, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v4, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v28, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v20, v12, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v4, v28, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v4, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v16, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v28, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v24, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v12, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v4, v24, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v8, v24, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v4, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v8, v20, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v20, v24, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v16, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v20, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v8, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v20, v16, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v20, v24, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v20, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v20, v4, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v4, v16, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v8, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v4, v24, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v16, v24, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v4, v16, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v16, v20, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v4, v12, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v20, v12, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v20, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v4, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v4, v24, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v4, v20, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v28, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v20, v16, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v4, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v20, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v20, v28, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v4, v28, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v8, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v20, v4, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v20, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v12, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v24, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v8, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v16, v12, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v28, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v8, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v16, v4, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v24, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v8, v12, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v12, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v8, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v28, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v16, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v12, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v20, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v16, v12, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v20, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v4, v28, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v20, v12, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v8, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v24, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v4, v20, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v16, v20, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v8, v28, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v24, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v24, v16, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v4, v16, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v4, v16, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v16, v4, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v4, v28, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v16, v8, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v20, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v28, v12, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vv v12, v4, v24

  li t2, 0x7700265de3294952
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v28

  li t2, 0x9c3cecb2820cc833
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v8, t2, v20

  li t2, 0xa3ed5c21e194ee69
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v4

  li t2, 0x27cf5a4baae0da0e
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0xe862ea3d82102fde
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v24

  li t2, 0xe52497ee5cb7bd35
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v16, t2, v28

  li t2, 0x877c8d2ac4d0f4dc
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v16

  li t2, 0xa851692a61ab147c
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v8

  li t2, 0x23ce5bc22247459b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v8, t2, v20

  li t2, 0xd75b82582e743886
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v8

  li t2, 0xd11dc1a2a9891c85
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v12

  li t2, 0x61e306c4f02ca019
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v8, t2, v12

  li t2, 0xa0b33daf879d96b5
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v8, t2, v12

  li t2, 0x71d3e7266384ba02
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v24

  li t2, 0xc1fae89a9764e095
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v24

  li t2, 0x6773b59dc333cdcf
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v20

  li t2, 0x9f6668dc339a0c72
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v28

  li t2, 0x0d306be36d121c06
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v8

  li t2, 0x22fe86b4eb6aae4b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v16

  li t2, 0xd0e8ee0a77536a6a
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v20

  li t2, 0xaced4ba275f8380b
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v24, t2, v28

  li t2, 0xc39adc4baa7cd539
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v4

  li t2, 0x4f04ea03596d2e20
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xc49559688b139ec7
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x40538ab540ebedf0
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v16, t2, v12

  li t2, 0x2bd98c78b7d6acf2
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v24, t2, v4

  li t2, 0xfe7f8385c8add9d6
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v8

  li t2, 0x61bd0f028e295910
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v20

  li t2, 0xd68f18197f168b56
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v20

  li t2, 0x886913960e401d7a
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v24

  li t2, 0xf5e99ce1528da134
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v8, t2, v4

  li t2, 0xc3fee14b93327105
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v24

  li t2, 0x8cab79f87808f383
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v20

  li t2, 0x11373e13888b8cc5
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0x3f23a62b9b1a9fd5
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v20

  li t2, 0x33a42f6982505ae5
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v20

  li t2, 0xe9123e67c2e38282
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v24

  li t2, 0xad8d8843da8d42a7
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v8

  li t2, 0x1759903ccb4d94e1
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v20

  li t2, 0xdece2fbb81a4e2d4
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v16

  li t2, 0x12d2e744a32bc2fe
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v28

  li t2, 0xaef0b9de8b1f2ac5
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x7bb30fef94e42982
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v20

  li t2, 0x3c13b8749c6c6ded
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v24

  li t2, 0x14d4867868198bec
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v24

  li t2, 0x6d53f46438278cfb
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v28

  li t2, 0x9372e42f39bca23e
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v20

  li t2, 0xcb9104bd7800c5d8
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v4

  li t2, 0xf3cfba7acef4a13a
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v8

  li t2, 0x6ba0c1ed4385d378
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v8

  li t2, 0xb5fd68727894fa84
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v20

  li t2, 0xe6e37b39c155be55
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v24

  li t2, 0x68a148a74c895196
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v4

  li t2, 0x5c95a4e8674c1d81
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v20

  li t2, 0xe984f68238d900cf
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v24, t2, v12

  li t2, 0xc0b5f1a43b7f28df
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x5cbb3b203c124152
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0x4068c7a9a012ace0
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v16

  li t2, 0x5775a3b663f6d606
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v24

  li t2, 0x3d5120498cbf3c4c
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v20

  li t2, 0x7adcb7ed1c7aa0c5
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0x83873fcc3ecbfc00
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v28

  li t2, 0xddfc2011bd5414bd
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xa826f52eb860835f
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v16, t2, v28

  li t2, 0xdb83332322b0c445
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v24, t2, v4

  li t2, 0xd8fa33b60b017862
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v28

  li t2, 0xe8ee16dded9e7a12
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0x45261bcda5e322cd
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v20

  li t2, 0x11adc56bc9a39ee0
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v4

  li t2, 0xb97d13a5d838c892
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x1d0d7345d4aab2c3
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x82253cfcd19b2018
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x0426880855ede83c
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v16

  li t2, 0x9979d18c7b874cc5
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v16, t2, v20

  li t2, 0x14336999ac1cd3a7
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v8, t2, v4

  li t2, 0xcbcb38718f8e05f5
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v8

  li t2, 0xe33d6154ae5c5f99
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0xe5e6a5429faf76d3
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v12

  li t2, 0x6e430a2ba45ab5d0
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v28

  li t2, 0xfe6db9f24c542aaf
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v4

  li t2, 0x057ab7132e63e97e
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v16

  li t2, 0xf789f557c504e771
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v24

  li t2, 0x83d76ebdd2864ccd
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v20

  li t2, 0xb084437ebc0cccc5
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x32f65d75e990af66
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xdc109c768cb63adb
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v8

  li t2, 0xeca352dc07db5051
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v20

  li t2, 0x7c69bd269b6c992e
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v8, t2, v12

  li t2, 0x8eb9cdf24c34c45f
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v12, t2, v20

  li t2, 0xa69f483270f776f4
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xe7ae5b76b6e48128
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v8

  li t2, 0x6949af5d3386f78d
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v20, t2, v16

  li t2, 0xb767b483e0bdf6f8
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v20

  li t2, 0xc2ae77387b001611
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v4, t2, v12

  li t2, 0xda9b465e9b304de3
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v4

  li t2, 0x8a8c66684089137e
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x3d99ccfd10b87e35
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v16

  li t2, 0xf9b79df1bfca0035
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v8

  li t2, 0xc6762c07ab2cd26d
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v28, t2, v24

  li t2, 0xf3e79bf8177e131d
  vsetvli t1, t0, e8, m2, ta, ma
  vwmaccu.vx v16, t2, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  li t2, 0x7b4545822dc76f0f
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x41a03213d9c304d8
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x7a814066a77d62cf
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x03f4f45b76918cc2
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xb9622743d09a8080
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x00e0552f45d5af48
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x39bea5f3e9f6aa09
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xc96302df6c58d61c
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x08552c9cfc567f9b
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xbd2082c0ca03241d
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x25632d65982a407b
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x6096b1fbfd86ba81
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xf6db76f854bb7722
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x4ece1f557963de57
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xea97887133aa1a33
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xdb073aa75c1f7469
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x7ca8a21f882eb6e3
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xd681254e536f6af4
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x5cc00e0951a41543
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xf62854a4843f615e
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xb47cd9303d78d2a5
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xee0163b189910b3e
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xe340c35aafb71c8b
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x2107ab72508fe613
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x8f5d6ae3ea1a5304
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xe063b2fd7898a974
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x248d97abf4ee3662
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xf15246465e580ffb
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x0f4654b1ee44b590
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x10123621cd80916e
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x10581a42d789d427
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xf49f48d95c715087
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x70bd0f134cbe8b02
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x71e1fb25226f2294
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xcfaf9dac3f7a175e
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xd0e8e023a9660b4a
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xcf396c26d361db0f
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xc7ecb7f48bdbe57d
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x61529da95d12ce78
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xbbf4295de25ae44c
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x9756733974185527
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x1e5463a93b0e81f8
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x3e3aa7022c250a39
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x0827d0dc01c6a284
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x356490339eeeaf33
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x940edcf5202dc2ca
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x3bc5731b98b151cd
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x667ae8cdc9970080
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xbe55d3f08c3cf00b
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x4da691c169a1b5f0
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xeb917b81efc590c7
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x264bc9aacad9e439
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x7c006ab226867814
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xa43e157eb89d6983
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x33bf7b7b2211f82f
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xac5f47894d4f5a33
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x0aea02809db3266a
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x572438b970114f3d
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x6db33efca2efbe29
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xc6ed7a24febbfbbc
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x04a74806ec4c4964
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xfd26f9f739acadd4
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xd3c7bcdb8d102db8
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x61f2f3d4e1c61b4e
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x51957f6fcf632157
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x7202290233c6e0db
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xf75e02cd5ccf077b
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x026498a694902aa0
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x94fb11ee6780c3c7
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x598d95f20cd12abf
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xcba18dbed062fe1f
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xab34eedbd2efbbbc
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x42883a70987fb49b
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xc94ae131cb2d95d4
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xf750cc2c223657af
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xc9d6b9a6a061f672
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xf79e2a50fec95a8b
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xd09a87d2d12d4649
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xbaa478e876319f7b
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xa6632d2f318eb4dc
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x9aef5c6abdcdb6e1
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x39bfaedd55f00f9e
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x43240766ce175730
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x4076c8715f704156
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x18ca9cb8595a61fa
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x2e072bd4adc9d978
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x461adf9951052111
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xb5e98b9b0af14a04
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x45433e3b51f33681
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x5949e70755b1869a
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x061c27b06ba01527
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x26fe92ff4d275e38
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x5a25325bd70afc9f
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x81e77daadc800ad2
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x7183c29403b7c2e4
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x647ec360c7017c85
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xb586b8ee853c69a9
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xa29974b314384a6a
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xd6daf722c6bfd75c
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x36669513a0d53b44
  vsetvli t1, t0, e8, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v20, v8, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v16, v10, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v22, v20, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v30, v4, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v30, v12, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v10, v14, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v20, v10, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v30, v10, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v6, v26, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v10, v24, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v2, v8, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v28, v2, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v14, v18, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v2, v14, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v30, v20, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v14, v16, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v18, v26, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v10, v30, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v26, v18, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v30, v18, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v18, v14, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v16, v4, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v28, v22, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v6, v26, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v8, v30, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v30, v26, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v2, v8, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v22, v26, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v2, v22, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v14, v16, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v18, v8, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v22, v24, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v8, v10, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v10, v6, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v10, v28, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v26, v4, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v24, v12, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v26, v20, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v16, v20, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v18, v16, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v18, v16, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v22, v28, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v22, v10, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v18, v8, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v28, v6, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v10, v6, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v6, v16, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v30, v24, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v20, v6, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v22, v12, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v16, v2, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v26, v16, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v20, v10, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v30, v14, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v2, v24, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v2, v18, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v28, v22, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v10, v28, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v20, v26, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v30, v4, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v16, v22, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v20, v18, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v12, v22, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v24, v16, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v2, v4, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v24, v4, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v30, v2, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v30, v6, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v12, v18, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v14, v12, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v12, v16, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v14, v28, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v20, v28, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v12, v16, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v4, v16, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v12, v8, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v22, v4, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v6, v30, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v2, v24, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v4, v24, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v20, v28, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v6, v10, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v16, v28, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v24, v20, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v4, v16, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v28, v18, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v2, v18, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v16, v22, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v26, v28, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v14, v6, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v26, v28, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v28, v18, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v2, v8, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v2, v12, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v24, v28, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v8, v6, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v22, v10, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v30, v20, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vv v4, v18, v12

  li t2, 0x26d8f272917f1b48
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v16, t2, v20

  li t2, 0x5124d4fcf33a2a0a
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v28, t2, v16

  li t2, 0xbc102469255029db
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v4, t2, v30

  li t2, 0x3d71dcf58346628d
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v28, t2, v22

  li t2, 0x5cbf388fdd6dbdee
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v8, t2, v26

  li t2, 0x8ff7ecf6557cc6d9
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v12, t2, v24

  li t2, 0xc94881bea2e5aa80
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v28, t2, v10

  li t2, 0x5847266a6b1060fa
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v14, t2, v20

  li t2, 0xa0ee2b5fdaf2adbe
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v12, t2, v14

  li t2, 0x70e46e2a40c6ade4
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x217445591fc7e911
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v4, t2, v12

  li t2, 0x332411757d1e7ea7
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v26, t2, v22

  li t2, 0xf4498100751a7bca
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v30, t2, v12

  li t2, 0xeb921d9903f98dcd
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v14, t2, v16

  li t2, 0xf4585b13cce443b5
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v30, t2, v22

  li t2, 0xb09c51e5a89317f6
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v24, t2, v10

  li t2, 0x8a00e5f3f62af6ef
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v2, t2, v14

  li t2, 0x70a9737d4e0c9dbf
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v22, t2, v8

  li t2, 0xdb50d32aef585e36
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v10, t2, v8

  li t2, 0xf4a1c604393e4f9f
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v28, t2, v16

  li t2, 0xdec7c2d808795098
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v20, t2, v6

  li t2, 0xe65223f671542f7e
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v30, t2, v4

  li t2, 0x8e82bd0707b385c5
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v6, t2, v8

  li t2, 0x1e596e851a099e8d
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v4, t2, v26

  li t2, 0x43eac46cfdb0e733
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v14, t2, v26

  li t2, 0x93d805576da09dbf
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v20, t2, v10

  li t2, 0x515dcde4f36dd1f7
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v20, t2, v28

  li t2, 0x77826544ef91854b
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v20, t2, v2

  li t2, 0x4357e89f01c40103
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xbd646d98b2de40e4
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v24, t2, v10

  li t2, 0xf9808efeca2d6859
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v16, t2, v14

  li t2, 0x559547528743ae71
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v26, t2, v16

  li t2, 0x6607ee298f675185
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v22, t2, v26

  li t2, 0x91a6af74a50bd833
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v30, t2, v4

  li t2, 0xa3567a132e5d194d
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v2, t2, v4

  li t2, 0xa630b720b88cc7ee
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v18, t2, v10

  li t2, 0xe2c7068f3ca6eb26
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v28, t2, v4

  li t2, 0x5360515e2d82e40d
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v14, t2, v2

  li t2, 0xb46fd19a62363776
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v18, t2, v28

  li t2, 0x32ee2b0b02d7229d
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v10, t2, v4

  li t2, 0x456d3f0f11c53b05
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v4, t2, v28

  li t2, 0x1ae4b9750fb2400c
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v12, t2, v18

  li t2, 0x31c8b3cd09e15876
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v6, t2, v10

  li t2, 0x1fd6bd1a2c2a9db8
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v4, t2, v30

  li t2, 0xdb1269861b69a735
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v20, t2, v28

  li t2, 0x218c9a205249ed23
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v28, t2, v6

  li t2, 0xe643b02d5a538d9e
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v6, t2, v28

  li t2, 0x91fbc85cdfbf01cb
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v18, t2, v16

  li t2, 0xc4024ef8be334ccc
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v12, t2, v4

  li t2, 0xbd06f33158b2d304
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v2, t2, v8

  li t2, 0x3b4061eba22ff8e5
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v12, t2, v30

  li t2, 0xa227a9d6c61bd85b
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v16, t2, v30

  li t2, 0xfdc547d7b8ee6eb2
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v30, t2, v20

  li t2, 0xe88708bb6652ca85
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v6, t2, v14

  li t2, 0xc2f22250f230801a
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v28, t2, v4

  li t2, 0x046acd52e0964d0a
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v8, t2, v18

  li t2, 0x36a146cc99ba694c
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v12, t2, v2

  li t2, 0xf8d134b3edbc9259
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v14, t2, v26

  li t2, 0xc06077b55647789e
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v10, t2, v24

  li t2, 0x8698613904076f11
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v20, t2, v22

  li t2, 0x7dde827e2cc4764c
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v12, t2, v16

  li t2, 0x89a683e892c408de
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v8, t2, v6

  li t2, 0x29973be529312954
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v26, t2, v12

  li t2, 0xfeb6afb27c8b5810
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v30, t2, v4

  li t2, 0xc9f15bd08374bea8
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v22, t2, v20

  li t2, 0x646e0042854c05c6
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v12, t2, v26

  li t2, 0x526b88c7efb0eeef
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v18, t2, v6

  li t2, 0xf10f9249bddc9d0f
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v22, t2, v6

  li t2, 0xdb5159a4a22f6d36
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v18, t2, v10

  li t2, 0x73c91a287a0364f2
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v10, t2, v6

  li t2, 0xfa24e7eabccf6b9c
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v30, t2, v16

  li t2, 0x8344de4dba5c7e0f
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v12, t2, v20

  li t2, 0x774f347566303b96
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v26, t2, v4

  li t2, 0x80213e19f3e6d6ac
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v2, t2, v16

  li t2, 0x92d0985641655f91
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v28, t2, v16

  li t2, 0x0c82bd762d41ab4f
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v10, t2, v22

  li t2, 0x8f92125de908aa61
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v4, t2, v12

  li t2, 0xeb3a58fa8c279aae
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v20, t2, v30

  li t2, 0x3eb90f62881f93d9
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v14, t2, v30

  li t2, 0xcc8c9f6a4f8d9df8
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v10, t2, v2

  li t2, 0xc0624108855eaaa3
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v6, t2, v28

  li t2, 0x092369120f502a5e
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v8, t2, v18

  li t2, 0xd8873857acf9763c
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v8, t2, v22

  li t2, 0x2e6d168a65a32e04
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v14, t2, v16

  li t2, 0x34fa25efa7aa1566
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v10, t2, v20

  li t2, 0x3a48e3abdab556c4
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v16, t2, v14

  li t2, 0x78e9c5777bcd8e97
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v4, t2, v14

  li t2, 0x3c9dc5d55e39852b
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v6, t2, v12

  li t2, 0xbe03c92722bd73ed
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v28, t2, v16

  li t2, 0xb55c970701ed1f1e
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v12, t2, v24

  li t2, 0x0d31c73c438f2f2a
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v28, t2, v18

  li t2, 0x58442f6ab9b95c9c
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v16, t2, v12

  li t2, 0x36250aee176402a0
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v8, t2, v2

  li t2, 0x870160d94fad5d65
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v20, t2, v8

  li t2, 0xa34505579c904f21
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v8, t2, v12

  li t2, 0x4ae108a91af092d2
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v14, t2, v22

  li t2, 0x9951f85b93f47daf
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v2, t2, v10

  li t2, 0x48fff46c53f896fe
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v20, t2, v8

  li t2, 0xd685bf8d08f64e35
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x24987775592a4d69
  vsetvli t1, t0, e16, m1, ta, ma
  vwmaccu.vx v2, t2, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v24, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v16, v4, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v16, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v16, v24, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v16, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v20, v4, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v16, v28, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v20, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v24, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v20, v4, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v16, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v12, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v20, v4, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v4, v8, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v16, v4, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v4, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v4, v8, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v20, v16, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v8, v12, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v28, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v8, v16, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v8, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v8, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v4, v12, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v16, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v16, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v16, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v8, v24, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v12, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v16, v28, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v12, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v8, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v20, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v24, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v20, v28, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v4, v16, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v4, v12, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v8, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v28, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v12, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v20, v8, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v20, v24, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v4, v12, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v20, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v4, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v28, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v20, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v20, v28, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v20, v28, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v4, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v20, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v20, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v28, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v16, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v24, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v16, v8, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v28, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v8, v16, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v20, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v8, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v8, v4, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v4, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v8, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v4, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v16, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v4, v28, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v16, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v4, v16, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v4, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v20, v24, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v8, v28, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v16, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v4, v20, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v16, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v28, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v20, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v20, v4, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v4, v16, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v4, v16, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v8, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v4, v24, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v8, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v16, v28, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v20, v16, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v20, v4, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v4, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v8, v20, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v28, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v4, v20, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v16, v24, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v4, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v16, v4, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v8, v16, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v28, v20, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v16, v24, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v12, v20, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v8, v16, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v24, v12, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v4, v28, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vv v8, v28, v12

  li t2, 0x1e47a612f2d13be5
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v28

  li t2, 0x1402ce9f7b3393ca
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v8

  li t2, 0xfc964add14e3b4b6
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v24

  li t2, 0xfdb2c417b66bd23e
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v8, t2, v20

  li t2, 0xf059d907d866d56d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v4

  li t2, 0x5705816b04edbc00
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v28

  li t2, 0xd1df50a164fa71e7
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v20

  li t2, 0x592284eb2b134928
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v24, t2, v28

  li t2, 0x347d388117f838b5
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v24, t2, v20

  li t2, 0x46b145c6a33fe9fa
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v4, t2, v16

  li t2, 0xf8c4fbd61a979f9b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v28

  li t2, 0x9ace22e4287490e4
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0x81faf0eb1b539a02
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x98f2ffdf2eb3213f
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v8, t2, v28

  li t2, 0x3336fee0b137af10
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v4, t2, v24

  li t2, 0x2b486c29eee25793
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v4

  li t2, 0xf9ce94b7d26d5405
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v28

  li t2, 0xd7d8e759f0d5bcba
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v20

  li t2, 0x0c2e1b6c9c88f6f8
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v28, t2, v24

  li t2, 0x871bea8122d70a1b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v20

  li t2, 0x2a5abaec91f507ba
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v16

  li t2, 0x954ede910c40fa67
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v16

  li t2, 0x36648c3a6da4bf97
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v28, t2, v24

  li t2, 0xcf7399156dba785d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x98e31ebafc487164
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v8, t2, v4

  li t2, 0x80a62a69671b898c
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v4

  li t2, 0xc9bfbe2c71525e97
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v4, t2, v20

  li t2, 0xb4b3824f63c775ca
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v8

  li t2, 0xbbc59b33b73a1511
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v12

  li t2, 0xcce2208d4cc47928
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v28

  li t2, 0x1d67a5031fd5383b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v8, t2, v4

  li t2, 0x6a326d593eec62f8
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v8, t2, v12

  li t2, 0x4b98c4f4a946bd48
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v8, t2, v4

  li t2, 0x175b90e2bede5225
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v28

  li t2, 0xd1fab1bd254515aa
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v28, t2, v16

  li t2, 0xe471b39b5c673950
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v24

  li t2, 0xb42dbc94d15c0458
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v16

  li t2, 0xc4d76f59497fa078
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v28, t2, v4

  li t2, 0x7a4095ff7f7e375a
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v4

  li t2, 0x6f18ba165d67e41d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v4, t2, v20

  li t2, 0xa3173f3b24b82c7b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xe65b7be589d0e237
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v24, t2, v12

  li t2, 0x72d846641b636dbc
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v8, t2, v28

  li t2, 0x72f1adf641eface4
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xdc73801b167b18a0
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v28, t2, v8

  li t2, 0x26166c3bccb834f4
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v24

  li t2, 0xfbef7139255351cd
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xffbb615ee9d14f39
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v8

  li t2, 0x7bd3f1825cc7c4b1
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x5a740e41eb9b6287
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v24

  li t2, 0xd91a54b3126eecf3
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v24, t2, v20

  li t2, 0x89b13ad85bffde9b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v28, t2, v12

  li t2, 0x56d52bbc1dd817c0
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v24, t2, v12

  li t2, 0x8a27c8745b01fa69
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v28, t2, v24

  li t2, 0xfaf11ef6ebfbf16d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v12

  li t2, 0x44befe83c37edebb
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v12

  li t2, 0x549347ad0c1c7ce1
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x77e5b2e099864139
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v8

  li t2, 0xdcd0173d050822fe
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v4

  li t2, 0x593c047848bf5825
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v28, t2, v8

  li t2, 0x72a69656328d1b58
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v4, t2, v24

  li t2, 0x36cda27c0d060052
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v28, t2, v16

  li t2, 0xa84f21472ecc5d55
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v20

  li t2, 0xbc6085635764ac7c
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x274a70de995dccb4
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v28, t2, v20

  li t2, 0xb05573b16f3c5ad8
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x909bfdde3014e826
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v28

  li t2, 0x86f668d20a31f487
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v24

  li t2, 0xf1844d7a77d6b5da
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v4, t2, v16

  li t2, 0x5a8a54314818e737
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v28

  li t2, 0xdd17ff394d14678d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v24

  li t2, 0xc87653eedb08d953
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xf4c20e16a8806ad6
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v4, t2, v12

  li t2, 0xb81d7772602b67f0
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v20

  li t2, 0x3dda06a061dbf2c3
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v8, t2, v12

  li t2, 0xdc1848060da2ca85
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v4, t2, v16

  li t2, 0xab3af98a410fdba8
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x04073a5a8185515b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v12

  li t2, 0xc686759437eb69f6
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v24

  li t2, 0x981e6af0ced6ee48
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v12

  li t2, 0x44de8138a3bf34a2
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v4, t2, v8

  li t2, 0x6823c378fbb90f48
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v24, t2, v12

  li t2, 0x2f4a16d239479493
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v12

  li t2, 0x6a186cc7c0baa17e
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v4

  li t2, 0x87eb01ed7863157d
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v4, t2, v16

  li t2, 0x243e1cea17b5c7c2
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0x263d54a822db96ce
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v24, t2, v28

  li t2, 0xd30f3d554d45c2e4
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0xe31dea4a349dce35
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v24, t2, v28

  li t2, 0x5166d5139a4b2a77
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v20

  li t2, 0x0407e2902773589c
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v28, t2, v16

  li t2, 0xeebad3b853ccba61
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v28

  li t2, 0xb46b3cc2ece8a681
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v24, t2, v4

  li t2, 0xa4abf87e08423bf6
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v28

  li t2, 0x0d5d06c62c2b52b5
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v24, t2, v28

  li t2, 0x3eb7ccbd88f67b9b
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v20, t2, v4

  li t2, 0xc32d307151039f7e
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v12, t2, v24

  li t2, 0x2d38d98d30b8b455
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x1c0f7e7ec4da9d01
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v16, t2, v20

  li t2, 0x33ea02b4d1f912ee
  vsetvli t1, t0, e16, m2, ta, ma
  vwmaccu.vx v24, t2, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  li t2, 0x97c94b2ed5a59e6f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x61a030e7a501ea29
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xdcc503c8c0c9b76f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x2a6b59bb3a91fe27
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x7fa0e0b4b04588f0
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x056b4f20a20300dd
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x1c45878631e85c78
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x74abc68319c35150
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x7aa234a4bde21df8
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xbaac49600cc98df2
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x31c02aea2665690f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xfa2d6102fac7cf99
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x15f8b325476ce1df
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x46afb39f1d6fb8b5
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x5505360166bddb29
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x45596465d4ba24a9
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x39ab6c5b5f7c1c30
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x5610407edc5ea70f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x6cb36da81c844a59
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x8c480c5b4b75a4b9
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x92aa9ad58c7d964b
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x73844051b0a7d8f8
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xc011043806000c46
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xca0ed47f4fd56614
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x27b900fbe88521c8
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x0bc36570bcc60ebb
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x5aca985cc267dc09
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x4bc144820f24e09e
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x843a25177ad41b76
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xdb1cdc1e9afcbedb
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x43922f946cf36855
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x20e26ca9983e7ab0
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xc74878c89726a704
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x0629da56bd1ad5e6
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x206f5fc6f967d82d
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x393c8635cd03053b
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x5fded7ac9858d3a9
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xf24a19de023f2b80
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x12375e20b241b463
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x2d0848847232f5b7
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x6081ddb1c575e20d
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x1bdce4414401875f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xb88a296f1f09ab26
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xe0656dd21730fe92
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x083453c044f85c96
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x93c105556e77408b
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xb11d4c083464cc1d
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xeca4a556c3abe69a
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xa01c37581f4c1579
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xe3dea0a15c06ace3
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x74eb5feff6bf1158
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x585344df83fbcca3
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x68ac6385940a44d7
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xa4f7b3acae2ea45d
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x092b782a20112a98
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x62e4f18a2b418a25
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x35a94f414afdfa9a
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x2cb17780f2cdff54
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x0e56d90fe2e19b9a
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x8fb9c6f5df6faec1
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xa96d60a9f05f5bea
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xcc87ee7d9e44848e
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xffc0bcbcd0ca31a8
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x0e77fa2399fa703e
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x9d824abf14e5d124
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x823178c15622bc37
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xb0c21ce017820c8f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x5934fe3415d67c2d
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xa23e39b218714424
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x4530a482ff156f91
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xfa3b76bf34dedd61
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x08f63ae4d3a25ddd
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x490444f7d15c289d
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xa9e354a8c0df67d2
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x9ba341fc07a4413f
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xcef90d3070433519
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x6118ca506d162316
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x896b00f428b20227
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x5a504f941654c7e9
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x768d2d608177c118
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x6faf317bf07c7c59
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x503abeca86ecd9e7
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x2dd28906183140df
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x5f5f4a05e6ca1a0e
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x6e5a9acce0fbf4eb
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x03898606346210f8
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x399322f2f02eb133
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x5eb1d57268df9561
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x4d3d275e8cb3f7e2
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xd97581d4d36ff124
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x9b10100a62404f27
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x4831e765bdf61b90
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xa0a6edc8a2f3c571
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xbd1145e90c521f69
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xee2b9158db2c2648
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x837381120acdacde
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xd0e58af39eb5299c
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x732c2ededbd3741c
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x43280a9590b55b78
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x92a9c3f5e05907e2
  vsetvli t1, t0, e16, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v28, v26, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v6, v2, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v14, v24, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v22, v10, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v24, v22, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v14, v20, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v28, v24, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v30, v24, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v14, v8, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v16, v26, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v2, v6, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v8, v10, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v18, v30, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v26, v6, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v20, v18, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v20, v2, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v4, v24, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v8, v12, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v14, v10, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v20, v8, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v22, v20, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v24, v2, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v10, v30, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v12, v22, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v18, v2, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v16, v10, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v18, v24, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v14, v20, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v14, v20, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v24, v16, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v2, v16, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v16, v2, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v18, v8, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v6, v20, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v18, v14, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v18, v12, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v2, v12, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v24, v22, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v6, v18, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v10, v2, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v14, v6, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v20, v4, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v16, v10, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v4, v22, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v12, v2, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v24, v10, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v4, v24, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v12, v4, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v24, v30, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v14, v4, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v30, v28, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v28, v16, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v16, v18, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v30, v24, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v16, v30, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v2, v6, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v26, v8, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v12, v30, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v16, v2, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v2, v28, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v6, v20, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v16, v6, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v18, v6, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v10, v4, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v22, v8, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v14, v30, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v10, v18, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v10, v8, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v26, v16, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v18, v22, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v4, v30, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v2, v22, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v28, v24, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v20, v4, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v18, v10, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v22, v12, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v22, v20, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v24, v4, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v20, v8, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v24, v16, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v22, v26, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v12, v26, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v14, v10, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v28, v22, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v20, v2, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v26, v24, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v16, v28, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v12, v16, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v8, v26, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v14, v20, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v26, v22, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v4, v6, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v20, v18, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v24, v30, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v12, v28, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v6, v12, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v26, v22, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v20, v12, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v8, v20, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vv v2, v30, v26

  li t2, 0x16ab3b644358e0ba
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v20, t2, v14

  li t2, 0xb4b6fc18b541874a
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v4, t2, v22

  li t2, 0xfbad9099cb32fbe0
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v18, t2, v20

  li t2, 0x7e5079c4ff4a2098
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v24, t2, v20

  li t2, 0x080df2f929db02fb
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v20, t2, v22

  li t2, 0x6bb8c23cf8cca705
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v16, t2, v18

  li t2, 0x038709b168952449
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v20, t2, v6

  li t2, 0x0845680d3ed4f5f6
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v8, t2, v28

  li t2, 0x54ba045798f21eb2
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v22, t2, v8

  li t2, 0x975c496bbc9a48cd
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v4, t2, v26

  li t2, 0x59e51b78acbaff80
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v20, t2, v16

  li t2, 0x4b63569989a526c2
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v30, t2, v12

  li t2, 0x33de2f2d8c4a72a5
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v28, t2, v4

  li t2, 0x2c6aeb6cb1b9c870
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v6, t2, v24

  li t2, 0x4416ba353fae7d02
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v30, t2, v16

  li t2, 0xe5121a40f1c9392a
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v18, t2, v24

  li t2, 0xa9e1d02431290c34
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v10, t2, v16

  li t2, 0x60cebb93f95bfb63
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v30, t2, v22

  li t2, 0x44544ede1d72b9d7
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v4, t2, v22

  li t2, 0x7a014a46c58e9e43
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v18, t2, v10

  li t2, 0x404c92c42555a8cd
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v8, t2, v12

  li t2, 0xf05c6decd6302ca6
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v10, t2, v28

  li t2, 0xcf7b5fea348280ee
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v14, t2, v22

  li t2, 0x27187f5a4360ed93
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v14, t2, v4

  li t2, 0x360793838a36bde3
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v22, t2, v18

  li t2, 0x8102ff3c16d9e15e
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v18, t2, v8

  li t2, 0x6df80cbe9c966a84
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v28, t2, v14

  li t2, 0x3229684f1f446c01
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v20, t2, v8

  li t2, 0xccd2cd6118eaf85d
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v14, t2, v28

  li t2, 0xbf3534eb2da11032
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v18, t2, v16

  li t2, 0xba2990677b003e35
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v16, t2, v30

  li t2, 0xd816147ad26dfc53
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v26, t2, v8

  li t2, 0xea7d4ddabf1dfeec
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v14, t2, v30

  li t2, 0x8563f2785730fab3
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v14, t2, v16

  li t2, 0xa627195ec5e62add
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v26, t2, v4

  li t2, 0x78cbbf8cb0fb6164
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v4, t2, v24

  li t2, 0xc39ddc1d759a6ac4
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v16, t2, v4

  li t2, 0x90828ee153464c82
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v30, t2, v26

  li t2, 0xb92b6629cea357fd
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v22, t2, v30

  li t2, 0xd31cf00f6c0901f4
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v28, t2, v16

  li t2, 0x64f3ad4f8a2c1c74
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v8, t2, v2

  li t2, 0x8da65221ca0adebd
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v10, t2, v22

  li t2, 0xceb4e2b6a4b3ad01
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v6, t2, v14

  li t2, 0x376defc27bbae002
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v6, t2, v12

  li t2, 0x0f79435aaa79c6a6
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v14, t2, v30

  li t2, 0xea414a117e53ef60
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v4, t2, v2

  li t2, 0x2759f40e0192b724
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v24, t2, v2

  li t2, 0x245c887ea3771e45
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v16, t2, v4

  li t2, 0x3264e7e86bdaaff0
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v6, t2, v4

  li t2, 0x94362f92b9679f3e
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v24, t2, v28

  li t2, 0x74905d01ebbd0cea
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v12, t2, v16

  li t2, 0x581f7267fe0b9186
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v30, t2, v28

  li t2, 0xf59983213ea97c76
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x3cd05d33b1b38794
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v18, t2, v2

  li t2, 0x1596580363cb6398
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v2, t2, v30

  li t2, 0xe7378970ad4a2106
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v10, t2, v2

  li t2, 0xd9922513dcace463
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v16, t2, v6

  li t2, 0xced9c2eee3021403
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v30, t2, v16

  li t2, 0xb23021e2f75c19a4
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v2, t2, v18

  li t2, 0x0fd4bdacd1a98fc7
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v16, t2, v10

  li t2, 0xff48ef99f36d0c62
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v22, t2, v18

  li t2, 0x53bde032ee7e4140
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v16, t2, v20

  li t2, 0xf92c60bcb10453f4
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v18, t2, v8

  li t2, 0x7f01191d27b64acd
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v22, t2, v8

  li t2, 0x33da09044cca07ac
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v10, t2, v6

  li t2, 0x1f013ec43cb62528
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v10, t2, v30

  li t2, 0x89b97e2fdb73f326
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v26, t2, v6

  li t2, 0x92f8aee6ed6298a2
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v8, t2, v4

  li t2, 0xc8f1f126c04c47cb
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v22, t2, v24

  li t2, 0xa1c0c14adb8b24d3
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v14, t2, v6

  li t2, 0xb011c394cc815e75
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v20, t2, v30

  li t2, 0x18b8ed4c585f4db3
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v10, t2, v2

  li t2, 0x3d4bb905a60a18dc
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v6, t2, v10

  li t2, 0xcdc371751017b129
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v18, t2, v16

  li t2, 0xf78a3e9960d5878f
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v6, t2, v12

  li t2, 0x2f05bd521f6e6c94
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v26, t2, v10

  li t2, 0x2f73aa1aad07d3aa
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v14, t2, v18

  li t2, 0x878b41a86e19c1dc
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v26, t2, v6

  li t2, 0xfbb9e1efd8d514fd
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v24, t2, v30

  li t2, 0x0b56dd617fdba8c2
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v28, t2, v22

  li t2, 0x87ee79680f24d0bb
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v22, t2, v14

  li t2, 0xa2dc52c3f87ce1cc
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v22, t2, v18

  li t2, 0x5372f359035b6aea
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v2, t2, v18

  li t2, 0xd260e9175008403b
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v6, t2, v2

  li t2, 0xccda635465a02eb4
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v14, t2, v26

  li t2, 0xcb6f95640c2ff102
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v12, t2, v10

  li t2, 0x8cb65fe4866d266d
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v20, t2, v30

  li t2, 0x5260739d8aefb9b2
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v18, t2, v12

  li t2, 0x966028aced362686
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v24, t2, v14

  li t2, 0x391c6e4ca24c43ae
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v22, t2, v24

  li t2, 0xbfe61d3726b44df1
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v12, t2, v8

  li t2, 0xaeee2d287a9a06fb
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v28, t2, v8

  li t2, 0xc5eb930a99066cb5
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v20, t2, v30

  li t2, 0xe86d0d98d4cd2e59
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v4, t2, v14

  li t2, 0x0b6fbf0ea740000d
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v18, t2, v28

  li t2, 0x5f7f9daab82d8cee
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v6, t2, v4

  li t2, 0xec0817385dcf914a
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v14, t2, v16

  li t2, 0x0448177083ae9ccd
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v22, t2, v6

  li t2, 0xaf64c215558718f0
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v2, t2, v28

  li t2, 0x841b0c39bf54d37d
  vsetvli t1, t0, e32, m1, ta, ma
  vwmaccu.vx v14, t2, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v8, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v8, v4, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v16, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v12, v20, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v8, v16, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v28, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v12, v8, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v12, v4, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v24, v28, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v24, v12, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v12, v4, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v16, v8, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v16, v24, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v8, v4, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v24, v16, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v24, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v4, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v24, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v16, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v24, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v20, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v16, v12, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v12, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v4, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v16, v28, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v8, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v24, v8, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v24, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v4, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v8, v16, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v8, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v24, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v12, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v8, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v16, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v8, v28, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v12, v4, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v12, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v8, v24, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v24, v4, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v4, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v16, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v24, v4, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v8, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v12, v16, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v24, v28, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v12, v24, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v12, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v16, v4, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v16, v8, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v20, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v12, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v24, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v12, v8, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v24, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v24, v16, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v28, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v8, v12, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v28, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v12, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v8, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v28, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v16, v12, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v16, v4, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v20, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v16, v20, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v12, v24, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v12, v24, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v8, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v16, v20, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v24, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v16, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v8, v28, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v12, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v24, v28, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v24, v28, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v16, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v12, v24, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v8, v4, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v4, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v28, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v20, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v20, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v12, v8, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v16, v24, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v16, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v8, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v12, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v24, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v12, v24, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v4, v12, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v4, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v8, v4, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v12, v28, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v24, v20, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v20, v8, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vv v28, v24, v16

  li t2, 0x4d0511b27d185e0d
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v28, t2, v4

  li t2, 0x2d610c074f87670b
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v4, t2, v12

  li t2, 0x4805e9f8e388e19a
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v4, t2, v8

  li t2, 0xa1a46c6700d3145c
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v24, t2, v12

  li t2, 0x044a3ac1dc730538
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v20

  li t2, 0x861227eac1164c5e
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v20

  li t2, 0x3b44f9db1d50f5d3
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x0fc04d6d6c09854c
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v4

  li t2, 0xe5cc10c4637949cf
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v12

  li t2, 0x629a63ffbbf6bc7b
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v28, t2, v12

  li t2, 0xbd2735a2c63bbd27
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0x25fc7511b62720ae
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xf4d73fb012d622b3
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v28, t2, v8

  li t2, 0xe939b94f1c73e587
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v16

  li t2, 0x7787e2b626aeafe0
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v4, t2, v16

  li t2, 0x5f5e34cab6871acf
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v24

  li t2, 0x905ed0e1a98b88f8
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v16, t2, v20

  li t2, 0xa8db6f0910839475
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v28

  li t2, 0x40e413edfc60d2e5
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v28, t2, v20

  li t2, 0x3cc6df584cc997f9
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0xf8e58835225d51bd
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x03a0bb30786df71a
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x2d796a0d6b678007
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v8

  li t2, 0x207589e84882de68
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v20

  li t2, 0x656c84ced870c274
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x1a54de59dfb730c4
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v4, t2, v16

  li t2, 0x4dfc28bb56cf371b
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v24, t2, v20

  li t2, 0x693921c194e75e79
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v4

  li t2, 0x52ba2c86048a3c5d
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v24

  li t2, 0x5e47518cd5b2b2ac
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0x1fa56275213223f7
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v24

  li t2, 0x4c9945cdfe7001f2
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v24

  li t2, 0xcbcbcb07f90204c9
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xc3e122bd0547338e
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v28, t2, v24

  li t2, 0x44b1aabccc261681
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v28

  li t2, 0x51fe3ba6b5172921
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v16, t2, v28

  li t2, 0xa14439bd19e621a6
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v24, t2, v12

  li t2, 0xd6dbb4594f62b4bd
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v16

  li t2, 0x82bd55d9583d0b9e
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v4, t2, v24

  li t2, 0x8bea6da26e62d093
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v24, t2, v28

  li t2, 0x004b363fd8059fa6
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v4, t2, v16

  li t2, 0x447e55877ded6c51
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v16, t2, v20

  li t2, 0x25655c96d9e5e6ee
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v4, t2, v28

  li t2, 0x0430f369bfd5d49b
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v16, t2, v12

  li t2, 0x124b45c80245815c
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v16, t2, v28

  li t2, 0xf729b4a185b45dcd
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v28, t2, v24

  li t2, 0xc10ac60323f93538
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v28, t2, v16

  li t2, 0xd02176863ef69464
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v12

  li t2, 0xdf83fd4ce2e91dd2
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v20

  li t2, 0x5ef02cf9f31e812f
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x64c9f1df2b2a8ef1
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v20

  li t2, 0xfe9e22116b772a25
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v8

  li t2, 0x606763dfb79f93fc
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v24

  li t2, 0x7c2319ecab251683
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v4, t2, v20

  li t2, 0xc8d5d2e669c13031
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x11a029feeb0a9b54
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v4, t2, v8

  li t2, 0x34366e9633166379
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0xd77cb295e1c4caf3
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v20

  li t2, 0xaa994b34290dbe47
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v28

  li t2, 0x50de80dd1a8478d4
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x6bc1514b850fd6cd
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v4

  li t2, 0x6800e034d977ce50
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v28, t2, v4

  li t2, 0x7a0dcf2eda56c311
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v28

  li t2, 0xbbbdfa7a99b3955e
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v8

  li t2, 0x15342bcb5fe5b648
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v28, t2, v12

  li t2, 0x02dc207ba3b760eb
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v28, t2, v24

  li t2, 0x010a101e63b3e12a
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v4, t2, v16

  li t2, 0xede2343a66b3926d
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v4

  li t2, 0x3bec2038f9314d64
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v24

  li t2, 0x34f524ef36111611
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x620fb3c801200f10
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v16, t2, v4

  li t2, 0x19fd9e2aaa8eec55
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v20

  li t2, 0x31711967dea00247
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v24, t2, v20

  li t2, 0xd463b609482d4f30
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v12

  li t2, 0xef5edcb72a756cdf
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x67f67349794dc169
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v24, t2, v12

  li t2, 0x79abb3c9ef33a9e5
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v4

  li t2, 0x6f1fcadad15bdf63
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v16, t2, v28

  li t2, 0xd6d2efbea0d24d92
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v4

  li t2, 0xad50a4db6fa64cf6
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v8

  li t2, 0x5dab13c675dc9635
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v24

  li t2, 0xac89e97836087290
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v8

  li t2, 0xeebc3dd41a8122c6
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v24, t2, v12

  li t2, 0x389168d9a5415f00
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v24, t2, v28

  li t2, 0xa66342b93d16fe79
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v4, t2, v20

  li t2, 0x03a4f797ee9c3f3d
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v16

  li t2, 0x13f2b3262043f665
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0xbdd9974232ee1adb
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v8, t2, v20

  li t2, 0x154ea52d70c5c93b
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v8

  li t2, 0x90a90ce4df51e6c3
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v4, t2, v20

  li t2, 0xf458201aca03c1c3
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0xbfcd2ca35e1d909f
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v28, t2, v4

  li t2, 0x3409a83dccdd3be1
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v20

  li t2, 0x8c0d546021e7a53d
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v24, t2, v4

  li t2, 0x435f8db245878134
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v28, t2, v24

  li t2, 0xf2eb21c29dc4fbf0
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v20, t2, v12

  li t2, 0xcb87cbf9521af7e1
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xfcc86a7aa5101afc
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v24, t2, v4

  li t2, 0xd2ff3ceb7a25f216
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v24, t2, v4

  li t2, 0x32fe9a136192b6e0
  vsetvli t1, t0, e32, m2, ta, ma
  vwmaccu.vx v12, t2, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v24, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v8, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vv v16, v24, v8

  li t2, 0x9fb2211749b751b2
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xf98f37c3ebb62bc1
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x0c7044092faebd22
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x6699c0b4690218b9
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x33c8627228b05011
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xd94baeb6511f7f8e
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xf881793e7408fa6b
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x55aefa4447618392
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x08d7dec48d6c3ec1
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x53eb86798177783c
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xfb48927a8a9973b5
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xc2a20c01074245ed
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x291827ed0f4f0f4a
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xcc6d96161aaa90a0
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x877f9f9a83560709
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x18a831cde68ec1e5
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x2594fd0b00913905
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x251ae325468fca1c
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x4b6724556f8b7da9
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xe46d9ade6157d208
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x180479fcdfe4ffd4
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x218e7a77685f9443
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x4697f73d4c9019f7
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x5d8d1589a9a7eeca
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xf6b385775fc53605
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x0c70b2c7f9f34e44
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x6cc1f62984a850db
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x56142050a104a233
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xa3c4695ecdb5d956
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x468b0d6a7e9cb8b7
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x5ef48c2a87ca345e
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x70d513197ffff92e
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xd2677187aa30bb24
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x3fd3bc5a9491e7c9
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xcff669d4186a996e
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x3b4460176a7a0d30
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xaf764ce6a3e5741c
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x33ce18c48f440734
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xd35541a3864b39b1
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x4ca18230653ecf4e
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xe9f37dc84b870c0a
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x62f17dc3c4ba3a10
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x03181f5228556580
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x4173ed37f86ad7b5
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x88ad8078c38dfbfa
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x65e13ee57e4d67bb
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x0cfaa756f68e37a4
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x4df77853b504657e
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x351fe1b74f415a80
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x54bb8daa030a96f2
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xd9f9ef50c7fa98cb
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xca6ff74ac1bad681
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x843f39910919b052
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xa2cf43d77a8849d0
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x3a0663b92c69c9dc
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x0a4f6bb884fcc03a
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x6619dbc5796aa45e
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x23289053d7ecf952
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x74a4866810d500d7
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x95f213361e7935e3
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x8be328387d0e5db7
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x38998b617562d022
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xd968edf5f3496f8b
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xadeee9f559f7e122
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x91c2b4e5350bcc88
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x8a98791bd7ca132f
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x1e7e29868d8a71e5
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x0233687921f82446
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x22acfaf21a383e35
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xd5b492f029f9760d
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xaea8e16889633e03
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x3e8203087fcfa006
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x3b05d78d8188c53d
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0x16ec8fdc7e592e06
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x2cde2e212e5b227d
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x893e564b6376e64a
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0xa4e6109daa0ac61c
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x4c310fce1a233f3e
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x048059ba537a8c32
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x6a14a64d8b68f63f
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x3015102a2627de1a
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0xd894c7845c7b184e
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x66ac6bc9d80b3419
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xfa4d46e0052b0062
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xd38036854f217425
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xddacc4c3d430fb4f
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x862a6223c3b6b8f9
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xc13dd89c438b5662
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0x98af8a59b4a3374e
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x8b2561db69180356
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xfd0c10a1c8b2cefe
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v16

  li t2, 0x6f23f22139769cb7
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0xa81cd3518423c72a
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x953d3897b21235d6
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v24

  li t2, 0xb9a66a01a85ef006
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  li t2, 0x3a97160f27f21c06
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0x365bc6392a335ea1
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v8

  li t2, 0xe34e57d4da5dc9ad
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v16, t2, v8

  li t2, 0x997d5129d000c2c9
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v24, t2, v16

  li t2, 0xd3ca603111f1086d
  vsetvli t1, t0, e32, m4, ta, ma
  vwmaccu.vx v8, t2, v24

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
