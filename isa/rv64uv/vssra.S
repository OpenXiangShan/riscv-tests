#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vv v30, v17, v23

  li t2, 0x855dd60f9650eee1
  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vx v17, v15, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vi v25, v4, 23

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vv v21, v19, v25

  li t2, 0xb181cc345c299a20
  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vx v15, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vi v9, v30, 17

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vv v30, v21, v16

  li t2, 0x4b08aef05e095727
  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vx v13, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vi v6, v11, 30

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vv v11, v5, v22

  li t2, 0x518661e4eb3aebee
  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vx v27, v13, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vi v17, v6, 18

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vv v16, v29, v10

  li t2, 0xac7043b2f3b3a07c
  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vx v20, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vi v12, v23, 16

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vv v17, v18, v13

  li t2, 0x5b29f9600b226038
  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vx v6, v14, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vi v10, v19, 5

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vv v24, v15, v25

  li t2, 0x7ea841ca2c93d69b
  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vx v7, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vi v20, v19, 13

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vv v21, v20, v10

  li t2, 0x4388fe31fbba1f02
  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vx v6, v14, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vi v26, v2, 0

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vv v31, v9, v27

  li t2, 0x4a24d0697047be89
  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vx v10, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vi v11, v22, 13

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vv v27, v23, v31

  li t2, 0x06752eb493252e3d
  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vx v21, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vssra.vi v14, v29, 1

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vv v8, v30, v2

  li t2, 0x3c4b04bfe63754e5
  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vx v18, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vi v16, v4, 29

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vv v24, v10, v6

  li t2, 0xa78ebbcd33961ebb
  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vx v30, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vi v16, v12, 24

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vv v14, v10, v2

  li t2, 0x2464eea7f976f7d5
  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vx v22, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vi v4, v6, 0

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vv v30, v18, v6

  li t2, 0xdceb175feb1ef6b5
  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vx v18, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vi v24, v6, 12

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vv v22, v6, v4

  li t2, 0xf1ea0808dbaee05b
  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vx v20, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vi v6, v18, 24

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vv v4, v6, v12

  li t2, 0x8295f2e1f89e46e2
  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vx v2, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vi v8, v16, 3

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vv v26, v4, v20

  li t2, 0x16a92c2c691b5139
  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vx v24, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vi v22, v20, 31

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vv v8, v26, v22

  li t2, 0x814989672d6b9354
  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vx v6, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vi v26, v24, 31

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vv v16, v14, v28

  li t2, 0xcae33566d8e901d7
  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vx v10, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vi v26, v14, 22

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vv v10, v28, v2

  li t2, 0x7cd6e5a30ea3208c
  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vx v4, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vssra.vi v8, v30, 6

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vv v4, v20, v12

  li t2, 0xb4c6b6fdd4d891ac
  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vx v16, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vi v12, v28, 17

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vv v24, v28, v16

  li t2, 0xae73df004da14344
  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vi v24, v12, 7

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vv v16, v20, v28

  li t2, 0xe2b2f3ed1cd709b7
  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vx v16, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vi v16, v28, 28

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vv v16, v20, v12

  li t2, 0xa559ac1d443fac7c
  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vx v16, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vi v16, v24, 14

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vv v12, v28, v20

  li t2, 0x13b4adaa36301cc5
  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vi v4, v8, 2

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vv v8, v20, v16

  li t2, 0x664133e07770695a
  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vx v8, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vi v20, v28, 21

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vv v20, v8, v4

  li t2, 0x78537741ab8a4dc9
  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vi v24, v4, 30

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vv v12, v20, v28

  li t2, 0x5cdfc54425cfa5e2
  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vx v28, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vi v8, v16, 16

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vv v28, v8, v20

  li t2, 0x55741a4e8c029f57
  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vx v28, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vi v16, v24, 7

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vv v8, v16, v12

  li t2, 0x2d0312614739a338
  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vx v8, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vssra.vi v4, v8, 20

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vv v16, v8, v24

  li t2, 0x26052d92acba8083
  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vi v8, v16, 22

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vv v8, v16, v24

  li t2, 0xaff36fbe361743eb
  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vi v24, v16, 21

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vv v16, v24, v8

  li t2, 0x990ea915d91dc027
  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vi v16, v24, 5

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vv v24, v8, v16

  li t2, 0x0615ab32298a8dbf
  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vi v16, v8, 26

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vv v16, v24, v8

  li t2, 0x20493db73bfa991c
  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vi v16, v8, 28

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vv v8, v16, v24

  li t2, 0x28571c79f62445c6
  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vi v8, v24, 5

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vv v16, v8, v24

  li t2, 0x35156ce0f0f893ba
  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vi v16, v8, 7

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vv v8, v16, v24

  li t2, 0x07463e811c484682
  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vi v24, v16, 10

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vv v24, v16, v8

  li t2, 0x72131f8dcdc9c654
  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vi v24, v16, 22

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vv v24, v8, v16

  li t2, 0xd38a864e1d8b5708
  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vssra.vi v8, v24, 26

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vv v6, v22, v8

  li t2, 0x02473bea4eea9940
  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vx v6, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vi v20, v7, 28

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vv v22, v25, v31

  li t2, 0x8580266a2b6df014
  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vx v11, v31, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vi v28, v22, 17

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vv v20, v17, v27

  li t2, 0x5a23529b5b0d81ba
  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vx v31, v27, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vi v3, v6, 15

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vv v5, v17, v16

  li t2, 0xe7cae57cbefc5258
  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vx v27, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vi v26, v22, 1

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vv v29, v23, v30

  li t2, 0x14e68ac652096676
  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vx v24, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vi v17, v14, 2

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vv v15, v29, v6

  li t2, 0x9b014ef98d208384
  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vx v31, v12, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vi v15, v18, 14

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vv v10, v20, v13

  li t2, 0x0bf515aba8d7ab79
  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vx v15, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vi v26, v9, 6

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vv v22, v3, v19

  li t2, 0x9914b0d4c8f4dfed
  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vx v29, v3, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vi v21, v27, 4

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vv v19, v14, v31

  li t2, 0xb0f65527ed3c5816
  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vx v31, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vi v9, v3, 0

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vv v2, v8, v31

  li t2, 0xe7ac728b66200a8c
  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vx v20, v6, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vssra.vi v27, v25, 29

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vv v28, v26, v8

  li t2, 0x6ad81a59425f6cb8
  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vx v6, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vi v2, v8, 21

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vv v6, v30, v18

  li t2, 0x4c94f90d9c4cdb7c
  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vx v28, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vi v12, v10, 11

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vv v14, v24, v18

  li t2, 0x102e32746f86afae
  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vx v4, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vi v18, v12, 24

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vv v14, v18, v20

  li t2, 0x25184697e1bb195d
  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vx v14, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vi v14, v16, 11

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vv v14, v20, v16

  li t2, 0xc745a40ab288a4ed
  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vx v22, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vi v14, v28, 8

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vv v22, v10, v8

  li t2, 0x32ba8a2a9c739b3c
  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vx v12, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vi v10, v6, 3

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vv v14, v6, v4

  li t2, 0x3a135e91265c02fc
  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vx v22, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vi v26, v16, 27

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vv v28, v26, v2

  li t2, 0x26a4c529bab93b43
  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vx v10, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vi v2, v24, 6

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vv v2, v22, v20

  li t2, 0x1020b2668669b185
  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vx v18, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vi v22, v10, 18

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vv v2, v22, v30

  li t2, 0x7a092cb427755056
  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vx v24, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vssra.vi v20, v22, 20

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vv v16, v12, v4

  li t2, 0x33a77435b52fe870
  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vx v24, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vi v24, v4, 7

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vv v28, v16, v24

  li t2, 0x00f2ed761d684f35
  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vx v4, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vi v12, v4, 25

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vv v24, v28, v16

  li t2, 0xcad2f5862d918777
  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vx v4, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vi v28, v8, 23

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vv v24, v16, v8

  li t2, 0x420ad1a8951fb4ed
  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vx v4, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vi v28, v8, 26

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vv v20, v4, v24

  li t2, 0x778618ee60636e7a
  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vx v4, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vi v12, v8, 4

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vv v28, v16, v8

  li t2, 0xa173861877c12bdf
  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vx v8, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vi v12, v4, 24

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vv v12, v16, v24

  li t2, 0xd356ce4ce83352f6
  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vx v24, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vi v8, v16, 29

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vv v8, v12, v16

  li t2, 0x9f301c314917174e
  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vi v24, v28, 27

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vv v20, v24, v12

  li t2, 0xe8d2486a227d312b
  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vi v24, v4, 0

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vv v4, v24, v8

  li t2, 0xbc94b232ca9c9a1f
  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vx v8, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vssra.vi v28, v24, 31

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vv v8, v16, v24

  li t2, 0xa6538813268824e7
  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vi v8, v16, 13

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vv v24, v8, v16

  li t2, 0x44ca6346a2e68d6e
  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vi v16, v8, 25

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vv v16, v24, v8

  li t2, 0x6319bc58356ab015
  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vi v24, v16, 9

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vv v16, v24, v8

  li t2, 0x4afec4a6825f731f
  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vi v16, v8, 30

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vv v8, v16, v24

  li t2, 0x54b7c7a5ef271790
  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vi v24, v8, 12

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vv v16, v8, v24

  li t2, 0x4c51c143d9e47ced
  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vi v8, v24, 29

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vv v16, v24, v8

  li t2, 0x04da324377a33306
  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vi v24, v8, 19

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vv v16, v24, v8

  li t2, 0x93248dda24b32f3c
  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vi v24, v16, 7

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vv v8, v16, v24

  li t2, 0x0eee2d147f4be821
  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vi v16, v8, 22

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vv v16, v24, v8

  li t2, 0x307439d3b6e2b75a
  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vssra.vi v16, v24, 10

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vv v1, v23, v27

  li t2, 0xc7f1ffff38be9a60
  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vx v1, v15, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vi v26, v29, 4

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vv v11, v28, v3

  li t2, 0x0261b2022e38940d
  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vx v27, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vi v1, v10, 13

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vv v30, v20, v1

  li t2, 0x8c58ed078c3d3cc6
  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vx v4, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vi v26, v6, 25

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vv v12, v26, v11

  li t2, 0x5110ddd022a53764
  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vx v10, v23, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vi v30, v4, 7

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vv v15, v6, v31

  li t2, 0x97bc733538b98992
  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vx v10, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vi v12, v5, 10

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vv v21, v6, v8

  li t2, 0x48b08597a3a993db
  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vx v4, v11, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vi v4, v13, 30

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vv v18, v4, v20

  li t2, 0x78807c95309007a0
  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vx v29, v22, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vi v11, v31, 24

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vv v3, v4, v2

  li t2, 0x0e36487eae396a8a
  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vx v23, v11, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vi v5, v22, 19

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vv v26, v28, v4

  li t2, 0x8902b6beb366cb95
  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vx v12, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vi v14, v31, 17

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vv v1, v11, v25

  li t2, 0x036e8cc846aea4ee
  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vx v26, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vssra.vi v12, v8, 6

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vv v6, v4, v8

  li t2, 0xcc67ac25ea71e401
  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vx v10, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vi v18, v4, 3

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vv v2, v6, v10

  li t2, 0xa5ef427756773ffe
  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vx v10, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vi v26, v8, 14

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vv v24, v28, v6

  li t2, 0x2b769b675401111f
  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vx v20, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vi v24, v12, 15

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vv v6, v24, v22

  li t2, 0x1861fa5eab136544
  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vx v18, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vi v6, v26, 9

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vv v2, v10, v14

  li t2, 0x08d3b880bb4a5a6d
  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vx v2, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vi v20, v8, 11

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vv v4, v14, v8

  li t2, 0xe9afb0f1887d65ce
  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vx v10, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vi v4, v8, 29

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vv v20, v24, v12

  li t2, 0xbae07fd197360060
  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vx v8, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vi v8, v10, 21

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vv v14, v30, v24

  li t2, 0x86073e2fcc434baf
  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vx v20, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vi v30, v22, 5

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vv v10, v6, v24

  li t2, 0x345f5e6f09af77e5
  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vx v4, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vi v10, v28, 0

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vv v14, v12, v4

  li t2, 0x4fcb67e3c513027e
  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vx v20, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vssra.vi v28, v30, 31

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vv v4, v28, v12

  li t2, 0xa4158d8a9193aa1a
  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vx v8, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vi v16, v24, 20

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vv v4, v12, v8

  li t2, 0xd0c12d5c317d6478
  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vx v20, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vi v12, v28, 14

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vv v28, v12, v24

  li t2, 0xe9364f1c11070862
  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vx v24, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vi v16, v4, 30

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vv v8, v4, v28

  li t2, 0xa238ea316fff3037
  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vx v20, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vi v4, v12, 29

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vv v28, v12, v20

  li t2, 0xf11a789a90f2b7fe
  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vx v28, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vi v16, v8, 14

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vv v28, v16, v4

  li t2, 0xec17f77a0b6c897c
  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vx v24, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vi v24, v16, 3

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vv v12, v28, v16

  li t2, 0x2fb38d886b9a9f0d
  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vi v28, v16, 31

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vv v8, v12, v16

  li t2, 0x5f2d86b131c05b78
  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vi v8, v16, 27

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vv v12, v24, v20

  li t2, 0x97e5bf9ae17fc82e
  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vi v12, v20, 12

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vv v20, v16, v8

  li t2, 0xaf724635d4885e89
  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vx v20, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vssra.vi v28, v20, 16

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vv v8, v16, v24

  li t2, 0x7866661ec7fc2f1f
  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vi v24, v8, 22

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vv v24, v8, v16

  li t2, 0xaf42194cdcdf2c04
  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vi v24, v8, 14

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vv v8, v16, v24

  li t2, 0x750d3b6fcd1a7a4f
  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vi v16, v8, 5

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vv v24, v8, v16

  li t2, 0x621b565d99f59978
  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vi v8, v24, 30

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vv v24, v16, v8

  li t2, 0xd343137d4fced7cc
  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vi v16, v8, 9

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vv v8, v24, v16

  li t2, 0x5bf3d9f4c8d38c1e
  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vi v24, v8, 18

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vv v16, v24, v8

  li t2, 0x54c5f759f0433f78
  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vi v16, v24, 27

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vv v24, v8, v16

  li t2, 0x871116d324739c8c
  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vi v16, v24, 2

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vv v16, v24, v8

  li t2, 0x5f60a897c7449beb
  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vi v24, v16, 23

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vv v24, v8, v16

  li t2, 0x8aa750640576551d
  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vssra.vi v16, v8, 8

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vv v27, v25, v22

  li t2, 0x99a36d1bdb35df16
  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vx v30, v10, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vi v7, v17, 7

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vv v7, v26, v14

  li t2, 0x83c8f570ea22f9d2
  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vx v24, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vi v30, v10, 6

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vv v24, v28, v20

  li t2, 0x68404c03340a96b8
  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vx v5, v13, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vi v24, v1, 27

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vv v7, v28, v10

  li t2, 0x10025f6567857109
  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vx v25, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vi v17, v19, 0

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vv v26, v31, v15

  li t2, 0x87b49e83be4d3bbf
  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vx v15, v22, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vi v3, v20, 4

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vv v29, v8, v3

  li t2, 0xec119dd432b12ab9
  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vx v22, v11, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vi v6, v25, 16

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vv v21, v27, v4

  li t2, 0x4b3b35e7ee92db99
  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vx v27, v13, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vi v12, v25, 3

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vv v21, v12, v4

  li t2, 0x01be97b541f68885
  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vx v25, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vi v27, v30, 6

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vv v18, v1, v19

  li t2, 0xe310568508f2e04b
  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vx v26, v23, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vi v29, v2, 1

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vv v27, v22, v31

  li t2, 0x327a0bd0e4f7f9fe
  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vx v24, v12, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vssra.vi v4, v15, 6

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vv v16, v20, v4

  li t2, 0xb93b915ae6c112c9
  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vx v4, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vi v14, v18, 29

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vv v28, v10, v2

  li t2, 0x1b29fb748329cb7b
  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vx v20, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vi v28, v8, 11

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vv v20, v22, v12

  li t2, 0xe7adc796a31b69a7
  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vx v20, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vi v2, v26, 24

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vv v8, v28, v12

  li t2, 0x34bfa25530481343
  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vx v18, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vi v2, v18, 27

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vv v10, v18, v28

  li t2, 0xc3ae3b4b2804d1a5
  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vx v8, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vi v24, v6, 1

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vv v6, v24, v14

  li t2, 0xfc01173652231a97
  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vx v2, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vi v14, v8, 7

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vv v24, v16, v22

  li t2, 0x20481ed494cf7f99
  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vx v22, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vi v6, v22, 0

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vv v22, v12, v6

  li t2, 0x78c3cc1508ced9a4
  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vx v26, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vi v12, v24, 10

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vv v14, v4, v20

  li t2, 0x8989790fca8e11b5
  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vx v8, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vi v14, v12, 13

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vv v4, v14, v18

  li t2, 0x6f8c1358e2538e48
  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vx v8, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vssra.vi v28, v26, 22

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vv v28, v24, v20

  li t2, 0x27bbea7af8fa7a8f
  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vx v24, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vi v4, v24, 29

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vv v28, v16, v24

  li t2, 0x7fbc75e04a8d81c0
  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vx v4, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vi v20, v24, 16

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vv v8, v4, v20

  li t2, 0x46991050df77c90e
  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vx v20, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vi v12, v16, 0

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vv v20, v24, v12

  li t2, 0xa133ea80686a4c55
  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vx v28, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vi v4, v12, 17

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vv v16, v28, v8

  li t2, 0xd6f35bda036d0745
  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vx v28, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vi v8, v12, 15

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vv v28, v12, v8

  li t2, 0xcf3c94ac798bbaf1
  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vx v20, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vi v28, v4, 27

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vv v4, v16, v20

  li t2, 0x4151abc17d63f7d4
  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vx v28, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vi v20, v16, 30

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vv v12, v24, v8

  li t2, 0x644da7d98b8de232
  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vx v12, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vi v16, v20, 8

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vv v16, v24, v28

  li t2, 0x0478555e8380d045
  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vi v8, v24, 26

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vv v28, v4, v24

  li t2, 0x1480c766659c4e14
  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vx v8, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vssra.vi v8, v4, 8

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vv v8, v24, v16

  li t2, 0xc3961e56f4dc10e7
  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vi v16, v8, 27

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vv v8, v24, v16

  li t2, 0x191c952edaf8c42a
  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vi v16, v24, 18

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vv v24, v8, v16

  li t2, 0x33da94e771daa0a8
  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vi v8, v24, 26

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vv v16, v24, v8

  li t2, 0x445a59ac4d1f0d53
  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vi v24, v8, 17

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vv v16, v8, v24

  li t2, 0xd3d7c21407bcffed
  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vi v24, v8, 9

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vv v24, v8, v16

  li t2, 0x48457c0e05550bdf
  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vi v24, v16, 18

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vv v8, v24, v16

  li t2, 0x240b396faafecf2e
  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vi v24, v16, 10

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vv v8, v16, v24

  li t2, 0xf92078a224592291
  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vi v8, v16, 14

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vv v8, v24, v16

  li t2, 0xcca2845f72f877b1
  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vi v8, v24, 28

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vv v8, v16, v24

  li t2, 0x681ec3b2a0748d12
  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vssra.vi v24, v8, 0

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
