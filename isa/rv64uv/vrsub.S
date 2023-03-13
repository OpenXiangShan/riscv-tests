#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  li t2, 0x03d1f746f6fcab90
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v20, v1, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v31, v3, -16

  li t2, 0xb3bdea6991fbb3f2
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v6, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v10, v1, 6

  li t2, 0x83a72099b84da7a6
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v31, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v26, v7, 1

  li t2, 0xbe5ff24a50f3e386
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v29, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v15, v19, 0

  li t2, 0xf1f60b55cb75d41f
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v13, v14, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v26, v31, -7

  li t2, 0xe2fe95c3030a8c34
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v14, v15, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v15, v30, 3

  li t2, 0x9ad196b86acdff55
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v6, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v26, v27, -3

  li t2, 0xab69dd7b0ee92d79
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v5, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v26, v23, -9

  li t2, 0x2d0c61f05d748ed7
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v9, v10, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v31, v20, -7

  li t2, 0xec581cd685b4d703
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v31, v1, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v6, v16, 3

  li t2, 0xebd552d43e77bc98
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v28, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v24, v25, -11

  li t2, 0xe5df515d59502b5b
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v23, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v15, v7, 12

  li t2, 0xead76e1fa1c8b7ce
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v14, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v23, v10, -11

  li t2, 0x742feb314971bfec
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v5, v10, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v16, v6, 12

  li t2, 0x71e508d8002d968e
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v7, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v14, v9, 0

  li t2, 0x5aa32b90c8976a37
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v29, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v14, v29, -16

  li t2, 0x5c979e18208974c5
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v8, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v13, v25, 1

  li t2, 0x3ad34c04d52e0ef7
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v1, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v9, v31, 0

  li t2, 0xe2a59d6c556f1d4f
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v15, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v7, v14, -8

  li t2, 0x41da84fd865767d8
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v8, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v24, v20, -7

  li t2, 0x88ae329a022676c7
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v13, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v25, v20, 13

  li t2, 0xb6ede6d736a6d3b0
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v20, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v29, v21, 0

  li t2, 0x5de7a46ccf46f893
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v31, v2, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v20, v27, -11

  li t2, 0xbcf1a430e9775fca
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v12, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v31, v30, -1

  li t2, 0x5b5e838a1017a9f8
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v25, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v7, v24, -13

  li t2, 0x8c1f05e9a8d74bbf
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v15, v1, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v21, v12, -6

  li t2, 0x9490b8a98a94252c
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v18, v15, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v7, v3, -13

  li t2, 0x75848c1e42c110c0
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v13, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v25, v1, 10

  li t2, 0x1bbb915fe6b3d6cf
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v28, v30, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v3, v26, -15

  li t2, 0xbf5d523fec5653b7
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v26, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v20, v26, -5

  li t2, 0x80ef9b9135672d9c
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v20, v19, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v5, v20, -6

  li t2, 0xaa57b0a861e29f22
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v12, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v17, v8, -16

  li t2, 0x3488fa81659d225c
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v17, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v12, v15, 2

  li t2, 0xda0bfbc207748aa6
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v28, v10, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v18, v26, 15

  li t2, 0x3c2060a8efccf62c
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v1, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v28, v10, -2

  li t2, 0xf77ff5b411bcae11
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v4, v1, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v18, v3, -7

  li t2, 0xd0d914580b257892
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v6, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v8, v4, -11

  li t2, 0x0945f9f0ff40af8e
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v7, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v26, v15, -4

  li t2, 0x21a934eedcb869ad
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v10, v13, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v2, v18, -13

  li t2, 0x716d42291601dd7e
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v8, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v13, v14, -8

  li t2, 0x8a944e6e10b87440
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v30, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v30, v24, -16

  li t2, 0xe87e77cba84314a0
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v4, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v3, v30, -10

  li t2, 0x64cc49441465a0da
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v17, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v24, v26, 12

  li t2, 0x4df17205485c6fe4
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v4, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v14, v5, -7

  li t2, 0x7a4b8a92db9eff64
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v1, v24, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v11, v16, -4

  li t2, 0x413dbd5811391f5b
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v26, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v20, v13, -5

  li t2, 0x90e3f6894688b34e
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v23, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v9, v11, 3

  li t2, 0x1e2144216b22b7d6
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v13, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v25, v21, -16

  li t2, 0x21d3fd31d0852f62
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v8, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v3, v29, -7

  li t2, 0x2b9181af75891225
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v19, v7, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v20, v18, 10

  li t2, 0xc0a965e7628d3b45
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v4, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v24, v12, 6

  li t2, 0x20522fe99c4c35d0
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v10, v19, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v22, v13, 13

  li t2, 0x75faa12ce5239626
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v20, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v19, v14, 0

  li t2, 0x563d85d99abe1b7a
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v27, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v15, v2, -15

  li t2, 0x2881df7debe9b0de
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v13, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v22, v30, -6

  li t2, 0xdd91a0a11b40233c
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v25, v26, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v24, v22, -15

  li t2, 0xf554ffffd27f3569
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v21, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v9, v21, 3

  li t2, 0xcc23e15a8cfe22aa
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v26, v30, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v6, v7, 11

  li t2, 0x2bdc6d06a6ce2787
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v21, v14, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v4, v20, -12

  li t2, 0xaae8030c820dde33
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v21, v1, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v28, v8, -3

  li t2, 0x716dd9a0f168721f
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v31, v20, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v11, v26, -14

  li t2, 0xd5cd76abec6caa2d
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v1, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v24, v27, 15

  li t2, 0x246e2c4e68d0cbac
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v16, v13, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v10, v1, 7

  li t2, 0x9a78e2596a11e494
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v16, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v21, v31, -8

  li t2, 0xdff6f1bb7b34d6b2
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v17, v11, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v16, v7, -6

  li t2, 0x51cfcdd88fe58b46
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v11, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v21, v19, 14

  li t2, 0x2a7bc48988619037
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v1, v19, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v16, v20, -9

  li t2, 0xf6ffbb7da90af1ec
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v2, v18, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v2, v9, -3

  li t2, 0x018be7fb7ea6e35a
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v30, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v1, v28, 1

  li t2, 0x4e35d4f39cccddb7
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v1, v26, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v21, v18, -15

  li t2, 0x6f11971fed167304
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v16, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v27, v23, -10

  li t2, 0xc66e602f4a99d974
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v3, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v8, v31, -15

  li t2, 0xddf1968d13863572
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v7, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v3, v7, -9

  li t2, 0xa5f2e3392fd8dfb7
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v12, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v12, v9, 1

  li t2, 0xc89269fa14ad733d
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v2, v26, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v25, v22, -1

  li t2, 0x544b580c4e69892a
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v20, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v23, v8, 13

  li t2, 0x4a09fa782ba734b7
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v6, v13, -7

  li t2, 0x67167726e76d6b7b
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v12, v27, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v6, v22, 11

  li t2, 0xd6521d75f65a43b6
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v22, v3, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v25, v12, 8

  li t2, 0x0dc5cec51e079fba
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v23, v3, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v13, v25, -3

  li t2, 0x6b4ee62746f395cc
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v24, v22, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v14, v2, -10

  li t2, 0x25958ddaba42542b
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v11, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v31, v6, -13

  li t2, 0x8ee40ee687566e4d
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v20, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v19, v29, -13

  li t2, 0x57fbc0617f90a92f
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v5, v16, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v6, v12, -9

  li t2, 0x729c9be8cb57f700
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v30, v3, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v25, v26, -1

  li t2, 0x6dc7092e12182cec
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v3, v6, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v26, v18, 9

  li t2, 0x13a503c34f7880f7
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v22, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v19, v17, 0

  li t2, 0xafd6965c9b14e8d9
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v16, v5, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v7, v3, 10

  li t2, 0xf0839fff17e008d4
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v26, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v25, v8, 6

  li t2, 0x3568f790f3a6933d
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v28, v29, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v1, v21, 8

  li t2, 0xab47c20c58531bde
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v30, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v2, v12, -8

  li t2, 0x71095c9e87e3304f
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v20, v12, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v11, v6, -13

  li t2, 0x566c50eff09bb34c
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v19, v23, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v5, v13, -8

  li t2, 0xfe8d18803950d232
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v4, v19, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v4, v27, -16

  li t2, 0xd726d1586cd7cdea
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v26, v25, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v25, v29, -9

  li t2, 0x7aadfe92dd02b935
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v17, v9, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v8, v15, -5

  li t2, 0x2366646a1979d841
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v20, v8, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v25, v7, -10

  li t2, 0x1a79fc9b2c546ea4
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v9, v31, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v28, v31, -5

  li t2, 0x6f96c1c969106c6b
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v30, v21, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v25, v7, -12

  li t2, 0xfeca7e617c1beafe
  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vx v12, v28, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vrsub.vi v30, v3, -13

  li t2, 0x11c12519459cdbc7
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v2, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v22, v8, -2

  li t2, 0x8ad99c6745b92d3a
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v22, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v8, v12, -6

  li t2, 0x071a4990ffea0269
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v12, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v20, v26, 11

  li t2, 0x18c292c892bcdb33
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v16, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v16, v24, -5

  li t2, 0x858ba186dc8e749c
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v6, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v2, v6, 15

  li t2, 0x40844161c8984e90
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v8, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v8, v24, -3

  li t2, 0xb34d167e40834126
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v26, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v16, v28, -3

  li t2, 0xcc02676519288da4
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v28, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v4, v2, -9

  li t2, 0xdeb0ff9a28123c95
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v6, v18, -7

  li t2, 0x08c6b7643e7d7f3f
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v20, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v12, v6, 1

  li t2, 0x4255e4f503d16943
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v22, v24, 13

  li t2, 0x7f99f64e5095b6e2
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v26, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v20, v6, 12

  li t2, 0x091bd525d69c4654
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v26, v24, -6

  li t2, 0x85d939ac7a79edad
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v2, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v8, v20, -16

  li t2, 0x0ff8747c26779835
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v2, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v30, v16, 0

  li t2, 0x1c9c787cb21fe695
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v10, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v14, v22, -6

  li t2, 0x8180db0a7a5dc4bd
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v22, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v2, v6, 11

  li t2, 0xc205704d9cd61782
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v26, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v30, v28, 7

  li t2, 0xef98e8f71fc2d72c
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v22, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v16, v24, 2

  li t2, 0x99b8c1e5dc8bb46b
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v30, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v6, v2, 12

  li t2, 0xa54a795cb1d96252
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v18, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v6, v30, -3

  li t2, 0xe61e56e907e19c98
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v14, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v24, v22, -1

  li t2, 0xb07e69cfe0280954
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v24, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v8, v24, 14

  li t2, 0x3ac6b0f45dde7e74
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v14, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v4, v20, 4

  li t2, 0xe0f379b6d2801d0d
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v20, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v12, v24, -3

  li t2, 0x1db32eed713a8413
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v12, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v28, v2, 5

  li t2, 0x299c4b4803bb84ee
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v26, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v30, v10, 3

  li t2, 0x002a58963f12c120
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v28, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v28, v2, 5

  li t2, 0xfcc1d93a62e16550
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v20, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v30, v24, -3

  li t2, 0xf67ae320a37b425e
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v4, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v14, v4, 11

  li t2, 0xcfe5439fbe85a1b9
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v20, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v30, v14, -9

  li t2, 0x7401b33308eb82eb
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v22, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v10, v24, 11

  li t2, 0x52a68e9e69e61b44
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v2, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v12, v28, -7

  li t2, 0xa421ccf53990c162
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v22, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v24, v22, 9

  li t2, 0x7cfc41ad48daf2a4
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v18, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v26, v28, 13

  li t2, 0x59d03d6de576b704
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v22, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v30, v18, 14

  li t2, 0x2804741ea20bdbd3
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v22, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v14, v8, 14

  li t2, 0x7f82719952942642
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v10, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v24, v14, -1

  li t2, 0x529fa496ffe3bd4d
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v20, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v4, v10, 5

  li t2, 0x93eabcff96b27b4c
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v8, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v20, v16, -5

  li t2, 0x042e0d032f650a3d
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v6, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v12, v8, 8

  li t2, 0xfd78599bd5977ed9
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v26, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v22, v24, 9

  li t2, 0xa10d8c3fc93eedf0
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v2, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v12, v22, -5

  li t2, 0xec3fd09106043447
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v2, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v6, v18, 10

  li t2, 0x5bfb260c783000a9
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v8, v28, -2

  li t2, 0x545d9ac03af614d3
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v4, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v22, v10, 2

  li t2, 0xc86e781735339392
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v12, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v14, v24, -2

  li t2, 0xde75602286c72f61
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v20, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v2, v18, 0

  li t2, 0x30a7d33687a718fa
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v26, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v20, v8, 0

  li t2, 0x78b9136ffd93c7a3
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v20, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v22, v8, -3

  li t2, 0x8f347da6f406085c
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v2, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v10, v6, -15

  li t2, 0x1ebf820ccbb878b0
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v8, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v14, v16, 9

  li t2, 0x47dc3ead5c3e77cd
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v30, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v16, v8, 3

  li t2, 0x5639d235d8b535de
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v24, v16, -15

  li t2, 0x4be10a80c9204dd4
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v10, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v14, v4, -1

  li t2, 0x51ba758f2a7a0a79
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v24, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v4, v12, -1

  li t2, 0xe7c8aa850701a9aa
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v18, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v8, v12, -11

  li t2, 0x8aaea5f7c022d53c
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v8, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v30, v16, -2

  li t2, 0xa97053ca24c05647
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v12, v10, -12

  li t2, 0x71c3efac66707732
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v6, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v14, v26, 5

  li t2, 0xab8d7d48501bfccd
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v8, v22, 0

  li t2, 0xe04c08a3a217ffa3
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v4, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v8, v20, -16

  li t2, 0x7807910dae4c8dd8
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v10, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v10, v14, 3

  li t2, 0x5e4ce2e7484a961c
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v2, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v18, v28, 13

  li t2, 0x2bdfa403fd1931bf
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v20, v12, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v28, v8, -3

  li t2, 0xa73336b1fe3440aa
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v8, v24, -5

  li t2, 0xfca8be8e97c59ba0
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v22, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v16, v20, 10

  li t2, 0x0646c2a2ff03f1ca
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v6, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v18, v12, 15

  li t2, 0xd132a4ec0ba306ce
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v24, v28, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v22, v8, 11

  li t2, 0x79ae4216ece3e0e0
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v24, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v12, v18, -3

  li t2, 0xf5afee6ba8e23f6c
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v24, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v6, v18, -14

  li t2, 0x6336fc2bd7450025
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v30, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v10, v4, -4

  li t2, 0xaf1b96ef7d5eb480
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v26, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v12, v4, 5

  li t2, 0x3fd9d313d49b417f
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v14, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v14, v12, 14

  li t2, 0xfc6e373f30e4cdc0
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v26, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v6, v8, -14

  li t2, 0x866745719a16aa0c
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v16, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v26, v28, 0

  li t2, 0xe820aa566dd4065d
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v22, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v18, v16, -12

  li t2, 0x98f019253370387e
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v20, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v14, v26, -11

  li t2, 0xf76a1fe50d598f86
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v18, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v26, v22, -6

  li t2, 0x1a7fa9a1ba43c9cf
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v26, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v18, v16, -14

  li t2, 0x10f0d01590b55533
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v16, v14, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v20, v10, -11

  li t2, 0x6326043124ab1489
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v16, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v20, v4, -2

  li t2, 0x491c3b2ab0c37d16
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v28, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v20, v12, 1

  li t2, 0xe45823638b171972
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v16, v20, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v22, v28, 11

  li t2, 0x4be9ee25ffc09063
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v26, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v14, v20, 6

  li t2, 0x1d6e8ab73930e08a
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v28, v18, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v10, v16, 6

  li t2, 0xc031528dea0e8f38
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v18, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v26, v4, 14

  li t2, 0xb8b881f6270d5046
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v10, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v22, v28, 5

  li t2, 0x485da0ff40637dbf
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v30, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v30, v12, 14

  li t2, 0x397c83b9d5052b9b
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v10, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v2, v18, 3

  li t2, 0x64ea94c15aa9c867
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v10, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v8, v30, 9

  li t2, 0x0ae0f60e45ded040
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v2, v10, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v12, v26, 15

  li t2, 0xe5d5d0263125f9ef
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v30, v6, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v6, v14, 14

  li t2, 0xf56c1380b8ffb928
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v28, v22, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v22, v12, 2

  li t2, 0x272f3c64b33b9593
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v30, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v12, v30, 4

  li t2, 0x805f3036f853ba61
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v14, v26, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v12, v16, -13

  li t2, 0x796bcbb049ee8c06
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v14, v24, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v14, v4, -10

  li t2, 0xa1af9c7a1b9e946d
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v12, v30, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v20, v6, -11

  li t2, 0xbeb299ff89e11341
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v22, v2, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v20, v10, 14

  li t2, 0xdf3e32bf0b94dddc
  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vx v14, v16, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vrsub.vi v8, v24, -14

  li t2, 0x2d319530e448dbb2
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v4, 11

  li t2, 0xcdcf2e408b64c782
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v4, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v12, v4, 1

  li t2, 0x17bf40b76abe56d4
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v8, v16, -14

  li t2, 0xcef951873b9f8467
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v28, -4

  li t2, 0xb790f284779b6f21
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v8, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v8, 10

  li t2, 0xf2e35f0074247197
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v4, -2

  li t2, 0xeb65a80f58379a74
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v4, 4

  li t2, 0xc2b15d0bb64ccd02
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v8, 10

  li t2, 0x584a6572dc4bb9e8
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v28, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v16, -3

  li t2, 0x230e71b81b8cad61
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v12, v4, -14

  li t2, 0x155f7239f681c4a6
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v12, 13

  li t2, 0xcf81481ede7649ab
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v4, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v8, v20, 6

  li t2, 0x620c314ba43eba69
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v8, v24, 6

  li t2, 0x9b3da43f9890123c
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v16, -16

  li t2, 0x63d0184b9ebdf2da
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v12, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v16, 6

  li t2, 0x956a1cc2e432d9c7
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v8, 7

  li t2, 0x8b01ea36fb7b60be
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v8, -15

  li t2, 0xc3d1d757dcd946a4
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v12, v24, -13

  li t2, 0x1e997bad839a893b
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v4, 5

  li t2, 0x370921668b752aa0
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v28, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v20, 1

  li t2, 0xabcb91d6457afe84
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v4, -6

  li t2, 0xee3f2bc04056f555
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v12, -1

  li t2, 0xb4fa61fe49fe9bbb
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v4, 6

  li t2, 0x5c6e7ed859d74355
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v12, v20, -1

  li t2, 0x5de987bf614209d0
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v12, -8

  li t2, 0x93f81d03e7754556
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v8, v20, 2

  li t2, 0x91e20d2b48a2197c
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v12, v16, -13

  li t2, 0x72b232e6d7249dff
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v12, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v16, -14

  li t2, 0xe10594a68b8747bc
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v4, v12, 12

  li t2, 0x1a4ea1fefb628bfc
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v24, -5

  li t2, 0x4609115b7d66a2c3
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v8, v4, 7

  li t2, 0x31c05cd636d69d78
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v4, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v16, -2

  li t2, 0x0c0ff47457ffb1e3
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v4, 12

  li t2, 0x3c9bcaddc8f27b22
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v4, v12, 9

  li t2, 0xb03272b1dafe4cce
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v12, v4, -3

  li t2, 0x4b5693b265b7281f
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v8, -3

  li t2, 0x0c4d237865ed7045
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v12, 11

  li t2, 0xd3da2a8d252ccdae
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v8, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v12, -1

  li t2, 0xa23716386e5bb601
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v8, v16, 6

  li t2, 0x3e5124d90efb3851
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v28, -2

  li t2, 0x4ecfbec60a23b336
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v8, -3

  li t2, 0x5d2415b3c39f704f
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v8, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v4, v12, 15

  li t2, 0x28f3f51214c8f824
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v8, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v12, 0

  li t2, 0xc3efb60267533958
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v8, -2

  li t2, 0x853bba1fd6813a10
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v28, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v16, 6

  li t2, 0xbf20d4ebae68af4e
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v24, -9

  li t2, 0x971fd89ef0d46ee8
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v4, v12, -5

  li t2, 0xc71d1c73d214a144
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v8, -3

  li t2, 0x876a8d68cb44fd39
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v28, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v28, 2

  li t2, 0x09292eabd903d82c
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v8, 14

  li t2, 0x283fe39a4661f6b3
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v28, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v8, 1

  li t2, 0xcea2dbfe2df3a874
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v4, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v4, v12, -5

  li t2, 0x823f7ce709ad2bba
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v28, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v8, v20, -12

  li t2, 0x9475972763191466
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v4, 6

  li t2, 0x6c3545ed324b6ee4
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v12, v4, -8

  li t2, 0x7a62320313a333ad
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v20, -9

  li t2, 0xf855c63c81c8bb99
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v12, v24, -14

  li t2, 0xc14b802ab79cc5e4
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v24, -1

  li t2, 0xd08bf30a141c1ebe
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v12, 15

  li t2, 0xfb42362bac91fbcc
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v8, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v16, -12

  li t2, 0xd9c223be26512645
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v8, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v20, 12

  li t2, 0xb821f617465e0554
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v28, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v4, v12, 2

  li t2, 0x802de9f244d8e4e7
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v12, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v4, v12, -7

  li t2, 0x294de47504c53aee
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v12, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v28, 7

  li t2, 0x92d2ef011ce66e42
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v12, 4

  li t2, 0x932359eb0d97b1bc
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v4, v20, -1

  li t2, 0x2fbf4ef114f697ba
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v24, -15

  li t2, 0x8f1d21309f84953a
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v20, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v8, 8

  li t2, 0xe42d0ff807ab0e36
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v8, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v12, v28, -6

  li t2, 0x465316b3e53d6f42
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v12, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v12, v24, 2

  li t2, 0xbd910a506e0e1182
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v12, -5

  li t2, 0xd3d5023ad3f88ed4
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v28, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v12, v8, 9

  li t2, 0xcc68296aedb6dabf
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v8, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v20, -3

  li t2, 0xf01c6c8df1cb302e
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v20, -5

  li t2, 0xaf2fb01d3d3f2197
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v20, 1

  li t2, 0xf069c044ac5f700e
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v8, v4, -14

  li t2, 0xc97f38f13d0257ce
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v4, v12, 1

  li t2, 0x3c4d4cf34146440b
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v28, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v12, 15

  li t2, 0x63881a2fecc9a020
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v4, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v4, v12, 1

  li t2, 0x15dd1ca0142995ee
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v12, -14

  li t2, 0xdd865b3b7e61fb15
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v12, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v4, 6

  li t2, 0xfe282077bed57571
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v12, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v8, v12, 11

  li t2, 0x05e17e6975fbe7e2
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v4, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v20, 0

  li t2, 0xda1e45e84774b71f
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v28, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v8, v12, 5

  li t2, 0xc8cc758976af5603
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v16, 10

  li t2, 0x01c6359270a86d2b
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v8, -5

  li t2, 0x6fedebc730ddf2e0
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v28, 13

  li t2, 0x86d75765477465c4
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v20, -14

  li t2, 0xc4fcad55dc125931
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v20, v12, 5

  li t2, 0x3f870406d3336302
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v4, -11

  li t2, 0xd66c797bb4735cef
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v28, 15

  li t2, 0xd0bbef76920c0ae3
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v8, 15

  li t2, 0xfe5f2044cace7598
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v4, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v12, v20, 15

  li t2, 0xb74d51e239e6faf7
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v4, v12, 11

  li t2, 0xe44eccddc366130f
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v28, v4, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v8, v12, -6

  li t2, 0xaad216f307126441
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v12, v28, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v28, v20, -15

  li t2, 0xa639e91eeb6e1f62
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v8, v4, 6

  li t2, 0xf1f1122aecfe60e6
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v12, v16, 0

  li t2, 0x38bdbe1b45882722
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v16, v28, 8

  li t2, 0xc44fe1815c02c7f3
  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vrsub.vi v24, v4, -8

  li t2, 0xdc2d915a0d48a2c3
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v24, 11

  li t2, 0xd90449a1abd8285a
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -11

  li t2, 0x76ef40d31a455d62
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, 14

  li t2, 0x18adee34a51087ce
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -6

  li t2, 0xbf97eed27ae3b20a
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v16, 8

  li t2, 0xdaa95074471afb09
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, 6

  li t2, 0x250cc8b7b211a9cc
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -6

  li t2, 0xc350bd14449665ef
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -1

  li t2, 0x0956f52781e1ab51
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, 3

  li t2, 0xb1da89d39be86c92
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, -13

  li t2, 0xe54a6cdaf7bf0399
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -16

  li t2, 0x84b287c66161f87a
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, 8

  li t2, 0x887411e1f34b5a73
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v16, 1

  li t2, 0x933385dd67f163f2
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -16

  li t2, 0xe0ff6af046a2705e
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v16, 8

  li t2, 0xe38749d039eca535
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v16, 1

  li t2, 0x1576c19c36ea802b
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, 7

  li t2, 0x3b7da670118ac89a
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -6

  li t2, 0xa5c9f036eccd3fa3
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, 0

  li t2, 0xd2c52fd9012c0c8b
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v16, -4

  li t2, 0xcf576bdce0aff17a
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -13

  li t2, 0x2c6e066290cd0166
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, 11

  li t2, 0xf7adee34cdc4e34b
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, -15

  li t2, 0x06d473c4c0dd50f1
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v24, -12

  li t2, 0x44f799c5a7484139
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, 14

  li t2, 0x5ea8072da3a55e8c
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v24, -13

  li t2, 0xe039c4e9e6f05496
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, 12

  li t2, 0x07ab92acf79fbd7c
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, -12

  li t2, 0xba6e90fc76e1f9a3
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, -11

  li t2, 0xd6cec2799446987b
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, 2

  li t2, 0x8a5f837690c89f1d
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -16

  li t2, 0x07863fb73d86305a
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, -2

  li t2, 0x01750bf74eec2ffb
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, 6

  li t2, 0xb3ba2fec5ba23acd
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, -12

  li t2, 0x483d5e9d2753b103
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v24, 4

  li t2, 0xaea88cbc41697871
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, 6

  li t2, 0xa4bb20f2ba509b9e
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, 9

  li t2, 0x20987b6adaaadba6
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, -9

  li t2, 0xdd6e768501236c9b
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, 7

  li t2, 0xb776fecf9a3e2fe8
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, -7

  li t2, 0x496e65e3783ae5d3
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, 10

  li t2, 0x8fe47fe91e8b4e5b
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v16, 12

  li t2, 0xe56278717b0cbecc
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, -8

  li t2, 0x80c73da178e8f49b
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -9

  li t2, 0x2c2233c260b1da7c
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, -15

  li t2, 0x67a61a375c8f88c8
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, -10

  li t2, 0x4f40e8ba96a84e97
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, 8

  li t2, 0x07335422ed7767e0
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, 0

  li t2, 0xfd2736c8c9c61f3d
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v24, 3

  li t2, 0xad81c83fcbe9ae20
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v16, -5

  li t2, 0xee13bd3ea677e536
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, -3

  li t2, 0x543f0de38d9f7c03
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -1

  li t2, 0x748086b8c9a74e8b
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, 2

  li t2, 0x0b156797cbb6ce8f
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -13

  li t2, 0x85774980e5c82503
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v16, 11

  li t2, 0x3fde768f00a3f58c
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, 5

  li t2, 0xb3b92038c602f09e
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, -5

  li t2, 0x14d533d4d80383b8
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, -12

  li t2, 0x6548be42e289045e
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v24, 9

  li t2, 0x2e604ba2183e4730
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, 2

  li t2, 0x1b831dc98038f610
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, -14

  li t2, 0x88404496aaddd5af
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, 2

  li t2, 0x5ab5f3dbaf83ed5c
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v24, 1

  li t2, 0xbb1734f26c7acd60
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, 2

  li t2, 0xc7a89edd8a6bf607
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -1

  li t2, 0x4e9502c1cde92ec1
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, 1

  li t2, 0xdfc14737d51ac275
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, -2

  li t2, 0x3d3175443daa0b32
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, 5

  li t2, 0x8b70418ccd285271
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, 14

  li t2, 0x6909e5aa9dc966f5
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v24, 2

  li t2, 0x2a6f5de71ec00af6
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, 6

  li t2, 0x1bfd8721572af7e5
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v24, 12

  li t2, 0xab006729776f3290
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v24, 9

  li t2, 0x0961968d81016541
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, 14

  li t2, 0xe9abc77751d816cb
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -16

  li t2, 0xe451c74f856b7bb7
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, 14

  li t2, 0xc487d5aa76c17ee6
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -13

  li t2, 0x835890f4b8c4290c
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, 2

  li t2, 0x4a2d8b2ab403ad3f
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, 5

  li t2, 0x86e52bf89f4f8762
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, -7

  li t2, 0x124282d0bd8eb160
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, 5

  li t2, 0xfb33fb26a5d9d516
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, -10

  li t2, 0x028235b07232d93c
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, 3

  li t2, 0xd371ffa7fb4abd4a
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, -9

  li t2, 0x56cb4d2027bba209
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -3

  li t2, 0x3abc1c15bcf9d80c
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v24, 10

  li t2, 0x78f417634d9ee348
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, -3

  li t2, 0x53f6b74f4825f8a6
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, -1

  li t2, 0xd3e6342233f1cc4d
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, 14

  li t2, 0xb941feb59e6925cf
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, -2

  li t2, 0x352fd46542738cde
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, 12

  li t2, 0x7588ac90b69e81f0
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v24, 13

  li t2, 0xc67bac416a838f67
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v16, -14

  li t2, 0xcc9e9118eb8299d9
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, -9

  li t2, 0x82ac4f3e7b1b0563
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, -2

  li t2, 0x0bed8631891b9aac
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v16, 8

  li t2, 0xdfc6e62201be2673
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v16, -2

  li t2, 0x06cf873d99918ce7
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v8, v16, -14

  li t2, 0x1e451cb001d7a90b
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v24, v8, 9

  li t2, 0xf44d4c63b3925fc6
  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e8, m8, ta, ma
  vrsub.vi v16, v8, 8

  li t2, 0x24be12e4f2a43abd
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v22, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v30, v17, -10

  li t2, 0x6bad3cedbe9108eb
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v1, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v16, v9, -15

  li t2, 0xe56da7c4c968b06d
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v29, v3, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v25, v26, 3

  li t2, 0xb9d5b471708a1995
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v9, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v6, v10, -1

  li t2, 0xd65a21d81ecb460c
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v19, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v8, v24, 15

  li t2, 0xf450429dc5538ddc
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v4, v27, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v10, v24, -13

  li t2, 0x2240b3bfcf8489a9
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v26, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v4, v13, -16

  li t2, 0xae3ed1693b33b06a
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v23, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v26, v31, -15

  li t2, 0xf2ab507d317ed687
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v2, v13, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v9, v1, -10

  li t2, 0x1cb915b68aed9e89
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v8, v13, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v20, v15, -6

  li t2, 0xcbc54680908d2527
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v4, v14, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v7, v29, -8

  li t2, 0xc03c02842c501af2
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v12, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v15, v17, 2

  li t2, 0xa6418ecbcaedf5c1
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v13, v9, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v4, v21, 4

  li t2, 0x94109e166a5931d8
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v15, v10, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v24, v14, 8

  li t2, 0x081df69f70c949de
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v2, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v15, v3, 10

  li t2, 0x193a4de416fb55a6
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v13, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v21, v20, -13

  li t2, 0xfcb8b295c23e831b
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v23, v6, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v12, v30, 9

  li t2, 0x4ff58d5efcb246dd
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v17, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v27, v17, -14

  li t2, 0x08a884eb3d022e85
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v12, v7, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v4, v10, 1

  li t2, 0x1d9a8332390d5ad4
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v15, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v31, v27, 9

  li t2, 0x777317277c76a3e7
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v29, v27, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v27, v18, -8

  li t2, 0x046d0916eab8a124
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v2, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v2, v7, 3

  li t2, 0x68641f9a56fc2710
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v8, v10, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v13, v21, 7

  li t2, 0x1f8c16f7dcbeaf3a
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v13, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v6, v22, -10

  li t2, 0x57b26d5f93bbbbb5
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v17, v23, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v31, v26, -15

  li t2, 0x9a2ec1424e5da98a
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v7, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v25, v12, -8

  li t2, 0x36c5a76fc7c9861e
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v30, v3, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v23, v29, 12

  li t2, 0xa7d8457136daf750
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v17, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v6, v27, -16

  li t2, 0x8d6c310cf04e38f2
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v20, v9, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v6, v8, 13

  li t2, 0x0d94fe1d554f072e
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v26, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v7, v13, 6

  li t2, 0x151c0949796aa2a9
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v3, v6, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v30, v28, 12

  li t2, 0x33a87c85bb195169
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v5, v26, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v4, v8, -6

  li t2, 0xeb8befe22489c79d
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v6, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v30, v21, -8

  li t2, 0xb8d0e5968cf5c43c
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v29, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v1, v9, -12

  li t2, 0xf15100d701ab1ee9
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v31, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v8, v3, -2

  li t2, 0xc9b2e836fef32968
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v11, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v23, v14, 6

  li t2, 0x4444deca8836726b
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v8, v5, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v23, v9, 7

  li t2, 0x03bd339695064312
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v18, v30, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v2, v26, -5

  li t2, 0x6c95243a084688d0
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v4, v6, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v19, v4, -8

  li t2, 0x69b8a2e3602a2cc2
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v4, v23, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v14, v3, 14

  li t2, 0x6209435ad6ec110e
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v24, v27, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v12, v31, -15

  li t2, 0x5b00907a1d67d4da
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v17, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v23, v18, 14

  li t2, 0x2aaedc53796b1259
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v28, v27, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v23, v19, -10

  li t2, 0x4f8a673be518387b
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v14, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v12, v27, -15

  li t2, 0x338346cef2d27ec8
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v14, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v6, v11, -7

  li t2, 0xa5f32461e848b05c
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v7, v21, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v15, v12, 1

  li t2, 0x49b9394c007b43b1
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v31, v14, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v5, v9, -12

  li t2, 0xbd36851641ce58f6
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v21, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v14, v2, 11

  li t2, 0x1cef4b7a5bf90769
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v1, v7, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v5, v7, 0

  li t2, 0xe5698f5d280ae0ce
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v2, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v9, v24, -5

  li t2, 0x9f3ca7cb07425519
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v28, v10, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v29, v15, -3

  li t2, 0x283bfa7ca00d9f7d
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v23, v12, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v22, v6, -11

  li t2, 0x9a83085b5589dfb3
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v13, v1, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v29, v23, 8

  li t2, 0x0383af8077440cbf
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v30, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v13, v7, -8

  li t2, 0x518f6e3b1674a7f5
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v17, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v19, v27, -8

  li t2, 0x431376d57f593215
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v29, v3, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v3, v24, -2

  li t2, 0x38ad8979da32007f
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v29, v12, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v9, v29, -14

  li t2, 0x1839a83ad0715490
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v7, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v23, v17, -3

  li t2, 0x508af7fae1422d7f
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v11, v13, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v20, v29, 12

  li t2, 0xa0e3f40d60f268e9
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v10, v17, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v13, v14, -16

  li t2, 0x341b4e2bc8a2247d
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v21, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v24, v30, 3

  li t2, 0xdd62256e379dbc10
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v21, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v5, v7, -2

  li t2, 0x3aeac3bbdf5fc10a
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v13, v17, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v17, v13, 5

  li t2, 0x84a0d96abace615f
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v17, v27, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v20, v11, 14

  li t2, 0x3ca1d8cebb9e8e5c
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v6, v17, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v21, v31, 0

  li t2, 0x5309f5738ffda67b
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v4, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v2, v8, 12

  li t2, 0x6c904c7aac0d7946
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v14, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v11, v5, 2

  li t2, 0x3b445a97497376f5
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v6, v30, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v12, v20, 9

  li t2, 0x898dd7d8caf71850
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v4, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v1, v3, -3

  li t2, 0x5afc033e52af2333
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v5, v24, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v24, v29, -1

  li t2, 0xc59c20ecbffccfed
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v23, v10, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v24, v6, -10

  li t2, 0x0ef7f2083b59fc12
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v18, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v26, v24, -7

  li t2, 0x12e45183b6a2c266
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v6, v22, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v16, v21, -15

  li t2, 0x572394151b8f386a
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v3, v25, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v19, v11, -1

  li t2, 0x62913bc0c1754a03
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v31, v28, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v11, v10, 10

  li t2, 0xf9f3141d6c8f0b24
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v15, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v19, v11, 10

  li t2, 0x77c3e4f0509b3afa
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v23, v5, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v18, v31, -7

  li t2, 0x1c4f62524dd42637
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v19, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v28, v27, -5

  li t2, 0x098e10fd4d74043c
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v21, v23, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v13, v16, 7

  li t2, 0x4386ded9dbce186e
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v4, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v23, v11, 4

  li t2, 0xc874890ae535ab0e
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v13, v6, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v5, v20, -13

  li t2, 0x694f8361669f5d3e
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v7, v10, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v29, v8, -13

  li t2, 0x347f9ac9e87cd333
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v9, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v17, v25, 9

  li t2, 0xeb914ed6e9b651fc
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v19, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v15, v4, 11

  li t2, 0x9f1b38d93d709d28
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v23, v29, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v29, v19, 13

  li t2, 0x3df163684fd9b968
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v9, v27, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v24, v30, 4

  li t2, 0xca8dcd498000d860
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v20, v8, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v19, v17, 2

  li t2, 0x0379477f261cedba
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v21, v15, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v29, v31, 5

  li t2, 0x1ac103b9887949c8
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v4, v2, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v21, v2, -16

  li t2, 0xb4a6747fba29e1d2
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v26, v14, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v13, v17, -7

  li t2, 0xcf8171ffdbbbde9e
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v2, v29, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v19, v31, -5

  li t2, 0xa593b40480dd4b3a
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v19, v1, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v11, v2, 13

  li t2, 0xafc3433e6961de2a
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v15, v23, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v1, v9, 1

  li t2, 0xb82faf9efdd30374
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v8, v19, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v22, v15, -4

  li t2, 0x7d8148dccf403fcd
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v3, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v11, v19, -16

  li t2, 0xeb610f0304cd1947
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v27, v11, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v1, v14, -5

  li t2, 0x3bf36c9d9537e1e5
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v14, v1, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v29, v25, -16

  li t2, 0x25567a250d6d25be
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v2, v26, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v1, v17, 1

  li t2, 0x039b3af6780133aa
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v16, v20, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v28, v4, 15

  li t2, 0x7d430bf851696d02
  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vx v5, v26, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vrsub.vi v1, v22, -13

  li t2, 0x9060db1d2667827f
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v24, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v4, v16, 3

  li t2, 0xd3176f953f673960
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v28, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v24, v14, -4

  li t2, 0x31e188008e4d8e0a
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v6, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v26, v24, -16

  li t2, 0x56ae385eb239f184
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v14, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v20, v26, -4

  li t2, 0x02cb1a84f8c0fb05
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v4, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v30, v4, -14

  li t2, 0xd2782f0dcbea7e1c
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v4, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v16, v24, 5

  li t2, 0x985a5ca004027c44
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v26, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v30, v8, 2

  li t2, 0x44d802dc9a95785f
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v22, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v4, v26, -8

  li t2, 0x70da608757dca5a0
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v28, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v24, v4, -12

  li t2, 0xe9c613b59fd23c5c
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v8, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v16, v30, 8

  li t2, 0xf4d66f020d4daaaa
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v6, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v22, v6, -9

  li t2, 0x1f5b9ba48316b1f7
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v20, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v8, v14, 8

  li t2, 0xff91d76ed5fc5d02
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v8, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v18, v30, -8

  li t2, 0xaae9d77b74f7a987
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v4, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v24, v30, 13

  li t2, 0xdcf222cb032651f1
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v14, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v14, v28, 10

  li t2, 0x7d2efa0ceaa28b59
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v8, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v14, v26, -4

  li t2, 0xbebee9d807275055
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v28, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v20, v4, 13

  li t2, 0x5c0d66758441d38b
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v12, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v18, v2, -5

  li t2, 0xe40c576e43863f4f
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v18, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v12, v18, -9

  li t2, 0x7731f969472a660f
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v2, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v8, v18, 8

  li t2, 0xbb5a6ecfb8746fed
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v6, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v22, v12, -5

  li t2, 0x635e63b6136c84a7
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v14, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v22, v12, 12

  li t2, 0x5481a0e08e53ee94
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v2, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v8, v26, -7

  li t2, 0x4472a3bf42927e54
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v24, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v12, v24, -10

  li t2, 0x03e33596ba206ff4
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v30, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v8, v12, 1

  li t2, 0x0d707766a44dc498
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v30, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v28, v20, 1

  li t2, 0xcfac43f3a7d9affe
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v14, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v16, v24, -2

  li t2, 0xb9c4a84b6625b678
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v4, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v22, v6, 13

  li t2, 0x16a2a9051d46cdd6
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v22, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v6, v14, 0

  li t2, 0x62edf07e1fbd3d4b
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v16, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v8, v16, -3

  li t2, 0x23405cf9ab49d05c
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v18, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v20, v28, -8

  li t2, 0xc486d349f7d47420
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v6, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v4, v26, -1

  li t2, 0x2fc8087a0b174e61
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v14, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v12, v14, 10

  li t2, 0xae5366d0bd595d4a
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v2, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v20, v10, 3

  li t2, 0x0f5acd75781b3fe4
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v24, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v28, v18, -4

  li t2, 0xef77567383ddebcc
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v10, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v22, v20, 10

  li t2, 0x4007a1eeeec9b553
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v28, v24, 1

  li t2, 0x234fa6ba1ec1a348
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v2, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v28, v4, -5

  li t2, 0x395ddcc95ae7b414
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v10, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v24, v30, 9

  li t2, 0x92e00224cf3e3e86
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v4, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v2, v8, 2

  li t2, 0x4f3dfeeb88a6429f
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v14, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v4, v26, -16

  li t2, 0x2268272308fbdf62
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v26, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v20, v12, -14

  li t2, 0x626661b879e82696
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v6, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v20, v8, 10

  li t2, 0x7d8ea9b9a5d72197
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v6, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v20, v24, 9

  li t2, 0x2ba0668a6080e352
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v28, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v24, v30, -14

  li t2, 0x2703a5138db31fa9
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v18, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v22, v28, -11

  li t2, 0xd0dabcd5d7ec7aa6
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v18, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v24, v22, 9

  li t2, 0x57366773b95942d2
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v2, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v12, v22, 1

  li t2, 0x29577598672e8cec
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v6, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v8, v22, 15

  li t2, 0x0d3ea03a545dd93e
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v18, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v12, v20, 0

  li t2, 0x89cc20c311a556f7
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v18, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v26, v28, 0

  li t2, 0xfb3ac1784fd34797
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v20, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v26, v28, -9

  li t2, 0xe039f4b15826e06b
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v10, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v6, v28, 11

  li t2, 0x6e70af836daf60e5
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v4, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v14, v16, -14

  li t2, 0xaafffe07f3950bb3
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v10, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v18, v20, 7

  li t2, 0xa7f37dd35b0de522
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v24, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v22, v20, 12

  li t2, 0x5497316841a85fce
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v16, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v26, v10, -6

  li t2, 0xe844a4d8189c708c
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v18, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v10, v28, 6

  li t2, 0xbf95a69136886b59
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v26, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v12, v28, 0

  li t2, 0xb7258b1fd9f47e4a
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v28, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v6, v16, -5

  li t2, 0x6f09201d4e4dd36d
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v30, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v2, v14, -11

  li t2, 0x5ce4057433b0d26c
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v30, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v6, v10, 10

  li t2, 0x6987cb6d00a21e5e
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v8, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v8, v28, 5

  li t2, 0x086c6bad265cf36d
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v28, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v2, v14, -12

  li t2, 0xc1fd8e413a349561
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v18, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v20, v8, 0

  li t2, 0x526aa2a3e2ea1be8
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v6, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v16, v30, 9

  li t2, 0x083263a9ae2998a1
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v30, v24, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v28, v18, -1

  li t2, 0xe65090233cf8a79a
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v8, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v28, v8, -2

  li t2, 0x6f4aacc1a424e6c2
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v16, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v12, v6, -1

  li t2, 0x328e27b3895a439b
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v16, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v24, v10, 7

  li t2, 0x79f103869778dab9
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v12, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v20, v22, 3

  li t2, 0xa104f7bf2356f163
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v10, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v22, v10, 10

  li t2, 0x76b610b2944f46e0
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v18, v10, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v18, v8, -1

  li t2, 0xecbca33d29d82a6b
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v10, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v2, v14, -14

  li t2, 0x18a73a09720a680b
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v12, v30, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v26, v6, 10

  li t2, 0xb828b6d4fcb0da72
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v30, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v18, v4, 9

  li t2, 0x7530ad63b8d9cfb9
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v18, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v28, v14, -14

  li t2, 0x9e545d4df6ebf5ec
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v4, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v16, v22, 7

  li t2, 0xcd9ddafa1723a1f2
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v18, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v24, v2, 12

  li t2, 0x5696c37ea5f78fce
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v16, v26, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v4, v12, -6

  li t2, 0xdf8e860c49f9e071
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v12, v18, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v10, v6, 14

  li t2, 0xb1badd095ca05bdc
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v26, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v12, v28, 8

  li t2, 0x89afa700374639dd
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v2, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v4, v18, 12

  li t2, 0xc65f882e9e578419
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v18, v30, 7

  li t2, 0x8f141e6229e9b6e1
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v12, v16, 4

  li t2, 0x5c16faa32da60e83
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v16, v30, -14

  li t2, 0xc56cb08bd594c20e
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v18, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v8, v30, -6

  li t2, 0xee3ed80548bf8586
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v18, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v12, v20, -2

  li t2, 0x99905f0d01c4357e
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v26, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v24, v8, -16

  li t2, 0x45e35182fc733c85
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v30, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v26, v24, -3

  li t2, 0x02bd059d073e846e
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v6, v28, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v14, v18, 5

  li t2, 0x59396b0b47596e44
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v18, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v6, v22, 9

  li t2, 0xa90f18e605daf0c0
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v6, v14, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v6, v20, -8

  li t2, 0xb7c0d82d17fc2829
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v8, v22, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v26, v4, -8

  li t2, 0x2c2558d339945a0a
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v8, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v6, v4, -2

  li t2, 0x4e1806757c9aabf9
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v14, v2, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v10, v12, -5

  li t2, 0x7038567800c32a2e
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v18, v24, 14

  li t2, 0xec5fab358b370c69
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v12, v16, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v10, v16, -10

  li t2, 0xd500113ed2b66b67
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v4, v20, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v26, v6, -7

  li t2, 0xd4ce3aec60cfd38d
  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vx v18, v6, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vrsub.vi v14, v2, -5

  li t2, 0xe9b5cda3c08bd814
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v12, -10

  li t2, 0x62386bb61fcd528b
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v4, -15

  li t2, 0xb53fd13a5f179456
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v20, 6

  li t2, 0x4f88881b225845b1
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v4, 5

  li t2, 0xb417296c9343e8a3
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v16, v20, -7

  li t2, 0x99cec5b79536eff0
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v16, v28, -16

  li t2, 0x45b51c411a57e076
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v16, v20, -4

  li t2, 0xe2780d1df6aa9375
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v20, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v16, -14

  li t2, 0xb4a1ba412d0717af
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v12, -7

  li t2, 0xf666a2fbbe28eb0b
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v28, v12, -10

  li t2, 0xf3dd6a3f929a6731
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v20, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v12, v8, 6

  li t2, 0x962fc625d00f43ed
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v20, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v12, v20, -9

  li t2, 0x9fc21b64386d3f17
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v8, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v12, v16, 7

  li t2, 0x2d8ad86e8a3c7e31
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v16, -6

  li t2, 0xeb2d12e7c2351d45
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v12, 11

  li t2, 0xdaa50090fcee0740
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v20, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v20, 9

  li t2, 0x79c23b6fefdcc009
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v28, 1

  li t2, 0xa1168707500e95dc
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v12, -10

  li t2, 0xe94eb8398ccc550f
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v28, v12, 2

  li t2, 0x7df5a86a059775ea
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v28, -3

  li t2, 0x5f56cc5a25190756
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v8, v24, 0

  li t2, 0xb9764a3e9b1576cb
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v28, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v8, v16, 0

  li t2, 0xbdd09f57fb432622
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v16, v28, -7

  li t2, 0x8e6f121fb9d03c82
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v24, -16

  li t2, 0xd7dc5e0f4161c438
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v8, v28, -16

  li t2, 0xabf0a6e8002607e7
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v28, 3

  li t2, 0xc4cac787c1ff522b
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v20, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v16, v8, -6

  li t2, 0x155dc07096ebed49
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v28, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v20, -5

  li t2, 0x0ecb343de5668f8b
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v8, -3

  li t2, 0x508bb18e0176a781
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v8, v24, 5

  li t2, 0x838a8860eecb437a
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v28, -11

  li t2, 0x017ca9dbb7f84552
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v20, -4

  li t2, 0x42dce3bb7969cbe1
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v28, v8, -12

  li t2, 0x4356e7cd57bdef0d
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v28, 13

  li t2, 0x4f98fcebac742207
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v16, 15

  li t2, 0x92585a0eee8fe48e
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v24, -16

  li t2, 0x3fbbd43da80880ce
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v12, v16, -4

  li t2, 0x70ac43820695f367
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v8, v28, -16

  li t2, 0x69926164c33f36b3
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v16, 12

  li t2, 0x3a3ba51f75772711
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v16, v28, 5

  li t2, 0xfd305cc1d5ecaa57
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v28, v24, -14

  li t2, 0x0f59fde6d769d273
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v12, 13

  li t2, 0x550e7f59ac9b4b7f
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v28, v4, 15

  li t2, 0x3f495911149bd798
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v12, -15

  li t2, 0x5d308df8ad5ceed1
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v8, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v12, -8

  li t2, 0x5af34e252973412f
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v12, v24, -6

  li t2, 0x4926b9699c08a068
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v28, v12, 11

  li t2, 0xf81aa8c0052c8a80
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v8, -4

  li t2, 0xd52e06e672ba0a35
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v8, v24, 14

  li t2, 0x2b7f36612ac75cae
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v28, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v28, v4, -11

  li t2, 0x143c53c3f2ce866f
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v12, v16, -6

  li t2, 0xa53112ed2cf780cf
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v28, v24, 5

  li t2, 0x2e5a3df0a10c1eda
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v12, -3

  li t2, 0x05974aa191a1c3e3
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v28, v4, 1

  li t2, 0xd36f3b041472e74d
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v12, v16, 14

  li t2, 0x2e40af96cadcf0fd
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v28, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v12, -1

  li t2, 0x5b384fa21eb37812
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v16, 13

  li t2, 0x497394a112a536ae
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v28, 7

  li t2, 0x78db7bcfc5bf8723
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v28, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v28, v16, 9

  li t2, 0x69f1cc98c5146e98
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v12, 4

  li t2, 0xeaa925b8cd375cfc
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v28, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v12, v8, -3

  li t2, 0x70a8d9a38b5b3661
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v28, 2

  li t2, 0x3ba76f859f12ba97
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v20, 5

  li t2, 0x9322bbc948c00b2b
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v16, -15

  li t2, 0x65e10eba6b3e67d4
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v12, 15

  li t2, 0x4f00353f7fb78218
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v12, v4, -4

  li t2, 0xdacfed7248187c3c
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v16, v12, 8

  li t2, 0x511e9aba062edcab
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v8, v4, 5

  li t2, 0x328fff44c92a285c
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v8, -10

  li t2, 0x5439f3ad19934c08
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v8, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v16, -11

  li t2, 0xff4d8b9b88b1680a
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v20, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v28, -2

  li t2, 0x5e3c693a3769f613
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v28, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v12, 13

  li t2, 0x6bee6fa96da8b3d2
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v20, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v16, v12, 6

  li t2, 0x5706661fb8bda99b
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v28, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v28, 6

  li t2, 0xc36e6eb88933019b
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v8, v4, 5

  li t2, 0x1eac6e4d0069b0f5
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v20, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v24, -5

  li t2, 0x6ecd14f6b3b01386
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v12, v16, -15

  li t2, 0xd1803aa9652eb636
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v24, -5

  li t2, 0xf20ec27e27213255
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v20, -2

  li t2, 0x7a2559c6f4ed7029
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v20, 0

  li t2, 0xcdc3a24d67164377
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v28, v20, -16

  li t2, 0x95d5f6c445899294
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v28, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v28, -1

  li t2, 0xc4a64e9aa5b7f686
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v24, 0

  li t2, 0x88729e5b125c08d6
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v8, v4, 6

  li t2, 0xc5f79073009bc87a
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v12, v24, 2

  li t2, 0x6048a74aeabe9acf
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v16, v20, 12

  li t2, 0xd8f04e4bcfa239c9
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v16, v4, -8

  li t2, 0xbebf13561c0ab3d8
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v20, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v16, v20, 2

  li t2, 0xe7d7d9ec016de82d
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v28, 14

  li t2, 0xf56bfccd40c836e3
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v24, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v8, v24, -2

  li t2, 0xc0172e9b31316a94
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v16, 15

  li t2, 0xaf3b341a6e23b77b
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v20, v28, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v12, v16, 14

  li t2, 0x1af85bedbbf86ad3
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v8, v4, -2

  li t2, 0x75c9aeb2427ad6de
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v4, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v24, -16

  li t2, 0xe2fbabadd3ed6c82
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v24, v12, -9

  li t2, 0x701f16aa8cd263c8
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v4, v20, 2

  li t2, 0xdb19f8559fd5cce0
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v12, v24, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v12, v16, 11

  li t2, 0x7ed3a415029b6787
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v16, v24, -13

  li t2, 0x2c24c1182c307c56
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v16, v4, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v20, v8, 11

  li t2, 0xeee7726ebdccd7f7
  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vx v20, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vrsub.vi v28, v12, -14

  li t2, 0x9b0ca4f04733867b
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v8, 1

  li t2, 0x3417936f4ce5c073
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, 7

  li t2, 0x3ba06c499ee23cf2
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, 3

  li t2, 0x9dc2e16ef2d81b9c
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, 9

  li t2, 0x10766fbad817cfcc
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, 6

  li t2, 0xbf4fe4bf8086bcce
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, -8

  li t2, 0xc82b0328cb56773a
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, 0

  li t2, 0x4d78ea17e118f9ad
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, 15

  li t2, 0xba2e313040e85e68
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, -14

  li t2, 0xe93e7ca7b4ffe724
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, 1

  li t2, 0xd6701be246a381c9
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, -9

  li t2, 0xdb68bc4992b40861
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, -1

  li t2, 0x74331a8d40d11a5b
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, -3

  li t2, 0x1a779e8ecb4af777
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, 4

  li t2, 0xc7f44921b8cdba7c
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, -5

  li t2, 0xb0de7983c3c13d26
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, -11

  li t2, 0xe6f91c8b97788bc9
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, 8

  li t2, 0x9fbaed481b90dfe4
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v8, -6

  li t2, 0x2f02b17a9464bbf0
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v8, 12

  li t2, 0xf2b045287abbd5a9
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, 13

  li t2, 0x81091b6aa1cb222e
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, 4

  li t2, 0x0821d66766afe59a
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, 8

  li t2, 0xfb15be83695d43fc
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, 8

  li t2, 0xed6d795480446df6
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, -8

  li t2, 0x5f8421895584f12b
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, -13

  li t2, 0x1b133d37053028da
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, -7

  li t2, 0xa371897e81162c7f
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, -15

  li t2, 0xa04cee8e28e07a3e
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, -13

  li t2, 0xd28bb316df5ba1bb
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, 4

  li t2, 0x20c5124c646ad410
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, -13

  li t2, 0xf5bcbd6f0328d3d2
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, -12

  li t2, 0x35a6c71c9d647687
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, 11

  li t2, 0xd4adcdd9eea41841
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, -13

  li t2, 0xa137f105e04f3363
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, 4

  li t2, 0xe2af9701c03130fb
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, -6

  li t2, 0x1d8ce7a5b1898301
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, 3

  li t2, 0xf758cbfc523beebe
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, 2

  li t2, 0xdcfdd4ca3d56cfa8
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, 14

  li t2, 0x5809daf8b5070e71
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, 1

  li t2, 0x0f0dfce8c8c597c7
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, -11

  li t2, 0x1f812e1010bfcb16
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, 9

  li t2, 0x455ba542870b9137
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, -13

  li t2, 0xb6cb3fda86cfa612
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v8, 2

  li t2, 0x13150b244554fcd0
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, 9

  li t2, 0xf979d3a2bad771f6
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, 1

  li t2, 0x3913520f1a5177bb
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, -7

  li t2, 0x7ce54bb9b0c5e1b5
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, -4

  li t2, 0x50a73144f315c01e
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, -5

  li t2, 0x73d5af59d6b4bdc8
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, 5

  li t2, 0xeb99e291c19f1fe9
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, 10

  li t2, 0x773b695020544ce8
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, 1

  li t2, 0xfcf80ed202133f91
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, -10

  li t2, 0x20e15372be111f4f
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, -4

  li t2, 0x9efc2d279bfac7fc
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, 7

  li t2, 0xdd981f545d17fef9
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v8, -3

  li t2, 0xffa22a3a7674151b
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, 4

  li t2, 0x67fb84d76223e408
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, 8

  li t2, 0x8143463d022940e0
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, -1

  li t2, 0xded4e53b577cd8fe
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v8, 1

  li t2, 0x67013292eb3a58ab
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, -7

  li t2, 0xc497d0d22a50e530
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, 12

  li t2, 0x3cad90aaed6c7e39
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, -1

  li t2, 0x41f73aceb924f1ba
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, 9

  li t2, 0xff38e84abb7009bc
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, -13

  li t2, 0xb9a68de1f4c9dc47
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v8, 7

  li t2, 0xe5120f83a87b80f9
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, 9

  li t2, 0x0a83664962216897
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, -9

  li t2, 0xfff03d2271293f7f
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, 7

  li t2, 0x09e6c6c84bcc972c
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, 7

  li t2, 0x345f30cf13b0ec17
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, -1

  li t2, 0x8d9276f1fd0abd68
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, -15

  li t2, 0xde7bd9de53be7b89
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, 8

  li t2, 0xfce305f5ec1cda29
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, 8

  li t2, 0xdd1e56d299661f7d
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, -10

  li t2, 0x0003511ab7041007
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, 0

  li t2, 0xa675a485aef7a6d7
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, -12

  li t2, 0x024ce408aac2200f
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v8, -4

  li t2, 0xcac87ca685888f8a
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, -3

  li t2, 0xe1c37bfc8390a35d
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, -12

  li t2, 0xf62c7a6327595359
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, -5

  li t2, 0xfaf07ba13d8ca0f4
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, -3

  li t2, 0x4fc1d655a7ede7fe
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, -13

  li t2, 0x7fa18daf8cdca4a0
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, 15

  li t2, 0x6a2c53080ec6800e
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, 5

  li t2, 0xf264b16aeb539bbd
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v8, 12

  li t2, 0x46c8ddc3a4914c81
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v8, -11

  li t2, 0x6a2aa67f928ce47f
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, 4

  li t2, 0x3ae73e29a7ce3ebd
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, 1

  li t2, 0xcec94af10d389b54
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v8, -5

  li t2, 0xd5a21eb1438a56de
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v16, 5

  li t2, 0x594fd99f765cdbd7
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, 12

  li t2, 0xe80de527869f7b61
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v8, 3

  li t2, 0x962bc4ea36d89caa
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, -8

  li t2, 0x61b8d681fde61448
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, -2

  li t2, 0xd9759da8edd6326c
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, -16

  li t2, 0xfc834942e8367f71
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v24, v8, 8

  li t2, 0x79775e077b482d89
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v24, -5

  li t2, 0x34bdc0c1b770901f
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, 1

  li t2, 0xab3e689219502bb8
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v8, v16, -13

  li t2, 0x5a130c162a97d795
  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e16, m8, ta, ma
  vrsub.vi v16, v24, -6

  li t2, 0xba8b00249f66c3fc
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v31, v23, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v13, v19, 13

  li t2, 0x21885f10c1e92134
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v15, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v1, v30, 3

  li t2, 0xd4fa251042649fb6
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v28, v19, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v3, v13, -13

  li t2, 0xe7db9bcefaba8447
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v16, v3, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v30, v27, -15

  li t2, 0xc29b3ffc55914d37
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v29, v4, 5

  li t2, 0x1f6513913f359c8a
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v17, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v29, v14, 12

  li t2, 0x47d2fae2520b5e97
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v20, v14, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v22, v30, -14

  li t2, 0x6555f40ee0222b0b
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v15, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v17, v19, -15

  li t2, 0x418c14b60c5b2de3
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v25, v1, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v27, v22, 2

  li t2, 0x6484324e06a0c4e5
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v23, v29, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v14, v2, -7

  li t2, 0x66d7fe77bd9d8210
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v10, v27, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v25, v14, -11

  li t2, 0x235fe4b080866840
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v28, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v28, v23, -9

  li t2, 0xe53db4d9ba39a93a
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v23, v15, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v3, v23, 5

  li t2, 0x1289766a9f06e9db
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v8, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v23, v13, 1

  li t2, 0x760e42f70bc3a83c
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v15, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v22, v28, -14

  li t2, 0xbf3083bad5a8e61e
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v13, v28, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v21, v3, 6

  li t2, 0xf96e1701b71c32bc
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v1, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v16, v20, 12

  li t2, 0xb3327822166e95ea
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v11, v29, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v28, v19, 12

  li t2, 0xff5532a47076d49d
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v26, v25, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v25, v12, 14

  li t2, 0xd27803aa8eb762ae
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v4, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v30, v11, -9

  li t2, 0x03e0988a1cc49bcd
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v6, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v26, v20, -9

  li t2, 0xe9e8aca71aa81335
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v26, v2, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v12, v16, 4

  li t2, 0x9b455a8a2377a762
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v20, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v6, v22, -9

  li t2, 0xd47257f24c3f7ef8
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v28, v1, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v7, v18, -16

  li t2, 0x9800f209badcfabd
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v8, v22, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v2, v22, -4

  li t2, 0xb3962fa93397bc09
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v5, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v6, v24, -16

  li t2, 0x551a4e3b857dcf58
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v15, v11, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v6, v20, 2

  li t2, 0xc794034521a3be91
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v7, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v16, v20, -13

  li t2, 0x3bed9a3a234d1199
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v3, v11, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v27, v30, 0

  li t2, 0x88a02a68d79419dd
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v14, v24, -1

  li t2, 0xe63e2de22254f915
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v24, v15, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v4, v20, -11

  li t2, 0x1f303916bb76a1f7
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v30, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v3, v20, -4

  li t2, 0xde1f1a3899bea63f
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v18, v19, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v15, v25, 14

  li t2, 0xae8b225f20fbcb5c
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v13, v3, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v4, v11, 2

  li t2, 0x5a43c23545609a81
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v4, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v31, v27, -15

  li t2, 0x923c3501a9c129e5
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v17, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v28, v24, 12

  li t2, 0xe83c44ecec2eae09
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v1, v15, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v17, v30, 13

  li t2, 0xcbecc7d24bca1228
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v5, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v11, v15, 3

  li t2, 0x12af9090fdcc7259
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v2, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v6, v9, -13

  li t2, 0xb3886a30736d8763
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v12, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v5, v18, -14

  li t2, 0xcac0b70a653f86dd
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v26, v14, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v27, v16, 6

  li t2, 0x9d72507b892b9b7b
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v9, v23, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v23, v13, -3

  li t2, 0x3f9852ebf5faba70
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v8, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v2, v7, 10

  li t2, 0xf95d2a9b59d76ad1
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v7, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v17, v21, 0

  li t2, 0x52f089b0f2f5e7ab
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v27, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v6, v28, -15

  li t2, 0x4a9972cbd6463ac8
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v15, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v9, v22, -6

  li t2, 0xc65804fe55e0ae6a
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v21, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v10, v31, -10

  li t2, 0x0a23fa07e6b82030
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v26, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v19, v31, 0

  li t2, 0xc02539eed94fdb92
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v8, v10, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v5, v27, -11

  li t2, 0x337b0c28712740de
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v11, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v21, v15, -4

  li t2, 0x166a14f4852606a0
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v21, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v16, v15, -3

  li t2, 0xba498770caff5304
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v21, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v20, v8, 12

  li t2, 0x559dce5964ade5f8
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v1, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v27, v24, 1

  li t2, 0x032bd3eb850e00d8
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v31, v28, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v4, v17, -15

  li t2, 0x8afbc4d1ae61a866
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v10, v15, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v27, v10, -15

  li t2, 0xcb5c583a8f1119a2
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v1, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v30, v8, 11

  li t2, 0x830e141e6f5c747d
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v26, v14, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v16, v29, 5

  li t2, 0x1614154690ca3b0d
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v22, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v27, v15, -4

  li t2, 0x7a3a3a95758ba795
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v31, v8, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v6, v25, -6

  li t2, 0xdd1498ebc95065c0
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v2, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v26, v10, 6

  li t2, 0x8cd5ab4732fa0e94
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v20, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v12, v21, -12

  li t2, 0x3b207d94d8404b5e
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v1, v25, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v19, v3, -9

  li t2, 0x5729d4cd7f3d2b28
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v16, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v18, v29, 11

  li t2, 0x1f9c4f443c65c76c
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v18, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v12, v23, -5

  li t2, 0x52f096918101e8dc
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v13, v17, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v5, v15, 3

  li t2, 0x583dad8671cbb3b4
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v3, v25, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v25, v20, -10

  li t2, 0xb261ef1a695a36a2
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v29, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v4, v21, -5

  li t2, 0x18d68a821b1f8ed6
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v8, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v8, v19, -5

  li t2, 0x9e80038a6d517889
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v6, v30, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v15, v24, -12

  li t2, 0xdc0b48ffa1ff5180
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v8, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v31, v11, -13

  li t2, 0x4eed8822158ba355
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v24, v17, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v9, v7, 14

  li t2, 0xeb75127e6093e17a
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v10, v13, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v19, v25, 1

  li t2, 0x1c2daeaa6c518fb8
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v17, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v7, v28, 13

  li t2, 0x1b70ab5032c371b7
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v11, v9, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v23, v1, 3

  li t2, 0xfbacb854eae7fed8
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v30, v29, 1

  li t2, 0xd968deacb855bde2
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v19, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v10, v3, 3

  li t2, 0x25ee467a0a1812c0
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v8, v6, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v16, v12, 3

  li t2, 0x881be36f93787af8
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v21, v30, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v4, v9, 4

  li t2, 0xe76cce8e58290062
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v28, v27, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v8, v25, 1

  li t2, 0xbf018f31b7e3f219
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v20, v27, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v28, v27, 15

  li t2, 0xe616dfe9065bc217
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v25, v12, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v11, v13, -16

  li t2, 0xd1db6c9ec2743eb3
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v14, v1, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v2, v5, -2

  li t2, 0x21d2cdb8235dbbac
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v28, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v31, v1, 11

  li t2, 0x32e527077ee2f337
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v29, v11, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v26, v4, -13

  li t2, 0xa1a628c1b0626816
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v12, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v4, v16, -16

  li t2, 0xc4e21d5b7632f1e7
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v9, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v10, v3, -14

  li t2, 0x0fef0e90a3bcc22b
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v3, v7, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v27, v1, 13

  li t2, 0xd0f48c9653175187
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v8, v17, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v20, v6, -12

  li t2, 0x12f7f0b68b1f7bd8
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v23, v24, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v26, v4, 6

  li t2, 0xdbb630a7f22b7360
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v5, v18, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v29, v5, 11

  li t2, 0x69a608afbfe5c369
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v8, v21, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v7, v10, 0

  li t2, 0xd39cde805c23c680
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v12, v28, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v22, v15, -3

  li t2, 0x5c6c8aa0e7862ad2
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v8, v23, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v28, v12, 12

  li t2, 0xddb79319d4119ada
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v19, v30, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v1, v5, 10

  li t2, 0x76cefc8e3147edd2
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v14, v19, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v23, v15, -9

  li t2, 0xa40a4a4ed3f329dd
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v6, v20, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v4, v25, 9

  li t2, 0x908ff2dee201b920
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v12, v19, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v16, v10, 11

  li t2, 0x54b62de7ade8e0b6
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v17, v5, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v6, v3, -4

  li t2, 0x23ac120b9b17f591
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v25, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v9, v5, 10

  li t2, 0x373b2d57588aead8
  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vx v12, v1, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vrsub.vi v1, v17, 4

  li t2, 0xe63240ac07df6772
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v18, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v2, v4, 9

  li t2, 0x0490e1323e50e06c
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v6, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v12, v14, -10

  li t2, 0x9249a75eac1411ac
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v14, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v14, v6, 12

  li t2, 0xf9b941ca64785ffe
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v2, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v10, v24, -4

  li t2, 0x1309d8a1c53fd6ba
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v30, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v30, v12, -13

  li t2, 0x52d1dab7f5a8aa83
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v22, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v2, v30, 7

  li t2, 0xb8dd2da910e7de12
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v16, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v26, v18, -11

  li t2, 0xc66d6429d761e89a
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v20, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v8, v16, 1

  li t2, 0x8dec74939c626f40
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v18, v8, 6

  li t2, 0x276d7849954ddef3
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v4, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v20, v22, -7

  li t2, 0x20728b9ccc9d2c80
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v24, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v2, v26, -12

  li t2, 0x23ff6b992301af6a
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v18, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v4, v14, -11

  li t2, 0x54c8275929c3f731
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v30, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v14, v28, -6

  li t2, 0x43b763eb3267373e
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v26, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v30, v28, -16

  li t2, 0x130b9b0056808f34
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v20, v4, 11

  li t2, 0x2343f8a4592b0597
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v14, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v18, v20, -7

  li t2, 0xec8f923413830571
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v20, v16, 11

  li t2, 0x12272075722d9292
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v30, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v4, v6, 9

  li t2, 0x7ab85f6072f76ec8
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v2, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v6, v22, 2

  li t2, 0xf75af62e43097c2c
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v26, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v26, v10, 15

  li t2, 0x10815d396f15f450
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v30, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v26, v14, -15

  li t2, 0xf079a9d7a3269f92
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v20, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v28, v18, -14

  li t2, 0x35545dab2d85d422
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v16, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v24, v20, -10

  li t2, 0x2032e9c8b1fc5c68
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v6, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v22, v4, -3

  li t2, 0x984227ded94a5a6d
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v26, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v6, v22, 8

  li t2, 0xded1f14e00921858
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v12, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v16, v8, 2

  li t2, 0xb564b32b4af05243
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v28, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v12, v22, 13

  li t2, 0x6c87b4b9411caf11
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v14, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v12, v22, 2

  li t2, 0x3506e6d482583b4b
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v16, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v20, v10, 13

  li t2, 0x410e307c7c47f307
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v22, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v4, v20, 10

  li t2, 0x4851b0a1cc748c81
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v8, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v8, v30, 13

  li t2, 0xe67abf34aba1d63b
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v28, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v18, v24, 0

  li t2, 0x23f74a7620673db2
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v20, v12, -12

  li t2, 0xfd5120bcb2c0bd77
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v30, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v30, v16, 13

  li t2, 0xc37dcafd4e8c860d
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v14, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v24, v4, -4

  li t2, 0x3fde3a526e1c3946
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v14, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v16, v20, -15

  li t2, 0x39bdb2e268afbb88
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v18, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v20, v4, 4

  li t2, 0x5b812bd3245a66bf
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v4, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v8, v28, -1

  li t2, 0xd2a0ed685158421e
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v30, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v6, v24, 14

  li t2, 0x159ff80d403b13b5
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v4, v2, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v20, v4, -1

  li t2, 0xd6bfc9fe6acc2a68
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v26, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v8, v12, 9

  li t2, 0x101b422544db47b4
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v14, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v6, v8, -4

  li t2, 0xc66a1a2c0eab817b
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v26, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v2, v8, 12

  li t2, 0x481e266615bb1eae
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v20, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v18, v16, -7

  li t2, 0x799e2ad7cc0a7fe1
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v30, v28, 3

  li t2, 0x93bf7f224458d538
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v26, v16, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v20, v4, -9

  li t2, 0x41bd85ce517f00a5
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v24, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v30, v6, -14

  li t2, 0xd9249ef10f90e774
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v12, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v30, v6, -12

  li t2, 0x3aec097c3da5ead0
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v18, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v4, v8, 9

  li t2, 0x875f27b27ac7174a
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v14, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v10, v26, 15

  li t2, 0x4d217f3ff152d0a0
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v24, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v2, v4, 2

  li t2, 0x6c0e6946b8ab202d
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v30, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v10, v12, 1

  li t2, 0x550d8edf8a0b06cd
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v20, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v26, v20, 13

  li t2, 0x16df715e3965b3b8
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v8, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v2, v24, 4

  li t2, 0x481a766a0cb22a10
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v10, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v14, v22, 2

  li t2, 0xf5ec2226b5b6a1ab
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v28, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v4, v28, -12

  li t2, 0x7c8bcde615f12506
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v24, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v4, v28, -5

  li t2, 0x25c0e319d8211fbb
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v20, v14, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v18, v30, 10

  li t2, 0xece1c8210876b08d
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v14, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v2, v28, -15

  li t2, 0x045085e149071cc9
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v20, v26, -9

  li t2, 0x01d9b21d4e0e43f7
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v2, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v6, v26, 5

  li t2, 0xb16d523b191dcc79
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v6, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v30, v20, 11

  li t2, 0x2971a5f570610979
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v20, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v30, v18, 14

  li t2, 0xbe19bb3e992d3ed4
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v16, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v6, v20, 8

  li t2, 0xa7f42eebc9aa1490
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v10, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v16, v8, -6

  li t2, 0x28e1449ebefd8861
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v22, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v30, v22, -16

  li t2, 0xf8f1419ca26dfc6b
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v20, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v4, v6, 1

  li t2, 0x2a8275f2260d05cf
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v20, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v6, v30, -11

  li t2, 0xf09cf084e7166e23
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v26, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v10, v26, -1

  li t2, 0x0818de96c59ee990
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v8, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v10, v8, 5

  li t2, 0xa41239768c530224
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v30, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v2, v30, -10

  li t2, 0xb185e85f2eeb2d0c
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v24, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v18, v10, 0

  li t2, 0x0e73dea27993750b
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v6, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v8, v10, 6

  li t2, 0xf337e8113ff1e94e
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v30, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v8, v10, -16

  li t2, 0x4c7c91f2f17d5fa6
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v20, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v4, v16, 8

  li t2, 0x09d1b51b51eadf64
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v12, v20, -12

  li t2, 0x5f37e7736a4c4c11
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v28, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v10, v8, 0

  li t2, 0xa562bebc1d237cd3
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v10, v28, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v12, v28, 4

  li t2, 0xa9107bf95febd12f
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v16, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v16, v10, -13

  li t2, 0x493fd4736525f530
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v26, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v18, v30, 12

  li t2, 0xf24dc33b0115db48
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v2, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v10, v24, 14

  li t2, 0x89ecefe664cbfeea
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v20, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v8, v18, -1

  li t2, 0xcfafa1f62452c95a
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v22, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v4, v16, -9

  li t2, 0xfc69155980c0bfba
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v16, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v24, v22, -2

  li t2, 0x48a409da7c3d8379
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v18, v8, 3

  li t2, 0x0375e8443e5e2bcc
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v20, v22, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v16, v4, 13

  li t2, 0xdc80eb1213c411ec
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v28, v6, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v4, v14, 4

  li t2, 0x68a867e522493295
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v22, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v24, v6, -12

  li t2, 0x336300b3f7867032
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v12, v24, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v30, v2, 8

  li t2, 0xa86a779c0bf18032
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v10, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v18, v6, -11

  li t2, 0xf700598220b3923e
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v16, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v6, v28, -11

  li t2, 0xcd4c2b928f5ef331
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v10, v20, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v8, v10, 8

  li t2, 0xe9593bffc07967a1
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v28, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v30, v2, -10

  li t2, 0xf188b51ca3ba92bb
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v8, v12, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v4, v18, 6

  li t2, 0xebdb6a83d21f18ef
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v14, v30, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v4, v6, -6

  li t2, 0xd2625a7084b77502
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v16, v18, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v4, v14, 7

  li t2, 0x16e6a9b8bf77d843
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v16, v10, -13

  li t2, 0x434ea8b3ad830bea
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v28, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v6, v28, 9

  li t2, 0xebbc3524b94c7a2c
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v20, v10, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v10, v4, 12

  li t2, 0x1eeaa4d776dd7893
  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vx v12, v26, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vrsub.vi v28, v16, -10

  li t2, 0x559347890b994456
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v24, v4, 7

  li t2, 0xf021b1e636abef9b
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v16, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v8, -1

  li t2, 0x4356a18bb7585766
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v24, v8, 11

  li t2, 0xccc7f54bbf6e5a05
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v16, 9

  li t2, 0x4923aae10b513689
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v20, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v24, v8, 11

  li t2, 0x6cbaba88788d099c
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v20, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v24, 0

  li t2, 0xe67f78d41dafce6b
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v24, v28, 14

  li t2, 0x66505f31b758ff73
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v24, v16, -8

  li t2, 0x430726f589ba70e0
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v28, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v4, v28, -15

  li t2, 0x27e012e724eec02c
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v28, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v24, 2

  li t2, 0x7a51d9fb18211b74
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v4, v20, -14

  li t2, 0x1be9cdd374eda90a
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v20, -4

  li t2, 0x279fbbe67a4daffa
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v4, 4

  li t2, 0x7f3673033c2cb18a
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v28, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v24, -11

  li t2, 0x4f8260c584fc88a1
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v12, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v20, 1

  li t2, 0x08896af2bb9df05d
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v16, 9

  li t2, 0x66e0a0d4f6345089
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v12, -9

  li t2, 0xd4d661f239e8eb76
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v4, v8, 9

  li t2, 0xdcc6e18dc47b0618
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v16, -13

  li t2, 0x9470190a6fb78bee
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v12, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v24, v12, 8

  li t2, 0x5700e5652b9cf2ea
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v24, v8, -11

  li t2, 0x19bb56c07092d583
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v20, 4

  li t2, 0x986e82f089b853e4
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v20, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v24, v20, 13

  li t2, 0x1e10c2d979fef21b
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v28, v12, -7

  li t2, 0xbc4c58f516942852
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v20, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v4, v20, 11

  li t2, 0x338e8c5e6b19e27c
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v28, v8, 11

  li t2, 0xd0c195f467713431
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v28, -2

  li t2, 0xc35067f7c5093928
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v24, v16, -13

  li t2, 0x8bbbed847f1051e0
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v16, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v24, 7

  li t2, 0x33c57ff95c735af8
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v12, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v24, 4

  li t2, 0xf4fe7e017762fa0a
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v28, v16, 8

  li t2, 0x96c3afa6f76ad20c
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v16, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v28, 1

  li t2, 0xaefb0ce8eada469b
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v28, v4, -14

  li t2, 0x3685fc70ef574b41
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v12, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v28, 3

  li t2, 0x253cfbda1eda65cf
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v12, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v4, 8

  li t2, 0x00dda732660adac3
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v16, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v4, -16

  li t2, 0x3cb21e8a6c0907b0
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v8, 3

  li t2, 0xd874a52a8eab2d76
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v28, v12, 14

  li t2, 0x7b5773272e52e8cc
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v20, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v4, v24, -11

  li t2, 0xe6cec7224e45011a
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v28, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v28, -12

  li t2, 0x82d6f005edc6e501
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v4, v20, -9

  li t2, 0x84314e0f3c7bb99b
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v28, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v24, -13

  li t2, 0x67e65d95e4040916
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v4, v8, 5

  li t2, 0x34ce5c789c8c4490
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v20, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v4, v20, 9

  li t2, 0x93a2d522660523f4
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v12, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v28, v12, -15

  li t2, 0xa48e59e580028a47
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v8, 12

  li t2, 0x4e04240bc77a235d
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v24, v28, -11

  li t2, 0x72f584797f5f460a
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v24, 7

  li t2, 0xae82e2b4f7c13fbd
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v24, -15

  li t2, 0xf2f2f0dbfaa34b80
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v12, -3

  li t2, 0xd69fa6b51f38c373
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v20, 2

  li t2, 0xf403ac861be1a0ac
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v4, 7

  li t2, 0xd2535dce1feb78cf
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v20, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v28, -8

  li t2, 0x5cd671c7bf75ce2e
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v8, -13

  li t2, 0x31c4d75dbd97d41e
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v24, -5

  li t2, 0xb78bf84e1ac6c564
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v28, -4

  li t2, 0x0b61072ca4cec69d
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v28, -7

  li t2, 0x4217b774221c614a
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v20, 2

  li t2, 0x5fbe26a648315351
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v20, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v20, -4

  li t2, 0xf7c37e2b855514b6
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v28, -8

  li t2, 0x5a0e5335e44496f8
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v28, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v8, -7

  li t2, 0x739f794540d7a9ca
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v20, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v4, v28, -16

  li t2, 0x444310b6c40f8cdf
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v4, v24, -5

  li t2, 0xefd341ff9044ae32
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v12, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v24, v8, 5

  li t2, 0x9ef601e40bef165b
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v4, 4

  li t2, 0xe2bb5d9b256d3c90
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v12, 11

  li t2, 0xc3b4a4977674a780
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v8, 11

  li t2, 0xe7a8fcf63534f77f
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v12, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v28, -14

  li t2, 0x1ecd323b11d259f0
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v28, v16, -8

  li t2, 0x34dfc0ed822710ed
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v24, 7

  li t2, 0x885e4c85a94268eb
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v4, 13

  li t2, 0x497e102bb2d041de
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v28, v20, 3

  li t2, 0xe480ceb23d12cc87
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v28, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v4, -2

  li t2, 0x81bd27a0443b9607
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v28, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v28, 5

  li t2, 0x49be7e33901955f7
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v12, 7

  li t2, 0x384632ccf07d2063
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v12, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v4, 11

  li t2, 0xab5d63642075b649
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v4, -14

  li t2, 0xb2efac21f2b29df7
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v20, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v12, -7

  li t2, 0xb3103df334f28ae3
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v20, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v4, 14

  li t2, 0x89d13db037042fca
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v20, -5

  li t2, 0xc20a3e76093a9637
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v16, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v4, v8, -3

  li t2, 0xa587658792d5f8a6
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v20, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v28, 1

  li t2, 0xb6c284a51c2a3e6c
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v28, 2

  li t2, 0x03abe616d22d62fa
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v28, 8

  li t2, 0xa1d1a981bead389f
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v28, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v24, v8, -4

  li t2, 0x27fac67bfa097cb1
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v20, 6

  li t2, 0x1b523e941ccc7675
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v28, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v8, -14

  li t2, 0x8c7cb48e549059db
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v28, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v16, -8

  li t2, 0xf2145ad210f15b30
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v20, 8

  li t2, 0x18bc8eb2b9e6affd
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v4, 15

  li t2, 0x98ad6634351ac627
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v28, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v24, 0

  li t2, 0x11fe4b81d297fa81
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v8, v24, 1

  li t2, 0x6e60ebe98772f9ae
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v20, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v12, 7

  li t2, 0x31fb8fa841b1e1e1
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v28, v24, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v28, -11

  li t2, 0x5d79a67dc09c3aec
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v12, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v12, v16, -15

  li t2, 0x26be8845f84eecda
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v12, v4, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v28, v12, -16

  li t2, 0x6756c7f160aaa621
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v12, v28, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v8, -3

  li t2, 0x8c98df69dd42b919
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v8, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v20, v12, -12

  li t2, 0x837a524b1b6f5316
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v8, -16

  li t2, 0x32fef8620bc5acbe
  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vx v4, v20, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vrsub.vi v16, v8, 7

  li t2, 0x718ccf66c8873398
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, 3

  li t2, 0x8568434aa0c99ae5
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, -2

  li t2, 0xc337e213b6d08d5f
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, 9

  li t2, 0xb9ddfc616ad21f33
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, 5

  li t2, 0x060bd6b0a45a4cf1
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, -8

  li t2, 0x11b01afbbef4ed77
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v8, 1

  li t2, 0x4a6aadcaade04135
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, -12

  li t2, 0xe410e24212295ab4
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, -6

  li t2, 0x525a413de60accc9
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, 5

  li t2, 0xbf7f64319aba9cde
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, -9

  li t2, 0x58ebecf8555e4d1f
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, 9

  li t2, 0x844b834812515852
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, -16

  li t2, 0x68f9a9105f33f4ce
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, -2

  li t2, 0x2c946a2778458750
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, 2

  li t2, 0x9d0900fc0c62417d
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, -10

  li t2, 0x4c9fd997205e21a5
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, 1

  li t2, 0x61e984acbeaf1e0b
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, -14

  li t2, 0xe9d50ce4096ddebd
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, 7

  li t2, 0x4d47129744ef9872
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, 0

  li t2, 0x1331de75eb135d4d
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, -13

  li t2, 0x9b10acee18ecdc8d
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v8, 8

  li t2, 0x964cf362d9560be8
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, -13

  li t2, 0xe4d379877b301572
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v8, 14

  li t2, 0xc0a33d1dce65c0ba
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, -12

  li t2, 0x4783bf63420ff443
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, 7

  li t2, 0x94ab5b7d0e29d43d
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v8, -9

  li t2, 0x16409e1eb5bf63f9
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, -12

  li t2, 0x970a59b3c292a38d
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, 15

  li t2, 0xb68f48c5be23c579
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, -10

  li t2, 0x37c1efd9e9fa41bd
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, -8

  li t2, 0xec90f7bcd698d141
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, 15

  li t2, 0x89596b43bc0207ab
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, -8

  li t2, 0x17dfc29180ddaf90
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, -3

  li t2, 0xc6a43c720650a617
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, -14

  li t2, 0xbca193f97af9b4b8
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, 1

  li t2, 0x40169a2e54ef0f93
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, -3

  li t2, 0x599ab7105e53e518
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, -5

  li t2, 0xe8f256fdd8c08452
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v8, -4

  li t2, 0x1b6ee12689ea8cbf
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, -1

  li t2, 0x1f422c240578db81
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, -14

  li t2, 0xf5c16ffb355ac6a4
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, -2

  li t2, 0x50143ee0ff3f18bb
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, 11

  li t2, 0x172786e1b23c5eb9
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, -12

  li t2, 0xf9f5456d5834db94
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, -1

  li t2, 0xaba26fbdb4a2978e
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, 3

  li t2, 0x2219a07efef786aa
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, 9

  li t2, 0x945627e853b057ab
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, 6

  li t2, 0x6dbfce2051593a0d
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v8, 7

  li t2, 0xd6023dfb61650be0
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, -4

  li t2, 0xc7b9ce702e2fd296
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v8, 3

  li t2, 0xb7e70e6dc9ad0df9
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, 13

  li t2, 0x00a5ac71730edbf5
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, -10

  li t2, 0xad794066c3e4733c
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, 3

  li t2, 0x32255289c975d2d0
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, -13

  li t2, 0xd37512c9c8849054
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, 3

  li t2, 0xc01aa91fa4f7872c
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, 2

  li t2, 0x467f6eff47cbbad1
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v8, -5

  li t2, 0x87b41dbb21ffbbb2
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, 13

  li t2, 0xa20a1e2c65fc1484
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, 7

  li t2, 0x34472dca1f355370
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, 1

  li t2, 0x08d961f4ab06f665
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, -3

  li t2, 0xba666fef6732c8fc
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v8, 1

  li t2, 0x0f20731f7f585967
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, 1

  li t2, 0x1d45e26ca4cc5af1
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, -5

  li t2, 0x39ce73b866712c6e
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, -15

  li t2, 0x7822db9263b29c0a
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, -14

  li t2, 0x28915a63a45b1fa9
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v8, 3

  li t2, 0x1a8f5a9f9d1dad8f
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, -5

  li t2, 0x4377ee564de89737
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, 13

  li t2, 0x2e723b8597ba0579
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, -7

  li t2, 0x1f73b30e5140e1e0
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, 15

  li t2, 0x1c950c1eeedbf5e5
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, -4

  li t2, 0x762e8a8f1b1fa442
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, -6

  li t2, 0x2fbcfa449a38ca37
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, -9

  li t2, 0x4296d7606f9dae24
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, 0

  li t2, 0xcfb8b323c1a31f44
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, -4

  li t2, 0xb440d391f18ad523
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, -10

  li t2, 0x553b7a46294c5247
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, -9

  li t2, 0x6d92c134656e8921
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, -1

  li t2, 0x4b53fed66f6ef59a
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, -6

  li t2, 0x7a7d1185eccd9699
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, 12

  li t2, 0x0d69d0d4a7d87fbd
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, -5

  li t2, 0x8836f41ec2d8e262
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v8, 7

  li t2, 0xbecb87a6c4a361c0
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, -16

  li t2, 0xda617ca27d570ef8
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, 3

  li t2, 0xc723c80ed7ad0f55
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, -14

  li t2, 0xc12a9beabb66bb03
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, -1

  li t2, 0x769c6e7ef15e7f67
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, -2

  li t2, 0x108ee5921af37ff3
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, 2

  li t2, 0x01be6d86b9bdf32b
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, 9

  li t2, 0xcac930db655be9fa
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, -13

  li t2, 0xc44064f08014dfab
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, -15

  li t2, 0xa5c95b8dc9eec105
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v24, -14

  li t2, 0xdbac36c5af8bd6ea
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, 7

  li t2, 0xa94130ad2f8d89bb
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, 3

  li t2, 0x7442d3d6693bc27d
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, -16

  li t2, 0x08770cdd148b4ef9
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v16, -9

  li t2, 0xde22ef8ce9e87a36
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v16, v24, 11

  li t2, 0x39cf9bdb6ef0170b
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v24, v8, -15

  li t2, 0x20b6695b25e69ce3
  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e32, m8, ta, ma
  vrsub.vi v8, v16, 3

  li t2, 0xf8368e93a6d1faf4
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v2, v21, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v20, v27, -3

  li t2, 0x2c3fb25c11cb6c9c
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v16, v4, 8

  li t2, 0xed81e278fe319ce9
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v1, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v3, v21, 8

  li t2, 0x85257fb9b54e70c2
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v28, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v14, v25, -11

  li t2, 0x22f2c1c19fa05f8d
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v16, v25, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v7, v16, -4

  li t2, 0x3b9370336dec8199
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v28, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v21, v13, -11

  li t2, 0xe564c045d36c3070
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v19, v13, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v25, v26, 3

  li t2, 0x9ac4567166c72b19
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v6, v29, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v9, v8, 2

  li t2, 0x12eee101a15783d9
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v28, v4, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v27, v26, 3

  li t2, 0xabd520e45cb6b45b
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v28, v25, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v6, v3, -8

  li t2, 0xb22024e585f05e58
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v24, v6, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v30, v28, -11

  li t2, 0x0036d13ab71549c9
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v3, v4, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v28, v31, -16

  li t2, 0x40b96b037c65d163
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v31, v7, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v10, v4, -13

  li t2, 0xf78b40743b00873d
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v4, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v4, v23, 11

  li t2, 0x71cbf2141784b518
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v16, v10, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v21, v22, -15

  li t2, 0xe2c5c2b98f598b24
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v22, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v9, v19, -11

  li t2, 0x9ac7853855835e37
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v3, v5, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v24, v7, -5

  li t2, 0xa4b5dc2dce9f08dd
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v10, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v2, v7, 3

  li t2, 0xac87ccd4836fa720
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v19, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v16, v4, -5

  li t2, 0x212fe25a3258eb39
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v3, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v8, v21, 14

  li t2, 0x52f137e8abc43864
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v26, v21, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v9, v15, 3

  li t2, 0x966895486c23b12e
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v16, v27, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v1, v4, -7

  li t2, 0x83981cb6b9ff95a7
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v6, v9, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v24, v26, 8

  li t2, 0x7277b2c4408eb1d9
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v31, v25, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v25, v27, -3

  li t2, 0x4a1bed53a7746db6
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v16, v29, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v23, v26, -4

  li t2, 0x10a61dffd358b188
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v10, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v29, v8, 5

  li t2, 0xd6d397454c2438ed
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v1, v12, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v3, v17, 15

  li t2, 0xecd51f05d9266b0d
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v4, v3, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v2, v26, -10

  li t2, 0xbc108204bdad63bd
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v26, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v14, v20, 13

  li t2, 0x1792256604f5dab8
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v13, v17, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v21, v5, 5

  li t2, 0x1d0e600221b510bf
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v11, v25, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v1, v28, 6

  li t2, 0xeac7929130d449c0
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v5, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v20, v30, -6

  li t2, 0xfd889201f69759d8
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v26, v15, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v21, v17, 10

  li t2, 0x3bf2c6a4ef9bc7a2
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v12, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v21, v20, -7

  li t2, 0x9bbe58d2ecd8f072
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v12, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v30, v28, 13

  li t2, 0x9c20c4527fc80262
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v11, v23, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v18, v30, -11

  li t2, 0x51b8e5ecb24504ba
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v1, v23, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v6, v23, -2

  li t2, 0x873ba669cd1b0061
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v8, v29, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v21, v14, 1

  li t2, 0x0f953f2bcb1b7dec
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v17, v12, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v1, v23, -5

  li t2, 0x59b6efbcbc5fa9a9
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v20, v25, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v6, v21, -9

  li t2, 0x668c6649904c8308
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v15, v22, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v18, v4, 1

  li t2, 0x4e80add6ee3d889d
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v12, v9, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v21, v13, -10

  li t2, 0x38bd1e819daa3a34
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v11, v29, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v19, v25, 1

  li t2, 0xc013ff5278c1f5b4
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v7, v10, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v5, v8, -5

  li t2, 0xd12a0f0d5ad8cd6f
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v12, v7, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v2, v10, 10

  li t2, 0x27e26d36a0d925ad
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v9, v14, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v23, v15, -13

  li t2, 0xf21356f455de71cb
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v2, v4, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v30, v4, -15

  li t2, 0x7496c96adbd09626
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v11, v23, -3

  li t2, 0x3c0b543fbabf7979
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v20, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v20, v26, -8

  li t2, 0xcb5085b71719800c
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v9, v11, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v11, v2, -15

  li t2, 0xd78419c35a95cdab
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v31, v17, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v26, v19, -6

  li t2, 0x019bc864ff908566
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v8, v13, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v7, v14, -12

  li t2, 0x446573856cdc3604
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v13, v3, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v6, v20, 4

  li t2, 0x56ace2e08649ed58
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v10, v26, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v6, v8, 7

  li t2, 0x943d4a52d915da10
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v8, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v14, v15, 3

  li t2, 0xffe07ccb4054e29f
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v23, v7, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v26, v4, -10

  li t2, 0x72398179ee5a8f4d
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v28, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v8, v4, -16

  li t2, 0x0bf502dc0dc3407e
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v11, v16, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v30, v10, 5

  li t2, 0xb62f7f29e293d498
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v20, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v28, v6, -1

  li t2, 0xc3dc140305757d64
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v9, v23, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v19, v23, 15

  li t2, 0xc4804337eb9d512a
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v31, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v12, v8, -3

  li t2, 0x8aad05bf3593a085
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v27, v5, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v29, v25, 6

  li t2, 0x399548eaa57b8d66
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v20, v21, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v25, v15, 1

  li t2, 0xc4e8b59ce35de715
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v20, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v6, v20, -1

  li t2, 0xd637c8350b555950
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v13, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v3, v7, 2

  li t2, 0xe540169f3c8b0521
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v8, v17, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v7, v13, -10

  li t2, 0x32f0dcf0933a5fe7
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v13, v20, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v14, v23, 13

  li t2, 0x0f8ef8accb43517a
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v17, v15, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v31, v24, 5

  li t2, 0x81d79f1be5e37d8f
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v20, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v27, v3, 7

  li t2, 0x0bec600c98087b22
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v28, v15, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v7, v27, 9

  li t2, 0x56beaee7ad1510fe
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v26, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v30, v9, 13

  li t2, 0x6e41a4eae1a44cf5
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v28, v17, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v18, v8, -12

  li t2, 0xbd72b9edbe595781
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v16, v7, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v15, v17, 14

  li t2, 0x1cfd27778a35e167
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v18, v29, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v18, v20, 6

  li t2, 0x0c706bce5a4c4c8d
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v22, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v22, v8, 8

  li t2, 0x11d705b73b814f3a
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v20, v26, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v26, v18, 10

  li t2, 0x1fb4b1ab62d17ae4
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v14, v12, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v11, v28, -8

  li t2, 0x2af79b6416c45751
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v22, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v29, v28, 3

  li t2, 0xc700ac8aaf76e0d4
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v30, v23, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v10, v28, -6

  li t2, 0xc483acfbb9b1f13a
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v11, v25, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v28, v18, -10

  li t2, 0xd7271b7ffbf468f8
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v4, v9, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v27, v17, -14

  li t2, 0x3084daa7fa9e853d
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v8, v4, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v24, v3, 5

  li t2, 0x533b7f1da1451599
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v4, v7, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v7, v25, -3

  li t2, 0x20f2d26e3eb41d9b
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v10, v1, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v24, v7, -12

  li t2, 0x309c0be2085ff323
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v31, v3, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v26, v16, 2

  li t2, 0x0ba8f5a0053a9108
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v15, v30, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v7, v2, 7

  li t2, 0x5ca4933d22c6abb0
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v21, v5, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v31, v4, -14

  li t2, 0xac0c20c2048d12b3
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v16, v31, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v3, v19, -12

  li t2, 0xd2a0962d8a2e6688
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v19, v4, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v9, v21, -13

  li t2, 0x9688bcf0805e13f4
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v22, v8, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v25, v2, -9

  li t2, 0x0f51bc9e84d811c2
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v23, v26, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v3, v21, 0

  li t2, 0x31dc071ba07b8792
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v1, v3, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v26, v14, -10

  li t2, 0xce62293482a1fcce
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v8, v7, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v10, v6, 10

  li t2, 0x8692fda3ab213da6
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v16, v21, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v15, v4, 6

  li t2, 0xde6fd0a47ab26c18
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v21, v18, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v4, v29, -1

  li t2, 0xc5291ce253467cd2
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v21, v19, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v17, v27, -13

  li t2, 0x7d6f22217dc3b92d
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v5, v13, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v21, v9, -9

  li t2, 0x2a5fb159b66c25fc
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v5, v4, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v17, v2, 12

  li t2, 0x6f09b34e76824006
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v12, v24, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v28, v17, -2

  li t2, 0x697487ad2866deb5
  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vx v20, v12, t2

  vsetvli t1, t0, e64, m1, ta, ma
  vrsub.vi v12, v7, -8

  li t2, 0x54540bfab2765151
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v8, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v28, v10, -8

  li t2, 0xbaa4df64eae1f9b0
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v28, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v12, v30, 1

  li t2, 0x995359756880b8c0
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v2, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v10, v28, -14

  li t2, 0x423dccf76f07bb1c
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v20, v16, 15

  li t2, 0xbe6dafedbf67d43d
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v30, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v12, v28, 9

  li t2, 0xb449349d32bc054b
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v16, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v14, v4, 7

  li t2, 0xbc9b542bb89f3b34
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v18, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v10, v30, 3

  li t2, 0x28b45f7b7b570792
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v6, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v18, v12, -9

  li t2, 0x00da806fe811b583
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v2, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v26, v10, -2

  li t2, 0x0b4d959a48a63d3c
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v2, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v4, v30, 0

  li t2, 0x091c2976954ec191
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v22, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v6, v24, 5

  li t2, 0xfe9e8f42e604e4fa
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v18, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v6, v26, -1

  li t2, 0xfddd39b901b4dbc4
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v28, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v4, v8, -7

  li t2, 0x6466edfdee49859d
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v14, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v8, v10, 7

  li t2, 0x6e700aa1c7add0f4
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v28, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v4, v8, 0

  li t2, 0x35b015345ce0400b
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v10, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v4, v20, 8

  li t2, 0x21a37c51aae92ffd
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v30, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v8, v22, -6

  li t2, 0x69cea26e710f7b7a
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v14, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v16, v2, 11

  li t2, 0xae4165be0ebc0657
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v18, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v24, v6, 8

  li t2, 0x08cd456f394748d3
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v10, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v8, v4, 10

  li t2, 0xcac3182c54ff6949
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v2, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v26, v30, -11

  li t2, 0xb5242a144d78b6fa
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v24, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v24, v14, 1

  li t2, 0x55e9baabde33acc9
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v6, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v4, v16, -6

  li t2, 0xe41395017a2c4bed
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v22, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v14, v6, -1

  li t2, 0xaabed2e464abbba0
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v2, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v16, v10, 8

  li t2, 0xa146a8005ed4b0e0
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v8, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v22, v2, 4

  li t2, 0x0377fa26bf5b76fe
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v24, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v2, v6, 14

  li t2, 0x4ab3995a120c13f0
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v24, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v4, v16, 14

  li t2, 0x9bcb77e049bd3afc
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v12, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v24, v18, -4

  li t2, 0x5fddd725d74a40ea
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v30, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v2, v30, -7

  li t2, 0x4a4c313d3168f687
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v10, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v12, v4, -12

  li t2, 0x777ecc7c31a65e4c
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v8, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v20, v8, -8

  li t2, 0x879bf84368f3a6ec
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v20, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v20, v14, -2

  li t2, 0x23786299a165c0db
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v4, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v18, v22, 5

  li t2, 0x0cdc6761029463c9
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v12, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v30, v8, 13

  li t2, 0x2bdcaa6f693a8161
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v8, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v12, v10, 0

  li t2, 0xcef040ea8e946483
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v26, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v4, v18, -11

  li t2, 0x84c6fd658a833876
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v26, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v6, v28, 7

  li t2, 0xcaead7054ccff794
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v8, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v26, v10, -11

  li t2, 0xad9d21b6bcde4a04
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v16, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v28, v12, -14

  li t2, 0xb2c95dd6c854ae1c
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v20, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v14, v12, 14

  li t2, 0x881467af766882e1
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v6, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v30, v12, 1

  li t2, 0xf9f35a387cf06908
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v12, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v24, v4, 11

  li t2, 0x61ffd419af9c88f0
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v14, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v14, v8, -12

  li t2, 0xad59f811df797e22
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v18, v20, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v14, v2, -1

  li t2, 0xf6584005e59a7cfc
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v12, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v18, v16, 1

  li t2, 0xfd43d016c8dc81c8
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v26, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v18, v16, -10

  li t2, 0xf8c432a6b30a0995
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v28, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v10, v8, -15

  li t2, 0xa77977e4a136d8af
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v22, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v8, v2, -8

  li t2, 0x76d0704b2db8c2d7
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v22, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v24, v4, -14

  li t2, 0x014aa9ea0a450651
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v12, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v16, v22, 12

  li t2, 0xea8352ddf5259020
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v28, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v2, v20, 12

  li t2, 0x705ba4fedc4eabc9
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v6, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v22, v28, -10

  li t2, 0xec70ef81764f9b36
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v16, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v6, v10, 14

  li t2, 0xf8404a868929c20f
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v30, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v30, v10, -9

  li t2, 0xb950d297c7fa27d9
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v2, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v16, v2, -4

  li t2, 0x6f6e6121c64eaddb
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v30, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v12, v14, -11

  li t2, 0x252ac29dbaa19a31
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v14, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v28, v12, -15

  li t2, 0xe8a185647967cc52
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v4, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v2, v28, -3

  li t2, 0x72fb310666863f9d
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v30, v18, -4

  li t2, 0x72bcadf7d40411c3
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v24, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v2, v26, 14

  li t2, 0xe67fbb8bdf56d9c8
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v8, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v28, v30, 2

  li t2, 0x05f5d75149afb8a7
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v2, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v6, v4, 15

  li t2, 0x5f8f08c4ad81af23
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v30, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v26, v18, 10

  li t2, 0x747ac1002c46146b
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v22, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v12, v30, 3

  li t2, 0xec411c24b60aa6b8
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v16, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v22, v6, -3

  li t2, 0x36cfe02b03ece95b
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v22, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v12, v18, -15

  li t2, 0xfe90e275d4cca60c
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v26, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v16, v2, 15

  li t2, 0x5af1f18fe9808b8c
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v4, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v30, v24, 6

  li t2, 0xe39db6123d95e29e
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v6, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v22, v18, -15

  li t2, 0x184832bf7d1a88d8
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v26, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v6, v20, 10

  li t2, 0xe5e4c920d2ada879
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v14, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v12, v22, -1

  li t2, 0xe08d3de048121ea8
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v20, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v26, v20, -11

  li t2, 0xb87bcff17b64150c
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v26, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v2, v30, 2

  li t2, 0x31eee6912ef14e17
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v26, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v12, v20, 12

  li t2, 0xa05e1d4ea2bf0ba3
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v10, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v14, v20, 0

  li t2, 0xf847777b2ebea81b
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v2, v28, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v10, v24, -5

  li t2, 0x0b97caf305ffa868
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v12, v10, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v12, v20, 5

  li t2, 0x5de80e65a0469353
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v2, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v22, v18, 3

  li t2, 0xbba3e4d88bb6d0c8
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v28, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v16, v8, 5

  li t2, 0x48efd8963e12291b
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v30, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v22, v12, 7

  li t2, 0xa5a0fe9397fc2d92
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v22, v8, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v8, v16, -2

  li t2, 0x1ff1f39967036c66
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v2, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v28, v22, 13

  li t2, 0x8a006de1ae866ba2
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v28, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v8, v12, -8

  li t2, 0x746f10121ad56562
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v10, v18, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v18, v26, 10

  li t2, 0xf6c10a96239632ea
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v28, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v10, v20, -11

  li t2, 0x6349de777bf5342f
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v28, v4, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v14, v6, -4

  li t2, 0xc864924ca39a0b87
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v12, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v8, v30, 11

  li t2, 0x40741f438fb76b60
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v22, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v12, v2, -11

  li t2, 0x759cfb3bc73837d4
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v10, v2, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v18, v16, 13

  li t2, 0xd4117fea329b2e6c
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v14, v24, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v6, v28, 6

  li t2, 0xf774d4680eb5a797
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v6, v30, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v16, v22, 7

  li t2, 0x15fd4d8d17cb2c30
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v30, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v10, v12, -16

  li t2, 0x95f90e7c860ae4f0
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v18, v6, 2

  li t2, 0xceaed8ee931edf2a
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v8, v26, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v6, v12, 12

  li t2, 0xf7b463387dc9e472
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v18, v22, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v4, v26, -11

  li t2, 0x847f450ba7ee14c6
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v8, v12, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v10, v24, -4

  li t2, 0x2b144100da755bcb
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v4, v6, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v26, v18, 13

  li t2, 0x260ee5dcfc4004d7
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v20, v14, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v8, v26, -4

  li t2, 0xe18ea2970c3982bd
  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vx v14, v16, t2

  vsetvli t1, t0, e64, m2, ta, ma
  vrsub.vi v18, v10, 13

  li t2, 0x1544766f60c99002
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v4, -8

  li t2, 0x9cacc40f0dfe5e73
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v12, 4

  li t2, 0x91c87091ae89163e
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v20, 0

  li t2, 0xd0178c2103715a86
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v16, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v24, 7

  li t2, 0x2ea507ad71a18680
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v28, -9

  li t2, 0x332f7799c89254dc
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v8, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v20, 9

  li t2, 0xa9dfe07ceb78e870
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v24, -3

  li t2, 0xcf9240055be812da
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v8, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v20, -2

  li t2, 0xd7fde6354a3cca66
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v28, -4

  li t2, 0x780897c4443656c5
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v24, -11

  li t2, 0xe856153f46bb7a8a
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v20, -3

  li t2, 0x5c98900fbbde28a4
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v24, v28, -15

  li t2, 0x6e3a30e84608c47a
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v24, v16, 5

  li t2, 0x546ebd06d62fbfea
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v8, -11

  li t2, 0x06bbcc130b613bf1
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v24, -11

  li t2, 0x373352ae89e28dcc
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v8, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v16, -14

  li t2, 0xbea48197797507c5
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v28, v16, 14

  li t2, 0xb140b346c1e9509b
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v16, 11

  li t2, 0xb133f14d0909d51c
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v16, v12, -10

  li t2, 0x9ce563065445ad4f
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v24, 4

  li t2, 0x0c12555b3e4814fc
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v28, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v16, v28, -8

  li t2, 0x47598fd51dfeb5b3
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v28, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v8, 6

  li t2, 0x83017e9aadef1e20
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v28, -10

  li t2, 0xbd7f0deced4d6cdf
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v24, -13

  li t2, 0xce9f82d792824e0e
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v12, -4

  li t2, 0x8b64bfb1f12a9ff8
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v28, 6

  li t2, 0x160b50ac8ed74240
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v28, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v12, -9

  li t2, 0xbddc90524e584377
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v20, 6

  li t2, 0xaa8e07864441e212
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v8, 10

  li t2, 0x83eaf0a341be3456
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v4, -7

  li t2, 0x28c887d759c35a54
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v24, v16, -12

  li t2, 0xc03a72b30bbe3ccf
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v16, -10

  li t2, 0x2fb80a6f89f84952
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v28, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v16, v12, -5

  li t2, 0x4134355cfcc42414
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v28, -10

  li t2, 0xa9eb2e9f289a9d45
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v4, -8

  li t2, 0xdfde1aa7ce7443df
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v16, v28, -6

  li t2, 0xd4bbb6c5071e40e0
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v8, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v16, 11

  li t2, 0xa82102d265eb9bab
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v8, 2

  li t2, 0x8c67c431f3cf0415
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v28, 9

  li t2, 0x2d6e656e0a3aecb0
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v24, v28, -1

  li t2, 0x9e959e6c489c33b0
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v20, 11

  li t2, 0x40f991f77a9e166c
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v24, v20, 9

  li t2, 0xc32cf7f3db656f96
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v28, v4, -13

  li t2, 0xcca3eaf307b2f2d4
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v20, -15

  li t2, 0xfb7b736f23de7383
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v28, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v24, 15

  li t2, 0x6466b82b00e92cac
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v24, -5

  li t2, 0xf8aa644bd666cbb1
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v12, -9

  li t2, 0x800277b4a79ba60a
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v28, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v16, v20, 5

  li t2, 0x7626d817f69bc430
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v24, v4, 6

  li t2, 0xd0329ed154b632c2
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v28, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v16, -8

  li t2, 0x3e3b5561a7da5aca
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v24, v4, -4

  li t2, 0x9272375b7fbc3368
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v20, 14

  li t2, 0x831c6cf52ce2fbde
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v24, 9

  li t2, 0x333eca12b5fd89d1
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v28, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v4, -13

  li t2, 0x118a153dae31f28c
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v16, v24, 9

  li t2, 0x7214f852586689e8
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v16, v12, 2

  li t2, 0x54313c91fed490a4
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v28, 15

  li t2, 0x8cf142b1676325bf
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v16, v12, -2

  li t2, 0xe8c52659e37fdc3a
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v8, 15

  li t2, 0x47294eccca133387
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v4, 0

  li t2, 0x75dc8fa2523fea48
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v28, 9

  li t2, 0x0268e7f83b7f6891
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v28, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v24, -11

  li t2, 0x2fe2232866c89b42
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v16, 10

  li t2, 0xa5dc862ddea0ca8e
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v12, 7

  li t2, 0xd4bca47441b03ef1
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v24, v12, -2

  li t2, 0x42bc8c01bcc39665
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v16, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v24, v4, 12

  li t2, 0x5d7602c5308d2f24
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v28, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v28, -6

  li t2, 0x6ebe19107fdc199d
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v16, v20, 5

  li t2, 0x44f7e464f128f2e4
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v24, v16, 13

  li t2, 0x9cbbc9cfebedbd43
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v8, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v24, 1

  li t2, 0x44afaaac009f448d
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v8, -14

  li t2, 0x69246bf553e14c41
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v16, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v4, 5

  li t2, 0xbcbb76d575b11f95
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v28, v4, 5

  li t2, 0xfb9032e49560a7e7
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v16, v12, -3

  li t2, 0x660276fc1564dbdb
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v28, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v12, 7

  li t2, 0x068b637ec38df293
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v8, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v20, 13

  li t2, 0xf01a0b3574c66dee
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v28, v4, -12

  li t2, 0xb6c4d461ab314bca
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v20, 14

  li t2, 0x51b84de87f0fc576
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v28, v16, -8

  li t2, 0x06e9f211cecb8658
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v8, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v28, v24, 1

  li t2, 0x8bc54574396834f2
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v20, -9

  li t2, 0x83ac0d57cc37b8a1
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v16, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v12, -4

  li t2, 0x9aa3a44ce635cfff
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v12, v16, -14

  li t2, 0x9a1deb1665cd68dd
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v28, v20, -16

  li t2, 0x0315233fbe174ae7
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v16, v4, -4

  li t2, 0xb06238ba118966e1
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v28, v12, -15

  li t2, 0xb6a6c6ca6e8c3024
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v16, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v20, -14

  li t2, 0x69f8112e37a5a5ee
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v28, v12, 10

  li t2, 0xccab50c533ffbcee
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v12, -2

  li t2, 0xfb5fed4e6ac35b21
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v28, v24, 8

  li t2, 0xd97a975495d406b7
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v12, 5

  li t2, 0x2a225df6c8f317d8
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v20, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v16, v20, -4

  li t2, 0x5f9e58474f940d49
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v8, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v4, v12, -8

  li t2, 0x493ebd60611ed8b9
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v24, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v24, v16, -14

  li t2, 0x78485b1ded131412
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v28, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v8, 13

  li t2, 0x5cebdd758786edfe
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v4, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v20, v16, -9

  li t2, 0x91976061dc0cd250
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v12, v4, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v8, v20, 14

  li t2, 0x0eda1ffd136f83c1
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v20, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v28, v16, 6

  li t2, 0xed5bd230564f48db
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v24, v8, 9

  li t2, 0x2a93e35f162be473
  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vx v16, v12, t2

  vsetvli t1, t0, e64, m4, ta, ma
  vrsub.vi v24, v16, 11

  li t2, 0x99285722a659cd6c
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, -10

  li t2, 0xda741b090ebba8e8
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, -4

  li t2, 0xe2c5bbdb872d508e
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, -1

  li t2, 0x1ecdf5544d0fb9a8
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, 7

  li t2, 0xf60d2161105f658a
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, -5

  li t2, 0xf93e46907d59411c
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, -15

  li t2, 0x9298ca6c2c86f8af
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, 14

  li t2, 0x7f525ee1357ee1ec
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, 12

  li t2, 0x80e6436264ab43db
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, -11

  li t2, 0x8c5d079e0f863fbd
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, -8

  li t2, 0x35497a9a592debde
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, 1

  li t2, 0xbea71a534a804efd
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, -10

  li t2, 0xfba1cf5116335425
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, -1

  li t2, 0xfa7393d0262ca701
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, -2

  li t2, 0x650f3b895a0d1714
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, 14

  li t2, 0x09449966beb1e893
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, 11

  li t2, 0x9f2475d1d3df418c
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, 8

  li t2, 0x2642bbffa0286499
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, -1

  li t2, 0x87b9c854cbda29fe
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, 15

  li t2, 0x1b824098730dbbd7
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, -12

  li t2, 0xe48980bf3972cc24
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, -3

  li t2, 0x8b4f1bb75d99bb80
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, -3

  li t2, 0x42a2cbb209a71834
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, -6

  li t2, 0x5ff9e415d0821f06
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, -3

  li t2, 0xf7faa70cc65c12ae
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, 9

  li t2, 0xe858f1648f792499
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, -15

  li t2, 0xe78fbb931c71a4b0
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, -11

  li t2, 0xf1057222775df96a
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, -2

  li t2, 0xe668953b084c5b64
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, 15

  li t2, 0x749cf748f27a343e
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, -14

  li t2, 0x03f8d2398d28e52b
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, 4

  li t2, 0x70a4ca2620417fc4
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, 13

  li t2, 0x1b4c0df7f4fddcc0
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, -2

  li t2, 0xa5340055da3a8c3d
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, -3

  li t2, 0x0faf5c53c01b078c
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, -7

  li t2, 0xe487aa7e608d223f
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, -15

  li t2, 0x7a0c18ad0ebb9f8a
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, 11

  li t2, 0x7a62678c63376e9f
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, 11

  li t2, 0x71e6d4f2fac30967
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, 7

  li t2, 0x6b3d86d5717b8691
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, 4

  li t2, 0x89b8a73b12a05555
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, -3

  li t2, 0x78c993411a1a4e7e
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, 9

  li t2, 0x420ac82a2196f426
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, -12

  li t2, 0xa099bfe7535dc9d3
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, 7

  li t2, 0xc79eefab1b8f56de
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, -4

  li t2, 0x79751b3265eb29ce
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, -8

  li t2, 0x912d9429483e0be1
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, -8

  li t2, 0xe6316017cd45ff98
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, 2

  li t2, 0x34b035acdf8f9353
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, -2

  li t2, 0xe7e8b800052e4151
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, 12

  li t2, 0x92e8aaeac967cdd4
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, -5

  li t2, 0x72050cd8915eb2fd
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, -3

  li t2, 0x15290bc5d1670520
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, -1

  li t2, 0x311c4852641ae24d
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, 12

  li t2, 0x3d0a4b7457522038
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, -14

  li t2, 0x7b91f36afad3bd64
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, -2

  li t2, 0x3335409c27c6b99a
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, -11

  li t2, 0xf9981792a9b55948
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, 3

  li t2, 0x843fb8f643eeaa93
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, -16

  li t2, 0x6d30fa3101d7763a
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, 14

  li t2, 0x1dae2471119f0204
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, -6

  li t2, 0x2d04b2b27f254651
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, -12

  li t2, 0x1b2ee877f31b4374
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, -3

  li t2, 0x60874e932d29a846
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, -12

  li t2, 0x3039147cb76d4fce
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, 11

  li t2, 0x235cbc91d8d06976
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, 7

  li t2, 0xd204e929a916eddf
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, 0

  li t2, 0xd1200f9954900126
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, 0

  li t2, 0xd1f971588ae4a721
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, -10

  li t2, 0x4e65526509a996e8
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, -9

  li t2, 0x75d87971026a6cee
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, 12

  li t2, 0x921515dbee6e76c5
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, -1

  li t2, 0x0c71209eac4f8da2
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, 0

  li t2, 0x5d521aa2d67b7cae
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, -11

  li t2, 0xf195f5e4052317fe
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, -1

  li t2, 0xaccf734f65b84075
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, 8

  li t2, 0x0f88bd72436c471b
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, -11

  li t2, 0xd88cdd1bf6f0cfa5
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, 4

  li t2, 0x9749220c5ba76cec
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, 4

  li t2, 0x2d2563f873d7ef62
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, -16

  li t2, 0xe73c88fb42a94da0
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, -2

  li t2, 0x85b713c7ef4df793
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, 15

  li t2, 0x48536141cd1990bb
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, -7

  li t2, 0xaeb2fd7cbd8fd14c
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v8, -12

  li t2, 0x75f8f8ce26e9ccbb
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, 11

  li t2, 0xc55f4abdee07eaf3
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, -16

  li t2, 0x8176c604dede5a4c
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, 15

  li t2, 0x54016f27cd183641
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, -13

  li t2, 0xef7d3cc00730c8c3
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, 14

  li t2, 0x07b04f11faf5b1c4
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, 14

  li t2, 0x94345ce01ad2cecd
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v16, 1

  li t2, 0xd2306d52cb99b803
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, 3

  li t2, 0x225e0b1d163f912f
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, 14

  li t2, 0xf1f403174082a81e
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, 13

  li t2, 0x3381ead67fe10a8a
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v16, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, 9

  li t2, 0x77bc10dadb6958f3
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v8, v24, 13

  li t2, 0x3381d6c6d1e578ec
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v24, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, -1

  li t2, 0x9d2e7900dd5498ea
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v16, -10

  li t2, 0xf9caee475df6a3c0
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v8, v16, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v16, v24, -16

  li t2, 0x62596401849594c1
  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vx v24, v8, t2

  vsetvli t1, t0, e64, m8, ta, ma
  vrsub.vi v24, v8, 9

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
