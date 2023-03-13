#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x72c8fe041c9e8705
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x967eb0800cf184e2
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x00d211ca48527bb1
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x3cbbd14bcb2839e3
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xb8f3765c240f6950
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x74e4c50df554eef2
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xac1c4c818f93806f
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xcb0853b216d0d276
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xa450e0bc9faa7e1e
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x99c7c2a59a656401
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xa5c1789afddea2ae
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xcb02f35d0e71f154
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x2d688d38c60bfe36
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xd1c723c956437343
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x3a90565d96435656
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xa0b003a309929589
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xb9c679345af8d599
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x03890ffce0dcfb8a
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xc8d70c223480bf56
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xacb06f56c91f4797
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x50962df3178132dc
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x9055bd0567821ab0
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x4cedeeaa70418e4a
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x35d59051555979a6
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x5c7c5fba387c488f
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xdd1bf98c39ee2dc9
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x355f4cc6c1cbfa10
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x67ea0c59bcab89a4
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x2b99d372b564a33d
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x1d9bfb7d7fe6fa56
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x89797553135a52f5
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x548b632ce51bdddf
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x3b96c2a21c30abf5
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xed5fef9a3ae49f02
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x9abc243b2acade71
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x7a78149b2f39e139
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xedc47cc7de03bd5b
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xd51a0233fd493ad5
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xc4a7b30ab3a7058b
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xeb5c8a34c220f4aa
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xcbf8dd419f513c4b
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xc14a4c941bbba74d
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x38a4ce6f6d569004
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x535e5e19e3cd4638
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xcd2caeca74462c0e
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xba128e25dc1bcf52
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x99e02fcde34f2d2d
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xcaeb46a1655d827d
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x5425df90efca3796
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x010cfcb60b740bb9
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xaabc3098222bb020
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x8c9ef9097e58cee7
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xa7f14b90e82e535f
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x3ca48b9630856b5a
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xd741b76be19fbf04
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x58301ede726c9e6f
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x10527797305caae9
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x7f45796bac81723d
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xb6a7d57379ef2014
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x5e712a1133e2d84c
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xa5ceef9b96fe731c
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x03cd60ab1e95dbbd
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xa6217309433a476e
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x84f9b282e55dfc8f
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x67b89b259df4d7f4
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x148d8bd97804c7a4
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xe20c32807496e95c
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x7a24cb355e014474
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xd54cbb534d0eb78e
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xc0758ccf25f690c0
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x5477fee35db6aad4
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x76bf8a38652bee27
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xb6e27ac045a1e31f
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xb880268f65a3ce59
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x88ef154c210dd3b2
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xfa7a05ec598939ba
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x0887a01bc5c0519c
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x01461d0adc42cabc
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xe6c608840fc7eac7
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xe484d17ad24c85c9
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x6842ebc8c1d6587d
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x919217e9650b8c0f
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x4272d4540813a895
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xcc0b65c047192bf4
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x6dde37b35f595c7e
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xab9714ae57fa2097
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x2ac89266acab0088
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x50773f5bfbd7ada5
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x522336e96d8bdce8
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x7a44ecef61ecdee5
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x75a32b5ec03dc84a
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x49f8e222c6ab5fba
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x544108b6ece54135
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x403281851dbc74de
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x5f6704991ba1080d
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xcf4d7b2f96147348
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x9085e0044368fd58
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xadc12bf12610a9f6
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xbf44559d3538d832
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x2a54399436e2c62a
  vsetvli t1, t0, e8, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x57431405074fb45a
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x78e9bd93430fe55d
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc94c2efd855b6adf
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xa4b2465aa0d79c08
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xcd63f4a71d68ab3b
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x8a7f8e8c63e7717d
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xe08d11cba923ae04
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x9c1642cb36474c87
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xedb0a6d80e749b67
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x4a0223785de7b85f
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x7aa3aebbb11592ef
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x481d3f251b012933
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc04952212f3f8e68
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x7989464474cf8d07
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x5c4aab0a5d930e42
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x8369a07ddca4089e
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xec2035400b93727b
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x6eb3350ca287d8ea
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf1678cb267bd26f4
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xee2fb0aa45f59f7e
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x470ae826261a4cba
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xab773d4d2c9fcac2
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x054e08a20dae1d2b
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x0ad41bcabeeb80bb
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x19637c6939933c6b
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x7041c623e3aee3ad
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x7d14f776142fa68a
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x1cd281dd311cbe8a
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x6c4a014154a0b406
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x331cfb2ef7f919e6
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x7df9220a13a1f1e7
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x00083aff00f78c21
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x2323369e90cd6219
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xae2d14720ca2f936
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x933737ec2413c7e6
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xcaf7707099c4f6f1
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x65f487697f872056
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x2a5f4dd7ba756efc
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc671fe35319d656f
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x65e88c844ffe0c0d
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x08845badc3b09983
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x2d5f8a267a75c765
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc6c69f813d35569f
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xd987b7ac5fadf329
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xdb5d610d21110eb7
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xe25b53fd39e3a7e2
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf56ae880cd0bb3f7
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x3c961618d96dc484
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x488ef8823d65244c
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xb801f4b15c2c81fb
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x9d9403ceb15ffa82
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x0940c18e2a17b3c3
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc86b454c00db4682
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x06feed5638e56968
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc73e65927f2b7de1
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x90dea9a4fdf4d5c2
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x7a878b3f6123a7cf
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf79cb9ae27de0582
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xdf35c9e7bae91644
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x11a5ef52351dac16
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xcca66c196fb8b15e
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xa098a193e8e014a0
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x08d82c8053225d71
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x11808003cf198c61
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x29dd95543e627799
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x162fbf3865476182
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xeaf61ec679129b32
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x8d133b559ea25b8b
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xed7c389e6323b2cd
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x9b167b40005f98fc
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xcd96902b57db2e1d
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xae49c01b460becfc
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xd129148c81fa4841
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x279ed1ed8dc65ddc
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x9726fecbd783607a
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x5988492b7bf1117e
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc4fa19b3048110f7
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xa86cb51df87558b4
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x6d78d160cb9111ea
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xec815370efa5df11
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x2e07638893f2c5a0
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x5bd585c2268e5fb0
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x0ff5c819529c03eb
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc991bf26b33d6453
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x6f8ef2d2aface182
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x84b507df8219e90b
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x059aa729f2401320
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x8eaebd25b408c131
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x5452fc2d3f0388d5
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x77006dc128ea42b2
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x18210854748ea616
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x132107e142e7fca4
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x3ba8a404ee34f930
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xaf9f9959512ddca4
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x5dd7c554ccb1a90c
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x622766a804e76f3d
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xdcfb8fd40b312918
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xfc87dbfd068ce12a
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xff7b7a6a32650c18
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x8d62abc6dec8585d
  vsetvli t1, t0, e8, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf385b85d359763ef
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x004798fb7b97fd35
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xbeabc79b0cdb36de
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x9711eaef7aee1a07
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xe56ce7e4ea1916b6
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x29d63797953c3b40
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xb62db8ef12d315ad
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x397010710d97c485
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x22a4b2a8f3ca3c2d
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x1d7381254de19569
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xdb3a52d4fb758761
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xfe479885f58d7c1a
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x9b664055deea6655
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x29dfb5de611052e1
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x1ea41b69bfc056ce
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6f8d29d6442480b6
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf5a1f2db4a8d0c26
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xc6b74afb78277efd
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x114298e6b2171421
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xaf72baf776bff33d
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x657afa6c200945db
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x36a89c425c820e01
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x1e698a64f8dbe6b9
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xc7b0dbcbf59540a4
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xde9a65f887828502
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x4dca64a226cddd8a
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6416fa1c3398089e
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xcfcab94e627c8bc9
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xdc35174d2b0e0368
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x9893e74b4adf6874
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xeb4996405869a413
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x49a5cb7bf4bd818b
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x27bd12a6c00d4220
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xcad7f7eb9a301d07
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x1703b8e39730319e
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x09729d6f5971d512
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x992747ae51fcc4ee
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x11f39060caa3d880
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf3354c957813c37a
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x74d2e1741dcff019
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf644e53b14ec17e0
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xc589e5f698d80ba2
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x0e914321ff714b95
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x8cb5affce2fb093b
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x5da1a531a3e2823f
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xc58557f0c632366a
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x8ff4e6e0de046e1b
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x33c3d9466decf19f
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x5c4772e8e7cd59e7
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xfe86104d7b07948c
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x252acd2d7370769b
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xdf4769bf4b7fe57a
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xbb9fc7c563a3d233
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x873099fda245e74e
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x788f583afa169e4f
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xdea7b66e85103bb4
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xb59a8b397f62f1a2
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x126d903207d9492e
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x5b8993a34b9c4f6c
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x168fbe2816b55fa5
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x3a8c0e39b42e57d9
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x2bfa220249bdee61
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xfa386650d59fa209
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x70dc60a2e6642316
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xd2169b7e28405164
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x283b798a29b5df69
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x3ce2133f6117637e
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x7347d70a95f2c4a7
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xa821c88429291390
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xcbe4ba1b36cfa302
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xe34205410eacbb7d
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf8944c79b5bc5159
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xe54e0e42e1f4b717
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x9969873c2f2f6c73
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6ea1116bc8c74343
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x4eed3712cdad2dc8
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x1caea8b9f72ae971
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x91b12387257eb826
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x9e63a6e45c284fc8
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x84b6eef72f53c36c
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x8762a6584adb3841
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xd62d8e58cfa0a83c
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xd585eac4fd5518ff
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x2d45e3203c40325a
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x38ee24f69cba1ff4
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x4203e611b41fcfc6
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x82ebec3dbc1f68e2
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xaba8b3a995e70d0f
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x0968b01e05a0438e
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x9fd6dec82839b0d1
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x0def7a76ad799370
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x1b76b85e41ec68a3
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf1608e495b528234
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xa6c56301521232be
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x5ee35234daa61d22
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x89968ef16b29d77b
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6a4d8045df838ea0
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xbd27481430f63b65
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x80e5ebdb6a8cc9de
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x727143810548f2fb
  vsetvli t1, t0, e8, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x8bc1a1c0c61201bd
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x2986c2627bca22d1
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x9292a19fbc644a3a
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xae17758ee04b8c29
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x5240b8cb02a6a7f3
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xd0f6747c65cb4c75
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xa10da55170eee353
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x2c8fff07a1e85788
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x3fba7441d982232a
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xcfc4a5f4f2877cab
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xaa31599b127393b4
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x26840b37f363e2d4
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x9b693c0895e8ce2b
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x2fc3e0095174a3a6
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x0e00df7e06d8fbf5
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xdea0e2cd8aefc6bd
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x52b01b0d4197e0f4
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x802286b3a22ea40e
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x36307b7d4b440776
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x2aba0e6c42a1f233
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xfec9d6bf2bd4c44f
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xd68eed47ae0659cd
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x681769d9d6ebf105
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x305df078241f0e04
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xa45726fd07c8741e
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x9422b1c2f8a3a41e
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xafd4825f19be06a1
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x9643843bf0b1495b
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x485bd78ff801a0ea
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x2e13ff69574f8db9
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xb3acae5b0ff2a9c3
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xd1ce06cc1d506d53
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x145e33ee3445dfcf
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x6d478793e15b5358
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x8f5fe1b04076b2fd
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xc1d7acbfb94d788f
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xcda3768219b8ac37
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xf0fb1a6f6e19a811
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xb0850a3aff047937
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xed8e344d82ecef9f
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x4e8c17a724236964
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x94ce20bd76bbcc7b
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x92cc93d09e4a3cf6
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xba5c18d5706db4de
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xf31daa74f33c8acc
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xf1c5150fc2a4dde3
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xee221564d0519e9c
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x495e053baf13f0c9
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x836c5b467fd0166d
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xc42fed74676381c7
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xb89a4c6e030fc24b
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x606cf8cae860b66b
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x3f4859d3b6cfa2b8
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x3f2faf9084706d61
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x0325513ea0a69040
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x7cae2567dc361713
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x4c781a7ca535bbea
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x6b7bf2b97527b996
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xc80326d497c79eeb
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x55e8fde872343ddc
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x8c3a8ff2ac591814
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x0576f36a0ba48b5a
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x5ed29cb23aa34d90
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x352498d2adebe92d
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x3ce1f2d203bac57c
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xcbefbdbf228368a1
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xc0a131c4842419fd
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xaa1814041be27a8c
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x42380ce08ec5a4d0
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x132b739a2e8d545b
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xb23fe3a126bafa54
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xce595a1762eb003e
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xa362194315a3c1b6
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x1b9a56423e26322c
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x6ee17a1dafb0a0ee
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x53d5a4473b861e36
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x54ed96d5a92af5dc
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x7ed145e2661209f8
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x6646b409d5f9fd28
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x4bccd7dde6f3dff9
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x767d578002e28a8b
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x2d824bd9caa9ff20
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xfae479fe854bed7d
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x89193abdf9697e81
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x275fa672e0fd0ff8
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xee0ae97cd2f4d6fa
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xdb3cde1acb8795ea
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x3aa2c62bc527cf32
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xc2b6f458c84247da
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x2895f0f935c685bf
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x79bf31d7ebe00c2c
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x84536bb89a44b219
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x6dc952b5b2a7a76a
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xab173108b8abbd46
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x7f0e2b71965ef7c5
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xb04408240ad87c0e
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x70c21f57c768d04f
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x86d78806e2b5a793
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x1e776f6e3df657e6
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x346880387ac9c746
  vsetvli t1, t0, e16, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x9197825eafea3252
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x4bb5639e88933305
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xbb5a0fe49c2dbbcf
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x36dabc7afe4e4ca4
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x1d60ef6e7756bc08
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xefa59de6d757fb05
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x3946b5e1e97b96ef
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xacb95cef371be29d
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xabe15705d48e4c36
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x1787855d464497c3
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x956a68928af2609e
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc5a68f0bfdf0bbbe
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x11c1b46c4f39fc93
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xaf98e8caeb7e798b
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x7e109ee5e980c8f9
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x348d0707383aa284
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x7e004472fae461b7
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xd7733990b6587a3b
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x8b6146157e885b0d
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x8252fcfaf4d53e33
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc164bfd17d9089b2
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x7870d2b67aec82b3
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xcbc5fc27dbdf46ef
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf57af4cbeecfbead
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x56ed0dad4c412d3e
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xcd74f21bd09fc2cc
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x2ea2e68b03bb1294
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x77b579bd9c653710
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf014d03d9b9a38c4
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x27b35ea86fa71354
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x762a092696f7226e
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x2a44d2e8a9c7a252
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x45162ddccaca3dd3
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x9a58d05ad3bf892a
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x71479d1867742edb
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x5090571e098d65f3
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x412d97d56c1aaf0b
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xa14307222fdf4ec9
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xd0cd49a4cdea5819
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x8d86711ac2365a6d
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x732a747d65961ab8
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xeaa5497b92749db8
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x569108f498279e4c
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x9a0b0d0f054f42b6
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xea5707ef2e2ef56a
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xe75d15aa11bf9bcf
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x7445159a91e6beb0
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x76b0bb615334897d
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x888ae5e6ae642601
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x1b5f022afd67439f
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf6ca33138ee79318
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf188e4d99435093a
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xb84c649a5b05bf85
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x78791dd18da4877d
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x571c071fec9ef977
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xdd313aa4d61d8077
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x463ce195166129d8
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x42836612a33d767f
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x15a101237a70c281
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc60752238238a1fb
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc2532a7e72239d0d
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xba78e776d5ca5088
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x586768e3dbbac3c6
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x14dc4cdf970c5f87
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x7f4642ad21c9f0e9
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xbb6a5f76ae60ac3e
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf49070589804453c
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x9f1719509f5bcc3b
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xe52308e094d0aa7a
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xb89fa9796f8fe30e
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xbd4f0517b2f85b01
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x5e984e4e2edfa91a
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x86daf963715c4482
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x1ec0adde0bf6bda2
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xe13add13c3c8acdd
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xe314378177a0932b
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xbee9bb4673f16c93
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf03a39876c3aee7d
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x6dd31563e8b27699
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x4b01bed58db2a951
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x52a8030307a1db40
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x2f8417ba3cac1aad
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x4ea1b4a281448287
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xa02bd304f34542b6
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x5e315bf043df73ab
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x77702cda6a47a231
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xe41dfbb2a9454af8
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x1475cff621e79137
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xdd389767a4e0c33d
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xb14c31119cd852c7
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xde05dd631a97328d
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf965a412c14a2cdc
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x2a665fe3bcc338a4
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x768eef2c2cdfd172
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc6ae7327a5518e3f
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xe7a2433583985805
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xea8709f925fbb9d2
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x8908303382c14f34
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xdfd8768f333cb565
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x5c4ebdde65d25930
  vsetvli t1, t0, e16, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x8b1b283cddb0b1ea
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x64d7a9a09eabd41f
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf31751e0bfb8e555
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xd98542fe3151b4a9
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x364daa24bcb60310
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xe00f14f59d35350a
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x3158354cc5867205
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x87e4c229fd4e6af0
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x103e9d04712b6319
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x9cba7bd820eaa296
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x54cabb930bf1e92f
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xc34cd32c12ee2321
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xbd6771534015aa03
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x502f2bd4455b4233
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x9a9c0657af6ab853
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf46d4241d8b60f4b
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x7125e0fdbc48a69c
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xeeccb162eec28d5c
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x814dced0a046775b
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x18172a95b3d700cf
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x7535a6921b36887b
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xe4701cf01f8f7e66
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x2c6cf629e96d380d
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x9caa21f64c64921b
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6c21f14cea5beef6
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x33bc9af9c28255f8
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xbeacccc3a9e901d2
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xcfff57ebee85f4a3
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xa1b31e832f2c411a
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x03b1d0c8b3199cf2
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xe3920eaa9625faa9
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x084f346a397ecafb
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x595569717d64599b
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x968b7f506ee04729
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xe80f0675e9a53528
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xd79530cdc7a4716b
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x2c91f068728e1573
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xa72685462e561b79
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x59be97fb4efb11aa
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x42edaee303a5bde4
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xad3a7ae92dc9d3d0
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xc59f8a0c32ca5932
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x77543077ae2abce9
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6f109daecf682468
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x0bfe8619b03a51a0
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x47546c5704fc4fd6
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xd649d9f865aea24f
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x7b4c24b1959b0a0c
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xc3853e950afd64b6
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x25e6ce0ad2bd0cac
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x66a9b522433eca42
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xb714f7da1ca94309
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x503ec6db69270160
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xe6a1b105ca9f0997
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x791e3b66305a7d0d
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x8319014c6e5c8cfd
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x16a41c713ecf09f6
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xc96267c1a6668675
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xfdcf1c491148fa1e
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x582832c2bee6a0f1
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x91ec3e238deb9467
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x9563abf3a833f29c
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xd9f5b7b072b9ea64
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x318dd42f7950a226
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xe62dc1951ed1f7aa
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xc9da96042847ac5c
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xe40c416b24510bb8
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x56ec1d7d65f60695
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x19cce10432c37651
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x48c38c09b3bb3229
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x4385266f9cb0a181
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x2d1561f8cabde828
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x01ecc6c169f48ee2
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xb67328ac512f8cc7
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x632071fa7eba851d
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x49c542037c7fd91d
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x10a603953674a422
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf6872a640631cef9
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x4388201d5656f1fd
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x18de1b3a3dc72b63
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x24221331766edb58
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x9bfedf70d9478208
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xb4b506c288c0bd8e
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf952ed49a6f34431
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xa11c45f37903d9a3
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x93cc698cba4e37f2
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xe87ef42b4f534c6c
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xd124c05e506f06d5
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x02a7f07a775d4a60
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xdadc60f285d580ba
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xef57af101ffc2acf
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x121a6d9b127d8263
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xad3454ff523f421b
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xbfac539c8728b158
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x595e19a61cbed486
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x836ed6a38055b18e
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xd8b2507fb03a71de
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xa974a2cceeaa9262
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x3f6c2511b67af487
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x20e8c6a4c29229d8
  vsetvli t1, t0, e16, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xc4314679af077e8f
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x711c833f1019bf9a
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x03a91aec7ff56239
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xe5a3d6446323c053
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x0a0fcd99ef19759e
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x58e0090e8762d583
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x6ddd324d5662ecde
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x4670c20702168058
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xa594e7bc1c6d42b7
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x9c706b31dac2cd8a
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x0fb545641f6af4bf
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x3c8043d4789bf540
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x712532f9e6c7ce5c
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x62a4901be16f41ae
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x9f7442eca87e1ac0
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x59dc84e497b6b781
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x5895a484faa2b972
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x9b5eb19a69214d5e
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x5c344ba3f6fce935
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x6f8e4870441a5640
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xad1cc63ed87da805
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xf5b30950e495ede0
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xcdf3862b92b211d4
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xa57ab6ed2891f892
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x7cf74c0be94e19a9
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x74afebd96729bf19
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x5b957590deffd1ea
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xfe7958bd68b7a62b
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x4e9a71fd8d7deb13
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x8109523db53b296c
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xc6119990040f3c41
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xf21eba7845b77e6a
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xb9b6881ff7ead6ba
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x5420568326c7a595
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x5c1d94a176599f48
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x7604ab79298d0bf3
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xd5ea7d7a044c25aa
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xf7a3b20e98b0aae8
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x22d9c8122a2788b6
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x43826667adf5779a
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x0fea15942919a453
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x3c26ac2ffe64aaf9
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xcd87b61a7f5f4f60
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xc42d2ae1045683c9
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x121d4c9c63957481
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x2efc6bbd7f64beed
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xfcbcfad35436a3b0
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x04cefca57711b843
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x76484b9460b27d84
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xf44429e84f85e2ba
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xfe0c14082baa8061
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xc0a0a803c13804c5
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xbe51990894245cdc
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xd9cfacf6d7b015cf
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x6ed601c046da94c0
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xcdfb0c3c66a1da00
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x57d3fda892ea7f81
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xa123e15b875232a2
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xfe339d86a2477aa7
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xd731716f134c077f
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x9e6837e67f45561e
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x07ad5fc7d86ed539
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xec03960a894be905
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x8b0882291cef1b6c
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x6205a14a82483a0a
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x622a91ab1040e246
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x4b716c0473b6934f
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xd1deed8c8b843620
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x34b17129cbd80176
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x1ad6f59e3bbbfd07
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xcc293a660f6a0fee
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x940d0e82adbe0007
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xd834a5ede6dca28a
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x1b1ae40406c2dd3c
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xe3b2f9af546fa2b0
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xe438bbf85a8420a1
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xc9bd39fd80439ca3
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x2fd5d6af4979b545
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xb323633338b396eb
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x5b5803e61fba4a8e
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x889400f62b798fd1
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xcd064df42015cd42
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x2656af90d9e6096d
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x90a742da8ac9c605
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xfc4649e672ec3f1f
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xe40aa2b04d1a7c7e
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xc3b08adf5f7b585b
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xdf62bd2f0d49a7f7
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x9b51aa3292ad18e7
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x9b0da311a226bcf2
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x38443631a61f2464
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x5a256bb652cce099
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x16e76ed9ea8e3def
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x6c47061212bb43c0
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x0139be1af82e9ad4
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x132e692437c37d0c
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xb92a1d805652fb1d
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x0442beff01ffdbad
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0x012f2d13153938a9
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vv v2, v4, v6

  li t2, 0xdfa5857bc019e5db
  vsetvli t1, t0, e32, m1, ta, ma
  vwadd.vx v2, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x38ddf92795e759f8
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x64611ec91bcdc9ae
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc83adbed264998a0
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x4d7ec1b69c4c201f
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xa0cc6966d0c2a15a
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf52337c2460f783a
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xe8396b1df5d29fe3
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x7c5df7cf8b621f20
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x268a5537c69e5bad
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xb527170b86b34f82
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x19c09632efa3dc60
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc5e121c967d3c8f8
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x940dff8ceb6e27f6
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xe0dedca738cb40c1
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x790961f65dd4dd96
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf45dc66ac580ab19
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x3c266d366a2f80fb
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x5fc6611e2883bbbf
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x0c1300ccc895f89c
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x99586e63576d093b
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf10230e3e45e5275
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf3debd68f998d126
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x37a1c50666a2f230
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x7b03e65e71a4bf6f
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x2794fb0d42c765a7
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xe2d96dbecd7f0b2f
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x39fcb72f75367384
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xbc4fd6d2a1766c70
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xbcf9fde020f23e4f
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x467516cf7b5f79b6
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf459a12404e1dc49
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xe01c868c12fdb9ec
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xec7605a48bd8e49e
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xbb8ad88bb7a6dc69
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc47380316d5365c9
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x4a3f6ab1aa047fcb
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x980d1028338a9167
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xfa1c146ff32716d2
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x791deb48e2dfc3fa
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc86c0b733a338db8
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xeda3511030dc8109
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x843694e4579dfdf5
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf14d39d321fb17ed
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf771d630399ba5d8
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x6b4e014f68c0f0d1
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x5e5d3b6280e8c7ba
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xfcf528de1bd24610
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xdfc13ee309748776
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x7165cf3dd1826ba7
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x9e36956e89711650
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xcab4ec8ba52e57d3
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x72403f969313a6e4
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x349c74cb33f67474
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xb4284e646da293cb
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x5050d52bef522110
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x65fc746c2359eca8
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xd7cfb018689172eb
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x3d9bfe6262c45049
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x6bcdcb737baafee5
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x21d56ee39e14ed4a
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xa43f8d8dbcbebd49
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x86a02a249b141c4c
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x076c50c6db3d480f
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xb38fb5434e87f611
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x0ac86ef55e440c74
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xbf355adb93a3260e
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x377bd46c322dddf1
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x1c532e7e9a7e3e20
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xd6e1508ee90f48b6
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x44e833bc0dfc3645
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x84ecf3ee9efe8792
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x75b8bc9d40f664a4
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x24dc8b0f016baa5c
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x27d41ca29f5b5f04
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x748803f38f84580c
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x5c9f74592aa78cbe
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x0090b36dd7824250
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x70017868f3d1a1d9
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x4914c0bd86105ecd
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x2b046b8658290f6e
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x211c2e15858d4828
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x61ff62b9b30e2a63
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x807be919e6d612fb
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x4677587b83a26a67
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x24d70509b7fff6a2
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x55c62893744df649
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc9617228e3763677
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x1ea11d8778dfcc80
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xe19d39c0ce3da497
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xc087ffa92b193a92
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xf599d8611ea95b22
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x82166adaf39e14e2
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x653b4b1005d1513b
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xe0c0ddb4744290cd
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x916e55ebf1bbece4
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x6acad0d6dc0a1729
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x8601a8d8d5cb7a5c
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x04ec5f4783b4197f
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0x706b4726210bf50c
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vv v4, v8, v12

  li t2, 0xb9d248f2895ac38c
  vsetvli t1, t0, e32, m2, ta, ma
  vwadd.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xbe77ef65a4f36264
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf2e45b9a4a052d28
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x8865d017ad5a9fd3
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x9de82ad7472a61cb
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x456612e7db5eb347
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x4050b1106a6feeaa
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xa60abe50125d6eb2
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x59845f036daf8bbc
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x2554725da8336112
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xbca3924785ce6e53
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xbf7d649466666706
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xb2ceca0ef08b202b
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xcb36b9524e75e615
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xa6f22913a2591572
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6a7c4ceaed7929f3
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x0348be69584433e8
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x1fc3451a476cea09
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x86751f4b131e0374
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xb99e960a248d7456
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x5995449992b379bd
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x728d8f39e0b75260
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6fd3cfc07e4fa0c0
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xfa23a6cf4ea1c04a
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6d0a5a85e2be1ba8
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x22512dffbdfd1be8
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x4d25e0ef5dd5c6aa
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xd9ba6c0c9d7a2b33
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x4cf24656c2251bf3
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x46f3d29025f05058
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xcd2cb1e06ef276eb
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x698b39ff287c63f6
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x8c184a320edd558e
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x97c366d7ebc38114
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xe7825a6eb316b233
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6632431f2a1fd519
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x9197237831c28e5a
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x1083d0d7b1f54c54
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf963013c9a69673f
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xc288f827872d44d7
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf23423c019b1fdc7
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x86c7dfd1d8754569
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x21341f688a8d19f2
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x027d2caef258e405
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x5a0b5b02a8d7544d
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x477b5bca6e910ce2
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x8a735a3d356c36f2
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x7ae3fa25cd051f1e
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x05a9dccbed0c19b4
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x44ac2bab36ecca00
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x4cfcc8fd54ef1fd3
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x7a81eb3073eee382
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xd46cd01c0365538f
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf4c011403df9d047
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x0bc1bdbd3fe16d3c
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf26f01258501fc40
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x92d72446edce2ec3
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x747f3c1f582eded4
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6df83bd891bd282c
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x627acdc8e7d3ec8b
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x14989e4d44a439fc
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x39949c3d01a13836
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x3d8b8b24c410afed
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x741c0e9b4b0a9ab5
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6921149fe413ed63
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x70ed141195686e0f
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xefe7405b172311b3
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x73e8982487d388e5
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6b53b24bf1f84a67
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x7db116cbbf9eed71
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x673b3719f6d9ea5e
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xdd572a918c98c5d1
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xd33611d545c954d9
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x221dc08f2ea42756
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x80328b014af936f0
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x56c2f00d04095086
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6c72f912ccbb9ed1
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf0f0cfa0314c22a9
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xf6c72e8ce2fdba05
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x23b058eec1096338
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xd594381492dec46b
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xdaef65c5218ad866
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xb6bd14d8a936a05a
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x7ca074bb2ed86d7e
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x72d742b92470634c
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x5f94a27b31297504
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x2db55dde5eba2cac
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xe9ece9568d8727a2
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6c6f553b59d8b6cf
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xd2f2b1567b1d1fe6
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xfc850d508c84486c
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xbe22baa5a6fe0270
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x89f465525b985a5c
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x4bc4732c852920bc
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x6fafdc9f5824f87a
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xb43f6b7c578d3eeb
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x2eccbe346ce215e0
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xde81aa153efb9404
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x92c3da08b71a35a7
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0xdd94068532840749
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vv v8, v16, v24

  li t2, 0x65317e003db31183
  vsetvli t1, t0, e32, m4, ta, ma
  vwadd.vx v8, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
