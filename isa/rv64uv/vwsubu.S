#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x2bb1eaefa7142209
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0311723eff2f7c1f
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x66cf6cd662e5fe6d
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0f8de07750257179
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x31231acd506146ca
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x605e4669cf8286e5
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xeb0fd867b8e63d29
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xa2376c0d78b71d82
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x3f1b7025f6c847b8
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x2a61ad5dd753f6a1
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xb1ce3c5f1d1a4d62
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x9c5bb8da5f42e008
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xba32964b7ce46c00
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xc9f096abd2860d62
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x03d63d29a52f63cf
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x8ae1ed99ab3240c2
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x697c1384b4cff98b
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x751fe61a917ea276
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x1a5b53350e1ceff4
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x07aab7a6ea387cc7
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x3e935b58592f26d7
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xec6e9135a70ea330
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x95040043fb23d3a5
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xa60b4629791c19f5
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x2f3be900a9ddc2ad
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x8b974d93fbf0c8f8
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xf75844e1884f7f20
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xe6634fc799a4d5d0
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x68f4689a469950fc
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xf7fc3e15451bd81d
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x3f1e7c4ce6d53068
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x5065e76e95cd8744
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xb62e75c40d9da70c
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xd4d171ddd3f6ff3c
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x6c79587b86d920af
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xbf0b6a0cc5a4fb38
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xa6ec37e8a22e7373
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xc16fd8f17ed1b95e
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xa90b71fff985e8d9
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xc912d5a8e4009086
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xcdea47236b5796b4
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x09c302f72f7c900b
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xf3423a8f95b2647d
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x57318659dab01f4b
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xa55e55bc68e44412
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x9f3741ff0a876c21
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x021894bd4386a12b
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x6d80d93c0cec04f3
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xba0eb3a6a08f0e16
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x02b513139d91e93c
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x1ca8238e84938c55
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xaf7e1ecf4a4b9640
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xd7305e56ba13418a
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xc2eed1d64e36a68c
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x7c9d7ed3c6617695
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xd4a4e16c7710a987
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x609f6ccf8aa52b00
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xb56466a183ae8e47
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x1bbc6bbdec726657
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0c56619c748577aa
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x3ed7d18b5de06cda
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0bff8aaf420ca0f7
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xccb5a23f158d8b82
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xe59cc7e124dc9f5d
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xec6efc0de86db9f9
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xe5d1ed93a97ed093
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xbf76a8a36eeff642
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x1247028db28b5da6
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x8efb5b368b17d609
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x9b2c97b4ff1b1ae4
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x6c6e89ec9ee33fc6
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x4819616089825db1
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x43c636c0052ccb01
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x4675e6efec4fad24
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x8f9c1e8160294bb0
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x2985979e2e4b9fdf
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x2500eed3cf2eb97b
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x65fdb0ca36675df8
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xc9cbb8d07fecdaf9
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x424eceffdbff2634
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xbeb9b74d947dc985
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x169f6710082bf3c5
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xb086bcf86a67d25d
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xdf50cb9e86fb84ec
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x6e1d9ff0f4ebfc10
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xa15f6ff99f882c08
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x4bbc3595a223add1
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xe1b4f87de085b99d
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x16957c18ca1dd337
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xbb49d77f4338211a
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x3bc968c9b15b1372
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x1298c85c9a2dc931
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x07836286867b67da
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xf2342ca464252d19
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xb2cf025bce3bae5a
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x2117899ee795b340
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xe378cbd8826f7a73
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x6dc1268ffe07cdd1
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xf496f74efa3b2fca
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xae6b7eebf65e4668
  vsetvli t1, t0, e8, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2dbfd9ead5a3e946
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x491caebc0476cdf8
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xb05b94220a1a2d28
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x7c3d63641a8cf857
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xc261e051047efd85
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x7bb52cd35f076e67
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xb9fdfad2a44a6f7a
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xc4864824433d4a98
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x5d8c2e7096797295
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x342b5e079f8c745d
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x0d27d5d45c8dcb87
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x777b4ad3f4d81ee8
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xfbad5564e657b9cc
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xbec321d568d8f468
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x8992b3ca16f0c7e9
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xc20d84d07738824d
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xdfb900cc284f2c09
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xfe494feed79ac5ba
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x84220f2e6a101cc1
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xb6ec278268613c3e
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x0aad24248635fa3e
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x704600d008d009ac
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x356222fa873a6c09
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xd8c984a42fe59e52
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x8feba102aa041135
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x6fc67c256f38a335
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2ab21708b344c442
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x067c39592c52ba48
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xae03abbc3d745b24
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x4a686c57f06df396
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xb095a1bc63b11944
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x7b3a116ccb4cf35b
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x9e37207e6c46420d
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x66928d4c38cab442
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x028142878e042d51
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x7748d24708ca6c4a
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xe739ee053338128b
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x9a8201b61c46081a
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2035719d104caa69
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x759c7f00cc8c5a83
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x417f699892a0a7f6
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xc8266141bea9c12a
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x698d3e622aa1bd51
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xc83ef78c01ed74b3
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x4c83bca44f9110df
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2cf60c2988dae411
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xc0834044b6133438
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x8bd3a5c10fd90749
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xfc1c9fd75dca96b7
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xb97fde3caac84a2d
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x3604ca22ff1026ef
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xa4de73316483af40
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xb8f3bd7727e4598e
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x92570e5deb2e0f72
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xf23a9f026cd2c2b0
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x3eddffd452cfd74e
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x524b973d81ee5331
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xa2d5ca43bc2bc8d8
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x8ffac7945e085162
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x633529e98e21a475
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x49b9cbd9be2f0b4b
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x0fc3ea4b18978a3a
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x0819c20bc6fc790f
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x3d2f1318dd5c1f39
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x5c9f3ecf22cda79f
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x4a7c201eb9320c90
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x4aa5c2837411d7d3
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2c31e2a137477db9
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x3004a012fc62046f
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x17e3fac4d83ed6c5
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xc72158cbc1fa5d5a
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x45286e166f565d15
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x49516d63f08d8406
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x14bf4f162bf1da9d
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x6ca729f6a874bb0a
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x479d546e47752981
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x3dfabc882966d388
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xbeb62b8c610d625a
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xdaf89814ef3d7525
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x60743067a2a89a7b
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x586206b3640f10da
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x9d9666bcbe54148a
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xf531ffe69c396d73
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xe41c4c74eed87f39
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x648ca1ad290faebe
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xf73b7321c1450120
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x095d2e546867c215
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x477fbd2dc910f8a4
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2cad44018a2036d1
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x640d0bed594a2206
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xd3baf68e137d191a
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x3aef9f3a0073de3a
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x339c8f6a2c2ed582
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x959c1a850d5c63fc
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2d9e81cf92ca9e4f
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x47ebfe33463b54ae
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x8119ecf00ac4414d
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x1568e69fef6e04c3
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x68ddebf2f642f65f
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x912650fb9be0fd35
  vsetvli t1, t0, e8, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xed240d61bffa3478
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x8640f728348319de
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x4a7234bd9b041120
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x83590c1f515f062d
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x282e2d248f551995
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x9dcee5839a739519
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xd38437c4d0f2cc6d
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x3ed8667ce5526dbc
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x033e5ce3c4b5daa3
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x918c19650199fd25
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x3c3f0ecb79fdedc2
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x1e9d40645bd8fc8f
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x57c2d52f6f2d9770
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xadda81496c48211b
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x0806cea295e7f553
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xe09100716fe6e1aa
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x1e0ce887602a5055
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x496a84e730cf5010
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x570fac34cbca1077
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x8ccdf7c72bda445d
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xecb50654feded416
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x5d20969b94902b03
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xe415924516c93d33
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x7214603c1c388a5e
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x62395107b704ad44
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xe6f416b7e7195d9f
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x9b6bbc605bb4f60c
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xd10e479d22ace71c
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x9d2ea84dc85ae22b
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x165b96a937f657ed
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x0828da7196be0160
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xfc36d115e20af215
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xfab0ed48fff0fed4
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x48c75f374ac881df
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x68fa03cbad6897b6
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x7be6eb61da2abc48
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x9b7ea481e067133c
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x39ade29068ee7655
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x96ae66509b4b3499
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x81bdab804eae152d
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x525d4283d594d438
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x6df2f278bca5128a
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x025a0342fa14b1e2
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xfd3726b3368ed217
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xef0406e413ebfe46
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x2d0db3a7df9a335f
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x8b4f3b3f9f8171e4
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x1d1bbc65c091d2f5
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x5937eeebd34af73b
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x82747887810e7598
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x1843c108c1960891
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x00a39628d14c7552
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x21a12da968ee6eab
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x3da6dbbb7e2d2302
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x507547373ef88149
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x38fa99bb2014ae18
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x582408a7338655e1
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x0e9f4e8a19133df6
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x6b3712eb47680312
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x5f4958a1a90f6664
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x2b00129a16bf4e59
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x39b3593a7a794a8b
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x72500685d8ff7ff8
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xf53e36f8bc5ee5be
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x477fb2b650e40a0b
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x13832ecffe7b1612
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x5bdac4751a3abf4d
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x2e1aae7620be9f0b
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xf09957fe1dee0bf5
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xddc959b7ebe862fb
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x9a8c784da46c8fd9
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x3d24b1943f2865f3
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xf9b5d9f8da5383cf
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x4a300cdaaa67f8e9
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x5819fa0b1f81409c
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x9de3f02cfc2f1bf8
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xaec89587c7675ebb
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xc02060fad725dee0
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xdb4c5697fdb60d3b
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x1ae6bf819eb30cbd
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x6e3a1067d61a4061
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x5fe9c393460cf411
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x4fee7068a4abc487
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x69c04f321188f658
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xc6353a8c1b45bc27
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x84e1c0649886af71
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x93c0f2c818525bbb
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x1924f2ed85e78959
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xcaa387f554400912
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x32ea8321ea1649e5
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x080c740e9bb7a801
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x988b6dc9075a5bc5
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xa525db3ab49bcaf5
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x69ace574972e0442
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x95103898e64c31a7
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x32628c704cc73f70
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x52e6e3b713c08514
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x0d53bb5f64caa01d
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xb60c9884b40af2ff
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xffb325f33dd3baa0
  vsetvli t1, t0, e8, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x908be79a544a6835
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x94fb46a023d34169
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x6070ba80446c8b71
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x7a540f4385dc5932
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x40de995bc7c2bea8
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xc01e13f2b3b51607
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x3b31968689a80c88
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xf829261806596434
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x3610ff296122a109
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xd8f266c14501c1ea
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x56ee5148fa77fb31
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xf02c0adf116e340a
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x86bce98c83a198d7
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x5c24588f86f99955
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x18521d8f93782731
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x45f17bc5a3a046c8
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x4ed7dfad81538e34
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xaf77edf44800a2f9
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x60a64cf88faa2316
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x36d2c5d49df1a9d3
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x113b5b07f4715775
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x45b88ab251059185
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xb1dd407d573c5004
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xc57f53318d9f2305
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x8e51dedc0b3ae33f
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0be8c9ad22dfc091
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xf9f60383bd21b2c8
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xe3e262e06e41c04b
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xb6d2de38db2730ff
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x64829df06c0cd10c
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xc3ad1944b2249ff3
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xebe9f1937e3e2fa1
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x2c25a6f96d91a18c
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x7b59aff3c611eb7f
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x11c7c17c718772dc
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x28fad60a534caf92
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x925dfb6ccae0b042
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x67c88c1eb7954709
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x9f0f2b0ef072a160
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xb61c234a99790356
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x526afb89e96a9164
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x6572a10c4827062c
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x6a37959374c689dc
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x394a930d13d23c6f
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x9f35e262ac7364b6
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x65ed9b093d06a1c8
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xefba46a0453d8e8c
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x26ae97b7fd6f81ee
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xfb55bf7b89f09c20
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x23b26914719a8289
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x78ae58f73cfc3607
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0a17dc3b30b6dd08
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x710e4f7d7c809cf9
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x402090f1e1452a63
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x6ffc7506e54430c4
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x15c353150baddea0
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xb8d1c73dad588ea4
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xfaa77c4e5e10fdc3
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x016c7c5ec47f9b16
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xeaafbc6348950e03
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xcdc553337b9c49ed
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x72a511cbe8e3045a
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xe2775346e912fb8e
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x74b5ff2a744fde0d
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x50ff4b5cc95ec390
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xf1db4ef47cb756da
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x5ee99326f61a00b4
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0006df080a000172
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x397a9860d7055794
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xd75509aa64dbb23f
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x3ac064880f10cc17
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x5d1512f204bff89c
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x10bc38ff5baabc79
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x72c6ff7f35ed3e14
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xd02b5d12b357edc9
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xad75d6dc28a11b0b
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x97d68308a3ea5a6d
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xef3aa24943410a96
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x4f2ac0e6b2b52aa9
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x90bf55831af59937
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xb20e71618c8da288
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x228bf3bd4609680a
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x7f00138bec68e856
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xa88cec5193b812bd
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xd63e409ac18676b2
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x9e2118522074c058
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x7890ca48f9afee45
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xa1a399ec9b5e7f5d
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x2bc4e8badcd7c160
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xc0c5aeb9e08dcd79
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x2dac91390987a320
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x096389779f1f5a2c
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xeb5a2a002888a056
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xfa33b37db62f4dfd
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xb2794350c50ff43f
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x47d68e20990883dd
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x8d380d90d997720c
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xa45df99c4e0f6fed
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x2112eb7c4bbbbea4
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xa6abd0bd05da3a7f
  vsetvli t1, t0, e16, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xe7ac2e1f47ce6c63
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x4cb551f3cbf9711b
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xea7eb8f562850515
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xd50f57975eed9bc8
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x8c4396eec7b0f31b
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x92f433243f77c8aa
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xe9255c0cf5b41438
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x29eac89a591f4df6
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xcbf441da003797f9
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x54611e4844928d27
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x94ae0f8b369e27c0
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xabea82438383895d
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x9f2e415d7afaa0d5
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xfa9e7b68564cd2e9
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x6bd1360097921a7f
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x0d1cacf9fe673081
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xb6d28c15cc0beb78
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x357226d2ade3d812
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x156bc349a03e3c20
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x88c6e242c418048e
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x5f346cabf8b8844b
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x11ae890ce3676cc6
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x15ea7eacdc6f8d0e
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2f8a97877e8874ac
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xa98943e8e449768a
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x23343cbd39a6b23e
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xc95ef9c2c62ec4b5
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xedf8dc417f8d2984
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x7076d38f37b92051
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xac81b314bb118225
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x8cab7173936de50c
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x605d491c12683e3e
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x664c39b9670427a4
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x5f667b635296bac6
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x7442021a0b30c1f1
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x9565e0106f7f826f
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x428616a61dd15038
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xdd40acda3e2eb034
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xd6bace5f434283d1
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xbb7caa54c476b702
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x504407e1577fb18e
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x7568c03574d58022
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x40ad6896ea949da0
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x1db1e3c785a628d1
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xda3df17ec432fada
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xd8587fe7d8bc9465
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x7b357740f6ab4b21
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x69e8f48ba601a79f
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x7f9beebea8ae1d49
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x5fd6ed2b7319cf9d
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xd9181e6fe8057efe
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xc9f8b6e1b176a43f
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x5aeed5ede1b37272
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x859992308deeeaea
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x4a2e09a6fdb0d8a0
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x64cf5384970f83e3
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xb0a5c9ac11c8a173
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x76612c848c391144
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x482b7b9960ac44ca
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xe8fcf64f91692065
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x8188ab98dc3d1c85
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xa9dae04338ba34a8
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x7525923d35f2d821
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x12f2b4e1f49caa6b
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x5a25854c3bc96234
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xac76fd82ce05b887
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xe82b1e681c491853
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xf015bca8015c17c6
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x5ce2cfa1a4883653
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x0a423ebe4fe1e2df
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xc5b8cb1a383cf040
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x0af447d5a5fa2308
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xbfe08316d2a1ecc7
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x357533ec6d47f184
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x209fbc4efd071472
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x65bfd37e9657da1d
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x94bc33e83d84f02c
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x81ce90110f92d39b
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x16a88543df7f037d
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x7fac4daac6eac926
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xab2c1742592cd52a
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xe7416d5043fc5934
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x41384172be719bde
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2dcba01e064ab886
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xff9798342ba50212
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x24831e13adb14020
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x146bdb8dce35f67d
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xfd36465460daf3ff
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xa708d787deb4c078
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xc37ac3ab32799ff0
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xcb21c1630bd431b9
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x9b604329709b89dc
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x085d867f7441d907
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x059cbe10f18aebf3
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2c2616dcdb481e4b
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xf50867504ffec5d9
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x459e5dce1d96091a
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x84c62abe4241a70f
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x78370ab5365ac7da
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xc15e993a4c2c4d87
  vsetvli t1, t0, e16, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xb494089d5896112a
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x436c3e8a7986f7de
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xdb63cd22ae8a5f85
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xe63f516913b98aa2
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xdfa3ea725a1b6604
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xfe9bd222a9512bce
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x5c8696207ae4c293
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x5de65d579d83fcfd
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xaa2211efc8ed6f69
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x45d43d1aea4c5f2a
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xb7aca5b04d35501e
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xf446f0f9b8cd34ba
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xceb62719db07084d
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xa684c7d8952c99d2
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x4ddb077c36a4e236
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xcddb144884c2f45f
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x1692512ab9b11da7
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x4ef5bbf52b1de7d1
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x0b4a44480dad1eda
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x76fb338298afe10c
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xb752d92a42555408
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xaeb277c0bdd35330
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x0ba1afbb2e891d2e
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x612868b6b128b1cc
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x71085556fea9a5d1
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xb857a0d4ef82ad40
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x4fdaab6f0cef5345
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x65b0bde17e00f5b6
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x6b03d94aaa40aea8
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x0b2daffc6ff793c7
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x30dc010382c2f7ef
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x8496366387a31bb4
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x2905baee06a77b4a
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x69a71467c223ae1f
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x2f3e6e52b2c58c00
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x47efa40e8e0a96d6
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x2fe23ece547a68e9
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xeb82af735863270f
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xe268a3407bd97522
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x544eedd02086c554
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xd91a840792290fdb
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x4d1a58cb873e8524
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xeaffb72fd8675e96
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xe65f4b2e0dce2a44
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x96d6507a21f4808f
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xac097e6a2f0440cb
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xee98082ec88a1f2d
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x061a71971c353ad8
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x30675dfeb8956a9b
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x5fbbb046b57e4041
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x18248ebc934cbb9f
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x3e160819fb8c2784
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x2b3cb56148526bfd
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x710117c3f45a0a7b
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xed33416e233259bf
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x10e9328c4cfc2912
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xaf3644412e36bc42
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x0206220cb88ce94e
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xef164f06a6c188c5
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xd228455354e3d891
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xbe6041ab0da68daa
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xd2769935e6ed278d
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x18ff7dd6487b46da
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x22c36def702ba817
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x6e6063aff602a000
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x45b0392a810a767e
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x783f5a59a29a6f96
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x7d331e799397a80a
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x41ca1a5c8111946e
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x0159bd5b904c8e0e
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xf4b66a8cc818ecb9
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x8eb08ccce6b3c231
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x46be3a7dd1ab606c
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x0ae301c346a7c83b
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x548971d258e725c2
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xfc36180b3d9d09fd
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xfd0e9419b0ec394a
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x3b6ebfb2d22f811e
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x71c29ae1fab5c756
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xc65fc07739596379
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x01dbdb5acca32429
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x7aa460be6d53878c
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x38c74c7f2d2354cb
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xfc5446ebb0155db9
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x77288c83b87246bc
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xab92e3277485f13d
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xf32dc607a6440d96
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x57d103a90c37c2ca
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x45faf0a8777212ab
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x77689c214d88d415
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xefc2163009169a2c
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x87d8d517d39789a8
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x758eebdc44692452
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x8db733171dcd3318
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x1dfd76c65f737448
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xb6099c2ca913a5b6
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xebceef8703dc5048
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xe202aba530bbe593
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xb4a246267302a592
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x214beaf9d0e9d0f8
  vsetvli t1, t0, e16, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x1a1919c02188017a
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x16c0d4aaaefff716
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x66bab08e6568e7fb
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x708213e894208a30
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0256edc2a272e31d
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xff2f66a9eb45c6e9
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xcb91a914e6329e95
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x6c906a024d7ee710
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xa72b6dca2985d52b
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x780912cfcd249ab3
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xb21bc543b4ec5160
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x9a6162ebc5d3fae7
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xf6a69e34812253ab
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xc734fac91f0a8d7e
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xce04ba1b9c1b64f3
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x55b05b2eb159b12f
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x47beef50ddf170a7
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xb7968ffb53cf8f62
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x1813607bc087d20a
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x94226014af1b76e5
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x19b1c5fdfd9e22e7
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x49aa7cac23594904
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xdbf42d9644ea0921
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x9e194a28f5186da9
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x124ff6a992cbccc9
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x1e62c39bd31247c2
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xc9a14d13275b7d31
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x494ba5c1de689350
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xaf6b365ec30a5933
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x14ad93f381d29735
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x58573f2a1bf10d5e
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x949a096a72470275
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x3f5bca9d219e1e1c
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x635460f915c99208
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0ba6296e9df8285e
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xbb292aff810fc495
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x9ee0f31def70a81d
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x8f5c2230b9eea88f
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xcb6c9c7f2b829299
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xcdbd443a0275fd8b
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x7a3432e52a6e7e7e
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xa69bfb6e22d264ee
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0a9cb391f53fe171
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x934b324224124d0f
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x40897a4207e1b430
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0ff2690a956f767f
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x4b514426fd92575c
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x5f7fddf1adcd1db0
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x3a017f7c0c0550f8
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xd2f2cde9ef057a00
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xf44b654bfa6f24e4
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0b899bd70f2a36f8
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x98a060dcf9ac6db1
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xe2b24c42c14fa03e
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xdd94101115130600
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x74fd942ef19d6371
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x96df16e8bb0bc682
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x430c26159a2f4e9c
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x85e789c922568bb7
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xfeced12618c2b820
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x1b8e246b5ba5e3d0
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x677a549b84d63c14
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xc22f68d90bf20af1
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x4a47497ce0e199e1
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0667c5bcbd55c53e
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x744fb15906c95931
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x5e4613e7f5ea6fd3
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x4e8a16eebfee579a
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x3e7817c8818ccbfd
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x97eddefb2283f573
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x36b8e874161b3cd0
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x8dfbeda2db565463
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xd048726b8bec4aff
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xd134e73bfc928d69
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0b59d6ebf3f90c3d
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x33841b3d7ea26e75
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x27a94f44f58c9785
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0ab962f5593b912f
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x5f98c0c8d5bb79af
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xedca3eecb2b9c92c
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xc0324d2e207fbdf7
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0340cae5492e235c
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x4a74435c7296589f
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x6430ceef64338c9c
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x725d8aa50e0ab53e
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x6172d2b780841d82
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xf78fb6b605bd2b3e
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xc4575ec52af997a9
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x0fa191dc9b72a1b6
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x6a70d042ba4e8047
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x58751542c9b7466d
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xc50bdca9d6379d49
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x6db8af8dff17313c
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x760170e1e43b99ad
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x2e3684725368f212
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x4569367c09e0dac9
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x8ec672e1f41506d6
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0xfb0853700fbd97a1
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x4aed0212b4a7b1f8
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vv v2, v4, v6

  li t2, 0x268640ed4d3d8bc1
  vsetvli t1, t0, e32, m1, ta, ma
  vwsubu.vx v2, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x9fdeaa9c904fb233
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x01418548e07e65c0
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xb1bba2b6aa229286
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2b88040bbb03453f
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xf065891a06aa07bf
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x74a9b6be3fb600ed
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x1cce0fdd2276cdb8
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xe1e56a59771905f1
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2b81edc692675070
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xd8d3c0d586e4b15e
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xa58923702594f6c0
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x8334977e05acbb9a
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x625abcdbcd5d67b2
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x587e31a4061ef867
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xd17ec0f92eb606cd
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xfad4e29557c6d235
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xee45a23b45564887
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x36ae1943c8a61e8d
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x8c917fba88832112
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xa9b3f34f3a4f7b6a
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x5e06f095e7d9e698
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x1ed5656c31a6787a
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x26350201fc6fd083
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x1e875d9280a72c01
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x3051d2209c8a57f2
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xf3f4146094eb86ea
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x6e558b29f60348d5
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x8e6adbb59249c04f
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x68c657d2cc80344a
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x6e890317b8df8c94
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x3cacc7a0a560dc26
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xff43f9aa7431127e
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x64ce9fb3f17a108b
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x88dc14d5523452b5
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x74b98fd14703518c
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xd22a9dee1f8eeba4
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x5942b7668bed58cc
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xeb6e05a5edd1a3b1
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x94090420d3d8a42f
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xfbee07023647d627
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xe5ac7bea75c32a07
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xa6d844f71ca221cb
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x8f6aeffb93be7d24
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xeb96766335e9b344
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2d0d207fa8c58953
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x0bddc235fa343cb5
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x02657df0eb7e4bab
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x70c937c19de6028f
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x5a034dff4f3ac3cb
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x9c3a7f0b6407a6a0
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x39a182731f9fbef8
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xa86aeccbee7ef386
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xd81f3ef7d838d33e
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x4195f9f832220fae
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2e2a4e2af0b32846
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xce50a06888b1eb50
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xcbcc925ae295285e
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x168db3ad3203de72
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x154d168044db1b09
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xb1a351fd2dc424ec
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xed932ea2af067663
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xb4b9d446479e21f4
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xac5b8b5ae05ef774
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xc94aa40b50941062
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x30055d819af85365
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x142beb41ebd94680
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x0f6298fa67066969
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x82a2aa2208fdc21f
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x4b6e97930c4080bf
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xc274a33117785051
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x1beb8d70db728f45
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x9da2aa20596889ce
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xdf658a9cceee2e1c
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x9098fc286113447e
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x4d9412b44d392fe2
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xaabf84375a9d9190
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xf7a9e786cf6126a0
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xc7f74aa3a79136be
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x76a7b8d8cc0a2e49
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x562f9e0c0f9b50f4
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2585cfb30fdc14c4
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x155e07ba023626c9
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x4cb2a44f6d6ce85d
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x0ff32805094c647e
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xdbb044a9e674a974
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x6e869cc491f74c4a
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xe67afba3a46ec51c
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x5fd154b7672ef711
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x3fb55c237cce5b09
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x22c3cf4cc277d9ee
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2b1dfe31f702af2f
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xff8fa19226b32b2b
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x1ebc436c351f6aa2
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0xedc472b606557b2b
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x845eb85fab34fb58
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x547f0aed12d3980b
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x59b6c667a98a5eea
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x2cbfbb2da36f052d
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x17dc2bf04bedd809
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vv v4, v8, v12

  li t2, 0x21240db8779efd9b
  vsetvli t1, t0, e32, m2, ta, ma
  vwsubu.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x4734774a7ac971c3
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xbf50e81cb4e5f877
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x2778594b8644a7a4
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xb815a6eaaa41026d
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x8454bfd75fc38779
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x0b145ffb77f90863
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x1e3df47d9a691978
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x2feb0ef1aaff9108
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xe8c46856200e0e0a
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xa5c153d64b105427
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x6b688ba1152621cb
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xe86859d2855aa499
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xea69cae5ae29c6b0
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xa95e4195a8907dac
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x794d0d512a0be941
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x3b130d5624a59f23
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xc75f6bbc4d80d261
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xf4740c93e7c66065
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x4ce8a04876ec2ede
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x803506f772276682
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x9c80122258eca0d1
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x893752f339ad4941
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x87a5f27e4b42e810
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xd8cd343687bf0c7f
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xee5054ebd9cbce19
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x1b1edefb2b96a4de
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x4564eeac830ad352
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x68e8eaebd3adacc5
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x76dc6e4c17e77130
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x7c2642c640e2b355
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x797baf86d37abc2e
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x887f1319b71dc17f
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xeeb2dd060ee32513
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x270d071bc04249dd
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x04cd6a7f79798f85
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x611592e1ac29e3fe
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xf65c6bf162b557ec
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x93f1f1b14cf975fb
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xf08530683e0a75c6
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x01500b4b837ab69a
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x61139463e92fee98
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xcba358e1002e7acd
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x781815d3205ed028
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x14cf7e0549b2679b
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x0bf50c2fa6a9bf8e
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x1098e21d19b51ad8
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x73338b7ac72c0541
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xa2d92854a5c9c083
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xdc8302c16937220c
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x8f5cc094e2349653
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xb7bde78db57e9b54
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x851fe015dd087d4c
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x42abfdf81714c34d
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x84e847904456caa3
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x15f0eb5d72e85830
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x15657c318b6f97ab
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x362215598df62552
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x6b7add76ed2d9ae6
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xd7c565b68ceb7d91
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x76f5c25d67c3c4e3
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x4052fb43b777f194
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xe3c222b11416bdf2
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xd583186461aec9a8
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x674f8b919d4e2669
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x9c05bfe04d09b541
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x215b7a36f5529fcc
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x4ca8cee9d062792b
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xd027c8fe35afd790
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xcaaef5d0120ec07f
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x154f2f85a75ee4dd
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x3a7adae8fa4784a5
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x8548840f437f46f0
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x232c70542541e15c
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x36353c3fdb5b8ff3
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x0db7cc8471b026bc
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xd6878097688cf71d
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x830872d7d797453a
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xb530a19e154814f2
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xbb58e36d5ba5df12
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xb8919032c406be76
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x51a84d78330aa920
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x35ac59ff96212779
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x9865e3e7c4b26722
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x1bc0f44ca2facb71
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xe6cb10438b22a859
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xc5cdf03fa40d6114
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x6fe197a3796c9a18
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x9ea8501fe5ce22aa
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xa9ad54c02fc7b637
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xfa8931e1bb8e611e
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xc3bfe1b156c86496
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xbe231345b1c9824f
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x3aa76a3254d12936
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xaed7572fa54f0bc3
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xad683347da7a8a36
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xab97aaba64c0e2d2
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x711134098810aff0
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0xed8da20aba3f573a
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x365c69c494c2fe8a
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vv v8, v16, v24

  li t2, 0x85a81842323b07c0
  vsetvli t1, t0, e32, m4, ta, ma
  vwsubu.vx v8, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
