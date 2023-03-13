#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf5477ae1cbbaff97
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x99d126be73d4b5d3
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xa75c273067ee5352
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x24fceb6336259431
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc20d22df4f5a9008
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x23ce9b471d7ab7f9
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x111dbfe6e282cfcd
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x21e8e728fe1e850a
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc2516a07178624b4
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x5c309a5902c60311
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x243d1ba6afe8091f
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x51dddd1d6b94766d
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x1d518dd19073241b
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xb19b159d571999ee
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf77f5641db68ab3c
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xad0989c7d34fd746
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x78680425fe2dd455
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xfe9a1653eb736ad5
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc302f4e37d69a1d8
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x71c8ae651f14d3c5
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf3378bc66b24a5b1
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x7dcc99cb16dcd002
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xfa7dfb76e3911aa2
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x957c11ee87bcec67
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x9c0d5be7d5a8be6b
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf16ec122a3bd276b
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xddf2f188abf697fa
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x20feef4fe17e5290
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x54ced0f988b60983
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xb69767ad039b91e7
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x47c4665d780c5ec9
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x8fe1e4e767ee9843
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x20a1aaeaff7d5c0f
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc129d5f2a9c19b65
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x3d4f6e635d256148
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x6de7090ad01269d5
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xd5face72ea61fa91
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x2340d37d5627d624
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xea368e66ee9fc5f4
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xb511584d23b96387
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x994f5a60c918dab6
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xdba45d0eeffceeeb
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x68cabbd09f4747e0
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xbedea4b53a725142
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x756013ecfb5ea8c3
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc688829ada4319d6
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x0a23462728c409da
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x13d3ec0afc9a8235
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xfa8824af44eeb0c9
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x83121f4b0bb24c79
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x11a351cc35205c9d
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf767bdae6d09ef09
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf821b80054c8953c
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf6182e23c97cf92f
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xbf4fa5e7ef8f8ed4
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xfaeb7643209ba1ff
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xabcf887fe9688fb0
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc8e93aa353c93d68
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x6b4a2f61cb56d06e
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xb2f4214a7c8c0b5e
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x5f1efe5d35aa1a5d
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xbb15c33bb7ac6560
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x2702b4fcb52fa2a6
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x2320d0aae6d95d50
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x149ebd394acc4394
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf620976ad4865d10
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xe428295b40fcce03
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x6428b11b01d6f3ba
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xda476d438b35616f
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x516efee0cbec1ff3
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xcfe811cd407018b0
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x9c6fe50994769333
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x804cc474d5fa97e7
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x37d03aad308ed24e
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x953fdfc404210606
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xe5bd62e1f332b30a
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xe1b2e554ba1ac0d7
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x3334c7d36fb1e369
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc425e36674692635
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x1673aafb18060073
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xa62d8bc29ef8a257
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x15b24e7a797d0aad
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x5016bccae533d41d
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc25d6493d6a3a3b2
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xa88a84d33a052828
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x526e54d641504311
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x4fa75b6bd40667ae
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xb1741bb422d13e41
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x80bbe6ca42a90802
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x27fd57931fa33086
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf7e2bad60ac39f1b
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x3597774b25afb089
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xa844598b27f0afb6
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xcfd2e13a9a4a04be
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xb819cae25a82c606
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x863741b3a3e8789c
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xdfd17511eaf7f45d
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xa7dcbf5f6d69465c
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xfcff63cbdfed061d
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc044ccf6bd588601
  vsetvli t1, t0, e8, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x2736fa369dcf8964
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x47e98721fb891d39
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xb613fd3ae7639e2e
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x6f3ebad0f8b17fee
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x15f900ae1cbc935f
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xfab1879ff5882e67
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xcefd453b12283982
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x522cdf05d8d44bd8
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc29ee85c5e240ee3
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x64257371e4b8b675
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x6b8362c686fce0e7
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xdb7f7895ea38f65b
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x4218591f042cbf09
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xad0642bc5ef9ba69
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xba268356ce10110c
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x90f21b78088309a1
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc19fbb3573087526
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x8fd1d9aee0d8b811
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xafab3458092c2645
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x026b213d0f37f2e5
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x9201b9b71baab3ac
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x806a9faa6be9dd99
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x19584d9dc892d419
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x705fa064d3351392
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x515e2d913af19361
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x4d57106fa2cf841d
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xd292a5d6e43d5012
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x987e315ced2ad4d5
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xd242d7e0add1e483
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x9a290b5db0aeaac9
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xe8f7241ca190183f
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x03755349806697e1
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x9846123a7f529062
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x846d32df6968cae5
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xcf76049f5c65072e
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x9ae650e5053aa468
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x32aeacd7bbcf8a67
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x8503bed3963b5490
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc4a019b2b4241e25
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xdcf2e6a07a26364a
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xa8532127d6fc145a
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x71c87b6a546cf259
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x199718edabe32f97
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xd7f57121d4ac9de9
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x4703474523563836
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x8fc210229b77e1a5
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x867c050093557a1b
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x5f1e604940edf2f9
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x56018ee7ec6703fa
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xbd1d4b806ddf2d86
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x6cf7d90985f5c83d
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xe06af160212e02c6
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xa4d658d5747b5229
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x86b8b00b000e7dc3
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x41a799f240280bb3
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x08dc924ad6aaaac5
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x14514f59d97146e1
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xca58e86a464d72dd
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x656ccecdf230dc0e
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xf8293253694a6ce7
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x98cd2aa7efda189c
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x3b0971ccd3bbe5e3
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xf240600cbf87e651
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x5f4b9cd8e5cf167c
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x191565e2a6984fea
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x91e2cf8ce9ba95b9
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x48eac417b58bdf3b
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xbae247ab95e631bf
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x953aa4965ec8a7c4
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc4bb858d22f936c1
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xf40747e78483f295
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x54b9fbbe19dcd01c
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x0d42147c9ed2c0fe
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x9159baaa10edfb2e
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xa04cb57cc72d4764
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x9e3b2f305f729cef
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x6c6c74a48f8cf757
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x689a7c1defc0c85b
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x07327605bccb2ed5
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xa985b7505362fc7d
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xfcfef6366580bc14
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x419fefafbf8d5271
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xdc19539dd78b6d07
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc629be31b9e0bb5f
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xe8a2ee8e4f08064f
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x5734e2178d9d00a4
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc7320215ee3893cc
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x5d94871ddcbc1c3b
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xeb7f023472a640a9
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x4fde9842bc8e188c
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xac249236c705225f
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x935ab378a2e05024
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xb2543d2854af943f
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x5b5ea529af66fe98
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x4114d61d7e02e87d
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xada571bbec61e3a1
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x5401209a5ccc33cb
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x6434a590928fbb36
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc0083a2227fe7a48
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x68760037c98a5aa1
  vsetvli t1, t0, e8, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xcf20051c68a2146c
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xb09283dcc9305c39
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x7c888a963f3edec3
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xaef7bfa41d5e6f20
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x4d1cf2a96f3f639b
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xea60c5eeb6ed79f0
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xffaaa6dfb9571661
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xc06bf0028489b000
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x5b38938387abc934
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xa77183a8a1a46442
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xdff17e79dd921565
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x68b5580c610dd785
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xa4a8b80f45ae6580
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xcbc0a91c3fc23a54
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x86eae35ed25568cd
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x4e642e99544e8ab1
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x838622a4b201b78f
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xdacc64bef2effe0b
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x50d1322b74befc3f
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x16f6e86ec07195c1
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x97fd441e6b0f64db
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x1b9756aa4213eb95
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x71fc9f321419f3e5
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xbedafcdcfe9a8a22
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x31637603baf8df90
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x842d611d9f83467f
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x9822a4c5cff7a779
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x710a6ae779e55ea1
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x80688d1b062aee00
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xdfe4d3a94d41b767
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x298bfd1e318ef753
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x5f993a274a62ce96
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x66c1376b765c7268
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x02fdacada88c6a9d
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x45364d35caa1e864
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x5aa60748a0c25edc
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xe09e91ccfed69a6f
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x6d83985956fe3079
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x79faba913da92f1c
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xdd15f269e27bed71
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xc1b13a2611de8924
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x2671d94ae26911b7
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xa46c3d3c7b5d2016
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x8dcb5536a9d4063a
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x48014804b759d29a
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x88ed3cdc41d76119
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xac72fb93d472aeb3
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xab2640b296a58260
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x350f72673ca97f78
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xf60ab64f5c9101c9
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xafc9a9873f68bc52
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x78f3582d3cb4b897
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xbbf2744d6febba99
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x944de9bc31d096f5
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xf512e221a4aa6170
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xf4453abe706b083d
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x35f02f911139fcd4
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xb7501e06c3c3c28b
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x60ab1b80a32562b8
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x53d305adb8bbceb8
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x307ef152155817b9
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xf48471dc4c9e4c1c
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x1e38d29c61159576
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x828aec85b2e67c2a
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x4b603a9f659f5305
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x5f46aec80e757f38
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x2337ba96093fac69
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x2a528fdc18c8b4b8
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x52b02fcfdd4c0754
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x1fb77b9f0333adb0
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xe5196e71aa3a4308
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x48c5a6e8cda575f1
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xfd8e9c795c42c80e
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xc5f480f6dd07032b
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x8f73fcff01c53166
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x653edce677f8f72a
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x23063073bda8724f
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x5e9857db62468213
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x615f98a20ec4051c
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x68ecebc3d5e17870
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x889f4bfa8bbe091f
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xaaf62b3783b48849
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xae5c673335393fd0
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x88a7af18dc4a90ef
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x0ce5897aefd23e14
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xe237cc5e9a06de98
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x61d205e3e7b782cf
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xcbb493ef1f6c38d6
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x91795fa5fbb81a39
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x10e825da6d535561
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xda8a7dc94c91f9ae
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x4361fffeb4fbfc1f
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xfb517cffed3d31d6
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xca51b61be8825ef1
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xaf62c0e1814ed475
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x7abb0eaa0120068d
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x13af4711d79a4982
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x499a3840591c64de
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x95a767f281597a29
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x27dfffb3969089c4
  vsetvli t1, t0, e8, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x27680f284f700c92
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc6bf4046d121e11d
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xbbbc73b9d25814d2
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc69f17da7571b73b
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x08b744173ad7b472
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x04fac0406748e9eb
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x1fd9b50a14ba7ec6
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x00814a7284b44674
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x28d373c4eb8c07c3
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xda33d7603f386320
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x30d3ad942d0debb9
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x5097f98c74d36043
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x7f087ce522f2df66
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf165c2614ae45930
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xff0105202c01eed6
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x503540d45ab2222e
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xfbd34fe1bb936236
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x78e2d3474195c19f
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x74e41f3e91dcbeea
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x23dfeda19d2b8154
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xfb0c3b3e3f6af91a
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xef3f42692a7a4bd5
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x77616a92000eeace
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x6837bbbd2880b380
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xd39281dd963556bd
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x5a3450055e856132
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x4a4f7181cf16efeb
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x2096635a53cffd28
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x931482d8472b18be
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xffdb00554931c363
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x617af47ea3b254e6
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x7d9936e0d9513efe
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x18c5bf2f7a542d4c
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc3e72f9c389fcdd5
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x59e141afc1fe123c
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf4672a84f5dd94f9
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xa13436cd66160aaf
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x8ec2051cdc6fd86f
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x48b71a896fe82a3d
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x93f3ce4b88262eb5
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x08bd9ae952866a8b
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x4984c39bf92f5087
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x42035ab879429a4a
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x9d01e8f517dbcd33
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x3d6600cfea77865b
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x56f6e54e86de8329
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x375c724d71c226df
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf81e33675e009bd3
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x446906d77e9cd9fb
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf3b9858791e6a0e1
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x7cca643c7127425c
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xaaf3d7abb66ec095
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf6d57913d44a1792
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xccbf983bd6adb8aa
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xe1a30868df07813b
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x9a078c502f3f89fe
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x6feec99eca0cf379
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x71fce102ec0ff97e
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x533817f425e6c9bb
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xe22c9cff9259212c
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xe0fd442c7a94e004
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x998e5bc601af7cc0
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x92123e6eccb209cd
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x0c5be5b99a5f1ac7
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x2f83b79b58a60e4d
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x8df2c109a69828f1
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x4b1503b7d3ae2499
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xdf49aa35c45864eb
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x218fd493c902a5d9
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xd31498550e888b90
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x41ff2a7fd8b9348b
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x72543e47930c6b90
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x17f0473e95c78e73
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x3686b9e4da829eb0
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc6cb86a6c160fea4
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xcec4eae81afb43ef
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xeaa4fdc8bf23bb03
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x5d30abb5c73263f0
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xe75796eef4aa09cf
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xcff8cb2547ab9e37
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x458f3e91a3697b48
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x07fd572fa7ea1fa1
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x322a6b8354e33695
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf1b5a35347031be0
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf052907ef6935870
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x6d8d7e101d7c2864
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x667db28e603522eb
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x5334f4e90901b7c2
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xedd785b34cc4e358
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc573df8998becef5
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf9df2cfa04bcd7bb
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xa11714a37d632c46
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xa270772da30774e2
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xededb772fdf5f86c
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xad6327cbe17548d3
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc0e3f0fb94ad3e0e
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xae28b57a20b0902e
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc63fd58840992b63
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xcf9cbeef66a37c95
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x0f17fdab132929c6
  vsetvli t1, t0, e16, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x3b51d966ef7fcf60
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xe2e1bd391a3dbe9a
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xccf09f90fe89bef5
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xbb270cfc28af5d63
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x711f9d7fa4b995fe
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xdd5c9d72fcb2286b
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x935930354f42c90a
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x4a8f638c833e63e3
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x7b4da801ebd03ce1
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xbc3fccb2c8e04609
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x838b61ae520f2f93
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x0f89661f29dcae5d
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x9f13cd101684d2de
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x54ca8b64e15529c9
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xb596c66d95bbb50d
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x98322f86315dd198
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x451128d0257fbb55
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x21af2c243dea5092
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xa93175b394db38d8
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x3f3d4efc8bb1ec47
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x907c3f414b36ebf2
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xde1981eb0228ab5d
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x4d0b8145e4b465ab
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xb5d22da965f0f902
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xab35209bc28be89f
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xd0a6afdc5d0a146e
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xe4449245480fbc85
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x00f7f4cbee20651d
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xad113781d923b39f
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x3d87e2b0d8d26079
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xfc26bc901f1f281d
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x91b1170451ed47f7
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xe08e8e438bd0ffe0
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x6f4a48f0565f84f1
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xdcdfcf86fa0f68f2
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xf1961a7ea43370a0
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xb6acd688a43381a3
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x028ac0ac6323f805
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x57f5ea2c8166a038
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x5bc7347c31f7878d
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x0f1ca7ff5d774439
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xf00a635e9b9d75d1
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xdd0178445f1f1c74
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x5fee4dca345138fb
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x07343efe7188ccc0
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xbeded0aad1040fe0
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x8afde5b2340dc468
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x902e063418d1f016
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x889e1fcfb77a0002
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xa563815951680899
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x1f0e4ccc59f78a9e
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x21662ae38387e854
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc36e276cadb57934
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x60a03f578266cdca
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x061f250db37d01c5
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xce1414130bd79d82
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x38bb8aa434c96cca
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x268ec8d22fed941d
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xf0dc07645cf6ffe3
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc4b8a6c84370e920
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xd844cabf65dd21aa
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x874c2816b23463e8
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xdb8fe74418e416b2
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x6b732017fd56e326
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x626b5dfc54fe46b8
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x12e14d0f91b9a28c
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xa7f432e567a17885
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x4e360040f7a6c6c6
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xbdbe5cff3cdd8221
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x8343045c7ea43823
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x53e716a4c12a54ed
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xe726e3777207f2d6
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x9762db6cc56e7d6d
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x1b0517b190e20782
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x83335243f21d4152
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x9b3c76ee954a6d95
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x4562cb0f1eccd53f
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x3f85deffbe3fd78f
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xa257a638a1842200
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc60e1e9c34de0eaa
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x19edfe2d1eb4b198
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x31fe490fed6e70c3
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x1ec15a4c77185d47
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x006be390cec0f9c9
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x30533993ff5e82e7
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xb343203d74e654d0
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xf2ba8db1519adf29
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x2ee0cd00774af4ab
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x2c74c03b95c2174b
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x4c77003a4599a715
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x7555f19cf9dea295
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x6929f8855d3262b0
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x55f77795b075b935
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x36418ba4be41e5b3
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x4f66f29ea7675692
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc59f9ff1678db45d
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x6a80f4cfb2f95283
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xe25dc5f68515424b
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xd2ab2caba9fdfb6c
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xae0b38dd8fb44a1e
  vsetvli t1, t0, e16, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x1b4efe171318e933
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xb462ee0f33619855
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x37220a1defcdcea0
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x69b453d0e9e036f6
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x481868569397a9b9
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xae8d8c73f992464a
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x2a48d6da28f32a17
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x614cd282511680ed
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x0c6747dce8d50154
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x2e3a362596871e77
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x1fbcc9f0e74f166b
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xfe567f6e6205d736
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x4fc190f2e3374def
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x9da0a999057b9247
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x5f4c076b0d327324
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x6d4e102aa3ad1edc
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x597546b1afb2f95d
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x812fec190dac17de
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xa8c9db92a81b51df
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x2068f980ee2ff278
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x502b73ef77bcfca7
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x101ca0a3467dbe9e
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xf93907a9f4e058dd
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x17838ee47d2982b2
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x661a96f9a1d56066
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x2415f22f89772b03
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x2e7c3823720aaf65
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xd64d153c91088db2
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x7bfc1016dc44a33f
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x2d9ac0a8580cef34
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x7d9a48e945ea746b
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xcc23dfff4f78e6ec
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xd73ea6fa550b1461
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x155a9e1885a9df84
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x865113118bf6e489
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x9043a76f442361ac
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xcaba39ca1e671660
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x94e40c39c309524b
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xa3d5f41caa3d9485
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xdf882b8bf77b88b7
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x4291bc5854fede6b
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x933b8855c0814d9e
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x16b5475661c30c59
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xbafe14cbfdfb08c5
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x3e99d7627a8fb140
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xcfbd8ce56339c85f
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x731cb4857482937a
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xda6d0b7acee1628e
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x02328324b56946a1
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x3d7ec547dde4d9f6
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x361893d5529f8007
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x0ce3a03e724dfadd
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x60898fd2fec52460
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xf3a84b5945b4fedb
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x72e374509398fa2c
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xc1026c4c662f9815
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x60ece36d9d549e00
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x54410a99cdc0a91d
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x9286178042b00cda
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xeaf68c7374190890
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xae0a6de4060da25e
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x4ec50ec848abed86
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xa8df6b01a701a547
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xa16e10cd50b62673
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x14fb666e8427c0ff
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x30015fa52e443c90
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x9701dbb64396d015
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x79c8ac8dfed99caa
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x2239dc458b14fd02
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x71ec983526c0d641
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x3c24d527149362dd
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xdfc5ca196538f588
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x515ce8272ea0d967
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xbeee3cdb4c290740
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x448595b79bafd608
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x08a268b55cc2eb43
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x762e1fb68f53fe44
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xeeb0a25b04090567
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xbdcc1dde9dd5449a
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xa73313df64cfdd49
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x9dbca206bf28ebac
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x3f792d11c1d5056f
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x02723e31ca124938
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xce89da49247cf775
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xbd707ff0e8559871
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x2bc21d9cc04de459
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x6c5fcbcbebc36c98
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x775184517c666757
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xafc7c687600e7c64
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xa9eeef4c98d2cc85
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x0acb3a3daa239082
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xce66d94834d960b9
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xfeef7f14d2b35f8b
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x9e3c97720a7b01ec
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x336941c4d2513ec7
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x9719fe1962ae44e2
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x141abce897715a45
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xb9183f14668206b3
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x6e9047bbb131aff9
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x564e3437a52dc41e
  vsetvli t1, t0, e16, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xcf9420dd80eb82b7
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x883d801316482ada
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xd7b04abe963f5c23
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x1e43c62425f4f9fd
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x0d617b53ad77e0bc
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x5713a42782fd75b2
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x20587f8028d54109
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x62b117d3c0af1716
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x27f0825c69c5ebc4
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x44b93402f09a6eae
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x8131affae6f91c33
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x1da1052a56d0ea82
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xbfde67aa34865207
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xcd914b7dd0c00ce7
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x0a107975b97c7d06
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x4fcd3e98535c60af
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xc7e29955fdd5a138
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xaf7d9c4c77f19c27
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x47c9d1b292494c29
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x6731b082dd3b02dd
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xcece2119bd9a1713
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xa6959fe3c16583f9
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xeedd287295662edb
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xfdd8d7283bce12f3
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x26fe025a033771fc
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x969750bd6361f5a8
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x4dd6c65d90306afe
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xd1ac13bfc41f818b
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xa9c81b4c8d78543b
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x38de3ad5b1e3f2a8
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x6e7f7bc16b11bceb
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x7bec13bf2bc8c576
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xbb76db5d5fa0f45f
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x588e2c3544a58b04
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x5724c7821e7a8cf2
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x593cc73da918b44e
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xa277184af5ed5902
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x6d02522273f5db5e
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x4465aff94eb5e362
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x40acd53fcbb6e136
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x885a516d5471d3b9
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x539d6523a7342fa4
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x4fbe5de09a39268c
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xe51d14bdf4b8591b
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x0dfb2a1168351d32
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x381ef6c0dd6a7e63
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xd100013567b9d879
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xb36c1ea88d80ec9e
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xfdf12576e69dd711
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x42a5d3ae47e9d9cd
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xfbc225ff2d17dd73
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x332ea90e5eea57b4
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x6c5c5d1b6e32f7a2
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x0f6653a3f2179349
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x3f817aa1d0bf0a24
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x968a8f04aad093a8
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x2561013142915e60
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x6d9eeb0522488b53
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xd8263db32cd37880
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x0b86a03550cbdc0e
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x5bb855b741f3159c
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x7d13aa97d36dc3f9
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xd59bc528c9e846a0
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x3873308cbdf8a83a
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x2c3227fa34320c8f
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xb27580bc0a3f3ee3
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x3c7eb1ede7131964
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xb1dcaa3bb9ff308e
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x25ec7841aabd12f7
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xa0034125a99aea91
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xdc91976c621ef3eb
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x46c32d8027aac9bb
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x7ff844e46abc7b61
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x614b8f1e7b3bc9bb
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xde01f373dc323475
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x35a759f3aeaf1522
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x74e405b3d113359d
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x6d864d97f225451f
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xbdc2e97fbe4aedb3
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x2627a8731d118b43
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x9e5c8ce677ba2520
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x3acf56badd11830c
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x40317efdc4c5d8e4
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x25353a492c9501e9
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xdb7053d874f6120a
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x9b3047d3a47850b4
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x5d8416c776d123b2
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x6c9cb4682ccbef54
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xa23d18acd39edcad
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x0c93542bc6eb5232
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xd2132f9e7c4af6d3
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xdd60272a620c0ab7
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xa463b3627db70558
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x3c01869be5b841e3
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x3adf5ec34576f289
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xb5df73e76dba5c7a
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xf5a9b2727ecc4e29
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x6b57544ec025f754
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0x77b95db45ccfe8be
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vv v2, v4, v6

  li t2, 0xa84b81dc74ca06c7
  vsetvli t1, t0, e32, m1, ta, ma
  vwsub.vx v2, v4, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x6e87bb3dd521a7e6
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x4d8f1c4069bcc880
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x638d800c7bf3f903
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xb3124326b8a9f925
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x3967f577004ac519
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x01e94e493d9ee403
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xd31257d0ec1ec3c3
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x0d4913080bfd7100
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x1f97b96429c464a0
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc5ffda153a1aaddd
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xaf82c8e93314facb
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xb295aa69549f39a7
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x0f3ff90ad54cacbe
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x02a2dd222c684d0a
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x428c05c0442f00e2
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc2b51be8de2a3268
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xbaa67be2bb9a00a5
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x220658104c2f38d7
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xf70aac7459e234f2
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x34105fdf175c27f0
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xa663f6d24fa8e8e8
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x3ce2518212393ec0
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x7eb0d1fda617d3b1
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xb50202cebbe21004
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x96b05bc2b9f52a25
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xd75474239b5ba035
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x56cd65d20554b60b
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xef25e89f2dd6cb26
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x51ff82ad030581c6
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x85c7eb6d65af7e7f
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x6f3604a4664dcae8
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x563819f008cc5c10
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc4198454dd6eef2f
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xdabc114a7c030601
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x19f1e7eb0efe26a2
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x3e0989645420c492
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xa14dc493a10e956c
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x368cd241612b7715
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x005584e6c813940e
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x28d38a0f067c9a28
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xbc815ad69188fd0c
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x42ca52cfa46d73e2
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xfaf3b062dac88bad
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x7f52ff888c7b2c2e
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x15fdc662e277038f
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xd30a41c34c3e5f21
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x1d113f507ee7654e
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xb36f061d980a3a70
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc191654f864b9484
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xa5eb4196bbccc6f3
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x32efbad575b7678b
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x62e761b23b3a48e9
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x5bbb1cb37b2f0f3c
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x26f7f669c3849a1a
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x46809ecbd37ff2d6
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x30f2a3657fc0f016
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x77121818afc4dbca
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x22bcfbd4fc5fc93b
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x95d0965506389f69
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x1b0463155fec0c2b
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x4466ab186f7c3977
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x0d33865c922fa5f5
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x91e16164b57c6c4f
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x94314a92fb694fc1
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x18bbd7de01f0b3e1
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x866866f77a6d9cb6
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x154835a80970b661
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xebf9a18a023d2d5b
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x9ecf6a4b257d653e
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xa57b2e9f3a1aaa1a
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x6bfe71d07c6454bc
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x73d7ade605d491af
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x702c219620d23730
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xa5b8af6b6767e08f
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x642f870e70e945b5
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x0018796e341bdc48
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc674b95b6d45180b
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x360d2866b5373123
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x7d157822761337c7
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x3012b080fbc32e08
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x0a7eda1d54bcd907
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xf0d92f489dfdd7f8
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xda63db1f4194556e
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xa4e1843c59679516
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x51dca257c7d46a9c
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x551f17054d315ece
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xe6f1dc8bf909e6f1
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xec7ac487283469d2
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x81d8b85b2ae03d09
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x9ed087cd52a93d28
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x7f66a2d53fb6586e
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x4aae3b4d89fb0d2e
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc5b58e138ef1ac16
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x6f27431022775f92
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xd0795f56be016865
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xd1e3dd09d636e8ca
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xb1b0e5c6ed90fa4c
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xc6a8f84e5bd924ab
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0x5e7960ac63b948bd
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vv v4, v8, v12

  li t2, 0xbe5dca7ceb1fef9b
  vsetvli t1, t0, e32, m2, ta, ma
  vwsub.vx v4, v8, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xe96255e86b069ac9
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x0762be66e31a89db
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xbd179ce913340e25
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x83df80bd108b289f
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xe0dc125056f45f1d
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xc02f4585ab11f9e9
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xce676fe4b027be03
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x3e587e218b91ac2d
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x38302a6258c5776c
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xeba00fc77b9cfd5e
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x9d8e20ef78900ee9
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x94cd0228513f513a
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x55fb616c9746f36d
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x2a9f0341d875e617
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x92cc3d7cea58d1b0
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x3dfa2a0620b5c580
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xcabfd4a2c2789ff3
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x2696bff6187f3c32
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xbab136e756d7adad
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x6ed2e78aafd5a48f
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x9f55731261ea57ae
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xc2925bcc23cbfe7c
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xb353289e8c48a265
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x925178946ea5c5ae
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x763e041c370fe7d7
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x6b04a2f31ce4ed84
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x5d53b873e8448e62
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xebbf6435445360c6
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xc5df76979c652f70
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x7684b0dbe7171eef
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xfd8031d03836c557
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xc73978e5d1b09dbe
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x042ad97c1bb0f2d5
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xce09328500d5c1ec
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x5d29beac78b26dca
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xf10af685e3f12f01
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xf820f6e3259958a8
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xb2b56f17a49599e2
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xbaa2f5d9031f4706
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xe49fe8858ddb9cd6
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xd55e874f408ed158
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x097e81475d1b2d8c
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xd3dc4e579422401d
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xbe0af15f6dd01194
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xf6e1543b5b47f6fc
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xf38aa327c18a4983
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xdc3a284918368155
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xa1516454f0f21307
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x2126e9f9ed2da10a
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x0e5cfec85ca00078
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x1806c4f5945a7d29
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x7aa49023632f1756
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xa81f5a8ce946860e
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xeaefa7f1f569bb15
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x1572ce803e69f91e
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x03b8f241b1d403c6
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xa5ed50828b4c590e
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x7deb0b368b99239b
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x8e4020a08ffc20b6
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x703d4d71b72b1211
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xcda7ccf7a4dc386c
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x546f3f609a500d74
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xad219ac5ccae7eca
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xbf8f506df194342e
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x481f80994b56b6b8
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xa61cf35b7b236e3e
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x57993a779ec54c59
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x3a642fc5185af723
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xbd721abee0a5c47e
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xa94498dfe3466d30
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x60eb0135da04d2b0
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x06cf11b332d3c1e8
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x21fb727699e840c2
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x23d01c5b4731143d
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x3803cb17aac1b5f1
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x798b51f422253cb6
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x51de0979b166af42
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x0e93876dc61bc91d
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x802262fda645631a
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x74c830f45a7cd0aa
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xc388559c6c2a0cfe
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xb4a4632c98dd772a
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x3a3675c1c1c7bdfd
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x01cc04b50529689f
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xc19b7cdf917f9db9
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xacf97db323bd70e2
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x45ef3eeb51c82446
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x298d156fe24850cd
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x149a082cc4d62656
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x11c3a7799f6f6dc6
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x6f3f0353e1292cf3
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x29f9f322f0f9b05c
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xadd2a9341ef431d8
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0xa20e79cd5b954a1e
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x00cd3ecacadd7006
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x3a8707d75f03ebe8
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x1ba7675f8554b82d
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x8dc2c2bbf072831a
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x04824171ca9001f2
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vv v8, v16, v24

  li t2, 0x8b3afd9650d5dfcb
  vsetvli t1, t0, e32, m4, ta, ma
  vwsub.vx v8, v16, t2

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
