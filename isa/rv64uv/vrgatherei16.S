#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v18, v26, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v4, v24, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v28, v22, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v10, v22, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v20, v28, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v24, v30, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v22, v30, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v22, v24, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v12, v16, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v30, v12, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v8, v26, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v10, v14, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v30, v26, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v20, v28, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v30, v12, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v16, v26, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v2, v28, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v26, v2, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v12, v10, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v26, v24, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v26, v30, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v22, v2, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v20, v26, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v2, v12, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v2, v18, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v12, v30, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v30, v28, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v22, v18, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v8, v18, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v6, v20, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v6, v12, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v14, v16, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v16, v30, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v8, v26, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v4, v16, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v30, v24, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v18, v20, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v2, v6, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v18, v24, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v2, v14, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v6, v8, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v14, v10, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v24, v22, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v14, v20, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v24, v20, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v14, v22, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v24, v6, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v24, v16, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v2, v26, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v16, v8, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v24, v16, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v18, v14, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v22, v18, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v12, v24, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v10, v28, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v26, v4, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v10, v2, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v16, v6, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v4, v24, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v28, v16, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v18, v12, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v6, v20, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v10, v12, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v2, v6, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v2, v10, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v12, v8, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v26, v14, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v8, v6, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v28, v22, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v8, v20, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v28, v30, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v20, v4, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v12, v28, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v24, v14, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v24, v30, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v4, v6, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v22, v20, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v22, v14, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v22, v10, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v20, v14, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v4, v8, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v4, v2, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v24, v14, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v2, v4, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v16, v4, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v2, v30, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v8, v18, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v4, v2, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v18, v24, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v6, v12, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v22, v4, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v16, v18, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v28, v14, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v6, v26, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v10, v4, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v30, v2, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v22, v12, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v22, v18, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v30, v4, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vrgatherei16.vv v22, v16, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v2, v28, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v20, v2, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v20, v6, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v2, v16, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v8, v16, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v8, v20, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v10, v18, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v22, v10, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v12, v2, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v26, v4, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v24, v12, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v8, v28, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v26, v10, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v18, v20, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v12, v30, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v4, v2, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v18, v8, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v30, v10, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v14, v4, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v2, v26, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v24, v20, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v18, v2, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v8, v10, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v18, v8, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v16, v8, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v16, v8, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v14, v16, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v12, v2, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v30, v14, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v16, v4, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v2, v8, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v6, v14, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v14, v2, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v4, v6, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v6, v26, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v26, v22, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v20, v18, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v20, v8, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v16, v6, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v30, v26, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v4, v20, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v10, v8, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v20, v14, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v10, v14, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v14, v10, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v12, v18, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v26, v2, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v10, v24, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v8, v20, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v4, v28, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v8, v14, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v12, v24, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v18, v30, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v20, v26, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v20, v6, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v4, v24, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v24, v10, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v22, v24, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v12, v16, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v4, v20, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v6, v28, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v10, v4, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v24, v14, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v28, v30, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v12, v16, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v12, v30, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v30, v16, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v12, v16, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v30, v2, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v30, v22, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v28, v20, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v16, v20, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v28, v18, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v22, v26, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v20, v2, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v26, v22, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v22, v28, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v10, v6, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v2, v20, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v28, v22, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v12, v10, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v26, v10, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v28, v2, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v10, v8, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v26, v8, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v10, v18, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v14, v12, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v28, v6, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v14, v26, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v12, v30, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v30, v16, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v4, v24, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v6, v12, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v8, v6, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v12, v14, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v22, v10, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v10, v24, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v4, v6, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v28, v22, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vrgatherei16.vv v8, v26, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v24, v30, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v4, v28, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v6, v28, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v2, v6, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v20, v12, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v6, v20, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v10, v26, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v16, v12, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v22, v16, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v6, v20, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v30, v10, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v30, v8, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v2, v28, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v16, v8, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v30, v24, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v28, v14, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v28, v12, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v18, v14, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v16, v30, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v18, v14, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v30, v20, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v8, v14, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v10, v4, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v24, v8, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v26, v28, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v2, v12, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v20, v4, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v20, v24, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v14, v4, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v26, v28, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v20, v28, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v12, v2, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v12, v20, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v28, v16, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v4, v22, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v20, v14, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v4, v6, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v20, v16, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v26, v20, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v12, v22, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v18, v8, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v4, v8, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v12, v26, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v26, v24, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v8, v4, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v6, v18, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v2, v16, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v6, v24, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v10, v26, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v22, v8, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v24, v2, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v20, v12, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v14, v16, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v20, v28, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v12, v28, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v24, v26, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v28, v20, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v22, v20, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v4, v2, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v28, v4, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v20, v8, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v18, v16, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v20, v22, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v8, v26, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v14, v10, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v8, v20, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v10, v24, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v22, v10, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v30, v2, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v16, v14, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v26, v24, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v8, v24, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v16, v12, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v6, v24, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v24, v10, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v16, v24, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v20, v18, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v12, v14, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v18, v8, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v8, v26, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v12, v14, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v14, v12, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v12, v30, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v26, v12, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v24, v22, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v26, v16, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v30, v2, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v2, v24, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v4, v24, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v6, v22, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v26, v2, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v24, v22, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v26, v22, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v6, v24, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v20, v2, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v24, v22, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v26, v28, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v8, v2, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v6, v8, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vrgatherei16.vv v26, v4, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v22, v14, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v30, v16, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v30, v14, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v28, v4, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v22, v14, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v14, v30, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v12, v20, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v16, v26, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v14, v22, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v14, v4, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v12, v28, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v2, v20, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v24, v28, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v4, v28, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v16, v26, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v28, v6, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v26, v4, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v24, v2, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v10, v24, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v26, v12, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v28, v12, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v6, v12, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v28, v14, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v14, v4, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v26, v8, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v16, v20, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v28, v30, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v2, v8, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v12, v20, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v12, v16, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v28, v22, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v22, v26, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v26, v16, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v20, v12, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v20, v26, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v10, v2, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v18, v12, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v8, v26, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v4, v18, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v8, v30, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v10, v30, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v26, v14, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v28, v14, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v24, v26, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v24, v4, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v8, v14, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v22, v20, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v16, v2, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v20, v24, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v26, v14, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v6, v16, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v2, v8, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v20, v14, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v18, v28, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v22, v2, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v6, v22, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v20, v24, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v26, v4, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v8, v6, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v30, v8, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v16, v10, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v10, v4, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v10, v4, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v4, v18, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v24, v18, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v26, v14, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v20, v30, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v22, v16, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v6, v20, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v18, v26, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v30, v4, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v16, v6, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v10, v4, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v20, v14, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v16, v4, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v24, v2, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v8, v16, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v16, v10, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v12, v18, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v4, v8, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v26, v10, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v26, v12, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v30, v14, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v12, v28, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v24, v4, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v12, v8, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v30, v22, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v22, v12, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v8, v2, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v28, v6, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v10, v4, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v6, v24, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v26, v22, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v26, v18, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v22, v2, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v6, v12, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v16, v12, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v4, v28, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v14, v20, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vrgatherei16.vv v26, v16, v10

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
