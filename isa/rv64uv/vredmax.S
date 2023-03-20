#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v28, v16, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v4, v13, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v3, v18, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v5, v16, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v2, v26, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v20, v9, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v20, v16, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v9, v30, v31

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v22, v4, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v20, v13, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v8, v16, v7

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v4, v25, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v25, v29, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v2, v8, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v20, v26, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v17, v16, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v3, v27, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v19, v9, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v29, v31, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v22, v10, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v14, v2, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v30, v16, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v1, v7, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v30, v31, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v18, v27, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v2, v20, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v11, v14, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v15, v29, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v24, v21, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v12, v13, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v2, v26, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v10, v3, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v21, v12, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v26, v6, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v5, v13, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v7, v11, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v10, v28, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v20, v18, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v6, v8, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v1, v9, v31

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v7, v4, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v16, v26, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v21, v20, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v6, v31, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v4, v29, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v23, v3, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v13, v31, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v28, v21, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v11, v4, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v6, v30, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v8, v18, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v24, v21, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v20, v7, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v14, v13, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v12, v10, v7

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v1, v5, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v14, v26, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v17, v21, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v22, v20, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v15, v13, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v17, v15, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v5, v31, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v10, v12, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v8, v26, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v17, v14, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v16, v13, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v30, v24, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v3, v7, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v6, v29, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v16, v27, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v24, v26, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v24, v28, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v12, v22, v7

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v29, v8, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v2, v12, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v10, v29, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v11, v6, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v19, v13, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v29, v4, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v26, v24, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v26, v2, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v20, v27, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v8, v27, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v8, v24, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v22, v18, v31

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v25, v26, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v3, v20, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v15, v17, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v13, v19, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v5, v14, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v1, v9, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v23, v22, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v7, v6, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v28, v5, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v15, v8, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v24, v29, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v9, v16, v14

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v23, v17, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v7, v4, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vredmax.vs v4, v2, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v6, v26, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v30, v28, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v18, v8, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v14, v20, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v30, v18, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v8, v16, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v10, v16, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v28, v20, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v10, v22, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v24, v6, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v8, v4, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v4, v6, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v16, v22, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v24, v30, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v30, v10, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v26, v6, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v12, v14, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v30, v22, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v14, v6, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v8, v24, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v24, v26, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v2, v4, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v10, v4, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v28, v10, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v22, v6, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v2, v8, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v22, v24, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v10, v12, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v12, v4, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v30, v8, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v10, v26, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v4, v6, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v24, v26, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v30, v6, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v14, v30, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v28, v18, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v18, v4, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v20, v2, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v22, v12, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v4, v30, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v10, v12, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v30, v4, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v30, v8, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v18, v14, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v4, v12, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v8, v18, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v24, v6, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v8, v10, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v14, v22, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v8, v24, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v10, v12, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v18, v14, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v4, v26, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v20, v10, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v8, v12, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v14, v2, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v18, v2, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v4, v8, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v18, v6, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v22, v8, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v6, v28, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v4, v8, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v8, v18, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v18, v2, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v30, v26, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v26, v2, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v24, v2, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v28, v4, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v24, v4, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v8, v2, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v28, v4, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v14, v6, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v20, v12, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v2, v4, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v4, v20, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v12, v8, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v8, v14, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v10, v26, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v14, v26, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v2, v24, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v10, v4, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v10, v24, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v30, v24, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v20, v4, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v8, v10, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v4, v16, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v24, v26, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v2, v16, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v28, v10, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v10, v20, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v30, v18, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v30, v20, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v12, v4, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v10, v28, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v10, v18, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v2, v4, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v20, v26, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v14, v8, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v30, v8, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredmax.vs v20, v18, v10

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v28, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v12, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v28, v8, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v28, v16, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v12, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v12, v16, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v16, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v28, v24, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v28, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v4, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v12, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v16, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v8, v20, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v4, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v4, v20, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v16, v20, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v12, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v20, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v20, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v20, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v28, v24, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v8, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v8, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v8, v24, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v12, v16, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v4, v24, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v20, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v4, v12, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v8, v4, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v16, v12, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v4, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v28, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v4, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v4, v8, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v4, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v4, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v16, v28, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v8, v4, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v4, v8, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v8, v24, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v16, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v16, v4, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v28, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v28, v24, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v12, v28, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v8, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v4, v8, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v16, v12, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v16, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v16, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v16, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v4, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v12, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v4, v24, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v8, v28, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v12, v28, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v28, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v4, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v8, v12, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v12, v24, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v4, v28, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v12, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v12, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v8, v4, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v8, v12, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v12, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v12, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v16, v24, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v12, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v12, v28, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v28, v8, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v12, v4, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v16, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v16, v12, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v12, v24, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v16, v12, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v28, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v4, v12, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v8, v12, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v28, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v4, v20, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v8, v16, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v12, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v8, v4, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v12, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v4, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v12, v4, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v12, v24, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v24, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v12, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v20, v4, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v12, v20, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredmax.vs v4, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v8, v29, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v24, v1, v29

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v3, v5, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v23, v5, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v16, v30, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v24, v2, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v4, v30, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v23, v7, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v1, v12, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v19, v22, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v7, v3, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v7, v11, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v21, v6, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v25, v2, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v9, v17, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v11, v14, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v24, v16, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v28, v6, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v6, v19, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v7, v27, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v30, v28, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v12, v16, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v14, v18, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v12, v3, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v23, v14, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v11, v20, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v23, v3, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v23, v18, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v11, v28, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v25, v4, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v28, v3, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v26, v11, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v3, v28, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v23, v24, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v29, v31, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v13, v19, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v27, v30, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v29, v27, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v24, v19, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v5, v16, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v29, v15, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v23, v13, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v3, v10, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v15, v7, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v19, v4, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v7, v28, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v1, v25, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v11, v2, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v13, v10, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v28, v24, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v1, v9, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v3, v19, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v5, v31, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v4, v29, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v7, v18, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v6, v25, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v18, v29, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v19, v8, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v17, v19, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v3, v13, v9

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v6, v30, v9

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v21, v16, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v23, v1, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v26, v31, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v25, v20, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v6, v13, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v14, v28, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v10, v27, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v18, v21, v29

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v13, v10, v9

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v5, v8, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v4, v3, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v15, v23, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v21, v17, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v28, v13, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v29, v25, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v25, v23, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v28, v6, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v14, v22, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v5, v7, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v6, v5, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v4, v27, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v21, v4, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v29, v28, v27

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v24, v15, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v4, v16, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v5, v15, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v11, v23, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v9, v30, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v17, v18, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v31, v20, v27

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v18, v8, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v1, v10, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v28, v4, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v12, v24, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v30, v5, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v17, v8, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v11, v16, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v8, v31, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vredmax.vs v1, v14, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v16, v4, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v24, v14, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v22, v24, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v22, v18, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v30, v22, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v10, v26, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v22, v6, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v8, v22, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v24, v22, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v24, v14, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v26, v30, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v2, v26, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v28, v20, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v24, v28, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v12, v4, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v10, v4, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v2, v22, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v10, v6, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v10, v30, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v14, v26, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v28, v16, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v14, v26, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v28, v30, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v22, v16, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v8, v22, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v30, v16, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v28, v30, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v30, v10, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v22, v6, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v26, v22, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v26, v20, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v26, v6, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v24, v4, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v12, v4, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v22, v12, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v26, v24, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v24, v4, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v16, v8, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v14, v22, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v16, v4, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v18, v4, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v10, v28, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v22, v2, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v20, v6, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v14, v20, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v24, v6, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v14, v30, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v28, v16, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v28, v30, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v30, v22, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v20, v6, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v30, v2, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v14, v26, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v20, v16, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v16, v10, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v2, v28, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v10, v12, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v14, v18, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v30, v4, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v14, v6, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v22, v26, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v16, v2, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v12, v6, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v26, v18, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v10, v24, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v18, v14, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v28, v8, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v6, v8, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v6, v22, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v4, v22, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v30, v14, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v28, v30, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v28, v26, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v26, v30, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v20, v12, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v28, v14, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v22, v2, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v4, v20, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v30, v4, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v30, v24, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v6, v26, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v6, v30, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v26, v4, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v26, v24, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v18, v26, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v26, v22, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v18, v12, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v6, v4, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v6, v10, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v30, v12, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v26, v14, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v22, v30, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v22, v12, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v10, v6, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v28, v24, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v12, v28, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v10, v26, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v8, v4, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v4, v8, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vredmax.vs v14, v28, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v28, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v4, v28, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v8, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v4, v8, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v24, v20, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v20, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v20, v12, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v20, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v20, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v20, v12, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v28, v8, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v20, v4, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v4, v8, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v4, v20, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v28, v24, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v20, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v8, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v24, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v8, v12, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v8, v20, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v28, v12, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v24, v16, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v28, v12, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v20, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v8, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v28, v12, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v8, v20, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v28, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v24, v12, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v8, v24, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v16, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v28, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v28, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v28, v12, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v28, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v28, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v28, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v8, v16, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v20, v8, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v28, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v8, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v28, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v8, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v24, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v12, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v8, v28, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v20, v12, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v8, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v28, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v8, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v28, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v8, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v8, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v24, v16, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v4, v16, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v24, v12, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v8, v16, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v24, v12, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v20, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v4, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v28, v24, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v4, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v20, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v20, v8, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v8, v20, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v24, v28, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v8, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v8, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v24, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v4, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v20, v12, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v4, v20, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v8, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v4, v28, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v24, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v24, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v4, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v24, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v20, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v4, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v24, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v4, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v24, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v20, v8, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v12, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v16, v20, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v12, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v24, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredmax.vs v8, v28, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v25, v13, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v17, v6, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v21, v10, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v27, v16, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v8, v19, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v17, v9, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v8, v20, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v21, v12, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v11, v6, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v17, v22, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v3, v30, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v25, v10, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v24, v5, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v3, v10, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v27, v13, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v27, v11, v17

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v7, v22, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v30, v15, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v26, v16, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v23, v24, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v2, v14, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v14, v15, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v19, v12, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v19, v7, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v26, v13, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v27, v11, v5

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v29, v13, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v6, v11, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v18, v24, v25

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v26, v12, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v2, v4, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v15, v16, v17

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v20, v7, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v8, v9, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v1, v20, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v3, v12, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v6, v27, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v15, v3, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v6, v3, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v11, v1, v5

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v25, v2, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v27, v11, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v29, v28, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v29, v19, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v3, v6, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v17, v23, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v1, v28, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v31, v30, v17

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v13, v23, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v26, v29, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v5, v21, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v2, v16, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v24, v18, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v29, v22, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v22, v31, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v17, v19, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v13, v6, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v23, v12, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v2, v8, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v18, v20, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v8, v1, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v6, v15, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v26, v6, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v26, v11, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v12, v23, v31

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v8, v24, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v29, v10, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v26, v5, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v14, v12, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v13, v11, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v22, v2, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v8, v13, v17

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v24, v16, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v1, v18, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v19, v18, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v16, v21, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v23, v30, v31

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v13, v6, v5

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v20, v28, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v1, v22, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v28, v2, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v5, v4, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v1, v11, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v10, v1, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v27, v3, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v29, v13, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v26, v27, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v1, v3, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v23, v18, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v26, v7, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v14, v8, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v29, v20, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v23, v12, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v7, v26, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v31, v25, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v9, v25, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v12, v8, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v24, v9, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v5, v26, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vredmax.vs v26, v20, v25

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v14, v24, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v24, v28, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v24, v10, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v10, v22, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v30, v8, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v6, v10, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v8, v24, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v16, v26, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v22, v8, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v18, v22, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v10, v6, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v2, v18, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v4, v12, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v30, v14, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v8, v16, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v26, v14, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v14, v4, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v8, v30, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v10, v20, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v28, v20, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v28, v6, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v2, v10, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v6, v24, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v6, v4, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v22, v20, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v20, v24, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v4, v14, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v24, v22, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v24, v14, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v16, v26, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v26, v12, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v26, v2, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v4, v18, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v18, v22, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v8, v14, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v12, v20, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v14, v12, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v2, v28, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v2, v6, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v20, v30, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v6, v24, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v30, v8, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v28, v24, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v20, v10, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v28, v14, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v4, v6, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v14, v2, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v12, v16, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v8, v12, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v12, v24, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v10, v12, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v30, v12, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v22, v24, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v18, v12, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v30, v10, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v24, v2, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v22, v10, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v22, v24, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v22, v14, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v2, v20, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v24, v20, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v2, v12, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v4, v12, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v28, v30, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v8, v14, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v8, v20, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v2, v30, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v6, v28, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v8, v10, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v30, v22, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v2, v4, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v30, v26, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v30, v8, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v26, v4, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v26, v24, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v30, v28, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v16, v20, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v30, v20, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v20, v24, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v10, v16, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v10, v2, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v2, v22, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v8, v18, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v16, v22, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v28, v18, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v6, v8, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v20, v4, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v28, v6, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v30, v4, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v4, v16, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v4, v12, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v6, v22, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v30, v4, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v26, v8, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v28, v26, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v28, v22, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v12, v20, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v6, v2, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v30, v8, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vredmax.vs v26, v24, v30

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v24, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v20, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v12, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v4, v12, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v4, v28, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v16, v24, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v24, v4, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v20, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v20, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v4, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v24, v4, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v28, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v4, v12, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v16, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v16, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v20, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v20, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v4, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v16, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v20, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v4, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v8, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v16, v8, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v28, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v16, v20, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v24, v4, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v4, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v20, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v4, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v20, v12, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v12, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v12, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v20, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v28, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v24, v28, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v20, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v24, v20, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v20, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v20, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v24, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v16, v24, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v24, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v4, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v4, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v20, v4, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v16, v12, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v24, v16, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v24, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v20, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v4, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v16, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v20, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v20, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v16, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v4, v20, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v20, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v24, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v4, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v28, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v16, v12, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v24, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v20, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v24, v8, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v20, v28, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v20, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v20, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v20, v24, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v16, v12, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v16, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v4, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v20, v24, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v8, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v24, v12, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v8, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v4, v28, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v16, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v24, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v16, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v24, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v4, v28, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v28, v24, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredmax.vs v12, v24, v4

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v8, v13, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v17, v31, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v28, v12, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v26, v27, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v18, v24, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v18, v15, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v10, v8, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v21, v28, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v23, v15, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v29, v20, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v4, v5, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v6, v14, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v22, v18, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v23, v12, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v25, v17, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v8, v28, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v25, v31, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v25, v21, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v23, v9, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v7, v15, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v11, v6, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v21, v14, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v1, v3, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v4, v22, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v15, v29, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v3, v25, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v30, v29, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v1, v4, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v27, v13, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v16, v11, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v8, v2, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v31, v18, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v13, v24, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v11, v5, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v12, v30, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v24, v25, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v7, v18, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v24, v19, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v6, v25, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v8, v20, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v15, v12, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v18, v20, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v12, v20, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v3, v25, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v27, v29, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v10, v20, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v6, v18, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v22, v31, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v25, v5, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v14, v15, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v26, v15, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v4, v26, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v16, v19, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v27, v13, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v28, v15, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v29, v26, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v18, v5, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v20, v22, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v21, v2, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v30, v26, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v25, v17, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v19, v18, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v23, v7, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v3, v31, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v7, v28, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v30, v9, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v1, v20, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v15, v25, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v7, v15, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v9, v6, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v11, v7, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v23, v11, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v15, v28, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v7, v23, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v13, v15, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v28, v22, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v13, v29, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v19, v8, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v13, v18, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v9, v24, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v19, v12, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v25, v23, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v12, v4, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v27, v1, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v9, v11, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v6, v22, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v13, v5, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v27, v13, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v18, v12, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v17, v13, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v14, v7, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v7, v29, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v7, v6, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v6, v19, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v8, v1, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v9, v30, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v15, v23, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v30, v22, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v9, v26, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vredmax.vs v12, v23, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v12, v24, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v6, v20, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v30, v20, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v2, v18, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v20, v16, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v26, v8, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v6, v4, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v4, v30, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v26, v10, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v22, v28, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v26, v30, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v16, v2, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v24, v12, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v20, v24, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v20, v30, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v28, v18, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v6, v16, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v18, v2, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v26, v2, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v2, v22, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v20, v26, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v30, v16, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v16, v8, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v2, v26, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v22, v14, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v22, v10, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v18, v14, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v18, v8, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v16, v22, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v30, v26, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v4, v24, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v4, v18, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v20, v28, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v18, v12, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v16, v6, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v28, v12, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v20, v16, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v8, v30, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v28, v2, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v22, v14, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v10, v4, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v14, v22, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v12, v16, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v8, v26, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v28, v18, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v24, v30, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v14, v26, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v8, v28, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v2, v28, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v26, v6, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v16, v4, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v2, v18, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v28, v2, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v4, v22, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v14, v12, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v16, v12, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v4, v28, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v26, v16, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v26, v10, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v12, v14, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v2, v24, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v24, v28, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v12, v6, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v6, v24, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v12, v10, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v20, v2, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v8, v10, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v10, v18, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v28, v18, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v26, v18, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v16, v10, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v20, v28, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v6, v30, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v14, v26, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v14, v30, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v20, v14, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v16, v12, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v20, v26, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v28, v2, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v28, v18, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v20, v24, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v6, v22, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v28, v4, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v16, v20, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v18, v6, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v24, v18, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v20, v30, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v18, v16, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v30, v6, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v6, v12, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v20, v6, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v6, v14, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v14, v20, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v16, v30, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v8, v10, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v30, v2, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v6, v4, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v22, v26, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v4, v30, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vredmax.vs v18, v4, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v20, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v20, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v16, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v4, v12, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v12, v20, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v4, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v8, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v28, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v8, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v24, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v4, v16, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v4, v20, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v20, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v20, v24, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v20, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v12, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v12, v24, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v24, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v28, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v28, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v20, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v16, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v12, v8, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v8, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v28, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v20, v4, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v28, v8, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v4, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v28, v4, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v24, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v28, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v4, v16, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v8, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v8, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v8, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v4, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v4, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v12, v8, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v24, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v4, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v12, v20, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v12, v8, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v4, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v4, v20, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v12, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v4, v16, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v16, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v12, v8, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v4, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v16, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v4, v20, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v20, v4, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v4, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v28, v16, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v28, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v20, v16, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v12, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v8, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v12, v24, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v4, v28, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v28, v12, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v4, v12, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v28, v4, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v20, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v12, v4, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v20, v16, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v8, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v12, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v12, v28, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v16, v8, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v4, v12, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v20, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v28, v8, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v12, v20, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v20, v8, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v28, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v28, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v4, v16, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v24, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v28, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v20, v16, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v16, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v4, v16, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v4, v28, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v8, v24, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v20, v28, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v12, v8, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v24, v20, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v28, v20, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredmax.vs v20, v4, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredmax.vs v8, v16, v24

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
