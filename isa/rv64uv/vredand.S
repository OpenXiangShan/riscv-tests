#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v24, v4, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v4, v14, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v6, v1, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v10, v28, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v18, v20, v7

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v10, v17, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v10, v1, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v9, v15, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v10, v29, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v13, v10, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v7, v1, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v7, v20, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v21, v26, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v19, v14, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v9, v29, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v14, v20, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v4, v7, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v21, v15, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v15, v11, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v1, v20, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v11, v1, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v15, v16, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v4, v25, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v15, v6, v7

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v27, v8, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v24, v19, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v20, v12, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v27, v5, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v6, v24, v2

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v31, v13, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v11, v24, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v29, v2, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v3, v30, v5

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v23, v13, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v17, v18, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v19, v4, v16

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v7, v21, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v22, v27, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v11, v14, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v21, v29, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v16, v24, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v16, v1, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v24, v12, v9

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v1, v7, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v20, v10, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v28, v31, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v16, v17, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v4, v17, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v1, v17, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v14, v18, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v17, v22, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v29, v20, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v7, v11, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v16, v18, v4

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v3, v23, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v16, v24, v18

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v7, v30, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v21, v26, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v6, v29, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v29, v2, v7

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v8, v25, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v22, v28, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v31, v23, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v21, v27, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v26, v11, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v16, v31, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v12, v25, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v18, v27, v25

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v22, v15, v27

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v3, v6, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v19, v6, v15

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v17, v23, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v27, v4, v28

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v28, v31, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v8, v11, v23

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v12, v6, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v8, v11, v3

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v11, v23, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v29, v8, v26

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v2, v6, v10

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v8, v22, v29

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v7, v21, v22

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v17, v11, v19

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v28, v7, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v2, v28, v1

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v28, v20, v12

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v27, v4, v31

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v31, v17, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v4, v12, v17

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v11, v14, v6

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v28, v22, v21

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v11, v6, v24

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v5, v19, v8

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v25, v29, v30

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v31, v16, v11

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v4, v18, v20

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v17, v19, v21

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v15, v12, v7

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v4, v30, v13

  vsetvli t1, t0, e8, m1, ta, ma
  vredand.vs v23, v2, v11

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v26, v10, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v14, v22, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v2, v18, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v10, v14, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v4, v28, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v16, v8, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v16, v4, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v26, v14, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v16, v2, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v14, v26, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v24, v14, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v24, v12, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v10, v20, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v8, v20, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v10, v2, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v12, v26, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v6, v2, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v12, v22, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v12, v26, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v30, v22, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v10, v8, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v6, v20, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v10, v20, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v14, v2, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v6, v4, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v4, v20, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v10, v6, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v18, v26, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v12, v24, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v2, v20, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v18, v12, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v12, v24, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v20, v10, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v4, v22, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v28, v8, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v12, v16, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v16, v22, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v28, v4, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v22, v12, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v28, v8, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v14, v10, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v26, v14, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v26, v6, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v8, v22, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v26, v18, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v4, v28, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v2, v22, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v20, v10, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v20, v4, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v12, v28, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v2, v8, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v12, v8, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v22, v6, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v12, v30, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v2, v8, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v2, v4, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v12, v14, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v20, v2, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v2, v28, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v20, v18, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v22, v8, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v12, v10, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v4, v20, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v22, v2, v10

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v28, v14, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v26, v18, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v10, v8, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v26, v2, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v14, v4, v20

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v14, v28, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v16, v18, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v24, v22, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v30, v4, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v18, v10, v8

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v30, v12, v28

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v4, v30, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v6, v14, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v30, v16, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v8, v28, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v8, v30, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v12, v28, v6

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v14, v16, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v30, v8, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v2, v20, v30

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v8, v16, v2

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v2, v20, v22

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v20, v16, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v14, v10, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v4, v28, v26

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v4, v16, v24

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v22, v10, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v12, v16, v14

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v8, v24, v18

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v4, v26, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v10, v4, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v30, v12, v4

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v4, v2, v16

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v18, v6, v12

  vsetvli t1, t0, e8, m2, ta, ma
  vredand.vs v18, v12, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v12, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v16, v12, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v16, v28, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v28, v12, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v24, v20, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v8, v12, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v28, v24, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v16, v12, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v20, v16, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v28, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v20, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v4, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v20, v12, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v16, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v8, v4, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v4, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v24, v4, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v24, v8, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v16, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v28, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v8, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v28, v4, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v24, v8, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v28, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v4, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v8, v20, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v28, v8, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v24, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v16, v28, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v28, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v16, v20, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v24, v20, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v28, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v28, v20, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v8, v4, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v20, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v20, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v24, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v24, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v16, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v8, v20, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v24, v20, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v28, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v20, v16, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v8, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v16, v28, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v28, v4, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v28, v4, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v4, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v8, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v8, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v24, v12, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v4, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v12, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v20, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v20, v8, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v8, v4, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v20, v4, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v24, v20, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v20, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v16, v24, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v20, v8, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v20, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v8, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v28, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v16, v4, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v28, v24

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v8, v28, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v16, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v28, v24, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v24, v28, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v28, v16, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v20, v12, v28

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v8, v16, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v28, v12, v4

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v24, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v16, v8, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v20, v8

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v12, v4, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v28, v4, v16

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v8, v12, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v20, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v24, v8, v20

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v20, v4, v12

  vsetvli t1, t0, e8, m4, ta, ma
  vredand.vs v4, v8, v12

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e8, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v6, v24, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v20, v11, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v4, v21, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v3, v1, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v3, v5, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v29, v31, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v10, v29, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v1, v11, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v7, v2, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v27, v10, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v28, v2, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v10, v20, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v12, v6, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v17, v2, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v10, v7, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v11, v26, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v20, v23, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v9, v5, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v4, v19, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v8, v15, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v11, v24, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v13, v31, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v14, v22, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v22, v30, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v17, v27, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v2, v1, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v16, v22, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v3, v13, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v4, v19, v9

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v25, v3, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v11, v14, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v2, v9, v27

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v9, v29, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v7, v2, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v7, v1, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v6, v27, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v9, v23, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v2, v17, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v1, v22, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v30, v19, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v31, v25, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v12, v7, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v21, v18, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v26, v28, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v17, v29, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v15, v4, v27

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v4, v11, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v11, v21, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v4, v31, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v16, v25, v27

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v11, v17, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v9, v2, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v13, v7, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v5, v31, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v3, v27, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v29, v28, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v14, v8, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v28, v26, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v2, v12, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v17, v6, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v28, v21, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v31, v20, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v17, v20, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v30, v16, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v26, v30, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v2, v23, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v30, v25, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v4, v20, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v28, v24, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v30, v22, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v30, v11, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v9, v10, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v14, v25, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v20, v28, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v6, v2, v9

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v4, v26, v29

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v24, v10, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v25, v23, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v19, v26, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v10, v30, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v19, v13, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v4, v18, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v5, v8, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v6, v29, v9

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v7, v27, v22

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v11, v7, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v12, v19, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v11, v20, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v30, v25, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v1, v21, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v28, v16, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v17, v6, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v14, v28, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v4, v19, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v21, v24, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v29, v19, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v23, v1, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v15, v17, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v22, v12, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vredand.vs v25, v30, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v8, v20, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v4, v26, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v18, v28, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v16, v20, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v8, v6, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v30, v4, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v16, v24, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v30, v28, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v12, v8, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v6, v30, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v8, v2, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v2, v4, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v6, v2, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v28, v12, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v22, v24, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v16, v18, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v22, v4, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v26, v16, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v2, v26, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v6, v12, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v12, v8, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v2, v12, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v12, v6, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v22, v26, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v28, v2, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v4, v24, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v8, v6, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v30, v8, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v24, v22, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v24, v8, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v22, v10, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v6, v24, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v24, v4, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v6, v16, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v2, v22, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v26, v20, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v30, v26, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v28, v4, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v2, v18, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v4, v14, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v10, v12, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v30, v2, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v18, v30, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v6, v14, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v2, v24, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v20, v26, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v16, v14, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v2, v28, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v18, v26, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v4, v8, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v2, v12, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v18, v12, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v20, v12, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v26, v12, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v18, v24, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v12, v10, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v10, v2, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v14, v12, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v10, v28, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v14, v20, v2

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v4, v18, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v24, v8, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v8, v4, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v28, v6, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v30, v8, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v22, v14, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v12, v22, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v28, v26, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v30, v16, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v28, v8, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v6, v10, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v18, v14, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v10, v14, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v24, v22, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v24, v26, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v12, v26, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v16, v18, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v12, v2, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v8, v12, v14

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v2, v10, v26

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v8, v10, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v16, v30, v8

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v24, v12, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v26, v16, v12

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v18, v24, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v24, v4, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v6, v12, v22

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v26, v18, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v14, v10, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v28, v24, v4

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v8, v16, v18

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v10, v14, v16

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v22, v12, v10

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v8, v18, v30

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v8, v20, v6

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v6, v28, v20

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v28, v30, v24

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v22, v6, v28

  vsetvli t1, t0, e16, m2, ta, ma
  vredand.vs v14, v24, v30

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v12, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v24, v16, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v24, v16, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v8, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v28, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v20, v28, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v16, v12, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v8, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v20, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v16, v20, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v20, v4, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v24, v28, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v20, v28, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v20, v12, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v8, v28, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v12, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v4, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v16, v24, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v24, v16, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v20, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v24, v4, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v12, v28, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v8, v16, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v20, v16, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v8, v4, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v16, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v12, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v8, v4, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v24, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v20, v24, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v8, v24, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v20, v16, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v20, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v28, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v12, v8, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v20, v12, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v16, v28, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v8, v28, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v24, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v12, v8, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v12, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v24, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v24, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v16, v12, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v12, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v16, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v24, v20, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v12, v20, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v16, v4, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v8, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v28, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v12, v24, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v4, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v24, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v24, v28, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v24, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v8, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v12, v24, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v8, v28, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v24, v20, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v28, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v16, v24, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v16, v24, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v8, v4, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v24, v4, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v20, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v16, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v20, v8, v28

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v16, v12, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v12, v28, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v4, v16, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v16, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v12, v20, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v20, v8, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v12, v20, v16

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v20, v12

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v24, v8, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v24, v20, v4

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v24, v28, v20

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v16, v4, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v28, v8, v24

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v16, v12, v8

  vsetvli t1, t0, e16, m4, ta, ma
  vredand.vs v8, v4, v20

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e16, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v20, v25, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v4, v25, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v15, v18, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v9, v25, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v11, v16, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v13, v10, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v26, v30, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v10, v11, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v23, v9, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v9, v2, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v31, v2, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v24, v31, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v23, v15, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v31, v6, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v7, v12, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v29, v24, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v24, v31, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v27, v1, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v8, v13, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v20, v9, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v3, v16, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v24, v18, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v31, v15, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v26, v5, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v31, v1, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v22, v31, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v24, v9, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v31, v2, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v31, v25, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v6, v17, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v17, v8, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v22, v15, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v19, v23, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v5, v24, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v23, v20, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v3, v26, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v9, v28, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v28, v4, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v8, v2, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v29, v15, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v28, v9, v17

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v2, v1, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v9, v12, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v30, v3, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v27, v23, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v26, v16, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v27, v7, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v20, v19, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v19, v20, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v18, v4, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v15, v11, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v16, v3, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v23, v27, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v11, v30, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v28, v26, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v21, v26, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v13, v16, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v31, v21, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v23, v3, v5

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v30, v22, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v1, v31, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v9, v17, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v18, v16, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v22, v15, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v4, v19, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v17, v23, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v27, v31, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v22, v9, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v18, v20, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v27, v4, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v14, v26, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v23, v5, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v9, v2, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v15, v8, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v2, v25, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v25, v23, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v10, v19, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v18, v24, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v9, v23, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v16, v10, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v8, v3, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v17, v9, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v31, v11, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v20, v23, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v31, v3, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v21, v9, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v17, v5, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v21, v31, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v19, v25, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v29, v30, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v6, v7, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v10, v17, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v3, v9, v23

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v15, v10, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v23, v4, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v6, v3, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v18, v31, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v25, v8, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v19, v20, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vredand.vs v5, v22, v9

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v14, v26, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v18, v12, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v4, v18, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v12, v6, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v2, v28, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v6, v28, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v4, v12, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v10, v16, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v14, v16, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v10, v20, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v6, v8, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v26, v8, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v22, v26, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v2, v26, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v28, v14, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v28, v6, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v14, v16, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v8, v4, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v30, v2, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v10, v24, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v4, v22, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v8, v12, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v22, v30, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v2, v22, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v4, v14, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v20, v4, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v28, v26, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v10, v20, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v16, v28, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v8, v22, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v14, v30, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v24, v8, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v4, v22, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v6, v26, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v22, v12, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v22, v6, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v30, v20, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v26, v22, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v18, v8, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v22, v28, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v14, v4, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v22, v10, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v16, v30, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v12, v6, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v12, v28, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v24, v16, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v2, v6, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v4, v30, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v22, v28, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v8, v6, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v24, v12, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v20, v12, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v20, v26, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v22, v24, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v18, v14, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v24, v2, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v12, v22, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v24, v22, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v14, v6, v2

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v24, v20, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v16, v28, v30

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v10, v18, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v26, v30, v10

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v30, v26, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v22, v6, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v14, v24, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v30, v10, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v4, v14, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v8, v18, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v12, v6, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v24, v12, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v28, v30, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v6, v10, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v12, v22, v14

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v10, v2, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v20, v12, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v14, v16, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v10, v30, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v8, v20, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v12, v14, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v12, v2, v22

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v22, v10, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v8, v22, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v16, v4, v18

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v14, v4, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v26, v6, v16

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v10, v30, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v12, v26, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v6, v4, v20

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v22, v30, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v2, v6, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v18, v12, v24

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v22, v28, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v20, v8, v6

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v26, v16, v28

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v20, v18, v8

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v22, v26, v4

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v16, v30, v26

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v24, v2, v12

  vsetvli t1, t0, e32, m2, ta, ma
  vredand.vs v4, v24, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v8, v12, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v24, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v4, v28, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v8, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v16, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v12, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v8, v20, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v24, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v28, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v12, v16, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v4, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v12, v8, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v20, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v24, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v12, v20, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v12, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v12, v4, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v20, v16, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v8, v16, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v4, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v4, v28, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v12, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v4, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v8, v4, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v20, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v12, v4, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v4, v20, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v28, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v12, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v8, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v4, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v20, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v4, v12, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v20, v16, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v8, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v8, v4, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v20, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v12, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v20, v28, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v20, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v4, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v24, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v20, v24, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v20, v28, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v20, v4, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v20, v4, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v8, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v20, v4, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v12, v16, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v28, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v8, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v4, v24, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v12, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v12, v28, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v8, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v4, v12, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v20, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v12, v8, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v20, v4, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v16, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v20, v4, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v4, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v4, v12, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v8, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v20, v4, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v12, v20, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v12, v24, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v12, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v8, v20, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v24, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v8, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v24, v20

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v4, v28, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v12, v28, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v4, v24, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v12, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v20, v8

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v12, v24, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v4, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v20, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v8, v16, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v8, v4, v28

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v8, v28, v4

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v20, v12, v16

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v24, v28, v12

  vsetvli t1, t0, e32, m4, ta, ma
  vredand.vs v28, v4, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e32, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v4, v14, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v30, v13, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v11, v13, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v25, v13, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v15, v21, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v13, v3, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v15, v18, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v14, v2, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v13, v18, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v1, v7, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v2, v3, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v16, v28, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v2, v13, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v21, v9, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v17, v2, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v10, v30, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v11, v13, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v16, v9, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v22, v10, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v5, v22, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v11, v10, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v19, v18, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v1, v22, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v31, v18, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v18, v27, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v24, v8, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v9, v1, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v1, v31, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v25, v18, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v26, v19, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v10, v15, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v25, v3, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v11, v18, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v17, v23, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v21, v8, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v20, v17, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v9, v19, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v4, v3, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v29, v24, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v2, v20, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v16, v23, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v2, v31, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v23, v12, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v8, v11, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v13, v10, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v11, v25, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v20, v9, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v16, v4, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v17, v21, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v14, v17, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v14, v5, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v1, v11, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v2, v29, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v28, v17, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v29, v14, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v14, v31, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v29, v26, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v23, v12, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v21, v23, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v4, v16, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v29, v1, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v14, v17, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v14, v11, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v2, v20, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v7, v31, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v8, v29, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v1, v20, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v11, v30, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v17, v15, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v14, v10, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v3, v17, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v30, v27, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v19, v13, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v19, v5, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v21, v20, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v10, v19, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v26, v21, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v30, v10, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v17, v12, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v29, v10, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v5, v24, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v12, v16, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v7, v21, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v16, v5, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v26, v12, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v28, v14, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v6, v19, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v13, v6, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v29, v10, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v17, v22, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v26, v25, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v19, v7, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v11, v25, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v14, v12, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v30, v25, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v20, v10, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v25, v16, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v26, v23, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v12, v13, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vredand.vs v6, v14, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v4, v12, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v2, v18, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v4, v18, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v20, v4, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v26, v22, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v18, v2, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v20, v10, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v18, v4, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v6, v12, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v2, v30, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v14, v18, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v12, v22, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v2, v22, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v14, v10, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v26, v14, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v18, v20, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v16, v4, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v20, v24, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v16, v2, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v24, v20, v8

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v26, v2, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v8, v20, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v16, v12, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v16, v18, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v22, v30, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v30, v26, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v10, v16, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v14, v28, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v20, v6, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v14, v28, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v22, v16, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v16, v6, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v16, v20, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v14, v26, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v2, v18, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v8, v20, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v26, v14, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v10, v2, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v26, v12, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v16, v10, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v30, v16, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v24, v8, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v20, v30, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v8, v30, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v30, v18, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v12, v16, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v28, v10, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v12, v22, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v30, v6, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v14, v28, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v14, v10, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v12, v26, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v22, v30, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v24, v2, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v18, v4, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v22, v16, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v6, v8, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v30, v28, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v8, v20, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v20, v16, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v8, v18, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v28, v10, v22

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v12, v24, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v8, v30, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v16, v30, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v8, v30, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v30, v22, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v24, v20, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v12, v26, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v8, v20, v18

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v10, v22, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v28, v20, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v28, v18, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v20, v10, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v14, v4, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v26, v12, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v12, v26, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v6, v16, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v18, v28, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v24, v10, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v2, v8, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v6, v18, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v22, v12, v26

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v20, v24, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v26, v12, v2

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v20, v10, v12

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v12, v4, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v12, v4, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v26, v12, v28

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v8, v4, v30

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v26, v28, v4

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v22, v18, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v18, v6, v24

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v10, v30, v14

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v22, v4, v10

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v26, v14, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v28, v12, v20

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v12, v22, v6

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v6, v8, v16

  vsetvli t1, t0, e64, m2, ta, ma
  vredand.vs v10, v16, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v20, v12, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v12, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v28, v12, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v16, v12, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v8, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v16, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v16, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v8, v20, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v8, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v8, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v12, v8, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v24, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v28, v20, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v8, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v12, v24, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v12, v8, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v8, v16, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v20, v16, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v8, v4, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v16, v28, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v8, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v8, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v20, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v28, v4, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v20, v16, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v8, v16, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v8, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v16, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v16, v8, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v8, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v20, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v20, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v20, v4, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v20, v4, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v20, v12, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v12, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v12, v20, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v28, v8, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v4, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v16, v4, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v20, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v12, v28, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v28, v24, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v8, v24, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v8, v16, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v12, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v12, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v16, v24, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v12, v16, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v20, v28, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v8, v20, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v8, v16, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v4, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v28, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v24, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v20, v16, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v16, v8, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v16, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v28, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v8, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v28, v16, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v20, v28, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v24, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v28, v12, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v16, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v12, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v12, v4, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v16, v24, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v12, v24, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v12, v28, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v16, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v8, v12, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v20, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v8, v12, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v28, v4, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v12, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v20, v8, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v8, v16, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v20, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v12, v16, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v16, v8, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v16, v24

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v20, v8, v4

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v12, v4, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v12, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v20, v16, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v16, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v16, v4, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v20, v24, v28

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v16, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v4, v28, v12

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v24, v12, v16

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v28, v4, v8

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v28, v12, v20

  vsetvli t1, t0, e64, m4, ta, ma
  vredand.vs v8, v16, v20

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v24, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v24, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v16, v8, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v8, v16

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v24, v16, v8

  vsetvli t1, t0, e64, m8, ta, ma
  vredand.vs v8, v16, v24

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
