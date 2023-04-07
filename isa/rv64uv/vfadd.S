#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v26, v21, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v3, v28, v27

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v6, v24, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v3, v25, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v19, v15, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v22, v31, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v10, v17, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v11, v1, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v31, v1, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v10, v17, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v4, v6, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v8, v2, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v14, v27, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v17, v20, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v4, v3, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v27, v3, v29

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v5, v20, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v16, v21, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v2, v20, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v14, v30, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v5, v3, v21

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v13, v11, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v17, v25, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v24, v11, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v13, v15, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v6, v10, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v4, v15, v2

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v21, v23, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v2, v11, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v16, v10, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v21, v13, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v2, v24, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v20, v17, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v12, v28, v7

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v25, v12, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v22, v4, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v2, v25, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v25, v11, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v4, v27, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v14, v26, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v27, v15, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v27, v3, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v27, v15, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v2, v9, v13

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v20, v9, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v20, v13, v10

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v22, v6, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v15, v18, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v19, v13, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v2, v8, v29

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v29, v23, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v17, v18, v16

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v22, v13, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v23, v15, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v5, v3, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v9, v23, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v19, v13, v5

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v3, v28, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v27, v16, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v11, v18, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v8, v15, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v20, v22, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v22, v3, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v14, v19, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v19, v22, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v28, v14, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v27, v1, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v24, v13, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v29, v24, v26

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v9, v13, v20

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v10, v3, v25

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v6, v29, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v25, v9, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v16, v7, v29

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v30, v4, v12

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v25, v5, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v17, v30, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v25, v27, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v19, v4, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v29, v17, v24

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v7, v20, v17

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v7, v27, v14

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v22, v20, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v23, v4, v31

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v21, v2, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v1, v28, v8

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v13, v6, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v7, v1, v15

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v26, v6, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v23, v10, v30

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v12, v27, v6

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v7, v9, v28

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v27, v1, v19

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v8, v2, v3

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v10, v30, v11

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v10, v12, v18

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v21, v19, v4

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v13, v25, v23

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v5, v17, v1

  vsetvli t1, t0, e16, m1, ta, ma
  vfadd.vv v3, v29, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v1, v2, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v27, v15, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v31, v7, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v5, v10, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v1, v19, v25

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v10, v12, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v21, v10, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v3, v8, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v15, v30, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v7, v3, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v28, v10, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v5, v31, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v19, v20, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v14, v15, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v2, v3, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v19, v8, v31

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v2, v7, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v8, v15, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v22, v24, v13

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v15, v2, v25

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v17, v7, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v15, v13, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v8, v13, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v3, v17, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v10, v3, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v13, v17, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v28, v8, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v8, v7, v25

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v10, v9, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v22, v20, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v25, v22, v12

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v6, v14, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v6, v28, v31

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v27, v24, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v23, v26, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v2, v30, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v31, v16, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v30, v23, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v1, v12, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v25, v15, v17

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v9, v21, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v21, v9, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v28, v2, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v5, v31, v25

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v12, v13, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v2, v31, v6

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v24, v3, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v13, v23, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v17, v2, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v22, v9, v18

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v3, v7, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v21, v30, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v25, v9, v24

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v10, v8, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v30, v28, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v24, v21, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v5, v15, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v21, v14, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v11, v5, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v12, v30, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v29, v18, v20

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v7, v25, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v8, v28, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v3, v27, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v28, v30, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v5, v12, v2

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v8, v21, v15

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v21, v11, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v16, v14, v17

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v4, v22, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v22, v6, v10

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v23, v27, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v12, v17, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v10, v19, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v20, v21, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v12, v31, v17

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v12, v26, v27

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v23, v31, v1

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v2, v19, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v23, v24, v11

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v10, v2, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v10, v23, v31

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v15, v8, v14

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v11, v22, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v16, v23, v25

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v6, v21, v16

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v4, v5, v22

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v16, v3, v28

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v17, v7, v3

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v13, v14, v21

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v11, v18, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v19, v4, v26

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v9, v22, v19

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v29, v2, v30

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v20, v3, v8

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v26, v5, v9

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v10, v30, v29

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v3, v26, v7

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v22, v9, v4

  vsetvli t1, t0, e32, m1, ta, ma
  vfadd.vv v31, v15, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v24, v7, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v30, v31, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v6, v4, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v23, v7, v28

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v5, v13, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v4, v5, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v16, v6, v20

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v6, v1, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v22, v31, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v6, v8, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v12, v30, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v28, v11, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v2, v18, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v31, v2, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v5, v31, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v1, v25, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v13, v26, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v25, v14, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v18, v8, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v25, v10, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v27, v11, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v19, v5, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v6, v1, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v16, v2, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v29, v26, v25

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v27, v26, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v16, v2, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v4, v26, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v18, v15, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v10, v3, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v1, v19, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v14, v12, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v21, v6, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v8, v24, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v13, v30, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v27, v31, v30

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v15, v3, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v28, v25, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v13, v8, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v23, v22, v27

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v2, v6, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v19, v27, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v6, v2, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v9, v21, v7

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v9, v23, v24

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v26, v31, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v19, v18, v16

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v5, v16, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v22, v17, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v16, v6, v10

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v4, v21, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v31, v12, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v19, v2, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v3, v28, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v29, v8, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v15, v23, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v31, v18, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v27, v11, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v13, v10, v21

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v6, v18, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v12, v16, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v21, v18, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v23, v17, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v25, v30, v6

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v22, v28, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v6, v10, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v12, v31, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v12, v16, v4

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v2, v26, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v30, v27, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v2, v18, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v1, v2, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v17, v9, v3

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v7, v12, v1

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v30, v7, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v7, v10, v2

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v18, v4, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v12, v25, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v11, v25, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v30, v26, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v13, v7, v17

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v27, v11, v23

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v20, v7, v26

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v10, v25, v22

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v12, v19, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v5, v31, v18

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v9, v5, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v30, v4, v5

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v28, v26, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v7, v17, v12

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v13, v25, v19

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v17, v30, v29

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v31, v19, v15

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v2, v20, v13

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v9, v5, v11

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v6, v14, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v16, v11, v31

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v2, v6, v14

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v20, v7, v9

  vsetvli t1, t0, e64, m1, ta, ma
  vfadd.vv v17, v7, v30

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
