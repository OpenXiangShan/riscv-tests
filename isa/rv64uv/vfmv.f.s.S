#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e32, m1, ta, ma
  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v14

  vfmv.f.s ft2, v30

  vfmv.f.s ft2, v11

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v9

  vfmv.f.s ft2, v29

  vfmv.f.s ft2, v26

  vfmv.f.s ft2, v23

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v1

  vfmv.f.s ft2, v7

  vfmv.f.s ft2, v3

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v5

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v3

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v26

  vfmv.f.s ft2, v21

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v21

  vfmv.f.s ft2, v7

  vfmv.f.s ft2, v25

  vfmv.f.s ft2, v19

  vfmv.f.s ft2, v5

  vfmv.f.s ft2, v21

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v3

  vfmv.f.s ft2, v26

  vfmv.f.s ft2, v23

  vfmv.f.s ft2, v19

  vfmv.f.s ft2, v21

  vfmv.f.s ft2, v27

  vfmv.f.s ft2, v29

  vfmv.f.s ft2, v30

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v19

  vfmv.f.s ft2, v21

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v23

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v21

  vfmv.f.s ft2, v1

  vfmv.f.s ft2, v19

  vfmv.f.s ft2, v21

  vfmv.f.s ft2, v29

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v26

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v13

  vfmv.f.s ft2, v29

  vfmv.f.s ft2, v1

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v7

  vfmv.f.s ft2, v27

  vfmv.f.s ft2, v27

  vfmv.f.s ft2, v19

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v19

  vfmv.f.s ft2, v31

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v1

  vfmv.f.s ft2, v25

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v21

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v3

  vfmv.f.s ft2, v9

  vfmv.f.s ft2, v5

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v23

  vfmv.f.s ft2, v29

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v15

  vfmv.f.s ft2, v30

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v31

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v7

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v21

  vfmv.f.s ft2, v13

  vfmv.f.s ft2, v31

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v30

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v22

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v14

  vfmv.f.s ft2, v22

  vfmv.f.s ft2, v30

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v30

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v26

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v14

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v30

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v14

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v26

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v30

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v14

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v22

  vfmv.f.s ft2, v30

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v26

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v14

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v14

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v27

  vfmv.f.s ft2, v7

  vfmv.f.s ft2, v25

  vfmv.f.s ft2, v11

  vfmv.f.s ft2, v7

  vfmv.f.s ft2, v19

  vfmv.f.s ft2, v11

  vfmv.f.s ft2, v9

  vfmv.f.s ft2, v15

  vfmv.f.s ft2, v23

  vfmv.f.s ft2, v5

  vfmv.f.s ft2, v3

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v30

  vfmv.f.s ft2, v30

  vfmv.f.s ft2, v26

  vfmv.f.s ft2, v3

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v5

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v11

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v9

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v14

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v27

  vfmv.f.s ft2, v22

  vfmv.f.s ft2, v13

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v3

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v7

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v25

  vfmv.f.s ft2, v25

  vfmv.f.s ft2, v19

  vfmv.f.s ft2, v1

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v9

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v17

  vfmv.f.s ft2, v27

  vfmv.f.s ft2, v3

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v15

  vfmv.f.s ft2, v23

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v1

  vfmv.f.s ft2, v14

  vfmv.f.s ft2, v31

  vfmv.f.s ft2, v17

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v29

  vfmv.f.s ft2, v11

  vfmv.f.s ft2, v31

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v21

  vfmv.f.s ft2, v5

  vfmv.f.s ft2, v25

  vfmv.f.s ft2, v25

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v17

  vfmv.f.s ft2, v22

  vfmv.f.s ft2, v25

  vfmv.f.s ft2, v14

  vfmv.f.s ft2, v15

  vfmv.f.s ft2, v29

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v27

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v25

  vfmv.f.s ft2, v9

  vfmv.f.s ft2, v25

  vfmv.f.s ft2, v27

  vfmv.f.s ft2, v25

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v11

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v27

  vfmv.f.s ft2, v13

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v27

  vfmv.f.s ft2, v31

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v22

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v26

  vfmv.f.s ft2, v22

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v22

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v26

  vfmv.f.s ft2, v14

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v26

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v26

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v22

  vfmv.f.s ft2, v26

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v30

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v22

  vfmv.f.s ft2, v30

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v14

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v26

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v22

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v2

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v14

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v26

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v6

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v14

  vfmv.f.s ft2, v10

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v22

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v18

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v4

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v12

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v28

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v20

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v24

  vfmv.f.s ft2, v16

  vfmv.f.s ft2, v8

  vfmv.f.s ft2, v24

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
