#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64UV

RVTEST_CODE_BEGIN

  li t0, -1

  vsetvli t1, t0, e32, m1, ta, ma
  vmv.x.s t2, v1

  vmv.x.s t2, v9

  vmv.x.s t2, v5

  vmv.x.s t2, v22

  vmv.x.s t2, v21

  vmv.x.s t2, v9

  vmv.x.s t2, v30

  vmv.x.s t2, v12

  vmv.x.s t2, v25

  vmv.x.s t2, v3

  vmv.x.s t2, v21

  vmv.x.s t2, v21

  vmv.x.s t2, v6

  vmv.x.s t2, v14

  vmv.x.s t2, v20

  vmv.x.s t2, v5

  vmv.x.s t2, v6

  vmv.x.s t2, v30

  vmv.x.s t2, v30

  vmv.x.s t2, v17

  vmv.x.s t2, v3

  vmv.x.s t2, v5

  vmv.x.s t2, v24

  vmv.x.s t2, v27

  vmv.x.s t2, v2

  vmv.x.s t2, v25

  vmv.x.s t2, v1

  vmv.x.s t2, v25

  vmv.x.s t2, v11

  vmv.x.s t2, v6

  vmv.x.s t2, v9

  vmv.x.s t2, v23

  vmv.x.s t2, v20

  vmv.x.s t2, v2

  vmv.x.s t2, v10

  vmv.x.s t2, v9

  vmv.x.s t2, v4

  vmv.x.s t2, v31

  vmv.x.s t2, v30

  vmv.x.s t2, v13

  vmv.x.s t2, v7

  vmv.x.s t2, v10

  vmv.x.s t2, v3

  vmv.x.s t2, v8

  vmv.x.s t2, v31

  vmv.x.s t2, v28

  vmv.x.s t2, v10

  vmv.x.s t2, v14

  vmv.x.s t2, v10

  vmv.x.s t2, v10

  vmv.x.s t2, v29

  vmv.x.s t2, v23

  vmv.x.s t2, v16

  vmv.x.s t2, v26

  vmv.x.s t2, v13

  vmv.x.s t2, v29

  vmv.x.s t2, v11

  vmv.x.s t2, v28

  vmv.x.s t2, v1

  vmv.x.s t2, v21

  vmv.x.s t2, v17

  vmv.x.s t2, v21

  vmv.x.s t2, v10

  vmv.x.s t2, v11

  vmv.x.s t2, v28

  vmv.x.s t2, v10

  vmv.x.s t2, v5

  vmv.x.s t2, v1

  vmv.x.s t2, v2

  vmv.x.s t2, v16

  vmv.x.s t2, v13

  vmv.x.s t2, v3

  vmv.x.s t2, v31

  vmv.x.s t2, v2

  vmv.x.s t2, v31

  vmv.x.s t2, v10

  vmv.x.s t2, v18

  vmv.x.s t2, v30

  vmv.x.s t2, v3

  vmv.x.s t2, v29

  vmv.x.s t2, v11

  vmv.x.s t2, v20

  vmv.x.s t2, v21

  vmv.x.s t2, v31

  vmv.x.s t2, v12

  vmv.x.s t2, v6

  vmv.x.s t2, v19

  vmv.x.s t2, v10

  vmv.x.s t2, v22

  vmv.x.s t2, v21

  vmv.x.s t2, v18

  vmv.x.s t2, v12

  vmv.x.s t2, v23

  vmv.x.s t2, v3

  vmv.x.s t2, v21

  vmv.x.s t2, v13

  vmv.x.s t2, v5

  vmv.x.s t2, v18

  vmv.x.s t2, v29

  vmv.x.s t2, v20

  vmv.x.s t2, v4

  vmv.x.s t2, v26

  vmv.x.s t2, v26

  vmv.x.s t2, v8

  vmv.x.s t2, v26

  vmv.x.s t2, v4

  vmv.x.s t2, v26

  vmv.x.s t2, v24

  vmv.x.s t2, v12

  vmv.x.s t2, v2

  vmv.x.s t2, v6

  vmv.x.s t2, v14

  vmv.x.s t2, v28

  vmv.x.s t2, v22

  vmv.x.s t2, v30

  vmv.x.s t2, v30

  vmv.x.s t2, v28

  vmv.x.s t2, v24

  vmv.x.s t2, v30

  vmv.x.s t2, v20

  vmv.x.s t2, v22

  vmv.x.s t2, v30

  vmv.x.s t2, v26

  vmv.x.s t2, v16

  vmv.x.s t2, v26

  vmv.x.s t2, v6

  vmv.x.s t2, v16

  vmv.x.s t2, v6

  vmv.x.s t2, v26

  vmv.x.s t2, v26

  vmv.x.s t2, v30

  vmv.x.s t2, v30

  vmv.x.s t2, v6

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v2

  vmv.x.s t2, v14

  vmv.x.s t2, v12

  vmv.x.s t2, v24

  vmv.x.s t2, v26

  vmv.x.s t2, v16

  vmv.x.s t2, v22

  vmv.x.s t2, v2

  vmv.x.s t2, v16

  vmv.x.s t2, v20

  vmv.x.s t2, v28

  vmv.x.s t2, v12

  vmv.x.s t2, v2

  vmv.x.s t2, v22

  vmv.x.s t2, v8

  vmv.x.s t2, v28

  vmv.x.s t2, v22

  vmv.x.s t2, v2

  vmv.x.s t2, v12

  vmv.x.s t2, v12

  vmv.x.s t2, v18

  vmv.x.s t2, v14

  vmv.x.s t2, v24

  vmv.x.s t2, v30

  vmv.x.s t2, v16

  vmv.x.s t2, v12

  vmv.x.s t2, v26

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v20

  vmv.x.s t2, v20

  vmv.x.s t2, v8

  vmv.x.s t2, v30

  vmv.x.s t2, v4

  vmv.x.s t2, v22

  vmv.x.s t2, v6

  vmv.x.s t2, v22

  vmv.x.s t2, v8

  vmv.x.s t2, v26

  vmv.x.s t2, v6

  vmv.x.s t2, v28

  vmv.x.s t2, v2

  vmv.x.s t2, v14

  vmv.x.s t2, v12

  vmv.x.s t2, v10

  vmv.x.s t2, v28

  vmv.x.s t2, v16

  vmv.x.s t2, v20

  vmv.x.s t2, v2

  vmv.x.s t2, v20

  vmv.x.s t2, v2

  vmv.x.s t2, v2

  vmv.x.s t2, v26

  vmv.x.s t2, v26

  vmv.x.s t2, v24

  vmv.x.s t2, v2

  vmv.x.s t2, v14

  vmv.x.s t2, v14

  vmv.x.s t2, v4

  vmv.x.s t2, v26

  vmv.x.s t2, v28

  vmv.x.s t2, v26

  vmv.x.s t2, v30

  vmv.x.s t2, v12

  vmv.x.s t2, v30

  vmv.x.s t2, v20

  vmv.x.s t2, v24

  vmv.x.s t2, v28

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v12

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v20

  vmv.x.s t2, v24

  vmv.x.s t2, v28

  vmv.x.s t2, v28

  vmv.x.s t2, v24

  vmv.x.s t2, v20

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v20

  vmv.x.s t2, v20

  vmv.x.s t2, v16

  vmv.x.s t2, v4

  vmv.x.s t2, v28

  vmv.x.s t2, v4

  vmv.x.s t2, v16

  vmv.x.s t2, v20

  vmv.x.s t2, v16

  vmv.x.s t2, v28

  vmv.x.s t2, v4

  vmv.x.s t2, v8

  vmv.x.s t2, v12

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v12

  vmv.x.s t2, v20

  vmv.x.s t2, v12

  vmv.x.s t2, v20

  vmv.x.s t2, v28

  vmv.x.s t2, v16

  vmv.x.s t2, v4

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v4

  vmv.x.s t2, v20

  vmv.x.s t2, v20

  vmv.x.s t2, v24

  vmv.x.s t2, v28

  vmv.x.s t2, v4

  vmv.x.s t2, v16

  vmv.x.s t2, v28

  vmv.x.s t2, v12

  vmv.x.s t2, v24

  vmv.x.s t2, v28

  vmv.x.s t2, v20

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v28

  vmv.x.s t2, v4

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v28

  vmv.x.s t2, v20

  vmv.x.s t2, v28

  vmv.x.s t2, v8

  vmv.x.s t2, v28

  vmv.x.s t2, v24

  vmv.x.s t2, v20

  vmv.x.s t2, v16

  vmv.x.s t2, v4

  vmv.x.s t2, v16

  vmv.x.s t2, v4

  vmv.x.s t2, v16

  vmv.x.s t2, v20

  vmv.x.s t2, v24

  vmv.x.s t2, v20

  vmv.x.s t2, v4

  vmv.x.s t2, v16

  vmv.x.s t2, v12

  vmv.x.s t2, v8

  vmv.x.s t2, v20

  vmv.x.s t2, v12

  vmv.x.s t2, v28

  vmv.x.s t2, v12

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v20

  vmv.x.s t2, v16

  vmv.x.s t2, v20

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vsetvli t1, t0, e64, m1, ta, ma
  vmv.x.s t2, v8

  vmv.x.s t2, v30

  vmv.x.s t2, v7

  vmv.x.s t2, v15

  vmv.x.s t2, v30

  vmv.x.s t2, v7

  vmv.x.s t2, v15

  vmv.x.s t2, v25

  vmv.x.s t2, v9

  vmv.x.s t2, v29

  vmv.x.s t2, v21

  vmv.x.s t2, v19

  vmv.x.s t2, v25

  vmv.x.s t2, v14

  vmv.x.s t2, v18

  vmv.x.s t2, v30

  vmv.x.s t2, v8

  vmv.x.s t2, v27

  vmv.x.s t2, v26

  vmv.x.s t2, v1

  vmv.x.s t2, v29

  vmv.x.s t2, v6

  vmv.x.s t2, v30

  vmv.x.s t2, v19

  vmv.x.s t2, v22

  vmv.x.s t2, v2

  vmv.x.s t2, v17

  vmv.x.s t2, v7

  vmv.x.s t2, v3

  vmv.x.s t2, v8

  vmv.x.s t2, v18

  vmv.x.s t2, v9

  vmv.x.s t2, v29

  vmv.x.s t2, v4

  vmv.x.s t2, v16

  vmv.x.s t2, v17

  vmv.x.s t2, v25

  vmv.x.s t2, v8

  vmv.x.s t2, v25

  vmv.x.s t2, v16

  vmv.x.s t2, v18

  vmv.x.s t2, v10

  vmv.x.s t2, v11

  vmv.x.s t2, v28

  vmv.x.s t2, v1

  vmv.x.s t2, v1

  vmv.x.s t2, v25

  vmv.x.s t2, v7

  vmv.x.s t2, v16

  vmv.x.s t2, v6

  vmv.x.s t2, v17

  vmv.x.s t2, v29

  vmv.x.s t2, v7

  vmv.x.s t2, v13

  vmv.x.s t2, v10

  vmv.x.s t2, v12

  vmv.x.s t2, v12

  vmv.x.s t2, v28

  vmv.x.s t2, v2

  vmv.x.s t2, v11

  vmv.x.s t2, v15

  vmv.x.s t2, v20

  vmv.x.s t2, v22

  vmv.x.s t2, v31

  vmv.x.s t2, v27

  vmv.x.s t2, v10

  vmv.x.s t2, v20

  vmv.x.s t2, v3

  vmv.x.s t2, v17

  vmv.x.s t2, v11

  vmv.x.s t2, v2

  vmv.x.s t2, v28

  vmv.x.s t2, v28

  vmv.x.s t2, v28

  vmv.x.s t2, v23

  vmv.x.s t2, v22

  vmv.x.s t2, v21

  vmv.x.s t2, v2

  vmv.x.s t2, v19

  vmv.x.s t2, v19

  vmv.x.s t2, v27

  vmv.x.s t2, v24

  vmv.x.s t2, v26

  vmv.x.s t2, v27

  vmv.x.s t2, v16

  vmv.x.s t2, v6

  vmv.x.s t2, v30

  vmv.x.s t2, v24

  vmv.x.s t2, v14

  vmv.x.s t2, v28

  vmv.x.s t2, v21

  vmv.x.s t2, v6

  vmv.x.s t2, v11

  vmv.x.s t2, v1

  vmv.x.s t2, v12

  vmv.x.s t2, v26

  vmv.x.s t2, v20

  vmv.x.s t2, v7

  vmv.x.s t2, v6

  vmv.x.s t2, v10

  vmv.x.s t2, v4

  vmv.x.s t2, v2

  vmv.x.s t2, v2

  vmv.x.s t2, v26

  vmv.x.s t2, v22

  vmv.x.s t2, v2

  vmv.x.s t2, v4

  vmv.x.s t2, v14

  vmv.x.s t2, v8

  vmv.x.s t2, v14

  vmv.x.s t2, v28

  vmv.x.s t2, v18

  vmv.x.s t2, v16

  vmv.x.s t2, v26

  vmv.x.s t2, v28

  vmv.x.s t2, v22

  vmv.x.s t2, v26

  vmv.x.s t2, v6

  vmv.x.s t2, v2

  vmv.x.s t2, v16

  vmv.x.s t2, v4

  vmv.x.s t2, v20

  vmv.x.s t2, v12

  vmv.x.s t2, v10

  vmv.x.s t2, v4

  vmv.x.s t2, v18

  vmv.x.s t2, v6

  vmv.x.s t2, v22

  vmv.x.s t2, v18

  vmv.x.s t2, v26

  vmv.x.s t2, v14

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v22

  vmv.x.s t2, v8

  vmv.x.s t2, v12

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v18

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v26

  vmv.x.s t2, v14

  vmv.x.s t2, v2

  vmv.x.s t2, v6

  vmv.x.s t2, v30

  vmv.x.s t2, v22

  vmv.x.s t2, v20

  vmv.x.s t2, v20

  vmv.x.s t2, v18

  vmv.x.s t2, v4

  vmv.x.s t2, v24

  vmv.x.s t2, v20

  vmv.x.s t2, v16

  vmv.x.s t2, v14

  vmv.x.s t2, v8

  vmv.x.s t2, v26

  vmv.x.s t2, v24

  vmv.x.s t2, v6

  vmv.x.s t2, v26

  vmv.x.s t2, v22

  vmv.x.s t2, v18

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v28

  vmv.x.s t2, v4

  vmv.x.s t2, v30

  vmv.x.s t2, v22

  vmv.x.s t2, v30

  vmv.x.s t2, v16

  vmv.x.s t2, v22

  vmv.x.s t2, v20

  vmv.x.s t2, v24

  vmv.x.s t2, v4

  vmv.x.s t2, v28

  vmv.x.s t2, v14

  vmv.x.s t2, v20

  vmv.x.s t2, v10

  vmv.x.s t2, v4

  vmv.x.s t2, v24

  vmv.x.s t2, v6

  vmv.x.s t2, v14

  vmv.x.s t2, v12

  vmv.x.s t2, v26

  vmv.x.s t2, v30

  vmv.x.s t2, v26

  vmv.x.s t2, v30

  vmv.x.s t2, v28

  vmv.x.s t2, v4

  vmv.x.s t2, v26

  vmv.x.s t2, v30

  vmv.x.s t2, v30

  vmv.x.s t2, v14

  vmv.x.s t2, v2

  vmv.x.s t2, v28

  vmv.x.s t2, v22

  vmv.x.s t2, v28

  vmv.x.s t2, v8

  vmv.x.s t2, v26

  vmv.x.s t2, v8

  vmv.x.s t2, v12

  vmv.x.s t2, v12

  vmv.x.s t2, v28

  vmv.x.s t2, v12

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v12

  vmv.x.s t2, v16

  vmv.x.s t2, v4

  vmv.x.s t2, v12

  vmv.x.s t2, v28

  vmv.x.s t2, v20

  vmv.x.s t2, v12

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v4

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v20

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v28

  vmv.x.s t2, v28

  vmv.x.s t2, v16

  vmv.x.s t2, v20

  vmv.x.s t2, v4

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v12

  vmv.x.s t2, v12

  vmv.x.s t2, v28

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v20

  vmv.x.s t2, v4

  vmv.x.s t2, v12

  vmv.x.s t2, v16

  vmv.x.s t2, v4

  vmv.x.s t2, v4

  vmv.x.s t2, v28

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v4

  vmv.x.s t2, v20

  vmv.x.s t2, v12

  vmv.x.s t2, v12

  vmv.x.s t2, v8

  vmv.x.s t2, v12

  vmv.x.s t2, v8

  vmv.x.s t2, v4

  vmv.x.s t2, v12

  vmv.x.s t2, v4

  vmv.x.s t2, v8

  vmv.x.s t2, v12

  vmv.x.s t2, v4

  vmv.x.s t2, v4

  vmv.x.s t2, v20

  vmv.x.s t2, v4

  vmv.x.s t2, v16

  vmv.x.s t2, v20

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v20

  vmv.x.s t2, v12

  vmv.x.s t2, v12

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v12

  vmv.x.s t2, v4

  vmv.x.s t2, v20

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v12

  vmv.x.s t2, v20

  vmv.x.s t2, v12

  vmv.x.s t2, v20

  vmv.x.s t2, v12

  vmv.x.s t2, v4

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v12

  vmv.x.s t2, v8

  vmv.x.s t2, v20

  vmv.x.s t2, v28

  vmv.x.s t2, v24

  vmv.x.s t2, v20

  vmv.x.s t2, v28

  vmv.x.s t2, v20

  vmv.x.s t2, v12

  vmv.x.s t2, v12

  vmv.x.s t2, v8

  vmv.x.s t2, v28

  vmv.x.s t2, v28

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v16

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v16

  vmv.x.s t2, v24

  vmv.x.s t2, v24

  vmv.x.s t2, v8

  la a0, res
  TEST_CASE(1, t0, 0, ld t0, 0(a0); addi a0, a0, 8)

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

res:
  .zero 16

RVTEST_DATA_END
