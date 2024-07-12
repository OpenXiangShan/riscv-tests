# See LICENSE for license details.

#*****************************************************************************
# csrEXII_3.S
#-----------------------------------------------------------------------------
#
# Test csr illegal instruction and check nemu tval
# 写入香山实现的只读的csr
#


#include "riscv_test.h"
#include "test_macros.h"
#undef RVTEST_RV64S
#define RVTEST_RV64S RVTEST_RV64VS
#define __HYPERVISOR_MODE

#include "../rv64si/csrEXII_1.S"