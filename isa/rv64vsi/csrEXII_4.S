# See LICENSE for license details.

#*****************************************************************************
# debugCsrEXII.S
#-----------------------------------------------------------------------------
#
# Test syscall trap.
#

#include "riscv_test.h"
#include "test_macros.h"
#undef RVTEST_RV64S
#define RVTEST_RV64S RVTEST_RV64VS
#define __HYPERVISOR_MODE

#include "../rv64si/csrEXII_4.S"