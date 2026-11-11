/* Host-build stand-in for lib/libutils/ext/include/fault_mitigation.h: the only macro mbedtls' rsa.c uses. */
#ifndef MAYHEM_SHIM_FAULT_MITIGATION_H
#define MAYHEM_SHIM_FAULT_MITIGATION_H
#include <string.h>
#define FTMN_CALLEE_DONE_MEMCMP(my_memcmp, p1, p2, nb) (my_memcmp)((p1), (p2), (nb))
#endif
