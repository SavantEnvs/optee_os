/* mbedtls' bignum.c (OP-TEE flavour) references the mempool API, but only dereferences it when
 * mbedtls_mpi_mempool is non-NULL; the host build never sets it, so these are unreachable. */
#include <stdlib.h>
#include <stddef.h>

void *mempool_alloc(void *pool, size_t size) { (void)pool; (void)size; abort(); }
void *mempool_calloc(void *pool, size_t nmemb, size_t size) { (void)pool; (void)nmemb; (void)size; abort(); }
void mempool_free(void *pool, void *ptr) { (void)pool; (void)ptr; abort(); }
