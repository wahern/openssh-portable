#ifndef FIPS_H
#define FIPS_H

#ifdef USE_OPENSSL_FIPS

#include <openssl/provider.h>

#define FIPS_mode() fips_isenabled()
void fips_init(void);
_Bool fips_isenabled(void);
void fips_setenabled(_Bool);

const char *fips_getpkeyctxname(EVP_PKEY_CTX *, const char *);
const char *fips_getprovidername(const OSSL_PROVIDER *, const char *);

/* logging helpers (see log.h interfaces) */
#define fips_error_s(...) (fips_logossl(), error(__VA_ARGS__))
#define fips_error_fs(...) (fips_logossl_f(), error_f(__VA_ARGS__))
#define fips_fatal_s(...) (fips_logossl(), fatal(__VA_ARGS__))
#define fips_fatal_fs(...) (fips_logossl_f(), fatal_f(__VA_ARGS__))
#define fips_logossl() (fips_logossl)(__FILE__, __func__, __LINE__, 0)
#define fips_logossl_f() (fips_logossl)(__FILE__, __func__, __LINE__, 1)
void (fips_logossl)(const char *, const char *, int, int);
#define fips_logprovider(what, prov, name) (fips_logprovider)(__FILE__, __func__, __LINE__, 0, (what), (prov), (name))
#define fips_logprovider_f(what, prov, name) (fips_logprovider)(__FILE__, __func__, __LINE__, 1, (what), (prov), (name))
void (fips_logprovider)(const char *, const char *, int, int,
    const char *, const OSSL_PROVIDER *, const char *);

#else /* USE_OPENSSL_FIPS */

#define FIPS_mode() 0

#define fips_logprovider(...) (void)0
#define fips_logprovider_f(...) (void)0

#endif /* USE_OPENSSL_FIPS */

#endif /* FIPS_H */
