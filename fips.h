#ifndef FIPS_H
#define FIPS_H

#ifdef USE_OPENSSL_FIPS

#include <openssl/provider.h>

#define FIPS_mode() fips_isenabled()
void fips_init(void);
_Bool fips_isenabled(void);
void fips_setenabled(_Bool);

_Bool fips_canskipforkeytype(const char *);
_Bool fips_isdefaultforkeytype(const char *);

const char *fips_getprovidername(const OSSL_PROVIDER *, const char *);

/* logging helpers (see log.h interfaces) */
#define fips_error_s(...) (fips_logossl(), error(__VA_ARGS__))
#define fips_error_fs(...) (fips_logossl_f(), error_f(__VA_ARGS__))
#define fips_fatal_s(...) (fips_logossl(), fatal(__VA_ARGS__))
#define fips_fatal_fs(...) (fips_logossl_f(), fatal_f(__VA_ARGS__))

#define fips_logossl() (fips_logossl)(__FILE__, __func__, __LINE__, 0)
#define fips_logossl_f() (fips_logossl)(__FILE__, __func__, __LINE__, 1)
void (fips_logossl)(const char *, const char *, int, int);

void fips_logprovider_EVP_CIPHER(const char *, const char *, int, int, const EVP_CIPHER *);
void fips_logprovider_EVP_CIPHER_CTX(const char *, const char *, int, int, const EVP_CIPHER_CTX *);
void fips_logprovider_EVP_KDF(const char *, const char *, int, int, const EVP_KDF *);
void fips_logprovider_EVP_KDF_CTX(const char *, const char *, int, int, const EVP_KDF_CTX *);
void fips_logprovider_EVP_MD(const char *, const char *, int, int, const EVP_MD *);
void fips_logprovider_EVP_MD_CTX(const char *, const char *, int, int, const EVP_MD_CTX *);
void fips_logprovider_EVP_PKEY(const char *, const char *, int, int, const EVP_PKEY *);
void fips_logprovider_EVP_PKEY_CTX(const char *, const char *, int, int, const EVP_PKEY_CTX *);
/*
 * NB: fips_logprovider_UNKNOWN is deliberately not defined in order to
 * induce a link error when passing unknown types to fips_logprovider, but a
 * a prototype is required to avoid warnings due to semantics of _Generic.
 * For similar semantic reasons a _Static_assert wouldn't work.
 */
extern void fips_logprovider_UNKNOWN(void);

#define fips_logprovider_T(showfunc, evp, T) \
	fips_logprovider_##T(__FILE__, __func__, __LINE__, (showfunc), (const T *)(evp))
#define fips_logprovider_EVP(showfunc, evp) \
	_Generic(evp, \
	const EVP_CIPHER *: fips_logprovider_T((showfunc), (evp), EVP_CIPHER), \
	const EVP_CIPHER_CTX *: fips_logprovider_T((showfunc), (evp), EVP_CIPHER_CTX), \
	const EVP_KDF *: fips_logprovider_T((showfunc), (evp), EVP_KDF), \
	const EVP_KDF_CTX *: fips_logprovider_T((showfunc), (evp), EVP_KDF_CTX), \
	const EVP_MD *: fips_logprovider_T((showfunc), (evp), EVP_MD), \
	const EVP_MD_CTX *: fips_logprovider_T((showfunc), (evp), EVP_MD_CTX), \
	const EVP_PKEY *: fips_logprovider_T((showfunc), (evp), EVP_PKEY), \
	const EVP_PKEY_CTX *: fips_logprovider_T((showfunc), (evp), EVP_PKEY_CTX), \
	EVP_CIPHER *: fips_logprovider_EVP_CIPHER(__FILE__, __func__, __LINE__, (showfunc), (const EVP_CIPHER *)(evp)), \
	EVP_CIPHER_CTX *: fips_logprovider_EVP_CIPHER_CTX(__FILE__, __func__, __LINE__, (showfunc), (const EVP_CIPHER_CTX *)(evp)), \
	EVP_KDF *: fips_logprovider_EVP_KDF(__FILE__, __func__, __LINE__, (showfunc), (const EVP_KDF *)(evp)), \
	EVP_KDF_CTX *: fips_logprovider_EVP_KDF_CTX(__FILE__, __func__, __LINE__, (showfunc), (const EVP_KDF_CTX *)(evp)), \
	EVP_MD *: fips_logprovider_EVP_MD(__FILE__, __func__, __LINE__, (showfunc), (const EVP_MD *)(evp)), \
	EVP_MD_CTX *: fips_logprovider_EVP_MD_CTX(__FILE__, __func__, __LINE__, (showfunc), (const EVP_MD_CTX *)(evp)), \
	EVP_PKEY *: fips_logprovider_EVP_PKEY(__FILE__, __func__, __LINE__, (showfunc), (const EVP_PKEY *)(evp)), \
	EVP_PKEY_CTX *: fips_logprovider_EVP_PKEY_CTX(__FILE__, __func__, __LINE__, (showfunc), (const EVP_PKEY_CTX *)(evp)), \
	default: fips_logprovider_UNKNOWN())

#define fips_logprovider(evp) fips_logprovider_EVP(0, (evp))
#define fips_logprovider_f(evp) fips_logprovider_EVP(1, (evp))
void (fips_logprovider)(const char *, const char *, int, int,
    const char *, const OSSL_PROVIDER *, const char *);

#else /* USE_OPENSSL_FIPS */

#define FIPS_mode() 0

#define fips_logprovider(...) (void)0
#define fips_logprovider_f(...) (void)0

#endif /* USE_OPENSSL_FIPS */

#endif /* FIPS_H */
