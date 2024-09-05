/*
 * Copyright (c) 2024 Akamai Technologies, Inc. All Rights Reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "includes.h"
#include "log.h"

#include <string.h>

#ifdef USE_OPENSSL_FIPS
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/self_test.h>

static _Bool fips_enabled = 0;

static int
self_test_cb(const OSSL_PARAM params[], void *arg)
{
	const OSSL_PARAM *p = NULL;
	const char *phase = "?", *type = "?", *desc = "?";

	p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_PHASE);
	if (p && p->data_type == OSSL_PARAM_UTF8_STRING)
		phase = (const char *)p->data;

	p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_DESC);
	if (p || p->data_type == OSSL_PARAM_UTF8_STRING)
		desc = (const char *)p->data;

	p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_TYPE);
	if (p || p->data_type == OSSL_PARAM_UTF8_STRING)
		type = (const char *)p->data;

	if (strcmp(phase, OSSL_SELF_TEST_PHASE_PASS) == 0) {
		debug3_f("%s: %s: %s", desc, type, phase);
	} else if (strcmp(phase, OSSL_SELF_TEST_PHASE_FAIL) == 0) {
		error_f("%s: %s: %s", desc, type, phase);
	}

	return 1;
}

static void
fips_initonce(void)
{
	static int initialized = 0;
	const char *v;

	if (initialized)
		return;
	initialized = 1;

	/*
	 * Try to detect and log configuration issues as early as possible.
	 * Various API functions (including EVP_default_properties_*) will
	 * trigger configuration loading, anyhow, but most callers outside
	 * this module are likely to drop any error messages on the floor.
	 */
	if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL)) {
		fips_error_fs("error loading OpenSSL configuration");
	}

	OSSL_SELF_TEST_set_callback(NULL, &self_test_cb, NULL);

	if (EVP_default_properties_is_fips_enabled(NULL)) {
		fips_setenabled(1);
	}

	if ((v = getenv("OPENSSL_FIPS"))) {
		if (*v == '1') {
			fips_setenabled(1);
		} else {
			error_f("OPENSSL_FIPS: expected '1', got 0x%.2x", *v);
		}
	}

	if ((v = getenv("SSH_FIPS"))) {
		if (*v == '1') {
			fips_setenabled(1);
		} else {
			error_f("SSH_FIPS: expected '1', got 0x%.2x", *v);
		}
	}

	/*
	 * Carp about the absence of both default and base providers as (at
	 * the time of writing) there are some error paths elsewhere which
	 * leave no hint about the root, configuration-related issue.
	 *
	 * Note that this simple constraint (at least one of base or default
	 * available) is still met in some otherwise similar cases. Be
	 * careful what implications you draw in the absence of this logging
	 * hint.
	 */
	if (!OSSL_PROVIDER_available(NULL, "default") &&
	    !OSSL_PROVIDER_available(NULL, "base")) {
		fips_error_fs("neither default nor base provider available");
	}
}

void
fips_init(void)
{
	fips_initonce();
}

_Bool
fips_isenabled(void)
{
	fips_initonce();

	return fips_enabled;
}

void
fips_setenabled(_Bool enabled)
{
	fips_initonce();

	if (!enabled) {
		if (fips_enabled)
			error_f("refusing to downgrade FIPS");
		return;
	} else if (fips_enabled) {
		return;
	}

	if (!EVP_default_properties_enable_fips(NULL, 1)) {
		fips_error_fs("unable to enable default fips property");
		return;
	}
	/*
	 * Ensure fips is loaded first; that's the most important provider,
	 * and it will also have the side effect of disabling default
	 * default (sic) loading.
	 */
	if (!OSSL_PROVIDER_load(NULL, "fips")) {
		fips_error_fs("unable to load fips provider");
		return;
	}
	/*
	 * Don't load base if default is loaded; that would result in
	 * duplicate registrations as default encoders and decoders already
	 * report the fips property. (XXX: Alternatively, always load base,
	 * possibly unloading default.)
	 *
	 * NB: OSSL_PROVIDER_available MUST be called AFTER we attempt to
	 * explicitly load the fips module above as OSSL_PROVIDER_available
	 * can have the side effect of loading the default provider if no
	 * provider has yet been activate.
	 */
	if (!OSSL_PROVIDER_available(NULL, "default")) {
		if (!OSSL_PROVIDER_load(NULL, "base")) {
			fips_error_fs("unable to load base provider");
			return;
		}
	}

	fips_enabled = 1;
}

/*
 * return whether we can (attempt to) set "provider!=fips" property for key
 * type
 */
_Bool
fips_canskipforkeytype(const char *keytype)
{
	/*
	 * XXX: it would be better to define and check an openssl.cnf
	 * configuration value rather than hardcode a heuristic
	 */
	return !FIPS_mode() && OSSL_PROVIDER_available(NULL, "default") &&
	    fips_isdefaultforkeytype(keytype);
}

/* return whether fips is default provider for specified keytype */
_Bool
fips_isdefaultforkeytype(const char *keytype)
{
	EVP_KEYMGMT *keymgmt = EVP_KEYMGMT_fetch(NULL, keytype, NULL);
	const OSSL_PROVIDER *prov = (keymgmt) ?
	    EVP_KEYMGMT_get0_provider(keymgmt) : NULL;
	const char *provname = (prov) ? OSSL_PROVIDER_get0_name(prov) : NULL;
	_Bool ret = (provname) ? 0 == strcmp("fips", provname) : 0;
	EVP_KEYMGMT_free(keymgmt);
	return ret;
}

const char *
fips_getprovidername(const OSSL_PROVIDER *prov, const char *unknown)
{
	const char *name = (prov) ? OSSL_PROVIDER_get0_name(prov) : NULL;
	return (name) ? name : unknown;
}

void
(fips_logossl)(const char *file, const char *func, int line, int showfunc)
{
	unsigned long e;

	while ((e = ERR_get_error()) != 0) {
		sshlog(file, func, line, showfunc, SYSLOG_LEVEL_ERROR, NULL,
		    "libcrypto error: %s", ERR_error_string(e, NULL));
	}
}

void
(fips_logprovider)(const char *file, const char *func, int line, int showfunc,
    const char *what, const OSSL_PROVIDER *prov, const char *name)
{
	sshlog(file, func, line, showfunc, SYSLOG_LEVEL_DEBUG2, NULL,
	    "%s object provider:%s name:%s", what,
	    fips_getprovidername(prov, "-"),
	    (name) ? name : "-");
}

void
fips_logprovider_EVP_CIPHER(const char *file, const char *func, int line,
    int showfunc, const EVP_CIPHER *cipher)
{
	(fips_logprovider)(file, func, line, showfunc, "EVP_CIPHER",
	    EVP_CIPHER_get0_provider(cipher),
	    EVP_CIPHER_get0_name(cipher));
}

void
fips_logprovider_EVP_CIPHER_CTX(const char *file, const char *func, int line,
    int showfunc, const EVP_CIPHER_CTX *ctx)
{
	const EVP_CIPHER *cipher = EVP_CIPHER_CTX_get0_cipher(ctx);
	(fips_logprovider)(file, func, line, showfunc, "EVP_CIPHER_CTX",
	    (cipher) ? EVP_CIPHER_get0_provider(cipher) : NULL,
	    (cipher) ? EVP_CIPHER_get0_name(cipher) : NULL);
}

void
fips_logprovider_EVP_MD(const char *file, const char *func, int line,
    int showfunc, const EVP_MD *md)
{
	(fips_logprovider)(file, func, line, showfunc, "EVP_MD",
	    EVP_MD_get0_provider(md),
	    EVP_MD_get0_name(md));
}

void
fips_logprovider_EVP_MD_CTX(const char *file, const char *func, int line,
    int showfunc, const EVP_MD_CTX *ctx)
{
	const EVP_MD *md = EVP_MD_CTX_get0_md(ctx);
	(fips_logprovider)(file, func, line, showfunc, "EVP_MD_CTX",
	    (md) ? EVP_MD_get0_provider(md) : NULL,
	    (md) ? EVP_MD_CTX_get0_name(ctx) : NULL);
}

void
fips_logprovider_EVP_KDF(const char *file, const char *func, int line,
    int showfunc, const EVP_KDF *kdf)
{
	(fips_logprovider)(file, func, line, showfunc, "EVP_KDF",
	    EVP_KDF_get0_provider(kdf),
	    EVP_KDF_get0_name(kdf));
}

void
fips_logprovider_EVP_KDF_CTX(const char *file, const char *func, int line,
    int showfunc, const EVP_KDF_CTX *ctx)
{
	/* EVP_KDF_CTX_kdf accidentally declared to take non-const */
	const EVP_KDF *kdf = EVP_KDF_CTX_kdf((EVP_KDF_CTX *)ctx);
	(fips_logprovider)(file, func, line, showfunc, "EVP_KDF_CTX",
	    (kdf) ? EVP_KDF_get0_provider(kdf) : NULL,
	    (kdf) ? EVP_KDF_get0_name(kdf) : NULL);
}

void
fips_logprovider_EVP_PKEY(const char *file, const char *func, int line,
    int showfunc, const EVP_PKEY *pkey)
{
	(fips_logprovider)(file, func, line, showfunc, "EVP_PKEY",
	    EVP_PKEY_get0_provider(pkey),
	    EVP_PKEY_get0_type_name(pkey));
}

void
fips_logprovider_EVP_PKEY_CTX(const char *file, const char *func, int line,
    int showfunc, const EVP_PKEY_CTX *ctx)
{
	const EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey((EVP_PKEY_CTX *)ctx);
	(fips_logprovider)(file, func, line, showfunc, "EVP_PKEY_CTX",
	    EVP_PKEY_CTX_get0_provider(ctx),
	    (pkey) ? EVP_PKEY_get0_type_name(pkey) : NULL);
}

#endif /* USE_OPENSSL_FIPS */
