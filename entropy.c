/*
 * Copyright (c) 2001 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#define RANDOM_SEED_SIZE 48

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#ifdef USE_OPENSSL_FIPS
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/self_test.h>
#endif

#include "openbsd-compat/openssl-compat.h"

#include "ssh.h"
#include "misc.h"
#include "xmalloc.h"
#include "atomicio.h"
#include "pathnames.h"
#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"

/*
 * Portable OpenSSH PRNG seeding:
 * If OpenSSL has not "internally seeded" itself (e.g. pulled data from
 * /dev/random), then collect RANDOM_SEED_SIZE bytes of randomness from
 * PRNGd.
 */

void
seed_rng(void)
{
	unsigned char buf[RANDOM_SEED_SIZE];

#ifdef USE_OPENSSL_FIPS
	fips_init();
#else
	/* Initialise libcrypto */
	ssh_libcrypto_init();
#endif /* USE_OPENSSL_FIPS */

	if (!ssh_compatible_openssl(OPENSSL_VERSION_NUMBER,
	    OpenSSL_version_num()))
		fatal("OpenSSL version mismatch. Built against %lx, you "
		    "have %lx", (u_long)OPENSSL_VERSION_NUMBER,
		    OpenSSL_version_num());

#ifndef OPENSSL_PRNG_ONLY
	if (RAND_status() == 1)
		debug3("RNG is ready, skipping seeding");
	else {
		if (seed_from_prngd(buf, sizeof(buf)) == -1)
			fatal("Could not obtain seed from PRNGd");
		RAND_add(buf, sizeof(buf), sizeof(buf));
	}
#endif /* OPENSSL_PRNG_ONLY */

	if (RAND_status() != 1)
		fatal("PRNG is not seeded");

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, sizeof(buf));
	explicit_bzero(buf, sizeof(buf));
}

#ifdef USE_OPENSSL_FIPS
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

	/*
	 * XXX: need better error checking
	 *
	 * XXX: need to devise and implement (or document) fallback policies
	 *
	 * XXX: is it necessary to explicitly load base?
	 */
	if (!OSSL_PROVIDER_load(NULL, "base")) {
		error_f("unable to load base provider");
		return;
	}
	EVP_default_properties_enable_fips(NULL, 1);

	fips_enabled = 1;
}

#endif /* USE_OPENSSL_FIPS */

#else /* WITH_OPENSSL */

#include <stdlib.h>
#include <string.h>

/* Actual initialisation is handled in arc4random() */
void
seed_rng(void)
{
	unsigned char buf[RANDOM_SEED_SIZE];

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, sizeof(buf));
	explicit_bzero(buf, sizeof(buf));
}

#endif /* WITH_OPENSSL */
