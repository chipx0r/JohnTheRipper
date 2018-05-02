/*
 * JtR format to crack Adobe AES (Adobe Experience Manager) hashes.
 *
 * This software is Copyright (c) 2018, Dhiru Kholia <kholia at kth.se> and it
 * is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * See "generateHash" in PasswordUtil.java from the following project,
 * https://github.com/apache/jackrabbit-oak.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_aem;
#elif FMT_REGISTERS_H
john_register_one(&fmt_aem);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               1  // MKPC and OMP_SCALE tuned on XXX

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "jumbo.h"
#include "sha2.h"
#include "aem_common.h"
#include "memdbg.h"

#define FORMAT_LABEL            "aem"
#define ALGORITHM_NAME          "SHA-256 / SHA-512"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(uint64_t)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      16

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(crypt_out);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void aem_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char buffer[64];
		SHA256_CTX ctx;
		SHA512_CTX bctx;
		int i;

		if (cur_salt->algo == 1) {
			// Initial step
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, cur_salt->salt, cur_salt->salt_length);
			SHA256_Update(&ctx, saved_key[index], strlen(saved_key[index]));
			SHA256_Final(buffer, &ctx);

			// Loop
			for (i = 0; i < cur_salt->iterations - 1; i++) {
				SHA256_Init(&ctx);
				SHA256_Update(&ctx, buffer, 32);
				SHA256_Final(buffer, &ctx);
			}
		} else {
			SHA512_Init(&bctx);
			SHA512_Update(&bctx, cur_salt->salt, cur_salt->salt_length);
			SHA512_Update(&bctx, saved_key[index], strlen(saved_key[index]));
			SHA512_Final(buffer, &bctx);

			for (i = 0; i < cur_salt->iterations - 1; i++) {
				SHA512_Init(&bctx);
				SHA512_Update(&bctx, buffer, 64);
				SHA512_Final(buffer, &bctx);
			}
		}

		memcpy(crypt_out[index], buffer, BINARY_SIZE_CMP);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (((uint32_t*)binary)[0] == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE_CMP);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_aem = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{
			"iteration count",
		},
		{ "{SHA-" }, // hack, hopefully magnum won't see this
		aem_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		aem_common_valid,
		fmt_default_split,
		aem_common_get_binary,
		aem_common_get_salt,
		{
			aem_common_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		aem_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
