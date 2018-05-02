/*
 * Common code for the Adobe AEM format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "aem_common.h"
#include "memdbg.h"

struct fmt_tests aem_tests[] = {
	// Real hashes
	{"{SHA-256}a9d4b340cb43807b-1000-33b8875ff3f9619e6ae984add262fb6b6f043e8ff9b065f4fb0863021aada275", "admin"},
	{"{SHA-256}fe90d85cdcd7e79c-1000-ef182cdc47e60b472784e42a6e167d26242648c6b2e063dfd9e27eec9aa38912", "Aa12345678!@"},
	// Artificial hash(es)
	{"{SHA-512}fe90d85cdcd7e79c-1000-4c29a0ac964e7bbc5380797f294d15928288cbcde3d501eb8746296de8d6c06b2b5ff27b56ae174744fe69ee157614ad126c1315ee3b67c891e42753e01a3e37", "Aa12345678!@"},
	{NULL}
};

int aem_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG_1, TAG_LENGTH) != 0 && strncmp(ciphertext, FORMAT_TAG_2, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "-")) == NULL) // salt
		goto err;
	if (strlen(p) > MAX_SALTLEN)
		goto err;
	if ((p = strtokm(NULL, "-")) == NULL)   // iterations
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "-")) == NULL)   // hash
		goto err;
	if (hexlenl(p, &extra) > BINARY_SIZE * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *aem_common_get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	static struct custom_salt *cs;

	cs = mem_calloc_tiny(sizeof(struct custom_salt), sizeof(uint64_t));
	if (!strncmp(ciphertext, FORMAT_TAG_1, TAG_LENGTH))
		cs->algo = 1;
	else
		cs->algo = 2;

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "-");
	strncpy((char*)cs->salt, p, sizeof(cs->salt) - 1);
	cs->salt[sizeof(cs->salt) - 1] = 0;
	cs->salt_length = strlen((char*)cs->salt);
	p = strtokm(NULL, "-");
	cs->iterations = atoi(p);
	MEM_FREE(keeptr);

	return (void *)cs;
}

void *aem_common_get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	memset(buf.c, 0, BINARY_SIZE);
	p = strrchr(ciphertext, '-') + 1;
	for (i = 0; i < BINARY_SIZE_CMP; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

unsigned int aem_common_iteration_count(void *salt)
{
	struct custom_salt *cs = salt;

	return (unsigned int) cs->iterations;
}
