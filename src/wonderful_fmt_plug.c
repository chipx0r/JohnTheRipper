/* This software is Copyright (c) 2014, Dhiru Kholia <dhiru at openwall.com>
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_wonderful;
#elif FMT_REGISTERS_H
john_register_one(&fmt_wonderful);
#else

#include <string.h>
#include <errno.h>
#include "arch.h"
#include "md5.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <assert.h>
#include "gost.h"
#include "md5_plug.h"
#include "unicode.h"

#include "memdbg.h"

#define FORMAT_LABEL            "wonderful"
#define FORMAT_NAME             ""
#define FORMAT_TAG              "$wonderful$"
#define TAG_LENGTH              11
#define ALGORITHM_NAME          "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define PLAINTEXT_LENGTH        64
#define BINARY_SIZE             16
#define SALT_SIZE               sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define BINARY_ALIGN            sizeof(ARCH_WORD_32)
#define SALT_ALIGN              sizeof(int)

static struct fmt_tests tests[] = {
	// $wonderful$salt$ ....
	{"$wonderful$$md5$0$109bf4b3611c53176f5c649aa4fc1ff6b2", "password"},
	{"$wonderful$$md5$0$12bb03b2b120eed0bc9934b5ae6e06697d", "password"},
	{"$wonderful$$md5$0$14408f53bf87e92acfd8eff64c13d44653", "password"},
	{"$wonderful$$md5$32$50d41d8cd98f00b204e9800998ecf8427e", "password"},
	{"$wonderful$$gost$0$10635c3b06d0c873034ecd94b5bff64564639e849fa7c9eab0a693781cecd3ab74", "password"},
	{"$wonderful$$sha384$0$1067316ba7d8a6b676943b689914d16888faa1689efc6528033ed31c7f52d3b6911b616d54d0216429356303fe39775bc", "password"},
	{"$wonderful$$sha512$0$10e90d1ce72fb4ea0f12d8b0ecfce428c943562e43dab37aa8e4d525737c69761589805fdce21a89a3439d44819bc1cc45e4c20dd8d3adf64ef56472cb89502589", "password"},

	{"$wonderful$$sha512$0$80ded1bda29058c02f011c01087e12543684821c54d42ac2a9924a1a0ee10830b5a2028a90febc0cda5188517bc79aecdbd720b00895181571496e8688c57ddfa0", "password"},

	{"$wonderful$$md5$0$015f4dcc3b5aa765d61d8327deb882cf99", "password"}, // UNICODE works
	{"$wonderful$$md5$0$01aed1dfbc31703955e64806b799b67645", "\xe4\xb8\xad"}, // UNICODE "中" works!
	{"$wonderful$$md5$0$01aed1dfbc31703955e64806b799b67645", "中"}, // UNICODE works!

	// {"$wonderful$$gost$0$804463230a0698ba7525ebc40383d7c0834d1559e738472b8af305b65965d83a6d", "password"}, // hmac-gost XXX

	{NULL}

};

static unsigned char *xor_arr;
static int local_salt_length;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int length;
	int saltlen;
	char salt[16];
	unsigned int mode;
	unsigned int xor_pos;
	int hash_type;
} *cur_salt;

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}

static void init(struct fmt_main *self)
{
	FILE *fp;
	long pos;
	size_t read;

	saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt, sizeof(*crypt_out));

	/* load "salt.txt" file into "xor_arr" */ // broken in the PHP code ;)

	/* fp = fopen("salt.txt", "rb");
	if (!fp) {
		fprintf(stderr, "[-] unable to load salt.txt file, exiting now!\n");
		exit(-1);
	}

	fseek(fp, 0, SEEK_END);
	pos = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	xor_arr = (unsigned char*)malloc(pos);
	local_salt_length = pos;
	read = fread(xor_arr, 1, pos, fp);
	fprintf(stderr, "[+] read %ld / %ld bytes from salt.txt file!\n", read, pos);
	fclose(fp);
	fp = NULL; */

	gost_init_table();
}

static inline void hex_encode(unsigned char *str, int len, unsigned char *out)
{
	int i;
	for (i = 0; i < len; ++i) {
		out[0] = itoa16[str[i]>>4];
		out[1] = itoa16[str[i]&0xF];
		out += 2;
	}
}

static int hash(int hash_type, unsigned char *inout, int length)
{

	MD5_CTX         m2;
	SHA512_CTX      m6;
	SHA512_CTX      m7;
	gost_ctx        ctx;

	switch(hash_type) {
		case 0:
			MD5_Init(&m2);
			MD5_Update(&m2, inout, length);
			MD5_Final(inout, &m2);
			return 16;
		case 1:
			john_gost_init(&ctx);
			john_gost_update(&ctx, inout, length);
			john_gost_final(&ctx, inout);
			return 32;
		case 2:
			SHA384_Init(&m6);
			SHA384_Update(&m6, inout, length);
			SHA384_Final(inout, &m6);
			return 48;;
		case 3:
			SHA512_Init(&m7);
			SHA512_Update(&m7, inout, length);
			SHA512_Final(inout, &m7);
			return 64;
		default:
			printf("[!] Unexpected hash_type %d found!\n", hash_type);
			exit(-1);
	}
}


static void hash_hmac(int hash_type, unsigned char *data, int datalen, unsigned char *key, int keylen, unsigned char *inout)
{
	const EVP_MD (*fptr);
	unsigned int len;
	unsigned char local_buffer[128] = {0};

	if (hash_type == 0) {
		fptr = EVP_md5();
	}
	else if (hash_type == 1) {
		// john_gost_hmac(key, keylen, data, datalen, local_buffer);
		// print_hex(local_buffer, 32);
	}
	else if (hash_type == 2)
		fptr = EVP_sha384();
	else if (hash_type == 3)
		fptr = EVP_sha512();
	else {
		printf("[!] Unexpected hash_type %d found!\n", hash_type);
		exit(-1);
	}

	if (hash_type != 1) {
		HMAC(fptr, key, keylen, data, datalen, local_buffer, &len);
	}

	memcpy(inout, local_buffer, 16);
}

#define UNICODE   (1 << 0)
#define PERMUTE_L (1 << 1)
#define PERMUTE_P (1 << 2)
#define HASH_L    (1 << 3)
#define HASH_P    (1 << 4)
#define POS       (1 << 5)
#define DO_XOR    (1 << 6)
#define HMAC      (1 << 7)

static void permute(unsigned char *s, int length)
{
	unsigned char buffer[64] = {0};
	int pad = (char)(length);
	int i;
	int map[] = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12,
		4, 62, 54, 46, 38, 30, 22, 14, 6, /* 64, */ 56, 48, 40, 32, 24, 16,
		8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7}; // 63 replacements

	memcpy(buffer, s, length);
	// pad input to ensure minimum length4
	for(i = length; i <= 63; i++) {
		buffer[i] = pad;
	}

	// permute operations
	for(i = 0; i < 63; i++) {
		s[i] = buffer[map[i]];
	}
}

static void do_xor(unsigned char *buffer, uint32_t xor_pos)
{
	int i;
	uint32_t location = 16 * xor_pos;

	// printf("[!] xor_arr location is %d, contents -> ", location);
	// print_hex(xor_arr + location, 16);

	for (i = 0; i < 16; i++) {
		buffer[i] = buffer[i] ^ xor_arr[location + i];
	}
}

static void hash_step(char *password, struct custom_salt *cur_salt, unsigned char *output)
{
	unsigned char password_buffer[2048] = {0};
	unsigned char salt_buffer[2048] = {0};

	unsigned char *p1, *p2;
	int p1_len, p2_len;

	unsigned char buffer[2048] = {0}; /* local operations */
	int mode = cur_salt->mode;
	int saltlen;
	int passlen = strlen(password);
	saltlen = cur_salt->saltlen;

	/* process mode */
	strncpy((char*)password_buffer, password, 2048);
	strncpy((char*)salt_buffer, cur_salt->salt, 2048);

	if (mode & UNICODE) {
		// XXX do nothing? :-)
	}

	if (mode & PERMUTE_L) {
		permute(password_buffer, passlen);
		passlen = 64 - 1; /* password_buffer[64] is skipped in PHP since it results in invalid access */
	}

	if (mode & PERMUTE_P) {
		permute(salt_buffer, saltlen);
		saltlen = 64 - 1; /* salt_buffer[64] is skipped in PHP since it results in invalid access */
	}

	if (mode & HASH_P) {
		passlen = hash(cur_salt->hash_type, password_buffer, passlen);
	}

	if (mode & HASH_L) {
		saltlen = hash(cur_salt->hash_type, salt_buffer, saltlen);
	}

	if (mode & POS) {
		p1 = password_buffer;
		p1_len = passlen;
		p2 = salt_buffer;
		p2_len = saltlen;
	} else {
		p1 = salt_buffer;
		p1_len = saltlen;
		p2 = password_buffer;
		p2_len = passlen;
	}

	if (mode & HMAC) {
		hash_hmac(cur_salt->hash_type, p1, p1_len, p2, p2_len, buffer);
	} else {
		memcpy(buffer, p1, p1_len);
		memcpy(buffer + p1_len, p2, p2_len);
		if (mode & DO_XOR) {
			// do_xor(buffer, cur_salt->xor_pos); // is buggy in PHP and returns a empty string!
			saltlen = passlen = 0;
		}

		// printf("%d %d\n", saltlen, passlen);
		passlen = hash(cur_salt->hash_type, buffer, saltlen + passlen);
	}

	memcpy(output, buffer, BINARY_SIZE); // 16 bytes (BINARY_SIZE) should be enough ;)
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;
	int saltlen = 0;
	int mode;
	int hash_type;
	unsigned char mode_buffer[3] = {0};

	p = ciphertext;

	if(strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return 0;

	// {"$wonderful$$md5$0$109bf4b3611c53176f5c649aa4fc1ff6b2"},
	p += TAG_LENGTH;
	if (!p)
		return 0;

	q = strchr(p, '$');
	if (!q)
		return 0;
	saltlen = q - p;
	assert(saltlen < 256);

	p = q + 1;
	if (!p)
		return 0;

	/* hash_type */
	p = q + 1;

	/* hash_type */
	p = q + 1;
	if(!strncmp(p, "md5", 3))
		hash_type = 0;
	else if (!strncmp(p, "gost", 4))
		hash_type = 1;
	else if (!strncmp(p, "sha384", 6))
		hash_type = 2;
	else if (!strncmp(p, "sha512", 6))
		hash_type = 3;
	else
		return 0;

	/* xor_pos */
	q = strchr(p, '$') + 1;

	/* mode */
	q = strrchr(ciphertext, '$') + 1;
	memcpy(mode_buffer, q, 2);
	mode = strtoul((char*)mode_buffer, NULL, 16);

	if (mode & PERMUTE_P) {
		//puts("pp Rej");
		// return 0;
	}
	if (mode & PERMUTE_L) {
		// puts("pl Rej");
		// return 0;
	}
	if (mode & DO_XOR) {
		// puts("xor Rej");
		// return 0;
	}
	if ((mode & HMAC) && hash_type == 1) {
		puts("hmac-gost rej");
		return 0;
	}

	return 1;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *p, *q;
	char mode_buffer[3] = {0};

	memset(&cs, 0, SALT_SIZE);
	p = ciphertext + TAG_LENGTH;

	/* extract salt */
	q = strchr(p, '$');
	if (!q)
		return 0;
	cs.saltlen = q - p;
	if (cs.saltlen)
		strncpy(cs.salt, p, cs.saltlen);

	/* hash_type */
	p = q + 1;
	if(!strncmp(p, "md5", 3))
		cs.hash_type = 0;
	else if (!strncmp(p, "gost", 4))
		cs.hash_type = 1;
	else if (!strncmp(p, "sha384", 6))
		cs.hash_type = 2;
	else if (!strncmp(p, "sha512", 6))
		cs.hash_type = 3;
	else
		cs.hash_type = 255;

	/* xor_pos */
	q = strchr(p, '$') + 1;
	cs.xor_pos = atoi(q);

	/* mode */
	q = strrchr(ciphertext, '$') + 1;
	memcpy(mode_buffer, q, 2);
	cs.mode = strtoul(mode_buffer, NULL, 16);

	return (void*)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	p = strrchr(ciphertext, '$') + 1 + 2;  // first 2 chars => mode
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return (void*)out;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	for (index = 0; index < count; index++)
	{
		hash_step(saved_key[index], cur_salt, (unsigned char*)crypt_out[index]);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (((ARCH_WORD_32*)binary)[0] == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return *((ARCH_WORD_32*)binary) == crypt_out[index][0];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void wonderful_set_key(char *key, int index)
{
	int saved_len = strlen(key);
	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_wonderful = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_UTF8,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests,
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		wonderful_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
