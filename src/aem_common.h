/*
 * Common code for the Adobe AEM format.
 */

#include "formats.h"

#define FORMAT_NAME             "Adobe AEM"
#define FORMAT_TAG_1            "{SHA-256}"
#define FORMAT_TAG_2            "{SHA-512}"
#define TAG_LENGTH              (sizeof(FORMAT_TAG_1) - 1)
#define BINARY_SIZE             64
#define BINARY_SIZE_CMP         16

#define MAX_SALTLEN             32

struct custom_salt{
	int salt_length;
	int iterations;
	int algo;
	unsigned char salt[MAX_SALTLEN];
};

extern struct fmt_tests aem_tests[];

int aem_common_valid(char *ciphertext, struct fmt_main *self);
void *aem_common_get_salt(char *ciphertext);
extern void *aem_common_get_binary(char *ciphertext);
unsigned int aem_common_iteration_count(void *salt);
