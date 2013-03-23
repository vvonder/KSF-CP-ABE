#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <libfenc.h>
#include <libfenc_group_params.h>
#include <libfenc_ABE_common.h>
#include <libfenc_LSSS.h>
#include <libfenc_WatersCP.h>
#include <libfenc_LSW.h>
#include <abe_policy.h>
#include <pbc/pbc.h>
#include <math.h>
#include "base64.h"

#define SCHEME_LSW "KP"
#define SCHEME_WCP "CP"
#define SCHEME_WSCP "SCP"
enum Scheme {LSW, WCP, SWCP, NONE};
typedef enum Scheme SchemeType;

#ifdef DEBUG
#define debug(...)	printf(__VA_ARGS__)
#define debug_e(...)	element_printf("DEBUG: "__VA_ARGS__)
#else
#define debug(...)
#define debug_e(...)
#endif

#define KEYSIZE_MAX 15000
#define SIZE 2048
#define SIZE_MAX KEYSIZE_MAX
#define MAX_ATTRIBUTES 100
#define SESSION_KEY_LEN 16

#define PARAM "d224.param"
#define MAGIC "ABE|"
#define IV_TOKEN "IV"
#define IV_TOKEN_END "IV_END"
#define AES_TOKEN "AES"
#define AES_TOKEN_END "AES_END"
#define ABE_TOKEN "ABE_CP"
#define ABE_TOKEN_END "ABE_CP_END"

#define PUBLIC_FILE "public.param"
#define SECRET_FILE "secret.param"

void report_error(char* action, FENC_ERROR result);
ssize_t read_file(FILE *f, char** out);
void print_help(void);
void print_buffer_as_hex(uint8* data, size_t len);

#endif
