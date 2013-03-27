#include <ctype.h>
#include <getopt.h>
#include "common.h"
#include "openssl/aes.h"
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include "openssl/hmac.h"

#define SIZE BUFSIZE

void tokenize_inputfile(char* in, char** abe, char** aes, char** iv);
int read_inputfile(char *inputfile, char **abe_blob64);
FENC_ERROR search_inputfile(char *input_file, char *index_file, fenc_context *context, fenc_trapdoor_KSFCP *trapdoor, fenc_Q_KSFCP *Q);
Bool search(FENC_SCHEME_TYPE scheme, char *g_params, char *public_params, char *path_file, char *trapdoor_file, char *outfile);

int main (int argc, char *argv[]) {

	FENC_SCHEME_TYPE mode = FENC_SCHEME_KSFCP;
	char *public_params = PUBLIC_FILE".ksfcp";
	char *path_file = "filepath.txt";
	char *trapdoor_file = "userCP.trapdoor";
	char *outfile = "searchresult.txt";

	return search(mode, PARAM, public_params, path_file, trapdoor_file, outfile);

}

void print_help(void)
{
	printf("Usage: ./ksf-search \n\n");
}

/* This function tokenizes the input file with the
expected format: "ABE_TOKEN : base-64 : ABE_TOKEN_END :
				  IV : base64 : IV :
				  AES_TOKEN : base-64 : AES_TOKEN_END"
 */
void tokenize_inputfile(char* in, char** abe, char** aes, char** iv)
{
	ssize_t abe_len, aes_len, iv_len;
	char delim[] = ":";
	char *token = strtok(in, delim);
	while (token != NULL) {
		if(strcmp(token, ABE_TOKEN) == 0) {
			token = strtok(NULL, delim);
			abe_len = strlen(token);
			if((*abe = (char *) malloc(abe_len+1)) != NULL) {
				strncpy(*abe, token, abe_len);
				(*abe)[abe_len] = '\0';
			}
		}
		else if(strcmp(token, AES_TOKEN) == 0) {
			token = strtok(NULL, delim);
			aes_len = strlen(token);
			if((*aes = (char *) malloc(aes_len+1)) != NULL) {
				strncpy(*aes, token, aes_len);
				(*aes)[aes_len] = '\0';
			}
		}
		else if(strcmp(token, IV_TOKEN) == 0) {
			token = strtok(NULL, delim);
			iv_len = strlen(token);
			if((*iv = (char *) malloc(iv_len+1)) != NULL) {
				strncpy(*iv, token, iv_len);
				(*iv)[iv_len] = '\0';
			}
		}
		token = strtok(NULL, delim);
	}
}

int read_inputfile(char *inputfile, char **abe_blob64)
{
	char *input_buf = NULL;
	char *aes_blob64 = NULL, *iv_blob64 = NULL;
	size_t input_len;
	FILE *fp;

	/* Load user's input file */
	fp = fopen(inputfile, "r");
	if(fp != NULL) {
		if((input_len = read_file(fp, &input_buf)) > 0) {
			// printf("Input file: %s\n", input_buf);
			tokenize_inputfile(input_buf, abe_blob64, &aes_blob64, &iv_blob64);
			debug("abe ciphertext = '%s'\n", abe_blob64);
			//debug("init vector = '%s'\n", iv_blob64);
			//debug("aes ciphertext = '%s'\n", aes_blob64);
			free(input_buf);
			free(aes_blob64);
			free(iv_blob64);
		}
	}
	else {
		fprintf(stderr, "Could not load input file: %s\n", inputfile);
		return -1;
	}
	fclose(fp);

	/* make sure the abe ptrs are set */
	if(abe_blob64 == NULL) {
		fprintf(stderr, "Input file either not well-formed or not encrypted.\n");
		return -1;
	}
	return 0;
}

FENC_ERROR search_inputfile(char *input_file, char *index_file, fenc_context *context, fenc_trapdoor_KSFCP *trapdoor, fenc_Q_KSFCP *Q)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	fenc_ciphertext ciphertext;
	char *abe_blob64 = NULL;
	FILE *fp;

	if(0 != read_inputfile(input_file, &abe_blob64))
		return FENC_ERROR_INVALID_CIPHERTEXT;

	memset(&ciphertext, 0, sizeof(fenc_ciphertext));

	size_t abeLength;
	uint8 *data = NewBase64Decode((const char *) abe_blob64, strlen(abe_blob64), &abeLength);
	ciphertext.data = data;
	ciphertext.data_len = abeLength;
	ciphertext.max_len = abeLength;
	free(abe_blob64);

	/* Match ciphertext. */
	result = libfenc_match_KSFCP(context, &ciphertext, trapdoor, Q);
	if(result != FENC_ERROR_NONE){
		goto cleanup;
	}

	/* Keyword Search ciphertext. */

cleanup:
	//ciphertext

	free(data);
	return result;
}

int search(FENC_SCHEME_TYPE scheme, char *g_params, char *public_params, char *path_file, char *trapdoor_file, char *outfile)
{
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	fenc_trapdoor_KSFCP trapdoor;
	fenc_Q_KSFCP Q;
	pairing_t pairing;
	FILE *fp, *out_fp;
	char c;
	int pub_len = 0;
	size_t serialized_len = 0;
	char public_params_buf[SIZE];
	char *trapdoor_buf = NULL;
	ssize_t trapdoor_len;

	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));
	memset(&public_params_buf, 0, SIZE);


	/* Initialize the library. */
	result = libfenc_init();
	/* Create a Sahai-Waters context. */
	result = libfenc_create_context(&context, scheme);
	/* Load group parameters from a file. */
	fp = fopen(g_params, "r");
	if (fp != NULL) {
		libfenc_load_group_params_from_file(&group_params, fp);
		libfenc_get_pbc_pairing(&group_params, pairing);
	} else {
		perror("Could not open parameters file");
		return -1;
	}
	fclose(fp);

	/* Set up the global parameters. */
	result = context.generate_global_params(&global_params, &group_params);
	report_error("Loading global parameters", result);

	result = libfenc_gen_params(&context, &global_params);
	report_error("Generating scheme parameters and secret key", result);

	/* read public parameters file */
	fp = fopen(public_params, "r");
	if(fp != NULL) {
		while (TRUE) {
			c = fgetc(fp);
			if(c != EOF) {
				// statically allocated to prevent memory leaks
				public_params_buf[pub_len] = c;
				pub_len++;
			}
			else {
				break;
			}
		}
	}
	else {
		fprintf(stderr, "Could not load input file: %s\n", public_params);
		return -1;
	}
	fclose(fp);

	debug("public params input = '%s'\n", public_params_buf);

	/* base-64 decode public parameters */
	uint8 *bin_public_buf = NewBase64Decode((const char *) public_params_buf, pub_len, &serialized_len);
	// printf("public params binary = '%s'\n", bin_public_buf);

	/* Import the parameters from binary buffer: */
	result = libfenc_import_public_params(&context, bin_public_buf, serialized_len);
	report_error("Importing public parameters", result);


	/* read trapdoor file */
	debug("trapdoor => '%s'\n", trapdoor_file);
	fp = fopen(trapdoor_file, "r");
	if(fp != NULL) {
		if((trapdoor_len = read_file(fp, &trapdoor_buf)) > 0) {
			size_t bin_trapdoor_len;
			uint8 *bin_trapdoor_buf = NewBase64Decode((const char *) trapdoor_buf, trapdoor_len, &bin_trapdoor_len);
			free(trapdoor_buf);

			/* base-64 decode user's trapdoor */
			debug("Base-64 decoded buffer:\t");
#ifdef DEBUG
			print_buffer_as_hex(bin_trapdoor_buf, bin_trapdoor_len);
#endif
			result = libfenc_import_trapdoor_KSFCP(&context, &trapdoor, bin_trapdoor_buf, bin_trapdoor_len);
			report_error("Importing trapdoor", result);

		}
	}
	else {
		fprintf(stderr, "Could not load input file: %s\n", trapdoor_file);
		/* clear allocated possibly allocated memory */
		return -1;
	}
	fclose(fp);


	/* searching */

	char input_file[MAX_PATH_SIZE];
	char index_file[MAX_PATH_SIZE];
	char Q_buf[SIZE];
	int Q_buf_len, b64_Q_buf_len;

	fp = fopen(path_file, "r");
	out_fp = fopen(outfile, "w");
	while(freadline(input_file, MAX_PATH_SIZE, fp))
	{
		freadline(input_file, MAX_PATH_SIZE, fp);
		FENC_ERROR search_result = search_inputfile(input_file, index_file, &context, &trapdoor, &Q);

		char Q_file[MAX_PATH_SIZE];
		strcat(Q_file, input_file);
		strcat(Q_file, ".Q");

		if(search_result == FENC_ERROR_NONE){
			fprintf(out_fp, "%s\n%s\n", input_file, Q_file);
		}

		libfenc_export_Q_KSFCP(&context, &Q, Q_buf, SIZE, &Q_buf_len);
		char *bin_Q_buf = NewBase64Encode(Q_buf, Q_buf_len, FALSE, &b64_Q_buf_len);

		FILE *Q_fp = fopen(Q_file, "w");
		if(Q_fp != NULL) {
			fprintf(Q_fp, "%s", b64_Q_buf_len);
		}
		else {
			perror("Error writing Q.");
		}
		fclose(Q_fp);

		/* free allocated memory */
		free(bin_Q_buf);

	}
	fclose(out_fp);
	fclose(fp);


	/* free allocated memory */
	//trapdoor

	/* Destroy the context. */
	result = libfenc_destroy_context(&context);
	report_error("Destroying the encryption context", result);

	/* Shutdown the library. */
	result = libfenc_shutdown();
	report_error("Shutting down library", result);
	return 0;
}

