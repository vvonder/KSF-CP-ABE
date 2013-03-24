#include <ctype.h>
#include <getopt.h>
#include "common.h"

#define SIZE BUFSIZE

int gen_ukeys(FENC_SCHEME_TYPE scheme, char *g_params, char *public_params, char *uskfile ,char *upkfile);
/* Description: mgabe-setup takes no arguments and simply reads in the global parameters from the filesystem,
 and generates the public parameters (or public key) and the master secret parameters (or master secret key).
 It serializes and writes to disk the public parameters and the master secret key.
 */
int main(int argc, char * argv[]) {
	FENC_SCHEME_TYPE mode = FENC_SCHEME_KSFCP;
	char *public_params = PUBLIC_FILE".ksfcp";
	char *uskfile = "USK.ksfcp";
	char *upkfile = "UPK.ksfcp";

	return gen_ukeys(mode, PARAM, public_params, uskfile, upkfile);
}


int gen_ukeys(FENC_SCHEME_TYPE scheme, char *g_params, char *public_params, char *uskfile ,char *upkfile) {
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	pairing_t pairing;
	FILE *fp;
	int c;
	size_t serialized_len = 0;
	size_t pub_len = 0;
	uint8 public_params_buf[SIZE];
	uint8 *uskBuffer = NULL;
	uint8 *upkBuffer = NULL;
	fenc_USK_KSFCP usk;
	fenc_UPK_KSFCP upk;
	size_t usk_len = 0, b64_usk_len = 0;
	size_t upk_len = 0, b64_upk_len = 0;

	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));
	memset(&usk, 0, sizeof(fenc_USK_KSFCP));
	memset(&upk, 0, sizeof(fenc_UPK_KSFCP));

	/* Initialize the library. */
	result = libfenc_init();
	report_error("Initializing library", result);

	// insert code here...
	debug("Generating master ABE system parameters...\n");
	/* Create a Sahai-Waters context. */
	result = libfenc_create_context(&context, scheme);

	/* Load group parameters from a file. */
	fp = fopen(g_params, "r");
	if (fp != NULL) {
		libfenc_load_group_params_from_file(&group_params, fp);
		libfenc_get_pbc_pairing(&group_params, pairing);
	} else {
		perror("Could not open parameters file.\n");
		goto cleanup;
	}
	fclose(fp);

	/* Set up the global parameters. */
	result = context.generate_global_params(&global_params, &group_params);
	report_error("Loading global parameters", result);

	result = libfenc_gen_params(&context, &global_params);
	report_error("Generating scheme parameters and secret key", result);

	debug("Reading the public parameters file = %s\n", public_params);
	/* read file */
	fp = fopen(public_params, "r");
	if(fp != NULL) {
		while (TRUE) {
			c = fgetc(fp);
			if(c != EOF) {
				public_params_buf[pub_len] = c;
				pub_len++;
			}
			else {
				break;
			}
		}
	}
	else {
		perror("File does not exist.\n");
		return -1;
	}
	fclose(fp);

	debug("public params input = '%s'\n", public_params_buf);

	/* base-64 decode */
	uint8 *bin_public_buf = NewBase64Decode((const char *) public_params_buf, pub_len, &serialized_len);
	/* Import the parameters from binary buffer: */
	result = libfenc_import_public_params(&context, bin_public_buf, serialized_len);
	report_error("Importing public parameters", result);

	result = libfenc_gen_ukey_KSFCP(&context, &usk, &upk);

	uskBuffer = (uint8 *) malloc(KEYSIZE_MAX);
	memset(uskBuffer, 0, KEYSIZE_MAX);
	upkBuffer = (uint8 *) malloc(KEYSIZE_MAX);
	memset(upkBuffer, 0, KEYSIZE_MAX);

	result = libfenc_export_usk_KSFCP(&context, &usk, uskBuffer, KEYSIZE_MAX, &usk_len);
	if(result != FENC_ERROR_NONE) {
		report_error("Generating USK error!", result);
		return result;
	}

	/* base-64 encode the key and write to disk */
	char *b64_usk_buf = NewBase64Encode(uskBuffer, usk_len, FALSE, &b64_usk_len);
	fp = fopen(uskfile, "w");
	if(fp != NULL) {
		fprintf(fp, "%s", b64_usk_buf);
	}
	fclose(fp);

	result = libfenc_export_upk_KSFCP(&context, &upk, upkBuffer, KEYSIZE_MAX, &upk_len);
	if(result != FENC_ERROR_NONE) {
		report_error("Generating UPK error!", result);
		return result;
	}

	/* base-64 encode the key and write to disk */
	char *b64_upk_buf = NewBase64Encode(upkBuffer, upk_len, FALSE, &b64_upk_len);
	fp = fopen(upkfile, "w");
	if(fp != NULL) {
		fprintf(fp, "%s", upkBuffer);
	}
	fclose(fp);

cleanup:
	/* Destroy the context. */
	result = libfenc_destroy_context(&context);
	report_error("Destroying context", result);

	/* Shutdown the library. */
	result = libfenc_shutdown();
	report_error("Shutting down library", result);

	free(public_params_buf);
	free(uskBuffer);
	free(upkBuffer);
	free(b64_usk_buf);
	free(b64_upk_buf);
	return 0;
}


