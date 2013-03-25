#include <ctype.h>
#include <getopt.h>
#include "common.h"

#define SIZE BUFSIZE

int generate_ksfkeys(FENC_SCHEME_TYPE scheme, char *g_params, char *public_params, char *secret_params, char *skfile, char *upkfile, char *outfile);

int main (int argc, char* argv[]) {
	FENC_SCHEME_TYPE scheme = FENC_SCHEME_KSFCP;
	char *public_params = PUBLIC_FILE".ksfcp";
	char *secret_params = SECRET_FILE".ksfcp";
	char *skfile = "userCP.key";
	char *upkfile = "UPK.ksfcp";
	char *outfile = "userCP.ksfkey";

	return generate_ksfkeys(scheme, PARAM, public_params, secret_params, skfile, upkfile, outfile);
}

int generate_ksfkeys(FENC_SCHEME_TYPE scheme, char *g_params, char *public_params, char *secret_params, char *skfile, char *upkfile, char *outfile)
{

	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	pairing_t pairing;
	FILE *fp;
	char c;
	size_t pub_len = 0, sec_len = 0, upk_len = 0, sk_len = 0;
	size_t serialized_len = 0;
	uint8 public_params_buf[SIZE];
	uint8 secret_params_buf[SIZE];
	uint8 upk_buf[SIZE];
	uint8 sk_buf[SIZE];
	uint8 *buffer = NULL;
	fenc_key sk;
	fenc_UPK_KSFCP upk;
	fenc_KSF_key_KSFCP ksfkey;

	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));
	memset(&public_params_buf, 0, SIZE);
	memset(&secret_params_buf, 0, SIZE);
	memset(&upk_buf, 0, SIZE);
	memset(&sk_buf, 0, SIZE);

	/* stores the user's private key */
	memset(&sk, 0, sizeof(fenc_key));
	/* stores the user's UPK key */
	memset(&upk, 0, sizeof(fenc_UPK_KSFCP));
	/* stores the user's KSF key */
	memset(&ksfkey, 0, sizeof(fenc_KSF_key_KSFCP));

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

	debug("Reading the secret parameters file = %s\n", secret_params);
	/* read file */
	fp = fopen(secret_params, "r");
	if(fp != NULL) {
		while (TRUE) {
			c = fgetc(fp);
			if(c != EOF) {
				secret_params_buf[sec_len] = c;
				sec_len++;
			}
			else {
				break;
			}
		}
	}
	else {
		perror("File does not exist.\n");
		goto cleanup;
	}
	fclose(fp);

	debug("public params input = '%s'\n", public_params_buf);
	debug("secret params input = '%s'\n", secret_params_buf);

	/* base-64 decode */
	uint8 *bin_public_buf = NewBase64Decode((const char *) public_params_buf, pub_len, &serialized_len);
	/* Import the parameters from binary buffer: */
	result = libfenc_import_public_params(&context, bin_public_buf, serialized_len);
	report_error("Importing public parameters", result);

	uint8 *bin_secret_buf = NewBase64Decode((const char *) secret_params_buf, sec_len, &serialized_len);
	result = libfenc_import_secret_params(&context, bin_secret_buf, serialized_len, NULL, 0);
	report_error("Importing secret parameters", result);


	/* read file */
	fp = fopen(skfile, "r");
	if(fp != NULL) {
		while (TRUE) {
			c = fgetc(fp);
			if(c != EOF) {
				sk_buf[sk_len] = c;
				sk_len++;
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

	uint8 *bin_sk_buf = NewBase64Decode((const char *) sk_buf, sk_len, &serialized_len);
	result = libfenc_import_secret_key_KSFCP(&context, &sk, bin_sk_buf, serialized_len);
	report_error("Importing Secret Key", result);

	/* read file */
	fp = fopen(upkfile, "r");
	if(fp != NULL) {
		while (TRUE) {
			c = fgetc(fp);
			if(c != EOF) {
				upk_buf[upk_len] = c;
				upk_len++;
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

	uint8 *bin_upk_buf = NewBase64Decode((const char *) upk_buf, upk_len, &serialized_len);
	result = libfenc_import_upk_KSFCP(&context, &upk, bin_upk_buf, serialized_len);
	report_error("Importing UPK", result);


	result = libfenc_extract_ksfkey_KSFCP(&context, &ksfkey, &sk, &upk);
	report_error("Extracting KSF key", result);

	buffer = (uint8 *) malloc(KEYSIZE_MAX);
	memset(buffer, 0, KEYSIZE_MAX);
	result = libfenc_export_ksfkey_KSFCP(&context, &ksfkey, buffer, KEYSIZE_MAX, &serialized_len);
	report_error("Exporting KSF key", result);

	size_t keyLength;
	char *ksf_key_buf = NewBase64Encode(buffer, serialized_len, FALSE, &keyLength);

	fp = fopen(outfile, "w");
	if(fp != NULL) {
		fprintf(fp, "%s", ksf_key_buf);
	}
	else {
		perror("Error writing KSF key.");
	}
	fclose(fp);

cleanup:
	/* Destroy the context. */
	result = libfenc_destroy_context(&context);
	report_error("Destroying context", result);

	/* Shutdown the library. */
	result = libfenc_shutdown();
	report_error("Shutting down library", result);

	/* free buffer */
	free(buffer);
	return 0;
}
