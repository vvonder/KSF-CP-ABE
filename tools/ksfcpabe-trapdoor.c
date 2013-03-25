#include <ctype.h>
#include <getopt.h>
#include "common.h"

#define SIZE BUFSIZE

int generate_trapdoor(FENC_SCHEME_TYPE scheme, char *g_params, char *public_params, char *skfile, char *ksfkeyfile, char *uskfile, char *keyword, char *outfile);

int main (int argc, char* argv[]) {
	int c;
	FENC_SCHEME_TYPE scheme = FENC_SCHEME_KSFCP;
	char *public_params = PUBLIC_FILE".ksfcp";
	char *skfile = "userCP.key";
	char *ksfkeyfile = "userCP.ksfkey";
	char *uskfile = "USK.ksfcp";
	char *keyword = NULL;
	char *outfile = "userCP.trapdoor";

	while ((c = getopt (argc, argv, "w:h")) != -1) {

		switch (c)
		{
			case 'w':
				keyword = optarg;
				break;
			case 'h':
				print_help();
				return 1;
			default:
				print_help();
				return 1;
		}
	}

	if(keyword == NULL)
	{
		print_help();
		return 1;
	}

	return generate_trapdoor(scheme, PARAM, public_params, skfile, ksfkeyfile, uskfile, keyword, outfile);
}

void print_help(void)
{
	printf("Usage: ./ksf-trapdoor -w KEYWORD \n\n");
}

int generate_trapdoor(FENC_SCHEME_TYPE scheme, char *g_params, char *public_params, char *skfile, char *ksfkeyfile, char *uskfile, char *keyword, char *outfile)
{

	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	pairing_t pairing;
	FILE *fp;
	char c;
	size_t pub_len = 0, usk_len = 0, sk_len = 0, ksfkey_len = 0;
	size_t serialized_len = 0;
	uint8 public_params_buf[SIZE];
	uint8 usk_buf[SIZE];
	uint8 sk_buf[SIZE];
	uint8 ksfkey_buf[SIZE];
	uint8 *buffer = NULL;
	fenc_key sk;
	fenc_USK_KSFCP usk;
	fenc_KSF_key_KSFCP ksfkey;
	fenc_trapdoor_KSFCP trapdoor;

	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));
	memset(&public_params_buf, 0, SIZE);
	memset(&ksfkey_buf, 0, SIZE);
	memset(&usk_buf, 0, SIZE);
	memset(&sk_buf, 0, SIZE);

	/* stores the user's private key */
	memset(&sk, 0, sizeof(fenc_key));
	/* stores the user's UPK key */
	memset(&usk, 0, sizeof(fenc_USK_KSFCP));
	/* stores the user's KSF key */
	memset(&ksfkey, 0, sizeof(fenc_KSF_key_KSFCP));
	/* stores the user's Trapdoor */
	memset(&trapdoor, 0, sizeof(fenc_trapdoor_KSFCP));

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

	debug("public params input = '%s'\n", public_params_buf);

	/* base-64 decode */
	uint8 *bin_public_buf = NewBase64Decode((const char *) public_params_buf, pub_len, &serialized_len);
	/* Import the parameters from binary buffer: */
	result = libfenc_import_public_params(&context, bin_public_buf, serialized_len);
	report_error("Importing public parameters", result);

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
	fp = fopen(uskfile, "r");
	if(fp != NULL) {
		while (TRUE) {
			c = fgetc(fp);
			if(c != EOF) {
				usk_buf[usk_len] = c;
				usk_len++;
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

	uint8 *bin_usk_buf = NewBase64Decode((const char *) usk_buf, usk_len, &serialized_len);
	result = libfenc_import_usk_KSFCP(&context, &usk, bin_usk_buf, serialized_len);
	report_error("Importing USK", result);

	/* read file */
	fp = fopen(ksfkeyfile, "r");
	if(fp != NULL) {
		while (TRUE) {
			c = fgetc(fp);
			if(c != EOF) {
				ksfkey_buf[ksfkey_len] = c;
				ksfkey_len++;
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

	uint8 *bin_ksfkey_buf = NewBase64Decode((const char *) ksfkey_buf, ksfkey_len, &serialized_len);
	result = libfenc_import_ksfkey_KSFCP(&context, &ksfkey, bin_ksfkey_buf, serialized_len);
	report_error("Importing KSF Key", result);


	result = libfenc_gen_trapdoor_KSFCP(&context, &sk, &ksfkey, &usk, keyword, &trapdoor);
	report_error("Generating KSF Trapdoor", result);

	buffer = (uint8 *) malloc(KEYSIZE_MAX);
	memset(buffer, 0, KEYSIZE_MAX);
	result = libfenc_export_trapdoor_KSFCP(&context, &trapdoor, buffer, KEYSIZE_MAX, &serialized_len);
	report_error("Exporting KSF Trapdoor", result);

	size_t tLength;
	char *trapdoor_buf = NewBase64Encode(buffer, serialized_len, FALSE, &tLength);

	fp = fopen(outfile, "w");
	if(fp != NULL) {
		fprintf(fp, "%s", trapdoor_buf);
	}
	else {
		perror("Error writing KSF Trapdoor.");
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
