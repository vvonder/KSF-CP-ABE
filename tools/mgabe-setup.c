#include <ctype.h>
#include <getopt.h>
#include "common.h"

#include "benchmark.h"

int gen_abe_scheme_params(FENC_SCHEME_TYPE scheme, char *g_params, char *secret_params, char *public_params);
/* Description: mgabe-setup takes no arguments and simply reads in the global parameters from the filesystem,
 and generates the public parameters (or public key) and the master secret parameters (or master secret key).
 It serializes and writes to disk the public parameters and the master secret key.
 */
int main(int argc, char * argv[]) {
	int c;
	FENC_SCHEME_TYPE mode = FENC_SCHEME_NONE;
	char *secret_params = NULL, *public_params = NULL;

	while ((c = getopt (argc, argv, "m:h")) != -1) {

		switch (c)
		{
			case 'm':
				if (strcmp(optarg, SCHEME_LSW) == 0) {
					debug("Generating Lewko-Sahai-Waters KP scheme parameters...\n");
					mode = FENC_SCHEME_LSW;
					secret_params = SECRET_FILE".kp";
					public_params = PUBLIC_FILE".kp";
				}
				else if(strcmp(optarg, SCHEME_WCP) == 0) {
					debug("Generating Waters CP scheme parameters...\n");
					mode = FENC_SCHEME_WATERSCP;
					secret_params = SECRET_FILE".cp";
					public_params = PUBLIC_FILE".cp";
				}
				else if(strcmp(optarg, SCHEME_WSCP) == 0) {
					debug("Generating Waters Simple CP scheme parameters...\n");
					mode = FENC_SCHEME_WATERSSIMPLECP;
					secret_params = SECRET_FILE".scp";
					public_params = PUBLIC_FILE".scp";
				}
				else if(strcmp(optarg, SCHEME_KSFCP) == 0) {
					debug("Generating KSF-CP scheme parameters...\n");
					mode = FENC_SCHEME_KSFCP;
					secret_params = SECRET_FILE".ksfcp";
					public_params = PUBLIC_FILE".ksfcp";
				}
				break;
			case 'h':
				print_help();
				return 1;
			case '?':
				if (optopt == 'm')
					fprintf (stderr, "Option -%o requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr,
							 "Unknown option character `\\x%x'.\n", optopt);
				return 1;
			default:
				print_help();
				return 1;
		}
	}

	if(mode == FENC_SCHEME_NONE) {
		fprintf(stderr, "Please specify a scheme type\n");
		print_help();
		return 1;
	}

	return gen_abe_scheme_params(mode, PARAM, secret_params, public_params);
}

void print_help(void)
{
	printf("Usage: ./abe-setup -m [ KP,CP or SCP]\n\n");
}


int gen_abe_scheme_params(FENC_SCHEME_TYPE scheme, char *g_params, char *secret_params, char *public_params) {
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	pairing_t pairing;
	FILE *fp;
	size_t serialized_len = 0;
	uint8* public_params_buf = NULL;
	uint8* secret_params_buf = NULL;
	char *publicBuffer = NULL;
	char *secretBuffer = NULL;

TEST_INIT("setup.txt")

	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));

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
START
		libfenc_get_pbc_pairing(&group_params, pairing);
STOP
	} else {
		perror("Could not open parameters file.\n");
		goto cleanup;
	}
	fclose(fp);

	/* Set up the global parameters. */
	result = context.generate_global_params(&global_params, &group_params);
	report_error("Loading global parameters", result);

START
	result = libfenc_gen_params(&context, &global_params);
STOP
	report_error("Generating scheme parameters and secret key", result);

	/* Serialize the public parameters into a buffer */
	result = libfenc_export_public_params(&context, NULL, 0, &serialized_len, FALSE);
	if (result != FENC_ERROR_NONE) { report_error("Computing public parameter output size", result); }
	if((public_params_buf = malloc(serialized_len)) == NULL) {
		perror("malloc failed.");
		return 1;
	}

	/* Export public parameters to buffer with the right size */
	result = libfenc_export_public_params(&context, public_params_buf, serialized_len, &serialized_len, FALSE);
	report_error("Exporting public parameters", result);

	debug("Base-64 encoding public parameters...\n");
	size_t publicLength;
	publicBuffer = NewBase64Encode(public_params_buf, serialized_len, FALSE, &publicLength);
	debug("'%s'\n", publicBuffer);

	/* base-64 encode the pub params and write to disk */
	fp = fopen(public_params, "w");
	if(fp != NULL) {
		fprintf(fp, "%s", publicBuffer);
	}
	fclose(fp);

	/* Serialize the secret parameters into a buffer (not strictly necessary, just a test). */
	result = libfenc_export_secret_params(&context, NULL, 0, &serialized_len, NULL, 0);
	if (result != FENC_ERROR_NONE) { report_error("Computing secret parameter output size", result); }
	if((secret_params_buf = malloc(serialized_len)) == NULL) {
		perror("malloc failed.");
		return 1;
	}
	result = libfenc_export_secret_params(&context, secret_params_buf, serialized_len, &serialized_len, NULL, 0);
	report_error("Exporting secret parameters", result);

	debug("Base-64 encoding secret parameters...\n");
	size_t secretLength;
	secretBuffer = NewBase64Encode(secret_params_buf, serialized_len, FALSE, &secretLength);
	debug("'%s'\n", secretBuffer);

	/* base-64 encode the pub params and write to disk */
	fp = fopen(secret_params, "w");
	if(fp != NULL) {
		fprintf(fp, "%s", secretBuffer);
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
	free(publicBuffer);
	free(secretBuffer);

PRINT_LINE
TEST_END
	return 0;
}


