#include <ctype.h>
#include <getopt.h>
#include <math.h>
#include "common.h"

#define SIZE BUFSIZE

#define DEFAULT_KEYFILE "private.key"
char *policy_string = NULL, *attribute_string = NULL;
int generate_keys(char *outfile, FENC_SCHEME_TYPE scheme, char *g_params, char *secret_params, char *public_params);
int generate_keys_with_string(FENC_SCHEME_TYPE scheme, char *key_string, char *g_params, char *secret_params, char *public_params, char *outfile);
/* Description: mgabe-keygen takes the outfile to write the users keys, and the .

 */
int main (int argc, char* argv[]) {
	int oflag = FALSE, aflag = FALSE, pflag = FALSE;
	char *keyfile = NULL;
	int  c;
	FENC_SCHEME_TYPE mode = FENC_SCHEME_NONE;
	char *secret_params = NULL, *public_params = NULL;
	char buf[SIZE];
	memset(buf, 0, SIZE);

	opterr = 0;

	while ((c = getopt (argc, argv, "a:o:m:p:h")) != -1) {

	switch (c)
	  {
		case 'a': // retrieve attributes from user
			  aflag = TRUE;
			  attribute_string = strdup(optarg);
			  break;
		case 'p':
			  pflag = TRUE;
			  policy_string = strdup(optarg);
			  break;
		case 'o':
			  oflag = TRUE;
			  keyfile = optarg;
			  break;
		case 'm':
			  if (strcmp(optarg, SCHEME_LSW) == 0) {
				  printf("Generating private key for Lewko-Sahai-Waters KP scheme...\n");
				  mode = FENC_SCHEME_LSW;
				  secret_params = SECRET_FILE".kp";
				  public_params = PUBLIC_FILE".kp";
			  }
			  else if(strcmp(optarg, SCHEME_WCP) == 0) {
				  printf("Generating private key for Waters CP scheme...\n");
				  mode = FENC_SCHEME_WATERSCP;
				  secret_params = SECRET_FILE".cp";
				  public_params = PUBLIC_FILE".cp";
			  }
			  else if(strcmp(optarg, SCHEME_WSCP) == 0) {
				  printf("Generating private key for Waters Simple CP scheme...\n");
				  mode = FENC_SCHEME_WATERSSIMPLECP;
				  secret_params = SECRET_FILE".scp";
				  public_params = PUBLIC_FILE".scp";
			  }
			  else if(strcmp(optarg, SCHEME_KSFCP) == 0) {
					debug("Generating private key for KSF-CP scheme...\n");
					mode = FENC_SCHEME_KSFCP;
					secret_params = SECRET_FILE".ksfcp";
					public_params = PUBLIC_FILE".ksfcp";
				}
			  break;
		case 'h':
			  print_help();
			  return 1;
		case '?':
			if (optopt == 'o' )
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

	/* attribute list required */
	if(aflag == FALSE && mode == FENC_SCHEME_WATERSCP) {
		fprintf(stderr, "Attributes list required to generate user's key!\n");
		print_help();
		return 1;
	}

	if(pflag == FALSE && mode == FENC_SCHEME_LSW) {
		fprintf(stderr, "Policy required to generate user's key under "SCHEME_LSW" scheme\n");
		print_help();
		return 1;
	}

	/* use default file name if not set */
	if(oflag == FALSE) {
		keyfile = DEFAULT_KEYFILE;
	}

	if(mode == FENC_SCHEME_NONE) {
		fprintf(stderr, "Please specify a scheme type\n");
		print_help();
		goto cleanup;
	}

	printf("Generating your private key...\n");
	int exit_status=generate_keys(keyfile, mode, PARAM, secret_params, public_params);

cleanup:
	return exit_status;
}

void print_help(void)
{
	printf("Usage: ./abe-keygen -m [ KP,CP or SCP ] -a [ ATTR1,ATTR2,ATT3,etc ] -p [ 'ATTR1 and ATTR2',etc ] -o [ key file ]\n\n");
}

int generate_keys(char *outfile, FENC_SCHEME_TYPE scheme, char *g_params, char *secret_params, char *public_params)
{
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	fenc_function_input func_object_input; // could be policy or list
	pairing_t pairing;
	fenc_key key;
	fenc_key key2;
	FILE *fp;
	char c;
	size_t pub_len = 0, sec_len = 0;
	size_t serialized_len = 0;
	uint8 public_params_buf[SIZE];
	uint8 secret_params_buf[SIZE];
	uint8 output_str[SIZE];
	uint8 *buffer = NULL;

	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));
	memset(&public_params_buf, 0, SIZE);
	memset(&secret_params_buf, 0, SIZE);
	memset(output_str, 0, SIZE);
	/* stores user's authorized attributes */
	memset(&func_object_input, 0, sizeof(fenc_function_input));
	/* stores the user's private key */
	memset(&key, 0, sizeof(fenc_key));
	memset(&key2, 0, sizeof(fenc_key));

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

	if(scheme == FENC_SCHEME_LSW) {
		result=fenc_create_func_input_for_policy(policy_string, &func_object_input);
		if(result != FENC_ERROR_NONE) {
			free(policy_string);
			return result;
		}

		debug_print_policy((fenc_attribute_policy *)(func_object_input.scheme_input));
		free(policy_string);
	}
	else if(scheme == FENC_SCHEME_WATERSCP || scheme == FENC_SCHEME_WATERSSIMPLECP
			|| scheme == FENC_SCHEME_KSFCP) {
		result=fenc_create_func_input_for_attributes(attribute_string, &func_object_input);
		if(result != FENC_ERROR_NONE) {
			free(attribute_string);
			return result;
		}

		debug_print_attribute_list((fenc_attribute_list*)(func_object_input.scheme_input));
		free(attribute_string);
	}

	result = libfenc_extract_key(&context, &func_object_input, &key);
	report_error("Extracting a decryption key", result);

	buffer = (uint8 *) malloc(KEYSIZE_MAX);
	memset(buffer, 0, KEYSIZE_MAX);
	result = libfenc_export_secret_key(&context, &key, buffer, KEYSIZE_MAX, &serialized_len);
	report_error("Exporting key", result);

	size_t keyLength;
	char *secret_key_buf = NewBase64Encode(buffer, serialized_len, FALSE, &keyLength);
	// printf("Your secret-key:\t'%s'\nKey-len:\t'%zd'\n", secret_key_buf, serialized_len);

	fp = fopen(outfile, "w");
	if(fp != NULL) {
		fprintf(fp, "%s", secret_key_buf);
	}
	else {
		perror("Error writing private key.");
	}
	fclose(fp);

	/*
	printf("........Confirming contents of exported key......\n");
	printf("Buffer contents:\n");
	print_buffer_as_hex(buffer, serialized_len);

	if(scheme == FENC_SCHEME_LSW) {
		result = libfenc_import_secret_key(&context, &key2, buffer, serialized_len);
		report_error("Import secret key", result);

		fenc_key_LSW *myKey2 = (fenc_key_LSW *) key2.scheme_key;

		size_t serialized_len2;
		uint8 *buffer2 = malloc(KEYSIZE_MAX);
		memset(buffer2, 0, KEYSIZE_MAX);
		result = libfenc_serialize_key_LSW(myKey2, buffer2, KEYSIZE_MAX, &serialized_len2);
		report_error("Serialize user's key", result);

		printf("Key-len2: '%zu'\n", serialized_len2);
		printf("Buffer contents 2:\n");
		print_buffer_as_hex(buffer2, serialized_len2);
	} */
cleanup:
	fenc_func_input_clear(&func_object_input);

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

int generate_keys_with_string(FENC_SCHEME_TYPE scheme, char *key_string, char *g_params, char *secret_params, char *public_params, char *outfile)
{
	if(scheme==FENC_SCHEME_LSW)
		policy_string=strdup(key_string);
	else
		attribute_string=strdup(key_string);
	int exit_status=generate_keys(outfile, scheme, g_params, secret_params, public_params);
	return exit_status;
}
