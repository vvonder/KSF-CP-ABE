#include <ctype.h>
#include <getopt.h>
#include "common.h"
#include "openssl/aes.h"
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include "openssl/hmac.h"
#include <math.h>

#include "benchmark.h"

#define SIZE BUFSIZE

/* include code that creates policy by hand */

#define BYTES 4
// size_t attr_len = 0;
// char *attr[MAX_CIPHERTEXT_ATTRIBUTES];
char *attribute_string = NULL, *policy_string = NULL;
int abe_encrypt(FENC_SCHEME_TYPE scheme, char *g_params, char *public_params, char *data, char *enc_file, int isXML, char *ext, char *keyword_file, char *index_file);
int abe_encrypt_from_file(FENC_SCHEME_TYPE scheme, char *key_string, char *g_params, char *public_params, char *data_file, char *enc_file, int isXML, char *ext, char *keyword_file, char *index_file);
fenc_attribute_policy *construct_test_policy();

/* Description: mgabe-keygen takes the outfile to write the users keys, and the .

 */
int main (int argc, char *argv[]) {
	int aflag,pflag,dflag,oflag,iflag,xflag;
	char *data = NULL, *enc_file = NULL;
	char *ext = NULL;
	FENC_SCHEME_TYPE mode = FENC_SCHEME_NONE;
	char *public_params = NULL;
	ssize_t data_len;
	FILE *fp;
	int c, exit_status = -1;
	char *keyword_file = NULL;
	char *index_file = "index.ksfcp";

	opterr = 0;
	// default
	aflag = pflag = dflag = oflag = iflag = xflag = FALSE;


	while ((c = getopt (argc, argv, "a:d:i:o:m:p:x:w:h")) != -1) {

		switch (c)
		{
			case 'a': // retrieve attributes from user
				aflag = TRUE;
				attribute_string = strdup(optarg);
				break;
			case 'p': /* holds policy string */
				pflag = TRUE;
				policy_string = strdup(optarg);
				break;
			case 'i':
				if(dflag == TRUE) /* i or d option, but not both */
					break;

				iflag = TRUE;
				fp = fopen(optarg, "r");
				if(fp != NULL) {
				  data_len = read_file(fp, &data);
				  data[data_len]='\0';
				}
				else {
					perror("failed to read input file");
					return -1;
				}

				break;
			case 'd': /* data to encrypt */
				if(iflag == TRUE) /* i or d */
					break;
				dflag = TRUE;
				if((data = malloc(strlen(optarg)+1)) == NULL) {
					perror("malloc failed");
					return -1;
				}
				strncpy(data, optarg, strlen(optarg));
				break;
			case 'o': /* output file */
				oflag = TRUE;
				enc_file = optarg;
				break;
			case 'm':
				if (strcmp(optarg, SCHEME_LSW) == 0) {
					debug("Encrypting for Lewko-Sahai-Waters KP scheme...\n");
					mode = FENC_SCHEME_LSW;
					public_params = PUBLIC_FILE".kp";
					ext = "kpabe";
				}
				else if(strcmp(optarg, SCHEME_WCP) == 0) {
					debug("Encrypting for Waters CP scheme...\n");
					mode = FENC_SCHEME_WATERSCP;
					public_params = PUBLIC_FILE".cp";
					ext = "cpabe";
				}
				else if(strcmp(optarg, SCHEME_WSCP) == 0) {
					debug("Encrypting for Waters Simple CP scheme...\n");
					mode = FENC_SCHEME_WATERSSIMPLECP;
					public_params = PUBLIC_FILE".scp";
					ext = "cpabe";
				}
				else if(strcmp(optarg, SCHEME_KSFCP) == 0) {
					debug("Encrypting for KSF-CP scheme...\n");
					mode = FENC_SCHEME_KSFCP;
					public_params = PUBLIC_FILE".ksfcp";
					ext = "cpabe";
				}
				break;
			case 'w':
				keyword_file = optarg;
				break;
			case 'x': /* output format: xml format */
				xflag = TRUE;
				break;
			case 'h':
				print_help();
				return 1;
			case '?':
				if (optopt == 'a' || optopt == 'p' || optopt == 'd' || optopt == 'o' || optopt == 'm')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
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

	if(dflag == FALSE && iflag == FALSE) {
		fprintf(stderr, "Need some data to encrypt!\n");
		print_help();
		return -1;
	}

	if(aflag == FALSE && mode == FENC_SCHEME_LSW) {
		fprintf(stderr, "No attribute list specified!\n");
		print_help();
		goto clean;
	}

	if(pflag == FALSE &&
		(mode == FENC_SCHEME_WATERSCP
		|| mode == FENC_SCHEME_WATERSSIMPLECP || mode == FENC_SCHEME_KSFCP)) {
		fprintf(stderr, "No policy specified to encrypt data!\n");
		print_help();
		goto clean;
	}

	if(oflag == FALSE) {
		fprintf(stderr, "Specify file to store ciphertext!\n");
		print_help();
		goto clean;
	}

	if(mode == FENC_SCHEME_NONE) {
		fprintf(stderr, "Please specify a scheme type\n");
		print_help();
		goto clean;
	}

	exit_status=abe_encrypt(mode, PARAM, public_params, data, enc_file, xflag, ext, keyword_file, index_file);
clean:
	free(data);
	// free attr
	return exit_status;
}

void print_help(void)
{
	printf("Usage: ./abe-enc -m [ KP or CP ] -d [ \"data\" ] -i [ input-filename ]\n\t\t -a Attr1,Attr2,Attr3 -p '((Attr1 and Attr2) or Attr3)' -o [ output-filename ]\n\n -w keyword_file");
}

int abe_encrypt(FENC_SCHEME_TYPE scheme, char *g_params, char *public_params, char *data, char *enc_file, int isXML, char *ext, char *keyword_file, char *index_file)
{
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	fenc_ciphertext ciphertext;
	fenc_function_input func_object_input;
	pairing_t pairing;
	FILE *fp;
	char c;
	size_t pub_len = 0;
	size_t serialized_len = 0;
	uint8 public_params_buf[SIZE];
	char session_key[SESSION_KEY_LEN];
	// size_t session_key_len;
	char pol_str[MAX_POLICY_STR];
	int pol_str_len = MAX_POLICY_STR;

TEST_INIT("encrypt.txt")

	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));
	memset(&public_params_buf, 0, SIZE);
	memset(&ciphertext, 0, sizeof(fenc_ciphertext));
	memset(pol_str, 0, pol_str_len);

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
		return -1;
	}
	fclose(fp);

	/* Set up the global parameters. */
	result = context.generate_global_params(&global_params, &group_params);
	report_error("Loading global parameters", result);

	result = libfenc_gen_params(&context, &global_params);
	report_error("Generating scheme parameters and secret key", result);

	//debug("Reading the public parameters file = %s\n", public_params);
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

	if(scheme == FENC_SCHEME_LSW) {
		result=fenc_create_func_input_for_attributes(attribute_string, &func_object_input);
		if(result != FENC_ERROR_NONE) {
			free(attribute_string);
			return result;
		}

		debug_print_attribute_list((fenc_attribute_list*)(func_object_input.scheme_input));
		free(attribute_string);
	}
	else if(scheme == FENC_SCHEME_WATERSCP || scheme == FENC_SCHEME_WATERSSIMPLECP
			|| scheme == FENC_SCHEME_KSFCP) {
		result=fenc_create_func_input_for_policy(policy_string, &func_object_input);
		if(result != FENC_ERROR_NONE) {
			free(policy_string);
			return result;
		}

		debug_print_policy((fenc_attribute_policy *)(func_object_input.scheme_input));
		free(policy_string);
	}

	/* base-64 decode */
	uint8 *bin_public_buf = NewBase64Decode((const char *) public_params_buf, pub_len, &serialized_len);
	// printf("public params binary = '%s'\n", bin_public_buf);

	/* Import the parameters from binary buffer: */
	result = libfenc_import_public_params(&context, bin_public_buf, serialized_len);
	// report_error("Importing public parameters", result);

START
	/* key encapsulation to obtain session key from policy */
	result = libfenc_kem_encrypt(&context, &func_object_input, SESSION_KEY_LEN, (uint8 *)session_key, &ciphertext);
STOP
TEST_END
	/* generated PSK from policy string */
	debug("Generated session key: ");
	print_buffer_as_hex((uint8 *) session_key, SESSION_KEY_LEN);

	/* encrypted blob that belongs in the <ABED></ABE> tags */
	// print_buffer_as_hex(ciphertext.data, ciphertext.data_len);

	/* use the PSK to encrypt using openssl functions here */
	AES_KEY key;
	size_t iv_length;
	uint8 iv[AES_BLOCK_SIZE+1];
	int data_len = (int) ceil((strlen(data) + strlen(MAGIC))/(double)(AES_BLOCK_SIZE)) * AES_BLOCK_SIZE; // round to nearest multiple of 16-bytes
	char aes_ciphertext[data_len], data_magic[data_len];

	/* generate a random IV */
	memset(iv, 0, AES_BLOCK_SIZE);
	RAND_bytes((uint8 *) iv, AES_BLOCK_SIZE);
	debug("IV: ");
	print_buffer_as_hex((uint8 *) iv, AES_BLOCK_SIZE);
	char *iv_base64 = NewBase64Encode(iv, AES_BLOCK_SIZE, FALSE, &iv_length);

	memset(aes_ciphertext, 0, data_len);
	AES_set_encrypt_key((uint8 *) session_key, 8*SESSION_KEY_LEN, &key);
	sprintf(data_magic, MAGIC"%s", data);
	debug("\nEncrypting data...\n");
	debug("\tPlaintext is => '%s'.\n", data);

	AES_cbc_encrypt((uint8 *)data_magic, (uint8 *) aes_ciphertext, data_len, &key, (uint8 *) iv, AES_ENCRYPT);
	// printf("\tAES Ciphertext base 64: ");
	// print_buffer_as_hex((uint8 *) aes_ciphertext, data_len);

	char filename[strlen(enc_file)+1];
	memset(filename, 0, strlen(enc_file));
	uint8 *rand_id[BYTES+1];
	if(isXML) {
		sprintf(filename, "%s.%s.xml", enc_file, ext);
		fp = fopen(filename, "w");
		/* generate the random unique id */
		RAND_bytes((uint8 *) rand_id, BYTES);
		debug("Generated random id: %08x\n", (unsigned int) rand_id[0]);
	}
	else {
		sprintf(filename, "%s.%s", enc_file, ext);
		fp = fopen(filename, "w");
	}
	debug("\tCiphertext stored in '%s'.\n", filename);
	debug("\tABE Ciphertex size is: '%zd'.\n", ciphertext.data_len);
	debug("\tAES Ciphertext size is: '%d'.\n", data_len);

	/* base-64 both ciphertexts and write to the stdout -- in XML? */
	size_t abe_length, aes_length;
	char *ABE_cipher_base64 = NewBase64Encode(ciphertext.data, ciphertext.data_len, FALSE, &abe_length);
	char *AES_cipher_base64 = NewBase64Encode(aes_ciphertext, data_len, FALSE, &aes_length);

	/* output ciphertext to disk: either xml or custom format */
	if(isXML) {
		fprintf(fp,"<Encrypted id='");
		fprintf(fp, "%08x", (unsigned int) rand_id[0]);
		fprintf(fp,"'><ABE type='CP'>%s</ABE>", ABE_cipher_base64);
		fprintf(fp,"<IV>%s</IV>", iv_base64);
		fprintf(fp,"<EncryptedData>%s</EncryptedData></Encrypted>", AES_cipher_base64);
		fclose(fp);
	}
	else {
		fprintf(fp, ABE_TOKEN":%s:"ABE_TOKEN_END":", ABE_cipher_base64);
		fprintf(fp, IV_TOKEN":%s:"IV_TOKEN_END":", iv_base64);
		fprintf(fp, AES_TOKEN":%s:"AES_TOKEN_END, AES_cipher_base64);
		fclose(fp);
	}

	if(ABE_cipher_base64 != NULL)
		free(ABE_cipher_base64);
	if(ABE_cipher_base64 != NULL)
		free(AES_cipher_base64);
	if(iv_base64 != NULL)
		free(iv_base64);

	fenc_func_input_clear(&func_object_input);

	/* Build Index */
	if(scheme == FENC_SCHEME_KSFCP){
		if(keyword_file==NULL || index_file==NULL){
			printf("No keyword file and index file specified, skip build index!\n");
		}else{
			result = build_index(&context, keyword_file, index_file);
			report_error("Building and Storing Index", result);
		}
	}

	free(bin_public_buf);

	/* Destroy the context. */
	result = libfenc_destroy_context(&context);
	report_error("Destroying the encryption context", result);

	/* Shutdown the library. */
	result = libfenc_shutdown();
	report_error("Shutting down library", result);

	return 0;
}

int abe_encrypt_from_file(FENC_SCHEME_TYPE scheme, char *key_string, char *g_params, char *public_params, char *data_file, char *enc_file, int isXML, char *ext, char *keyword_file, char *index_file)
{
	char *data = NULL;
	ssize_t data_len;
	FILE *fp;
	fp = fopen(data_file, "r");
	if(fp != NULL) {
		data_len = read_file(fp, &data);
		data[data_len]='\0';
	}
	else {
		perror("failed to read input file");
		return -1;
	}

	if(scheme==FENC_SCHEME_LSW)
		attribute_string=strdup(key_string);
	else
		policy_string=strdup(key_string);
	int exit_status=abe_encrypt(scheme, g_params, public_params, data, enc_file, isXML, ext, keyword_file, index_file);
	free(data);
	return exit_status;
}

int build_index(fenc_context *pcontext, char *keyword_file, char *index_file)
{
	FENC_ERROR result;
	FILE *fp;
	char keywords[MAX_INDEX_KEYWORDS][KEYWORD_SIZE];
	int i = 0, num_keywords = 0;
	fenc_index_KSFCP index;
	fenc_index_HK_KSFCP hk_buffer[MAX_INDEX_KEYWORDS];
	uint8 R[R_SIZE];
	uint8 *digest;
	uint8 *R_buf, *MAC_buf;
	int buf_len;

TEST_INIT("encrypt_index.txt")

	fp = fopen(keyword_file, "r");
	while(i<MAX_INDEX_KEYWORDS
		&& freadline(keywords[i], KEYWORD_SIZE, fp))
	{
		i++;
	}
	fclose(fp);

	num_keywords = i;

#ifdef DEBUG
	printf("Reading Keywords:\n");
	for(i=0; i<num_keywords; i++)
		printf("%d %s\n", strlen(keywords[i]), keywords[i]);
#endif

START
	libfenc_build_index_KSFCP(pcontext, keywords, num_keywords, &index);
STOP
	report_error("Building Index", result);

	libfenc_export_index_KSFCP(pcontext, &index, hk_buffer);
	report_error("Exporting Index", result);

	/* Store Index to HMAC */
	fp = fopen(index_file, "w");

	fprintf(fp, "SIZE:%d|", index.num_components);

	for(i=0; i<num_keywords; i++)
	{
#ifdef DEBUG
		debug("HK %d: ", i);
		print_buffer_as_hex(hk_buffer[i].buffer,  hk_buffer[i].len);
#endif
		RAND_bytes(R, R_SIZE);
		digest = HMAC(EVP_sha1(), hk_buffer[i].buffer, hk_buffer[i].len, R, R_SIZE, NULL, NULL);

		R_buf = NewBase64Encode(R, R_SIZE, FALSE, &buf_len);
		fprintf(fp, "%s", R_buf);
		MAC_buf = NewBase64Encode(digest, MAC_SIZE, FALSE, &buf_len);
		fprintf(fp, "%s", MAC_buf);

		free(digest);
		free(R_buf);
		free(MAC_buf);
	}

	fclose(fp);

TEST_END

	return 0;
}


