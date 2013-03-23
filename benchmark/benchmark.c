#include "common.h"
#include <time.h>
#include <libfenc_LSW.h>
#include <libfenc_WatersSimpleCP.h>

char *kp_abe_priv_keyfile = "private-kp.key";
char *cp_abe_priv_keyfile = "private-cp.key";
char *scp_abe_priv_keyfile = "private-scp.key";
//void benchmark_schemes(void);
int get_key(char *keyfile, fenc_context *context, fenc_key *secret_key);
//void apply_LSW(void);
void apply_scheme(FENC_SCHEME_TYPE scheme, char *public_params, char *policy, char *outfile);
//void apply_WatersSimpleCP(void);
void test_secret_sharing(fenc_attribute_policy *policy, pairing_t pairing);
void test_libfenc(char *policy);
fenc_attribute_policy *construct_test_policy();
fenc_attribute_policy *construct_test_policy1();
fenc_attribute_policy *construct_test_policy2();

int main(int argc, char *argv[])
{
	// argv[1] => policy string
	// argv[2] => scheme type
	// argv[3] => outfile name
	if(argc != 4) {	
		printf("Usage %s: [ policy or attributes ] [ scheme ] [ outfile ]\n", argv[0]);
		exit(1);
	}
	
	char *string = argv[1];
	char *scheme = argv[2];
	char *outfile = argv[3];
	printf("Benchmarking libfenc ABE schemes...\n");
	if(strcmp(scheme, "KP") == 0) {
		apply_scheme(FENC_SCHEME_LSW, PUBLIC_FILE".kp", string, outfile);
	}
	else if(strcmp(scheme, "CP") == 0) {
		apply_scheme(FENC_SCHEME_WATERSCP, PUBLIC_FILE".cp", string, outfile);
	}
	else if(strcmp(scheme, "SCP") == 0) {
		apply_scheme(FENC_SCHEME_WATERSSIMPLECP, PUBLIC_FILE".scp", string, outfile);
	}
	else {
		// run some tests
		test_libfenc(string);
	}


	return 0;
}

/* inputs => 'scheme' and a string which represents policy or attributes dependent on the scheme */
/* output => # leaves and decryption time. In addition, an well defined output format of the results */
/*TODO void benchmark_schemes(void)
{
	FENC_ERROR result;	
}*/

int get_key(char *keyfile, fenc_context *context, fenc_key *secret_key)
{
	FENC_ERROR result;
	char *keyfile_buf = NULL;
	size_t key_len;
	FILE *fp;
	fp = fopen(keyfile, "r");
	if(fp != NULL) {
		if((key_len = read_file(fp, &keyfile_buf)) > 0) {
			// printf("\nYour private-key:\t'%s'\n", keyfile_buf);
			size_t keyLength;
			uint8 *bin_keyfile_buf = NewBase64Decode((const char *) keyfile_buf, key_len, &keyLength);
			
#ifdef DEBUG
			/* base-64 decode user's private key */
			printf("Base-64 decoded buffer:\t");
			print_buffer_as_hex(bin_keyfile_buf, keyLength);
#endif			
			result = libfenc_import_secret_key(context, secret_key, bin_keyfile_buf, keyLength);
			report_error("Importing secret key", result);
			free(keyfile_buf);
			free(bin_keyfile_buf);
		}			
	}
	else {
		fprintf(stderr, "Could not load input file: %s\n", keyfile);
		return FALSE;
	}
	fclose(fp);
	
	return TRUE;
}

void apply_scheme(FENC_SCHEME_TYPE scheme, char *public_params, char *data, char *outfile) 
{
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	fenc_function_input func_input;
	fenc_ciphertext ciphertext;
	fenc_key master_key;
	pairing_t pairing;
	FILE *fp;
	char *public_params_buf = NULL, *scheme_text = NULL;
	char session_key[SESSION_KEY_LEN];
	fenc_plaintext rec_session_key;
	size_t serialized_len;
	clock_t start, stop;
	uint32 num_leaves;
	fenc_attribute_policy *parsed_policy = NULL;
	fenc_attribute_list *parsed_attributes = NULL;
	
	memset(&context, 0, sizeof(fenc_context)); 
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));	
	memset(&ciphertext, 0, sizeof(fenc_ciphertext));
	memset(&master_key, 0, sizeof(fenc_key));
	
	/* Initialize the library. */
	result = libfenc_init();
	report_error("Initializing library", result);
	
	/* Create a Sahai-Waters context. */
	result = libfenc_create_context(&context, scheme);
	report_error("Creating context for Waters CP scheme", result);
	
	/* Load group parameters from a file. */
	fp = fopen(PARAM, "r");
	if (fp != NULL) {
		libfenc_load_group_params_from_file(&group_params, fp);
		libfenc_get_pbc_pairing(&group_params, pairing);
	} else {
		perror("Could not open type-d parameters file.\n");
		return;
	}
	fclose(fp);
	
	/* Set up the global parameters. */
	result = context.generate_global_params(&global_params, &group_params);	
	result = libfenc_gen_params(&context, &global_params);
	
	/* Set up the publci parameters */
	fp = fopen(public_params, "r");
	if(fp != NULL) {
		size_t pub_len = read_file(fp, &public_params_buf);
		/* base-64 decode */
		uint8 *bin_public_buf = NewBase64Decode((const char *) public_params_buf, pub_len, &serialized_len);
		/* Import the parameters from binary buffer: */
		result = libfenc_import_public_params(&context, bin_public_buf, serialized_len);
		report_error("Importing public parameters", result);
		free(public_params_buf);
		free(bin_public_buf);
	}
	else {
		perror("Could not open public parameters\n");
		return;
	}
	fclose(fp);
	
	if(scheme == FENC_SCHEME_LSW) {
		/* convert the list of attributes into a fenc_attribute_list structure */
		parsed_attributes = (fenc_attribute_list *) malloc(sizeof(fenc_attribute_list));		
		fenc_buffer_to_attribute_list(&data, parsed_attributes);
						
		func_input.input_type = FENC_INPUT_ATTRIBUTE_LIST;
		func_input.scheme_input = (void *) parsed_attributes;
		
		/* store attribute list for future reference */
		char attr_str[SIZE];
		memset(attr_str, 0, SIZE);
		size_t attr_str_len;
		fenc_attribute_list_to_buffer((fenc_attribute_list*)(func_input.scheme_input), (uint8 *)attr_str, SIZE, &attr_str_len);
		printf("Attribute list: %s\n", attr_str);
		
		/* test */
		num_leaves = 0;
		
	}
	else {
	//else if(scheme == FENC_SCHEME_WATERSCP) {
		/* encrypt under given policy */ 
	// fenc_attribute_policy *parsed_policy = construct_test_policy2();
		parsed_policy = (fenc_attribute_policy *) malloc(sizeof(fenc_attribute_policy));
		memset(parsed_policy, 0, sizeof(fenc_attribute_policy));

		fenc_policy_from_string(parsed_policy, data); 
		func_input.input_type = FENC_INPUT_NM_ATTRIBUTE_POLICY;
		func_input.scheme_input = (void *) parsed_policy;
		
		/* store the policy for future reference */
		char policy_str[SIZE];
		memset(policy_str, 0, SIZE);
		fenc_attribute_policy_to_string(parsed_policy->root, policy_str, SIZE);	
		printf("POLICY => '%s'\n", policy_str);	
	}
		
	/* perform encryption */
	result = libfenc_kem_encrypt(&context, &func_input, SESSION_KEY_LEN, (uint8 *) session_key, &ciphertext);	
	
	printf("Decryption key:\t");
	print_buffer_as_hex((uint8 *)session_key, SESSION_KEY_LEN);
	
	/* now perform decryption with session key */		
	
	if(scheme == FENC_SCHEME_LSW) {
		printf("Successful import => '%d'\n", get_key(kp_abe_priv_keyfile, &context, &master_key));
		fenc_key_LSW *key_LSW = (fenc_key_LSW *) master_key.scheme_key;
		num_leaves = prune_tree(key_LSW->policy->root, parsed_attributes);
		scheme_text = "KP";
	}
	else if(scheme == FENC_SCHEME_WATERSCP) {
		printf("Successful import => '%d'\n", get_key(cp_abe_priv_keyfile, &context, &master_key));
		fenc_key_WatersCP *key_WatersCP = (fenc_key_WatersCP *) master_key.scheme_key;	
		num_leaves = prune_tree(parsed_policy->root, &(key_WatersCP->attribute_list));
		scheme_text = "CP";
	}
	else {
		printf("Successful import => '%d'\n", get_key(scp_abe_priv_keyfile, &context, &master_key));
		fenc_key_WatersSimpleCP *key_WatersSimpleCP = (fenc_key_WatersSimpleCP *) master_key.scheme_key;	
		num_leaves = prune_tree(parsed_policy->root, &(key_WatersSimpleCP->attribute_list));	
		scheme_text = "SCP";
	}
	
	printf("Start timer.\n");
	/* start timer */
	start = clock();
	/* Descrypt the resulting ciphertext. */
	result = libfenc_decrypt(&context, &ciphertext, &master_key, &rec_session_key);	
	/* stop timer */
	stop = clock();
	printf("Stop timer.\n");
	double diff = ((double)(stop - start))/CLOCKS_PER_SEC;

	printf("Recovered session key:\t");
	print_buffer_as_hex(rec_session_key.data, rec_session_key.data_len);		
	
	if(memcmp(rec_session_key.data, session_key, rec_session_key.data_len) == 0) {
		printf("\nDECRYPTION TIME => %f secs.\n", diff);
		printf("NUMBER OF LEAVES => %d\n", num_leaves);		
		fp = fopen(outfile, "a");
		fprintf(fp, "%s:%d:%f\n", scheme_text, num_leaves, diff);
		fclose(fp);
	}
	
	if(parsed_attributes != NULL)
		free(parsed_attributes);
	if(parsed_policy != NULL)
		free(parsed_policy);
	/* Shutdown the library. */
	result = libfenc_shutdown();
	report_error("Shutting down library", result);		
}

fenc_attribute_policy *construct_test_policy()
{
	fenc_attribute_policy *policy;
	fenc_attribute_subtree *subtree_AND, *subtree_AND1, *subtree_AND2, *subtree_AND3, *subtree_AND4, *subtree_AND5;
	fenc_attribute_subtree *subtree_L1, *subtree_L2, *subtree_L3, *subtree_L4, *subtree_L5;
	fenc_attribute_subtree *subtree_L6, *subtree_L7, *subtree_L8, *subtree_L9, *subtree_L10, *subtree_L11;
	
	policy = (fenc_attribute_policy*)SAFE_MALLOC(sizeof(fenc_attribute_policy));
	memset(policy, 0, sizeof(fenc_attribute_policy));
	
	/* Add a simple one-level 3-out-of-3 policy.  Eventually we'll have helper routines to
	 * do this work.	*/
	subtree_AND = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_AND1 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_AND2 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_AND3 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_AND4 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_AND5 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L1 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L2 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L3 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L4 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L5 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L6 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L7 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L8 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L9 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L10 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L11 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	
	// subtree_OR = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	memset(subtree_AND, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_AND1, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_AND2, 0, sizeof(fenc_attribute_subtree));	
	memset(subtree_AND3, 0, sizeof(fenc_attribute_subtree));	
	memset(subtree_AND4, 0, sizeof(fenc_attribute_subtree));	
	memset(subtree_AND5, 0, sizeof(fenc_attribute_subtree));		
	memset(subtree_L1, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L2, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L3, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L4, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L5, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L6, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L7, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L8, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L9, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L10, 0, sizeof(fenc_attribute_subtree));	
	memset(subtree_L11, 0, sizeof(fenc_attribute_subtree));	
	
	subtree_L1->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L1->attribute.attribute_str, "attr_aa");
	
	subtree_L2->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L2->attribute.attribute_str, "attr_ab");
	
	subtree_L3->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L3->attribute.attribute_str, "attr_ac");
	
	subtree_L4->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L4->attribute.attribute_str, "attr_ad");
	
	subtree_L5->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L5->attribute.attribute_str, "attr_ae");

	subtree_L6->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L6->attribute.attribute_str, "attr_af");
	
	subtree_L7->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L7->attribute.attribute_str, "attr_ag");
	
	subtree_L8->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L8->attribute.attribute_str, "attr_ah");
	
	subtree_L9->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L9->attribute.attribute_str, "attr_ai");
	
	subtree_L10->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L10->attribute.attribute_str, "attr_aj");			  
	
    subtree_L11->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L11->attribute.attribute_str, "attr_ak");	
	
	subtree_AND->node_type = FENC_ATTRIBUTE_POLICY_NODE_AND;
	// subtree_AND->threshold_k = 3;
	subtree_AND->num_subnodes = 3;
	subtree_AND->subnode = SAFE_MALLOC(sizeof(fenc_attribute_subtree*) * 3);
	subtree_AND->subnode[0] = subtree_L1;
	subtree_AND->subnode[1] = subtree_L2;
	subtree_AND->subnode[2] = subtree_AND1;
	
	subtree_AND1->node_type = FENC_ATTRIBUTE_POLICY_NODE_AND;
	subtree_AND1->subnode = SAFE_MALLOC(sizeof(fenc_attribute_subtree*) * 3);
	subtree_AND1->num_subnodes = 3;
	subtree_AND1->subnode[0] = subtree_L3;
	subtree_AND1->subnode[1] = subtree_L4;
	subtree_AND1->subnode[2] = subtree_AND2;

	subtree_AND2->node_type = FENC_ATTRIBUTE_POLICY_NODE_AND;
	subtree_AND2->subnode = SAFE_MALLOC(sizeof(fenc_attribute_subtree*) * 3);
	subtree_AND2->num_subnodes = 3;
	subtree_AND2->subnode[0] = subtree_L5;
	subtree_AND2->subnode[1] = subtree_L6;
	subtree_AND2->subnode[2] = subtree_AND3;	
	
	subtree_AND3->node_type = FENC_ATTRIBUTE_POLICY_NODE_AND;
	subtree_AND3->subnode = SAFE_MALLOC(sizeof(fenc_attribute_subtree*) * 3);
	subtree_AND3->num_subnodes = 3;	
	subtree_AND3->subnode[0] = subtree_L7;	
	subtree_AND3->subnode[1] = subtree_L8;	
	subtree_AND3->subnode[2] = subtree_AND4;	

	subtree_AND4->node_type = FENC_ATTRIBUTE_POLICY_NODE_AND;
	subtree_AND4->subnode = SAFE_MALLOC(sizeof(fenc_attribute_subtree*) * 2);
	subtree_AND4->num_subnodes = 2;
	subtree_AND4->subnode[0] = subtree_L9;
	// subtree_AND4->subnode[1] = subtree_L5;	
	subtree_AND4->subnode[1] = subtree_AND5;
	
	subtree_AND5->node_type = FENC_ATTRIBUTE_POLICY_NODE_AND;
	subtree_AND5->subnode = SAFE_MALLOC(sizeof(fenc_attribute_subtree*) * 2);
	subtree_AND5->num_subnodes = 2;
	subtree_AND5->subnode[0] = subtree_L10;
	subtree_AND5->subnode[1] = subtree_L11;	
	
	policy->root = subtree_AND;
	
	return policy;
}

fenc_attribute_policy *construct_test_policy1()
{
	fenc_attribute_policy *policy;
	fenc_attribute_subtree *subtree_AND, *subtree_L1, *subtree_L2, *subtree_L3, *subtree_L4, *subtree_L5, *subtree_OR;
	
	policy = (fenc_attribute_policy*)SAFE_MALLOC(sizeof(fenc_attribute_policy));
	memset(policy, 0, sizeof(fenc_attribute_policy));
	
	/* Add a simple one-level 3-out-of-3 policy.  Eventually we'll have helper routines to
	 * do this work.	*/
	subtree_AND = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L1 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L2 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L3 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L4 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L5 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_OR = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	memset(subtree_AND, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L1, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L2, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L3, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L4, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L5, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_OR, 0, sizeof(fenc_attribute_subtree));
	
	subtree_L1->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L1->attribute.attribute_str, "ONE");
	
	subtree_L2->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L2->attribute.attribute_str, "TWO");
	
	subtree_L3->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L3->attribute.attribute_str, "THREE");
	
	subtree_L4->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L4->attribute.attribute_str, "FOUR");
	
	subtree_L5->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L5->attribute.attribute_str, "FIVE");
	
	subtree_AND->node_type = FENC_ATTRIBUTE_POLICY_NODE_OR;
	subtree_AND->threshold_k = 2;
	subtree_AND->num_subnodes = 3;
	subtree_AND->subnode = SAFE_MALLOC(sizeof(fenc_attribute_subtree*) * 5);
	subtree_AND->subnode[0] = subtree_L1;
	subtree_AND->subnode[1] = subtree_L2;
	subtree_AND->subnode[2] = subtree_OR;
	
	subtree_OR->node_type = FENC_ATTRIBUTE_POLICY_NODE_AND;
	subtree_OR->subnode = SAFE_MALLOC(sizeof(fenc_attribute_subtree*) * 3);
	subtree_OR->num_subnodes = 3;
	subtree_OR->subnode[0] = subtree_L3;
	subtree_OR->subnode[1] = subtree_L4;
	subtree_OR->subnode[2] = subtree_L5;
	
	policy->root = subtree_AND;
	
	return policy;
}

fenc_attribute_policy *construct_test_policy2()
{
	fenc_attribute_policy *policy;
	fenc_attribute_subtree *subtree_AND,*subtree_L1,*subtree_L2,*subtree_L3,*subtree_L4,*subtree_L5,*subtree_L6,*subtree_L7,*subtree_L8,*subtree_L9,*subtree_L10,*subtree_L11;
	
	policy = (fenc_attribute_policy *) SAFE_MALLOC(sizeof(fenc_attribute_policy));
	subtree_AND = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L1 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L2 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L3 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L4 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L5 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
    subtree_L6 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L7 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L8 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L9 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L10 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
    subtree_L11 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
			  
	memset(subtree_AND, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L1, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L2, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L3, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L4, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L5, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L6, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L7, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L8, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L9, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L10, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L11, 0, sizeof(fenc_attribute_subtree));	
	
	subtree_L1->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L1->attribute.attribute_str, "attr_aa");
			  
	subtree_L2->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L2->attribute.attribute_str, "attr_ab");
			  
	subtree_L3->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L3->attribute.attribute_str, "attr_ac");
			  
	subtree_L4->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L4->attribute.attribute_str, "attr_ad");
			  
	subtree_L5->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L5->attribute.attribute_str, "attr_ae");
	
	subtree_L6->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L6->attribute.attribute_str, "attr_af");
			  
	subtree_L7->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L7->attribute.attribute_str, "attr_ag");
			  
	subtree_L8->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L8->attribute.attribute_str, "attr_ah");
			  
	subtree_L9->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L9->attribute.attribute_str, "attr_ai");
			  
	subtree_L10->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L10->attribute.attribute_str, "attr_aj");			  

    subtree_L11->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L11->attribute.attribute_str, "attr_ak");
			  
	subtree_AND->node_type = FENC_ATTRIBUTE_POLICY_NODE_AND;
	subtree_AND->num_subnodes = 11;
    subtree_AND->threshold_k = 2;
	subtree_AND->subnode = SAFE_MALLOC(sizeof(fenc_attribute_subtree*) * 11);
	
    subtree_AND->subnode[0] = subtree_L1;
	subtree_AND->subnode[1] = subtree_L2;
    subtree_AND->subnode[2] = subtree_L3;
	subtree_AND->subnode[3] = subtree_L4;
	subtree_AND->subnode[4] = subtree_L5;
	subtree_AND->subnode[5] = subtree_L6;
	subtree_AND->subnode[6] = subtree_L7;
	subtree_AND->subnode[7] = subtree_L8;
    subtree_AND->subnode[8] = subtree_L9;
	subtree_AND->subnode[9] = subtree_L10;
	subtree_AND->subnode[10] = subtree_L11;			  
			  
	policy->root = subtree_AND;
			  
	return policy;
}


void test_secret_sharing(fenc_attribute_policy *policy, pairing_t pairing)
{
	element_t secret, recovered_secret, tempZ, temp2Z;
	FENC_ERROR err_code;
	fenc_attribute_list attribute_list;
	fenc_lsss_coefficient_list coefficient_list;
	unsigned int i;
	char *policy_str;
	size_t str_len = 2048;
	
	/* Print the policy.	*/
	//fenc_attribute_policy_to_string(policy->root, NULL, &str_len, 100000);
	fenc_attribute_policy_to_string(policy->root, NULL, 100000);
	policy_str = (char*)SAFE_MALLOC(str_len);
	fenc_attribute_policy_to_string(policy->root, policy_str, str_len);
	//fenc_attribute_policy_to_string(policy->root, policy_str, &index, str_len);
	printf("%s\n", policy_str);
	
	/* Pick a random secret value.	*/
	element_init_Zr(secret, pairing);
	element_init_Zr(recovered_secret, pairing);
	element_random(secret);
	element_printf("Original secret: %B\n", secret);
	
	/* Share the secret.  The shares are placed within a newly-initialized attribute_list.	*/
	memset(&attribute_list, 0, sizeof(fenc_attribute_list));
	err_code =  fenc_LSSS_calculate_shares_from_policy(&secret, policy, &attribute_list, pairing);
	if (err_code != FENC_ERROR_NONE) {
		printf("could not share secrets!\n");
		return;
	}
	
	printf("\nCreated %d shares:\n", attribute_list.num_attributes); 
	for (i = 0; i < attribute_list.num_attributes; i++) {
		element_printf("\t share %d:\t%B\n", i, attribute_list.attribute[i].share);
	}
	
	/* Take the resulting attribute_list and feed it as input to the coefficient recovery mechanism.
	 * Note that the coefficient recovery doesn't use the shares as input, it just looks at the
	 * attributes.	*/
	err_code = LSSS_allocate_coefficient_list(&coefficient_list, attribute_list.num_attributes, pairing);
	if (err_code != FENC_ERROR_NONE) {
		printf("could not allocate coefficient list!\n");
		return;
	}
	
	err_code = fenc_LSSS_calculate_coefficients_from_policy(policy, &attribute_list, &coefficient_list, pairing);
	if (err_code != FENC_ERROR_NONE) {
		printf("could not compute coefficients!\n");
		return;
	}
	
	printf("\nComputed %d coefficients:\n", attribute_list.num_attributes); 
	for (i = 0; i < attribute_list.num_attributes; i++) {
		if (coefficient_list.coefficients[i].is_set == TRUE) {
			element_printf("\t coefficient %d: %B\n", i, coefficient_list.coefficients[i].coefficient);
		} else {
			printf("\t coefficient %d: <pruned>\n", i);
		}
	}
	
	/* Now let's manually try to recover the secret.  Unfortunately this requires some messy
	 * element arithmetic.	*/
	printf("How many attributes in policy?: '%d'\n", attribute_list.num_attributes);
	element_init_Zr(tempZ, pairing);
	element_init_Zr(temp2Z, pairing);
	element_set0(recovered_secret);
	for (i = 0; i < attribute_list.num_attributes; i++) {
		if (coefficient_list.coefficients[i].is_set == TRUE) {
			element_mul(tempZ, coefficient_list.coefficients[i].coefficient, attribute_list.attribute[i].share);
			element_add(temp2Z, tempZ, recovered_secret);
			element_set(recovered_secret, temp2Z);
		}
	}
	
	element_printf("Recovered secret: %B\n", recovered_secret);
	
	element_clear(secret);
	element_clear(recovered_secret);
	element_clear(tempZ);
	element_clear(temp2Z);
}

void test_libfenc(char *policy)
{
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	fenc_function_input policy_input;
	pairing_t pairing;
	FILE *fp;
	char *public_params_buf = NULL;
	size_t serialized_len;
	
	memset(&context, 0, sizeof(fenc_context)); 
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));	
	
	/* Initialize the library. */
	result = libfenc_init();
	report_error("Initializing library", result);
	
	/* Create a Sahai-Waters context. */
	result = libfenc_create_context(&context, FENC_SCHEME_WATERSCP);
	report_error("Creating context for Waters CP scheme", result);
	
	/* Load group parameters from a file. */
	fp = fopen(PARAM, "r");
	if (fp != NULL) {
		libfenc_load_group_params_from_file(&group_params, fp);
		libfenc_get_pbc_pairing(&group_params, pairing);
	} else {
		perror("Could not open type-d parameters file.\n");
		return;
	}
	fclose(fp);
	
	/* Set up the global parameters. */
	result = context.generate_global_params(&global_params, &group_params);	
	result = libfenc_gen_params(&context, &global_params);
	
	/* Set up the publci parameters */
	fp = fopen(PUBLIC_FILE".cp", "r");
	if(fp != NULL) {
		size_t pub_len = read_file(fp, &public_params_buf);
		/* base-64 decode */
		uint8 *bin_public_buf = NewBase64Decode((const char *) public_params_buf, pub_len, &serialized_len);
		/* Import the parameters from binary buffer: */
		result = libfenc_import_public_params(&context, bin_public_buf, serialized_len);
		report_error("Importing public parameters", result);
		free(public_params_buf);
		free(bin_public_buf);
	}
	else {
		perror("Could not open public parameters\n");
		return;
	}
	fclose(fp);
	
	/* encrypt under given policy */
	// fenc_attribute_policy *parsed_policy = construct_test_policy();
	fenc_attribute_policy *parsed_policy = (fenc_attribute_policy *) malloc(sizeof(fenc_attribute_policy));
	memset(parsed_policy, 0, sizeof(fenc_attribute_policy)); 
	
	fenc_policy_from_string(parsed_policy, policy);
	
	policy_input.input_type = FENC_INPUT_NM_ATTRIBUTE_POLICY;
	policy_input.scheme_input = (void *) parsed_policy;
	
	printf("START: test_secret_sharing\n");
	test_secret_sharing(parsed_policy, pairing);
	printf("END: test_secret_sharing\n");

	/* simple test */
	element_t ONE, TWO, THREE, ONEG2, TWOG2, THREEG2, ONEGT, TWOGT, FinalGT;
	element_init_G1(ONE, pairing);
	element_init_G1(TWO, pairing);
	element_init_G1(THREE, pairing);
	element_init_G2(ONEG2, pairing);
	element_init_G2(TWOG2, pairing);
	element_init_G2(THREEG2, pairing);
	element_init_GT(ONEGT, pairing);
	element_init_GT(TWOGT, pairing);
	element_init_GT(FinalGT, pairing);

	clock_t start, stop;
	double timeG1, timeG2, timePairing;
	element_random(ONE);
	element_random(TWO);
	element_random(ONEG2);
	element_random(TWOG2);
	// element_random(ONEGT);
	// element_random(TWOGT);
	
	/* time G1 */
	start = clock();
	element_mul(THREE, ONE, TWO);	
	stop = clock();
	timeG1 = ((double)(stop - start))/CLOCKS_PER_SEC;

	element_printf("THREEG1: %B, ", THREE);
	printf("G1 mul time: %f secs\n", timeG1);
	
	/* time G2 */
	start = clock();
	element_mul(THREEG2, ONEG2, TWOG2);	
	stop = clock();
	timeG2 = ((double)(stop - start))/CLOCKS_PER_SEC;
		
	element_printf("THREEG2: %B, ", THREEG2);
	printf("G2 mul time: %f secs\n", timeG2);
	
	/* time GT 
	start = clock();
	element_mul(FinalGT, ONEGT, TWOGT);	
	stop = clock();
	timeGT = ((double)(stop - start))/CLOCKS_PER_SEC;	

	element_printf("FinalGT: %B, ", FinalGT);
	printf("GT mul time: %f secs\n", timeGT); */
	
	/* time pairings */
	start = clock();
	pairing_apply(FinalGT, THREE, THREEG2, pairing);
	stop = clock();
	timePairing = ((double)(stop - start))/CLOCKS_PER_SEC;

	element_printf("Pairing: %B, ", FinalGT);
	printf("GT pairing time: %f secs\n", timePairing);
	
	free(parsed_policy);
	result = libfenc_shutdown();
	report_error("Shutting down library", result);	
}
