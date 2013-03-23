/*!	\file libfenc_LSW.c
 *
 *	\brief Routines for the Lewko-Sahai-Waters ABE scheme.
 *  
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <pbc/pbc.h>
#include "libfenc.h"
#include "libfenc_group_params.h"
#include "libfenc_ABE_common.h"
#include "libfenc_utils.h"
#include "libfenc_LSW.h"
#include "libfenc_LSSS.h"

/********************************************************************************
 * Lewko-Sahai-Waters Implementation
 ********************************************************************************/

/*!
 * Initialize a fenc_context data structure for use with the Sahai-Waters scheme.  
 * Any number of fenc_context structures may be simultaneously used, with the same
 * or different schemes.  The caller assumes responsible for allocating the context
 * buffer.
 *
 * @param context		Pre-allocated buffer for the fenc_context data structure.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_create_context_LSW(fenc_context *context)
{
	CHECK_LIBRARY_STATE;
	
	FENC_ERROR result = FENC_ERROR_UNKNOWN;
	
	/* Allocate a scheme-specific context. */
	context->scheme_context = SAFE_MALLOC( sizeof(fenc_scheme_context_LSW) );
	
	if (context->scheme_context != NULL) {
		/* Set up the scheme context. */
		memset(context->scheme_context, 0, sizeof(fenc_scheme_context_LSW) );
		
		/* TODO */
		result = FENC_ERROR_NONE;
	} else {
		 /* Couldn't allocate scheme context. */
		 result = FENC_ERROR_OUT_OF_MEMORY;
	}
	
	/* Configure  function pointers within the fenc_context to point to
	 * LSW scheme-specific routines.									*/
	if (result == FENC_ERROR_NONE) {
		context->gen_params				= libfenc_gen_params_LSW;
		context->set_params				= libfenc_set_params_LSW;
		context->extract_key			= libfenc_extract_key_LSW;
		context->encrypt				= libfenc_encrypt_LSW;
		context->kem_encrypt			= libfenc_kem_encrypt_LSW;
		context->decrypt				= libfenc_decrypt_LSW;
		context->destroy_context		= libfenc_destroy_context_LSW;
		context->generate_global_params	= libfenc_generate_global_params_COMMON;
		context->destroy_global_params	= libfenc_destroy_global_params_COMMON;
		context->export_public_params	= libfenc_export_public_params_LSW;
		context->export_secret_params	= libfenc_export_secret_params_LSW;
		context->import_public_params	= libfenc_import_public_params_LSW;
		context->import_secret_params	= libfenc_import_secret_params_LSW;
		context->export_global_params	= libfenc_export_global_params_LSW;
		context->import_global_params	= libfenc_import_global_params_LSW;
		context->export_secret_key		= libfenc_export_secret_key_LSW;
		context->import_secret_key		= libfenc_import_secret_key_LSW;		
	}
		
	/* Return success/error. */
	return result;
}

/*!
 * Generate public and secret parameters.
 *
 * @param context		The fenc_context data structure
 * @param global_params	Global params (scheme-specific).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_gen_params_LSW(fenc_context *context, fenc_global_params *global_params)
{
	FENC_ERROR result = FENC_ERROR_UNKNOWN, err_code = FENC_ERROR_NONE;
	element_t eggT, alphaZ, loghZ;
	fenc_scheme_context_LSW* scheme_context;
	Bool elements_initialized = FALSE;
	
	/* Get the scheme-specific context. */
	scheme_context = (fenc_scheme_context_LSW*)context->scheme_context;
	if (scheme_context == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
		goto cleanup;
	}
	
	/* Validate the global parameters. */
	err_code = libfenc_validate_global_params_LSW(global_params);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("libfenc_gen_params_LSW: could not validate global params, error: %s", libfenc_error_to_string(err_code));
		result = err_code;
		goto cleanup;
	}
	
	/* Global parameters check out ok.  Copy them and generate the scheme-specific parameters.  The NULL
	 * parameter causes the structure to be allocated.		*/
	scheme_context->global_params = initialize_global_params_LSW(global_params->group_params, NULL);
	
	/* Initialize the elements in the public and secret parameters, along with some temporary variables. */
	public_params_initialize_LSW(&(scheme_context->public_params), scheme_context->global_params->pairing);
	secret_params_initialize_LSW(&(scheme_context->secret_params), scheme_context->global_params->pairing);
	element_init_GT(eggT, scheme_context->global_params->pairing);
	element_init_Zr(alphaZ, scheme_context->global_params->pairing);
	element_init_Zr(loghZ, scheme_context->global_params->pairing);
	elements_initialized = TRUE;
	
	/* Select randoms generators g, h \in G1, h, g2 \in G2 and secret exponents alpha', alpha'', b \in Zp */
	element_random(scheme_context->public_params.gONE);
	element_random(scheme_context->public_params.gTWO);
	element_random(loghZ);																			/* log_g(h) */
	element_pow_zn(scheme_context->secret_params.hONE, scheme_context->public_params.gONE, loghZ);	/* gONE^log_g(h) */
	element_pow_zn(scheme_context->secret_params.hTWO, scheme_context->public_params.gTWO, loghZ);	/* gTWO^log_g(h) */
	element_random(scheme_context->secret_params.alphaprimeZ);
	element_random(scheme_context->secret_params.alphaprimeprimeZ);
	element_random(scheme_context->secret_params.bZ);
	
	/* Compute g^b, g^{b^2}, h^b, e(g,g)^\alpha, */
	element_pow_zn(scheme_context->public_params.gbONE, scheme_context->public_params.gONE, scheme_context->secret_params.bZ);	/* gbONE = gONE^b */
	element_pow_zn(scheme_context->public_params.gb2ONE, scheme_context->public_params.gbONE, scheme_context->secret_params.bZ); /* gb2ONE = gbONE^b */
	element_pow_zn(scheme_context->public_params.hbONE, scheme_context->secret_params.hONE, scheme_context->secret_params.bZ);	/* hbONE = hONE^b */

	/* Compute e(gONE,gTWO)^(alpha' * alpha'') */
	pairing_apply(eggT, scheme_context->public_params.gONE, scheme_context->public_params.gTWO, scheme_context->global_params->pairing);	/* eggT = e(gONE, gTWO) */
	element_mul(alphaZ, scheme_context->secret_params.alphaprimeZ, scheme_context->secret_params.alphaprimeprimeZ);					/* alphaZ = alphaprimeZ * alphaprimeprimeZ */
	element_pow_zn(scheme_context->public_params.eggalphaT, eggT, alphaZ);															/* eggalphaT = eggT^alpha */

	/* Success */
	result = FENC_ERROR_NONE;
	
cleanup:
	if (elements_initialized == TRUE) {
		/* Destroy any temporary elements. */
		element_clear(eggT);
		element_clear(alphaZ);
		element_clear(loghZ);
	}
	
	return result;
}

/*!
 * Load public and (optionally) secret parameters into the context.  All relevant global
 * parameters are embedded within the public_params data structure.
 *
 * @param context		The fenc_context data structure
 * @param public_params	Public scheme parameters.
 * @param secret_params	Secret scheme parameters (optional).
 * @return				FENC_ERROR_NONE or an error code.
 */
// TODO : unused parameter(s).
FENC_ERROR
libfenc_set_params_LSW(/*fenc_context *context, fenc_public_params *public_params, fenc_secret_params *secret_params*/)
{
	return FENC_ERROR_NOT_IMPLEMENTED;
}

/*!
 * Extract a secret key representing a given function input, which is defined as an access structure.
 * Note that this function will only be called if the secret parameters (MSK) are available within 
 * the context.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input from which this key will be built.
 * @param key			A pre-allocated buffer for the resulting key
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_extract_key_LSW(fenc_context *context, fenc_function_input *input, fenc_key *key)
{
	FENC_ERROR					result = FENC_ERROR_UNKNOWN, err_code = FENC_ERROR_NONE;
	fenc_key_LSW				*key_LSW = NULL;
	fenc_attribute_policy		*policy = NULL;
	fenc_attribute_list			attribute_list;
	fenc_scheme_context_LSW*	scheme_context;
	int							i;
	element_t					rZ, hashONE, tempONE, temp2ONE, tempZ, temp2Z, tempTWO, temp2TWO;
	Bool						elements_initialized = FALSE;

	//char output_str[length];
	//memset(output_str, 0, length);
	
	/* Get the scheme-specific context. */
	scheme_context = (fenc_scheme_context_LSW*)context->scheme_context;
	if (scheme_context == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
		goto cleanup;
	}
	
	/* Parse the function input as an attribute policy.  This will allocate memory
	 * that will ultimately be released when the key is cleared.				*/
	policy = (fenc_attribute_policy*)SAFE_MALLOC(sizeof(fenc_attribute_policy));
	err_code = libfenc_parse_input_as_attribute_policy(input, policy);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("%s: could not parse function input as policy", __func__);
		result = FENC_ERROR_INVALID_INPUT;
		goto cleanup;
	}
	
	/* test print out */
	//fenc_attribute_policy_to_string(policy->root, output_str, length);
	//printf("Copied policy: '%s'\n", output_str);
	//print_buffer_as_hex((uint8 *) output_str, strlen(output_str));
	
	/* Use the Linear Secret Sharing Scheme (LSSS) to compute an enumerated list of all
	 * attributes and corresponding secret shares.  The shares will be placed into 
	 * a fenc_attribute_list structure that we'll embed within the fenc_key_LSW struct.	*/
	memset(&attribute_list, 0, sizeof(fenc_attribute_list));
	err_code = fenc_LSSS_calculate_shares_from_policy(&(scheme_context->secret_params.alphaprimeZ), policy, &attribute_list, 
													  scheme_context->global_params->pairing);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("%s: could not calculate shares", __func__);
		result = FENC_ERROR_INVALID_INPUT;
		goto cleanup;
	}	
	
	/* Initialize the LSW-specific key data structure and allocate some temporary variables.	*/
	key_LSW = fenc_key_LSW_initialize(&attribute_list, policy, FALSE, scheme_context->global_params);
	if (key_LSW == NULL) {
		LOG_ERROR("%s: could not initialize key structure", __func__);
		result = FENC_ERROR_INVALID_INPUT;
		goto cleanup;
	}
	element_init_Zr(rZ, scheme_context->global_params->pairing);
	element_init_Zr(tempZ, scheme_context->global_params->pairing);
	element_init_Zr(temp2Z, scheme_context->global_params->pairing);
	element_init_G1(hashONE, scheme_context->global_params->pairing);
	element_init_G1(tempONE, scheme_context->global_params->pairing);
	element_init_G1(temp2ONE, scheme_context->global_params->pairing);
	element_init_G2(tempTWO, scheme_context->global_params->pairing);
	element_init_G2(temp2TWO, scheme_context->global_params->pairing);
	elements_initialized = TRUE;
		 
	/* For every share/attribute, create one component of the secret key.	*/
	for (i = 0; i < (signed int)key_LSW->attribute_list.num_attributes; i++) {		
		/* Hash the attribute string to Zr, if it hasn't already been.	*/
		hash_attribute_string_to_Zr(&(key_LSW->attribute_list.attribute[i]), scheme_context->global_params->pairing);
		
		/* Pick a random value r_i (rZ).	*/
		element_random(rZ);
		
		if (key_LSW->attribute_list.attribute[i].is_negated == TRUE) {
			/* For negated attributes, compute:
			 *   D3ONE[i] = gONE^{alphaprimeprimeZ * share[i]} * gb2ONE^{r_i}
			 *   D4TWO[i] = gTWO^{b * r_i * attribute[i]} * hTWO^{r_i}
			 *   D5TWO[i] = gTWO^{- r_i}									*/
			
			/* tempONE = gONE^{alphaprimeprimeZ * share[i]} */
			element_mul(tempZ, scheme_context->secret_params.alphaprimeprimeZ, key_LSW->attribute_list.attribute[i].share);
			element_pow_zn(tempONE, scheme_context->public_params.gONE, tempZ);									
			
			/* temp2ONE = gb2ONE^{r_i} --- D3ONE[i] = tempONE * temp2ONE		*/
			element_pow_zn(temp2ONE, scheme_context->public_params.gb2ONE, rZ);									
			element_mul(key_LSW->D3ONE[i], tempONE, temp2ONE);
			
			/* tempTWO = gTWO^{b * r_i * attribute[i]}		*/
			element_mul(tempZ, scheme_context->secret_params.bZ, rZ);
			element_mul(temp2Z, tempZ, key_LSW->attribute_list.attribute[i].attribute_hash);
			element_pow_zn(tempTWO, scheme_context->public_params.gTWO, temp2Z);
			
			/* temp2TWO = hTWO^{r_i} --- D4TWO[i] = tempTWO * temp2TWO		*/
			element_pow_zn(temp2TWO, scheme_context->secret_params.hTWO, rZ);
			element_mul(key_LSW->D4TWO[i], tempTWO, temp2TWO);
			
			/* D5TWO[i] = gTWO^{- r_i}										*/
			element_pow_zn(tempTWO, scheme_context->public_params.gTWO, rZ);
			element_invert(key_LSW->D5TWO[i], tempTWO);		/* could be faster	*/
		} else {
			/* For positive (non-negated attributes), compute:
			 *   D1ONE[i] = g^{alphaprimeprimeZ * share[i]} * H(attribute_hash[i])^{r_i}
			 *   D2TWO = g^{r_i}															*/
			
			/* hashONE = H(attribute_hash[i])^{r_i}.			*/
			err_code = hash2_attribute_element_to_G1(&(key_LSW->attribute_list.attribute[i].attribute_hash), &tempONE);	/* result in tempONE  */
			DEBUG_ELEMENT_PRINTF("extract key -- hashed to G1: %B\n", tempONE);
			if (err_code != FENC_ERROR_NONE) {
				LOG_ERROR("%s: could not compute hash2", __func__);
				result = FENC_ERROR_UNKNOWN;
				goto cleanup;
			}
			element_pow_zn(hashONE, tempONE, rZ);									
			
			/* tempONE = gONE^(secret_params.alphaprimeprimeZ * share)	*/
			DEBUG_ELEMENT_PRINTF("share %d=%B\n", i, key_LSW->attribute_list.attribute[i].share);
			element_mul(tempZ, scheme_context->secret_params.alphaprimeprimeZ, key_LSW->attribute_list.attribute[i].share);
			element_pow_zn(tempONE, scheme_context->public_params.gONE, tempZ);									

			/* D1ONE = tempONE * hashONE.	*/
			element_mul(key_LSW->D1ONE[i], tempONE, hashONE);
			
			/* D2TWO = g^{r_i}.	*/
			element_pow_zn(key_LSW->D2TWO[i], scheme_context->public_params.gTWO, rZ);									
		}
	}
	
	/* Stash the key_LSW structure inside of the fenc_key.		*/
	memset(key, 0, sizeof(fenc_key));
	key->scheme_type = FENC_SCHEME_LSW;
	key->valid = TRUE;
	key->scheme_key = (void*)key_LSW;
	
	/* Success!		*/
	result = FENC_ERROR_NONE;
	
cleanup:
	/* If there was an error, clean up after ourselves.	*/
	if (result != FENC_ERROR_NONE) {
		if (key_LSW != NULL) {
			if (key_LSW->policy != NULL)	{ 
				/* TODO: should properly clear up this policy structure if it's a copy.	*/
				SAFE_FREE(key_LSW->policy);
				key_LSW->policy = NULL;
			}
		
			fenc_attribute_list_clear(&(key_LSW->attribute_list));

			/* Clear out the key internals.		*/
			if (elements_initialized == TRUE)	{
				key_LSW_clear(key_LSW);
			}
		}
	}
	
	/* Wipe out temporary variables.	*/
	if (elements_initialized == TRUE) {
		element_clear(rZ);
		element_clear(hashONE);
		element_clear(tempONE);
		element_clear(temp2ONE);
		element_clear(tempZ);
		element_clear(temp2Z);
		element_clear(tempTWO);
		element_clear(temp2TWO);
	}
	
	return result;
}

/*!
 * Encrypt a plaintext, return a ciphertext.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input under which which the ciphertext will be encrypted.
 * @param plaintext		The plaintext message.
 * @param ciphertext	A pre-allocated buffer for the returned fenc_ciphertext.
 * @return				FENC_ERROR_NONE or an error code.
 */
// TODO : unused parameter(s).
FENC_ERROR
libfenc_encrypt_LSW(/*fenc_context *context, fenc_function_input *input, fenc_plaintext *plaintext,
					fenc_ciphertext *ciphertext*/)
{
	LOG_ERROR("libfenc_encrypt_LSW: standard encryption not supported, use libfenc_kem_encrypt");
	return FENC_ERROR_NOT_IMPLEMENTED;
	
	/*return encrypt_LSW_internal(context, input, plaintext, FALSE, NULL, 0, ciphertext); */
}

/*!
 * Key encapsulation variant of encryption.  Generate an encryption key and encapsulate it under 
 * a given function input.  Returns the encapsulated key as well as the ciphertext.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input under which which the ciphertext will be encrypted.
 * @param key_len		Desired key size (in bytes).  Will be overwritten with the actual key size.
 * @param key			Pointer to an initialized buffer into which the key will be written.
 * @param ciphertext	A pre-allocated buffer for the returned fenc_ciphertext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_kem_encrypt_LSW(fenc_context *context, fenc_function_input *input, size_t key_len,
									uint8* key, fenc_ciphertext *ciphertext)
{
	return encrypt_LSW_internal(context, input, NULL, TRUE, key, key_len, ciphertext);
}

/*!
 * Decrypt a ciphertext using a specified secret key.
 *
 * @param context		The fenc_context data structure
 * @param ciphertext	The ciphertext to decrypt.
 * @param key			The secret key to use.
 * @param plaintext		A pre-allocated buffer for the resulting plaintext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_decrypt_LSW(fenc_context *context, fenc_ciphertext *ciphertext, fenc_key *key,
										 fenc_plaintext *plaintext)
{
	FENC_ERROR						result = FENC_ERROR_UNKNOWN, err_code;
	fenc_ciphertext_LSW				ciphertext_LSW;
	fenc_scheme_context_LSW			*scheme_context;
	fenc_key_LSW					*key_LSW;
	fenc_attribute_list				attribute_list_N;
	fenc_lsss_coefficient_list		coefficient_list;
	element_t						tempGT, temp2GT, tempONE, temp2ONE, temp3ONE, tempZ, temp2Z;
	element_t						temp3GT, temp4GT, prodT, finalT;
	uint32							i, j;
	int32							index_ciph, index_key;
	Bool							elements_initialized = FALSE, coefficients_initialized = FALSE;
	Bool							attribute_list_N_initialized = FALSE;
	
	/* Get the scheme-specific context. */
	scheme_context = (fenc_scheme_context_LSW*)context->scheme_context;
	if (scheme_context == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
		goto cleanup;
	}
	
	/* Obtain the LSW-specific key data structure and make sure it's correct.	*/
	if (key->scheme_key == NULL) {
		LOG_ERROR("libfenc_decrypt_LSW: could not obtain scheme-specific decryption key");
		result = FENC_ERROR_INVALID_KEY;
		goto cleanup;
	}
	key_LSW = (fenc_key_LSW*)key->scheme_key;
	err_code = attribute_list_compute_hashes(&(key_LSW->attribute_list), scheme_context->global_params->pairing);
	err_code = attribute_tree_compute_hashes(key_LSW->policy->root, scheme_context->global_params->pairing);
	
	/* Deserialize the ciphertext.	*/
	err_code = libfenc_deserialize_ciphertext_LSW(ciphertext->data, ciphertext->data_len, &ciphertext_LSW, scheme_context);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("libfenc_decrypt_LSW: unable to deserialize ciphertext");
		result = err_code;
		goto cleanup;
	}
	
	/* libfenc_fprint_ciphertext_LSW(&ciphertext_LSW, stdout);   */

	/* Apply the N() function to the ciphertext's attribute list and the key.  This derives a list of 
	 * negated/non-negated attributes that we'll use in the decryption procedure below.	*/
	memset(&(attribute_list_N), 0, sizeof(fenc_attribute_list));

	// TODO : unused parameter.
	err_code = fenc_apply_N_function_to_attributes(&attribute_list_N, &(ciphertext_LSW.attribute_list), /*key_LSW->policy,*/
						      scheme_context->global_params->pairing);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("libfenc_decrypt_LSW: unable to apply N() function to ciphertext attributes");
		result = err_code;
		goto cleanup;
	}
	attribute_list_N_initialized = TRUE;
	
	/* Use the policy to calculate the \Beta coefficients that will be used in the decryption process.
	 * This is a procedure associated with the LSSS (linear secret sharing scheme) used to generate
	 * the decryption key.	We are responsible for allocating and initializing the coefficient list that 
	 * will hold the coefficients.  We must also clear it when we're done.  If the policy isn't satisfied
	 * we get an error from this routine.
	 *
	 * Note: all this memory allocation probably slows decryption down; it should be amortized. */

	/* Use the LSSS-associated procedure to recover the coefficients.  This gives us a list of coefficients
	 * that should match up in a 1-to-1 fashion with the components of the decryption key. 
	 * First, initialize a coefficients list:													*/
	err_code = LSSS_allocate_coefficient_list(&coefficient_list, key_LSW->num_components, scheme_context->global_params->pairing);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("libfenc_decrypt_LSW: could not allocate coefficients");
		result = err_code;
		goto cleanup;
	}
	coefficients_initialized = TRUE;

	/* Now calculate the actual coefficients.													*/
	err_code = fenc_LSSS_calculate_coefficients_from_policy(key_LSW->policy, &attribute_list_N, &coefficient_list,
															scheme_context->global_params->pairing);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("libfenc_decrypt_LSW: unable to compute LSSS coefficients");
		result = FENC_ERROR_INVALID_CIPHERTEXT;
		goto cleanup;
	}
	
	/* Allocate some temporary work variables.	*/
	elements_initialized = TRUE;
	element_init_GT(tempGT, scheme_context->global_params->pairing);
	element_init_GT(temp2GT, scheme_context->global_params->pairing);
	element_init_GT(temp3GT, scheme_context->global_params->pairing);
	element_init_GT(temp4GT, scheme_context->global_params->pairing);
	element_init_GT(prodT, scheme_context->global_params->pairing);
	element_init_GT(finalT, scheme_context->global_params->pairing);
	element_init_G1(tempONE, scheme_context->global_params->pairing);
	element_init_G1(temp2ONE, scheme_context->global_params->pairing);
	element_init_G1(temp3ONE, scheme_context->global_params->pairing);
	element_init_Zr(tempZ, scheme_context->global_params->pairing);
	element_init_Zr(temp2Z, scheme_context->global_params->pairing);

	/* Now compute the product of the sub-components raised to the coefficients:
	 *		prodT = \prod_{i=0}^num_attributes (Z_i^{coefficient[i]}).  
	 * We compute one of these for every value in attribute_list_N.	 */
	element_set1(prodT);
	for (i = 0; i < coefficient_list.num_coefficients; i++) {		

		if (coefficient_list.coefficients[i].is_set == TRUE) {
			if (key_LSW->attribute_list.attribute[i].is_negated == FALSE) {
				/* For positive (non-negated) attributes:
				 * 
				 * Let index_ciph be the attribute's index in the ciphertext structure.
				 * Let index_key be the attribute's index in the key structure.
				 *
				 * Compute finalT = e(D1ONE[index_key] , E2TWO) / e(E3ONE[index_ciph] , D2TWO[index_key]).		*/

				/* Find the corresponding indices in the ciphertext attribute list and in the key.	*/
				index_ciph = libfenc_get_attribute_index_in_list(&(key_LSW->attribute_list.attribute[i]), &(ciphertext_LSW.attribute_list));
				index_key = i;/*libfenc_get_attribute_index_in_list(&(attribute_list_N.attribute[i]), &(key_LSW.attribute_list));*/
				
				if (index_ciph < 0 || index_key < 0) {
					DEBUG_ELEMENT_PRINTF("key element %d=%B\n", index_key, key_LSW->attribute_list.attribute[i].attribute_hash);
					LOG_ERROR("libfenc_decrypt_LSW: could not find attribute in key and ciphertext");
					/*DEBUG_ELEMENT_PRINTF("attribute(%s)=%B\n", attribute_list_N.attribute[i].attribute_str, attribute_list_N.attribute[i].attribute_hash);*/
					result = FENC_ERROR_INVALID_INPUT;
					goto cleanup;
				}
			
				/* Compute Z_vals[i] = e(D1ONE[index_key] , E2TWO) / e(E3ONE[index_ciph] , D2TWO[index_key]).		*/
				pairing_apply(tempGT, ciphertext_LSW.E3ONE[index_ciph], key_LSW->D2TWO[index_key],
							  scheme_context->global_params->pairing);
				element_invert(temp2GT, tempGT);
				pairing_apply(tempGT, key_LSW->D1ONE[index_key], ciphertext_LSW.E2TWO, scheme_context->global_params->pairing);
				element_mul(finalT, tempGT, temp2GT);
				
				DEBUG_ELEMENT_PRINTF("finalT=%B\n", finalT);
			
			} else {
				/* For negated attributes: 
				 *
				 * Let neg_atr be the negated attribute
				 * Let (attribute[j] \in ciphertext) represent an attribute in the ciphertext (at index j).
				 *
				 * Compute finalT = e(D3ONE[index_key] , E2TWO) / 
				 *					e(\prod_{attribute[j] \in ciphertext}(E4ONE[j])^{1/(neg_atr - attribute[j])} , D4TWO[i]) *
				 *					e(\prod_{attribute[j] \in ciphertext}(E4ONE[j])^{1/(neg_atr - attribute[j])} , D5TWO[i]).			 */
			
				/* Find the corresponding index in the key.	*/
				index_key = i;/*libfenc_get_attribute_index_in_list(&(attribute_list_N.attribute[i]), &(key_LSW->attribute_list));*/
				if (index_key < 0) {
					LOG_ERROR("libfenc_decrypt_LSW: could not find attribute in key");
					result = FENC_ERROR_INVALID_INPUT;
					goto cleanup;
				}
			
				/* Compute	tempONE =	\prod_{attribute[j] \in ciphertext}(E4ONE[j])^{1/(neg_atr - attribute[j])}
				 *			temp2ONE =	\prod_{attribute[j] \in ciphertext}(E5ONE[j])^{1/(neg_atr - attribute[j])}		*/

				element_set1(tempONE);
				element_set1(temp2ONE);
				for (j = 0; j < ciphertext_LSW.attribute_list.num_attributes; j++) {
					/* First compute tempZ = (1/(neg_atr - attribute[j])).	*/
					element_sub(temp2Z, attribute_list_N.attribute[i].attribute_hash, ciphertext_LSW.attribute_list.attribute[j].attribute_hash);
					element_invert(tempZ, temp2Z);
				
					/* tempONE = tempONE * E4ONE[j]^{tempZ}	*/
					element_mul(temp3ONE, tempONE, ciphertext_LSW.E4ONE[j]);
					element_pow_zn(tempONE, temp3ONE, tempZ);
				
					/* temp2ONE = temp2ONE * E5ONE[j]^{tempZ}	*/
					element_mul(temp3ONE, temp2ONE, ciphertext_LSW.E5ONE[j]);
					element_pow_zn(temp2ONE, temp3ONE, tempZ);
				}
				 
				/* Compute	tempGT =	e(D3ONE[index_key] , E2TWO),
							temp2GT	=	e(tempONE , D4TWO[index_key])
							temp3GT =	e(temp2ONE , D5TWO[index_key])	*/
				pairing_apply(tempGT, key_LSW->D3ONE[index_key], ciphertext_LSW.E2TWO, scheme_context->global_params->pairing);
				pairing_apply(temp2GT, tempONE, key_LSW->D4TWO[index_key], scheme_context->global_params->pairing);
				pairing_apply(temp3GT, temp2ONE, key_LSW->D5TWO[index_key], scheme_context->global_params->pairing);
			
				/* Compute finalT = tempGT / (temp2GT * temp3GT)			*/
				element_mul(temp4GT, temp2GT, temp3GT);
				element_invert(temp2GT, temp4GT);
				element_mul(finalT, tempGT, temp2GT);
				DEBUG_ELEMENT_PRINTF("negated: finalT=%B\n", finalT);
			}	/* end of if clause	*/
		
			/* We computed the Z value as "finalT", now raise it to coefficient[i] and multiply it into 
			 * prodT.	*/
			element_pow_zn(tempGT, finalT, coefficient_list.coefficients[i].coefficient);
			element_mul(temp2GT, tempGT, prodT);
			element_set(prodT, temp2GT);
		} /* end of if coefficient.is_set clause */
	} /* end of for clause */
	
	/* Final computation: this depends on whether this is a KEM or a standard encryption.	*/
	if (ciphertext_LSW.type == FENC_CIPHERTEXT_TYPE_KEM_CPA) {
		/* If its a KEM, hash prodT and that's the resulting session key.	*/
		// TODO : unused parameter... reused.
		err_code = derive_session_key_from_element(plaintext, prodT, ciphertext_LSW.kem_key_len, scheme_context->global_params->pairing);
		if (err_code != FENC_ERROR_NONE) {
			result = err_code;
			goto cleanup;
		}
	} else {
		/* If it's a standard ciphertext, compute the plaintext as finalT = (E1T / prodT).	*/
		element_invert(tempGT, prodT);
		element_mul(finalT, ciphertext_LSW.E1T, tempGT);
	
		DEBUG_ELEMENT_PRINTF("decrypted plaintext=%B\n", finalT);
		
		/* Convert the group element "finalT" back into a bit string.	*/
		// TODO : unused parameter... reused
		err_code = decode_plaintext_GT(plaintext, &finalT, scheme_context->global_params->pairing);
		if (err_code != FENC_ERROR_NONE)	{
			LOG_ERROR("libfenc_decrypt_LSW: could not decode plaintext from group element");
			result = err_code;
			goto cleanup;
		}
	}

	/* Success!	*/
	result = FENC_ERROR_NONE;
	
cleanup:
	/* If the coefficient list was allocated/initialized, we have to clear it.	*/
	if (coefficients_initialized == TRUE) {
		LSSS_clear_coefficients_list(&coefficient_list);
	}
	
	/* Clear temporary variables.	*/
	if (elements_initialized == TRUE) {
		element_clear(finalT);
		element_clear(prodT);
		element_clear(tempGT);
		element_clear(temp2GT);	
		element_clear(temp3GT);	
		element_clear(temp4GT);	
		element_clear(tempONE);
		element_clear(temp2ONE);	
		element_clear(temp3ONE);	
		element_clear(tempZ);	
		element_clear(temp2Z);	
	}
	
	/* Clear out the attribute_list_N structure.	*/
	if (attribute_list_N_initialized == TRUE) {
		fenc_attribute_list_clear(&(attribute_list_N));
	}
	
	return result;
}

/*!
 * Internal function for computing a ciphertext.  In key-encapsulation mode this function
 * returns a key and a buffer.  In standard mode it encrypts a given plaintext.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input under which which the ciphertext will be encrypted.
 * @param plaintext		The plaintext message.
 * @param kem_mode		Set to "TRUE" if using KEM mode, false for normal encryption.
 * @param kem_key_buf	Buffer for the returned session key (KEM mode only).
 * @param kem_key_len	Pointer to a key length; input is desired, overwritten with actual length.
 * @param ciphertext	A pre-allocated buffer for the returned fenc_ciphertext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
encrypt_LSW_internal(fenc_context *context, fenc_function_input *input, fenc_plaintext *plaintext,
					 Bool kem_mode, uint8* kem_key_buf, size_t kem_key_len, fenc_ciphertext *ciphertext)
{
	FENC_ERROR result = FENC_ERROR_UNKNOWN, err_code = FENC_ERROR_NONE;
	fenc_scheme_context_LSW* scheme_context;
	fenc_ciphertext_LSW ciphertext_LSW;
	element_t sZ, hashONE, tempZ, plaintextT;
	element_t eggalphasT, tempONE, temp2ONE;
	element_t sxZ[MAX_CIPHERTEXT_ATTRIBUTES];
	uint32 i;
	Bool elements_initialized = FALSE;
	size_t serialized_len = 0;
	fenc_attribute_list attribute_list;
	
	/* Wipe the attribute list structure clean.	*/
	memset(&attribute_list, 0, sizeof(fenc_attribute_list));
	
	/* Get the scheme-specific context. */
	scheme_context = (fenc_scheme_context_LSW*)context->scheme_context;
	if (scheme_context == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
		goto cleanup;
	}
	
	/* Parse the "function" to obtain an attribute list (first allocate memory). */
	err_code = libfenc_parse_input_as_attribute_list(input, &attribute_list, scheme_context->global_params->pairing);
	if (attribute_list.num_attributes < 1 || attribute_list.num_attributes > MAX_CIPHERTEXT_ATTRIBUTES) { err_code = FENC_ERROR_INVALID_INPUT; }
	if (err_code != FENC_ERROR_NONE) {
		/* Fail if the attribute list is empty or too long. */
		LOG_ERROR("libfenc_encrypt_LSW: too many or too few attributes specified: %d", attribute_list.num_attributes);
		result = err_code;
		goto cleanup;
	}
	
	/* Initialize the ciphertext structure and temporary elements. */
	elements_initialized = TRUE;
	fenc_ciphertext_LSW_initialize(&ciphertext_LSW, attribute_list.num_attributes, FENC_CIPHERTEXT_TYPE_UNDEFINED, scheme_context);
	memcpy(&(ciphertext_LSW.attribute_list), &attribute_list, sizeof(fenc_attribute_list));
	
	element_init_GT(plaintextT, scheme_context->global_params->pairing);
	element_init_GT(eggalphasT, scheme_context->global_params->pairing);
	element_init_G1(hashONE, scheme_context->global_params->pairing);
	element_init_Zr(sZ, scheme_context->global_params->pairing);
	element_init_Zr(tempZ, scheme_context->global_params->pairing);
	element_init_G1(tempONE, scheme_context->global_params->pairing);
	element_init_G1(temp2ONE, scheme_context->global_params->pairing);
	for (i = 0; i < ciphertext_LSW.attribute_list.num_attributes; i++) {
		element_init_Zr(sxZ[i], scheme_context->global_params->pairing);
	}
		
	/* Pick a random value s \in Zp */
	element_random(sZ);
	
	/* Select a collection of num_attributes random values s_x such that the sum of these values is equal to s */
	element_set(sxZ[0], sZ);
	for (i = 1; i < ciphertext_LSW.attribute_list.num_attributes; i++) {
		/* Pick random value sxZ[i], set sxZ[0] -= sxZ[i]. */
		element_random(sxZ[i]);
		element_sub(tempZ, sxZ[0], sxZ[i]);
		element_set(sxZ[0], tempZ);
	}
	
	/* Compute: eggalphasT = e(gONE,gTWO)^{alpha s} */
	element_pow_zn(eggalphasT, scheme_context->public_params.eggalphaT, sZ);	/* eggalphasT = eggalphaT^s */
	
	/* If we're in KEM mode, compute the hash of eggalphasT and return this as the session key.
	 * In standard encryption mode, we compute E1T.			*/
	if (kem_mode == TRUE) {
		/* In key encapsulation mode we derive a key from eggalphasT.	*/
		err_code = fenc_derive_key_from_element(eggalphasT, kem_key_len, kem_key_buf);
		if (err_code != FENC_ERROR_NONE) {
			result = err_code;
			goto cleanup;
		}
		ciphertext_LSW.type = FENC_CIPHERTEXT_TYPE_KEM_CPA;
		ciphertext_LSW.kem_key_len = kem_key_len;
	} else {
		/* In normal encryption mode we compute E1T = M * eggalphasT.	*/
		ciphertext_LSW.type = FENC_CIPHERTEXT_TYPE_CPA;
		err_code = encode_plaintext_GT(plaintext, &plaintextT, scheme_context->global_params->pairing);
		if (err_code != FENC_ERROR_NONE) {
			result = err_code;
			goto cleanup;
		}
		DEBUG_ELEMENT_PRINTF("initial plaintext=%B\n", plaintextT);
		
		element_mul(ciphertext_LSW.E1T, eggalphasT, plaintextT);					/* E1T  = eggalphasT * M */
	}
	
	/* Compute: E2 = gTWO^s */
	element_pow_zn(ciphertext_LSW.E2TWO, scheme_context->public_params.gTWO, sZ);	/* E2TWO = gTWO^s */
	
	/* For each attribute, set E3, E4, E5. */
	for (i = 0; i < ciphertext_LSW.attribute_list.num_attributes; i++) {
		/* Note that in the LSW description the attributes are in Z*p and these integers are subsequently hashed 
		 * into group elements.  We accept attributes as C strings and first hash to Zp to encode the attribute as
		 * an integer.  As part of the encryption, we then hash these integers to elements of G1.  These operate as
		 * two distinct hash functions.
		 *
		 * First, compute the attribute ciphertext_LSW.attribute[i] = H1(attribute_i) */
		err_code = hash_attribute_string_to_Zr(&(attribute_list.attribute[i]), scheme_context->global_params->pairing);
		if (err_code != FENC_ERROR_NONE) { result = err_code; goto cleanup; }
		
		/* Now compute the group element hashONE = H2(ciphertext_LSW.attribute[i]) */
		err_code = hash2_attribute_element_to_G1(&(ciphertext_LSW.attribute_list.attribute[i].attribute_hash), &hashONE);
		DEBUG_ELEMENT_PRINTF("hashed to G1: %B\n", hashONE);
		if (err_code != FENC_ERROR_NONE) { result = err_code; goto cleanup; }
		
		/* Compute E3 = H(attribute_i)^s */
		element_pow_zn(ciphertext_LSW.E3ONE[i], hashONE, sZ);	/* E3ONE = H(attribute_i)^s */
		
		/* Compute E4 = gbONE^{sxZ[i]} */
		element_pow_zn(ciphertext_LSW.E4ONE[i], scheme_context->public_params.gbONE, sxZ[i]);
		
		/* Compute E5 = gb2ONE^{sxZ[i] * ciphertext_LSW.attribute[i]} * hbONE^{sxZ[i]} */
		element_mul(tempZ, sxZ[i], ciphertext_LSW.attribute_list.attribute[i].attribute_hash);					
		element_pow_zn(tempONE, scheme_context->public_params.gb2ONE, tempZ); /* tempONE = gb2ONE^{sxZ[i] * ciphertext_LSW.attribute[i]} */
		element_pow_zn(temp2ONE, scheme_context->public_params.hbONE, sxZ[i]); /* temp2ONE = hbONE^{sxZ[i]} */
		element_mul(ciphertext_LSW.E5ONE[i], tempONE, temp2ONE);					
	}
	
	/* Serialize the LSW ciphertext structure into a fenc_ciphertext container 
	 * (which is essentially just a binary buffer).  First we get the length, then we 
	 * allocate the ciphertext buffer, then we serialize. *.
	 * First get the length: */
	libfenc_serialize_ciphertext_LSW(&ciphertext_LSW, NULL, 0, &serialized_len);	/* This gets the serialized length. */
	libfenc_ciphertext_initialize(ciphertext, serialized_len, FENC_SCHEME_LSW);
	if (err_code != FENC_ERROR_NONE) {	result = err_code;	goto cleanup;	}
	err_code = libfenc_serialize_ciphertext_LSW(&ciphertext_LSW, ciphertext->data, ciphertext->max_len, &ciphertext->data_len);	/* Serialization. */
	if (err_code != FENC_ERROR_NONE) {	result = err_code;	goto cleanup;	}
	
	/* Success. */
	result = FENC_ERROR_NONE;
	
cleanup:
	
	/* If any elements were initialized, release their memory.  This includes the LSW ciphertext structure. */ 
	if (elements_initialized == TRUE) {
		element_clear(plaintextT);
		element_clear(eggalphasT);
		element_clear(hashONE);
		element_clear(sZ);
		element_clear(tempZ);
		element_clear(tempONE);
		element_clear(temp2ONE);
		for (i = 0; i < ciphertext_LSW.attribute_list.num_attributes; i++) {
			element_clear(sxZ[i]);
		}
		
		fenc_ciphertext_LSW_clear(&ciphertext_LSW);
	}
	
	/* Get rid of the attribute list, if one was allocated. */
	fenc_attribute_list_clear(&(ciphertext_LSW.attribute_list));
	
	return result;
}

/*!
 * Export the public parameters (MPK) to a binary buffer.  Calling this function with buffer 
 * set to NULL will return the length of the exported material.
 *
 * @param context		The fenc_context data structure
 * @param buffer		A pre-allocated buffer for the resulting export.
 * @param max_len		The maximum allocated size of the buffer (in bytes).
 * @param result_len	The size of the resulting export (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_export_public_params_LSW(fenc_context *context, uint8 *buffer, size_t max_len, size_t *result_len)
{
	FENC_ERROR err_code;
	fenc_scheme_context_LSW* scheme_context;
	
	/* Get the scheme-specific context. */
	scheme_context = (fenc_scheme_context_LSW*)context->scheme_context;
	
	/* Export the elements to the buffer.  Note that if buffer is NULL this routine will
	 * just compute the necessary buffer length.									*/
	err_code = export_components_to_buffer(buffer, max_len, result_len, "%C%C%C%C%C%E",
									   &(scheme_context->public_params.gONE), 
									   &(scheme_context->public_params.gTWO),
									   &(scheme_context->public_params.hbONE),
									   &(scheme_context->public_params.gbONE),
									   &(scheme_context->public_params.gb2ONE),
									   &(scheme_context->public_params.eggalphaT));
	
	return err_code;
}	

/*!
 * Export a context's secret parameters (MSK) to a binary buffer.  Calling this function with buffer 
 * set to NULL will return the length of the exported material.
 *
 * @param context		The fenc_context data structure
 * @param buffer		A pre-allocated buffer for the resulting export.
 * @param max_len		The maximum allocated size of the buffer (in bytes).
 * @param result_len	The size of the resulting export (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_export_secret_params_LSW(fenc_context *context, uint8 *buffer, size_t max_len, size_t *result_len)
{
	fenc_scheme_context_LSW* scheme_context;
	
	/* Get the scheme-specific context. */
	scheme_context = (fenc_scheme_context_LSW*)context->scheme_context;
	
	/* Export the elements to the buffer.  Note that if buffer is NULL this routine will
	 * just compute the necessary buffer length.									*/
	return export_components_to_buffer(buffer, max_len, result_len, "%C%C%E%E%E",
										 &(scheme_context->secret_params.hONE), 
										 &(scheme_context->secret_params.hTWO),
										 &(scheme_context->secret_params.alphaprimeZ),
										 &(scheme_context->secret_params.alphaprimeprimeZ),
										 &(scheme_context->secret_params.bZ));
}	

/*!
 * Import the public parameters (MPK) from a binary buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param max_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */
// TODO : unused parameter, fenc_global_params *global_params.
FENC_ERROR
libfenc_import_public_params_LSW(fenc_context *context, uint8 *buffer, size_t buf_len, fenc_global_params *global_params)
{

	fenc_scheme_context_LSW* scheme_context;
	
	scheme_context = (fenc_scheme_context_LSW*)context->scheme_context;
	if (scheme_context == NULL) {
		return FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Sanity check: Make sure that we have initialized group/global parameters.		*/
	if (scheme_context->global_params == NULL) {
		LOG_ERROR("libfenc_import_public_params_LSW: global/group parameters are not set");
		return FENC_ERROR_INVALID_GLOBAL_PARAMS;
	}
	
	/* Initialize the public parameters, allocating group elements.		*/
	public_params_initialize_LSW(&(scheme_context->public_params), scheme_context->global_params->pairing);

	/* Import the elements from the buffer.								*/
	return import_components_from_buffer(buffer, buf_len, NULL, "%C%C%C%C%C%E",
										 &(scheme_context->public_params.gONE), 
										 &(scheme_context->public_params.gTWO),
										 &(scheme_context->public_params.hbONE),
										 &(scheme_context->public_params.gbONE),
										 &(scheme_context->public_params.gb2ONE),
										 &(scheme_context->public_params.eggalphaT));
}

/*!
 * Import the secret parameters (MPK) from a binary buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param max_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_import_secret_params_LSW(fenc_context *context, uint8 *buffer, size_t buf_len)
{

	fenc_scheme_context_LSW* scheme_context;
	
	scheme_context = (fenc_scheme_context_LSW*)context->scheme_context;
	if (scheme_context == NULL) {
		return FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Initialize the secret parameters, allocating group elements.		*/
	secret_params_initialize_LSW(&(scheme_context->secret_params), scheme_context->global_params->pairing);
	
	return import_components_from_buffer(buffer, buf_len, NULL, "%C%C%E%E%E",
										 &(scheme_context->secret_params.hONE), 
										 &(scheme_context->secret_params.hTWO),
										 &(scheme_context->secret_params.alphaprimeZ),
										 &(scheme_context->secret_params.alphaprimeprimeZ),
										 &(scheme_context->secret_params.bZ));
}


/*!
 * Import the global parameters (MPK) from a binary buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param max_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_import_global_params_LSW(fenc_context *context, uint8 *buffer, size_t buf_len)
{
	FENC_ERROR err_code;
	fenc_scheme_context_LSW* scheme_context;
	fenc_group_params group_params;
	
	scheme_context = (fenc_scheme_context_LSW*)context->scheme_context;
	if (scheme_context == NULL) {
		return FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Read the global parameters out of the buffer, if they're in there.	*/
	err_code = libfenc_load_group_params_from_buf(&(group_params), buffer, buf_len);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("libfenc_import_global_params_LSW: could not read group params");
		return FENC_ERROR_INVALID_GLOBAL_PARAMS;
	}
	
	/* Initialize the scheme's global parameters.	*/
	scheme_context->global_params = initialize_global_params_LSW(&group_params, scheme_context->global_params);
	
	return err_code;
}

/*!
 * Export the global parameters to a binary buffer.  Calling this function with buffer 
 * set to NULL will return the length of the exported material.
 *
 * @param context		The fenc_context data structure
 * @param buffer		A pre-allocated buffer for the resulting export.
 * @param max_len		The maximum allocated size of the buffer (in bytes).
 * @param result_len	The size of the resulting export (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	
libfenc_export_global_params_LSW(fenc_context *context, uint8 *buffer, size_t max_len, size_t *result_len)
{
	FENC_ERROR err_code;
	fenc_scheme_context_LSW* scheme_context;
	
	/* Get the scheme-specific context. */
	scheme_context = (fenc_scheme_context_LSW*)context->scheme_context;
	
	/* Export the group parameters to the buffer.  If th buffer is NULL this only compute the length.		*/
	err_code = libfenc_export_group_params(&(scheme_context->global_params->group_params), buffer, max_len, result_len);
	
	return err_code;
}	

/*!
 * Serialize an ABE key structure.
 *
 * @param context		The fenc_context data structure
 * @param key			The fenc_key data structure.
 * @param buffer		A pre-allocated buffer for the resulting export.
 * @param buf_len		The maximum allocated size of the buffer (in bytes).
 * @param result_len	The size of the resulting export (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	
libfenc_export_secret_key_LSW(fenc_context *context, fenc_key *key, uint8 *buffer, size_t buf_len, size_t *result_len)
{ 
	FENC_ERROR err_code = FENC_ERROR_NONE;
	fenc_scheme_context_LSW *scheme_context;
	
	scheme_context = (fenc_scheme_context_LSW*)context->scheme_context;
	if (scheme_context == NULL) {
		return FENC_ERROR_INVALID_CONTEXT;
	}	
	
	/* retrieve the key for the WatersCP context */ 
	fenc_key_LSW *key_LSW = (fenc_key_LSW *) key->scheme_key;
	if(key_LSW == NULL) {
		err_code = FENC_ERROR_INVALID_INPUT;
		LOG_ERROR("%s: fenc_key structure non-existent.", __func__);
		goto cleanup;
	}
	
	/* serialize key structure to buffer */
	err_code = libfenc_serialize_key_LSW(key_LSW, buffer, buf_len, result_len);		
	if (err_code != FENC_ERROR_NONE) {
		err_code = FENC_ERROR_INVALID_INPUT;
		LOG_ERROR("%s: cannot serialize key to buffer. has key been constructed?", __func__);
		goto cleanup;
	}
	
cleanup:	
	return err_code;
}

/*!
 * Deserialize an ABE key structure.
 *
 * @param context		The fenc_context data structure
 * @param key			The fenc_key data structure (pre-allocated), but not initialized.
 * @param buffer		The buffer which contains the binary contents of key?
 * @param buf_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	
libfenc_import_secret_key_LSW(fenc_context *context, fenc_key *key, uint8 *buffer, size_t buf_len)
{
	FENC_ERROR err_code = FENC_ERROR_NONE;
	fenc_key_LSW			*key_LSW;
	fenc_scheme_context_LSW *scheme_context;
	fenc_attribute_policy	*policy_tree = NULL;
	fenc_attribute_list		*attribute_list = NULL;
	uint32					num_components;
	size_t					import_len;
	
	/* Get the scheme-specific context. */
	scheme_context = (fenc_scheme_context_LSW*)context->scheme_context;
	if (scheme_context == NULL) {
		return FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* import policy structure */
	policy_tree = (fenc_attribute_policy*) SAFE_MALLOC(sizeof(fenc_attribute_policy));
	if (policy_tree == NULL) {
		LOG_ERROR("%s: could not allocate policy structure", __func__);
		err_code = FENC_ERROR_OUT_OF_MEMORY;
		goto cleanup;
	}		
	
	/* Allocate an attribute list data structure.	*/
	attribute_list = (fenc_attribute_list*) SAFE_MALLOC(sizeof(fenc_attribute_list));
	if (attribute_list == NULL) {
		LOG_ERROR("%s: could not allocate attribute list", __func__);
		free(policy_tree);
		err_code = FENC_ERROR_OUT_OF_MEMORY;
		goto cleanup;
	}	
	
	/* import attributes only -- should be first in buffer */
	err_code = import_components_from_buffer(buffer, buf_len, &import_len, "%P%A%d",
											 policy_tree,
											 attribute_list,
											 &(num_components));
	
	// debug_print_policy(policy_tree);
	// debug_print_attribute_list(attribute_list);
	// printf("num_components => '%d'\n", num_components);
	// printf("import_len => '%zu'\n", import_len);
	
	/* sanity check */
	if(num_components != attribute_list->num_attributes) {
		LOG_ERROR("%s: mis-match in attributes found in key", __func__);
		err_code = FENC_ERROR_INVALID_INPUT;
		goto cleanup;
	}
	
	/* initialize the key structure */
	key_LSW = fenc_key_LSW_initialize(attribute_list, policy_tree, FALSE, scheme_context->global_params);
	if (key_LSW == NULL) {
		LOG_ERROR("%s: could not initialize key structure", __func__);
		err_code = FENC_ERROR_INVALID_INPUT;
		goto cleanup;
	}

	/* deserialize rest of key components -- D1-D5 for each attribute. Worry about negation later. */
	err_code = libfenc_deserialize_key_LSW(key_LSW, (uint8 *) (buffer + import_len), (buf_len - import_len));
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("%s: could not deserialize into key structure", __func__);
		err_code = FENC_ERROR_INVALID_INPUT;
		goto cleanup;
	}

	/* Stash the key_WatersCP structure inside of the fenc_key.		*/
	memset(key, 0, sizeof(fenc_key));
	key->scheme_type = FENC_SCHEME_LSW;
	key->valid = TRUE;
	key->scheme_key = (void*)key_LSW;	

	/* Success */
	err_code = FENC_ERROR_NONE;
cleanup:
	
	return err_code;
}

/**************************************************************************************
 * Utility functions
 **************************************************************************************/
	
/*!
 * Destroy the internal contents of a fenc_context structure.  The caller is responsible for
 * de-allocating the context buffer itself.
 *
 * @param context		The fenc_context data structure.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	
libfenc_destroy_context_LSW(fenc_context *context)
{
	FENC_ERROR result = FENC_ERROR_UNKNOWN;
	fenc_scheme_context_LSW *scheme_context;
	
	scheme_context = (fenc_scheme_context_LSW*)context->scheme_context;
	
	/* Destroy the scheme-specific context structure */
	if (scheme_context != NULL) {
		/* Destroy the internal global parameters.	*/
		if (scheme_context->global_params != NULL) {
			SAFE_FREE(scheme_context->global_params);
		}
		
		memset(context->scheme_context, 0, sizeof(fenc_scheme_context_LSW) );
		SAFE_FREE(context->scheme_context);
	}
	
	/* Other destruction operations go here... */
	result = FENC_ERROR_NONE;
	
	return result;
}

/*!
 * Destroy the internal contents of a fenc_context structure.  The caller is responsible for
 * de-allocating the context buffer itself.
 *
 * @param global_params	The global parameters.
 * @return				FENC_ERROR_NONE or an error code.
 */
// TODO : unused parameter(s).
FENC_ERROR
libfenc_destroy_global_params_LSW(/*fenc_global_params *global_params*/)
{
	return FENC_ERROR_NOT_IMPLEMENTED;
}

/*!
 * Validate a set of global parameters for the LSW scheme.
 *
 * @param global_params	The global parameters.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_validate_global_params_LSW(fenc_global_params *global_params)
{
	FENC_ERROR result;
	
	/* Sanity check -- make sure the global_params exist. */
	if (global_params == NULL) {
		return FENC_ERROR_INVALID_GLOBAL_PARAMS;
	}
	
	/* Utility call --- check that bilinear group parameters have
	 * been loaded into global_params.  We might someday want to require
	 * a specific class of group parameters, but for the moment we're ok. */
	result = libfenc_validate_group_params(global_params->group_params);
	
	/* Since there are no other global parameters in the LSW scheme, we're done. */
	return result;
}

/*!
 * Serialize a decryption key to a binary buffer.  Accepts an LSW key, buffer, and buffer length.
 * If the buffer is large enough, the serialized result is written to the buffer and returns the
 * length in "serialized_len".  Calling with a NULL buffer returns the length /only/ but does
 * not actually serialize the structure.
 *
 * @param key				The key to serialize.
 * @param buffer			Pointer to a buffer, or NULL to get the length only.
 * @param max_len			The maximum size of the buffer (in bytes).
 * @param serialized_len	Total size of the serialized structure (in bytes).
 * @return					FENC_ERROR_NONE or FENC_ERROR_BUFFER_TOO_SMALL.
 */

FENC_ERROR
libfenc_serialize_key_LSW(fenc_key_LSW *key, unsigned char *buffer, size_t max_len, size_t *serialized_len)
{
	FENC_ERROR err_code = FENC_ERROR_NONE;
	unsigned char *buf_ptr = (unsigned char*)buffer;
	size_t result_len = 0;
	uint32 i;
	
	/* Export the policy, result length, number of components in the key.	*/
	err_code = export_components_to_buffer(buf_ptr, max_len, &result_len, "%P%A%d",
										   key->policy,
										  &(key->attribute_list),
										   key->num_components);
	if (err_code != FENC_ERROR_NONE) {
		return err_code;
	}
	*serialized_len = 0;
	*serialized_len += result_len;
	if (buffer != NULL) {	buf_ptr = buffer + *serialized_len;	}
	max_len -= result_len;	/* TODO: may be a problem.	*/
	
	/* Now output each component of the key.								*/
	for (i = 0; i < key->num_components; i++) {
		/* Export the five group elements that correspond to an element.	*/
		if (key->attribute_list.attribute[i].is_negated == FALSE) {
			err_code = export_components_to_buffer(buf_ptr, max_len, &result_len, "%C%C",
												   &(key->D1ONE[i]),
												   &(key->D2TWO[i]));
		} else {
			err_code = export_components_to_buffer(buf_ptr, max_len, &result_len, "%C%C%C",
												   &(key->D3ONE[i]),
												   &(key->D4TWO[i]),
												   &(key->D5TWO[i]));
		}
		
		if (err_code != FENC_ERROR_NONE) {
			return err_code;
		}
		
		*serialized_len += result_len;
		if (buffer != NULL) {	buf_ptr = buffer + *serialized_len;	}
		max_len -= result_len;	/* TODO: may be a problem.	*/
	}

	/* All done.	*/
	return err_code;
}

/*!
 * Deserialize a decryption key from a binary buffer.  Accepts an LSW key, buffer, and buffer length.
 * If the buffer is large enough, the serialized result is written to the buffer and returns the
 * length in "serialized_len".  Calling with a NULL buffer returns the length /only/ but does
 * not actually serialize the structure.
 *
 * @param key				The key to serialize.
 * @param buffer			Pointer to a buffer, or NULL to get the length only.
 * @param buf_len			The length of the buffer (in bytes).
 * @param serialized_len	Total size of the serialized structure (in bytes).
 * @return					FENC_ERROR_NONE or FENC_ERROR_BUFFER_TOO_SMALL.
 */

FENC_ERROR
libfenc_deserialize_key_LSW(fenc_key_LSW *key, unsigned char *buffer, size_t buf_len)
{
	FENC_ERROR err_code = FENC_ERROR_NONE;
	unsigned char *buf_ptr = (unsigned char*)buffer;
	size_t result_len = 0, serialized_len = 0;
	uint32 i;
	
	serialized_len += result_len;
	if (buffer != NULL) {	buf_ptr = buffer + serialized_len;	}
	buf_len -= result_len;
	
	/* Now output each component of the key.								*/
	for (i = 0; i < key->num_components; i++) {
		/* Export the five group elements that correspond to an element.	*/
		if (key->attribute_list.attribute[i].is_negated == FALSE) {
			err_code = import_components_from_buffer(buf_ptr, buf_len, &result_len, "%C%C",
												   &(key->D1ONE[i]),
												   &(key->D2TWO[i]));
		} else {
			err_code = import_components_from_buffer(buf_ptr, buf_len, &result_len, "%C%C%C",
												   &(key->D3ONE[i]),
												   &(key->D4TWO[i]),
												   &(key->D5TWO[i]));
		}
		
		if (err_code != FENC_ERROR_NONE) {
			return err_code;
		}
		
		serialized_len += result_len;
		if (buffer != NULL) {	buf_ptr = buffer + serialized_len;	}
		buf_len -= result_len;	/* TODO: may be a problem.	*/
	}
	
	/* All done.	*/
	return err_code;
}

/*!
 * Serialize a ciphertext to a binary buffer.  Accepts an LSW ciphertext, buffer, and buffer length.
 * If the buffer is large enough, the serialized result is written to the buffer and returns the
 * length in "serialized_len".  Calling with a NULL buffer returns the length /only/ but does
 * not actually serialize the structure.
 *
 * @param ciphertext		The ciphertext to serialize.
 * @param buffer			Pointer to a buffer, or NULL to get the length only.
 * @param max_len			The maximum size of the buffer (in bytes).
 * @param serialized_len	Total size of the serialized structure (in bytes).
 * @return					FENC_ERROR_NONE or FENC_ERROR_BUFFER_TOO_SMALL.
 */

FENC_ERROR
libfenc_serialize_ciphertext_LSW(fenc_ciphertext_LSW *ciphertext, unsigned char *buffer, size_t max_len, size_t *serialized_len)
{
	int i;
	unsigned char *buf_ptr = (unsigned char*)buffer;
	uint32 type, kem_key_len;
	
	/* First, compute the length (in bytes) of the serialized ciphertext, then (if buffer is non-null)
	 * and there's sufficient room, serialize the value into the buffer. */
	*serialized_len = 0;
	*serialized_len += sizeof(uint32);												/* ciphertext type	*/
	if (buffer != NULL && *serialized_len <= max_len) {
		type = ciphertext->type;
		EXPORT_INT32(buf_ptr, (uint32)type);
		buf_ptr = buffer + *serialized_len;
	}
	
	if (ciphertext->type == FENC_CIPHERTEXT_TYPE_KEM_CPA)	{						/* KEM session key size */
		*serialized_len += sizeof(uint32);												/* only in KEM mode	*/
		if (buffer != NULL && *serialized_len <= max_len) {
			kem_key_len = ciphertext->kem_key_len;
			EXPORT_INT32(buf_ptr, kem_key_len);
			buf_ptr = buffer + *serialized_len;
		}
	}
	
	*serialized_len += sizeof(ciphertext->attribute_list.num_attributes);			/* num_attributes	*/
	if (buffer != NULL && *serialized_len <= max_len) {
		EXPORT_INT32(buf_ptr, ciphertext->attribute_list.num_attributes);
		buf_ptr = buffer + *serialized_len;
	}
	
	if (ciphertext->type == FENC_CIPHERTEXT_TYPE_CPA)	{
		*serialized_len += element_length_in_bytes(ciphertext->E1T);				/* E1T	(skipped in KEM mode!)	*/
		if (buffer != NULL && *serialized_len <= max_len) {
			element_to_bytes(buf_ptr, ciphertext->E1T);
			buf_ptr = buffer + *serialized_len;
		}
	}
	
	*serialized_len += element_length_in_bytes_compressed(ciphertext->E2TWO);		/* E2TWO			*/
	if (buffer != NULL && *serialized_len <= max_len) {
		element_to_bytes_compressed(buf_ptr, ciphertext->E2TWO);
		buf_ptr = buffer + *serialized_len;
	}

	/* For every attribute in the ciphertext... */
	for (i = 0; (unsigned) i < ciphertext->attribute_list.num_attributes; i++) {
		*serialized_len += element_length_in_bytes(ciphertext->attribute_list.attribute[i].attribute_hash);			/* attribute[i]		*/
		if (buffer != NULL && *serialized_len <= max_len) {
			element_to_bytes(buf_ptr, ciphertext->attribute_list.attribute[i].attribute_hash);
			buf_ptr = buffer + *serialized_len;
		}
		
		*serialized_len += element_length_in_bytes(ciphertext->E3ONE[i]);	/* E3ONE[i]		*/
		if (buffer != NULL && *serialized_len <= max_len) {
			element_to_bytes(buf_ptr, ciphertext->E3ONE[i]);
			buf_ptr = buffer + *serialized_len;
		}
		
		*serialized_len += element_length_in_bytes(ciphertext->E4ONE[i]);	/* E4ONE[i]		*/
		if (buffer != NULL && *serialized_len <= max_len) {
			element_to_bytes(buf_ptr, ciphertext->E4ONE[i]);
			buf_ptr = buffer + *serialized_len;
		}
		
		*serialized_len += element_length_in_bytes(ciphertext->E5ONE[i]);	/* E5ONE[i]		*/
		if (buffer != NULL && *serialized_len <= max_len) {
			element_to_bytes(buf_ptr, ciphertext->E5ONE[i]);
			buf_ptr = buffer + *serialized_len;
		}
	}
	
	/* If the buffer pointer is NULL, we're done --- just return the length. */
	if (buffer == NULL) {
		return FENC_ERROR_NONE;
	}
	
	/* If the serialized length was too large for the buffer, return an error. */
	if (*serialized_len > max_len) {
		return FENC_ERROR_BUFFER_TOO_SMALL;
	}
	
	/* Return success. */
	return FENC_ERROR_NONE;
}

/*!
 * Deserialize a ciphertext from a binary buffer.  Accepts a buffer and buffer length and
 * transcribes the result into an LSW ciphertext data structure.  
 *
 * Note: this routine uses deserialization functionality from the PBC library; this could
 * fail catastrophically when given an invalid ciphertext.
 *
 * @param buffer			Pointer to a buffer from which to deserialize.
 * @param buf_len			The size of the buffer (in bytes).
 * @param ciphertext		The fenc_ciphertext_LSW structure.
 * @param scheme_context	The scheme context which contains the group parameters.
 * @return					FENC_ERROR_NONE or FENC_ERROR_BUFFER_TOO_SMALL.
 */

FENC_ERROR
libfenc_deserialize_ciphertext_LSW(unsigned char *buffer, size_t buf_len, fenc_ciphertext_LSW *ciphertext, fenc_scheme_context_LSW *scheme_context)
{
	unsigned int i;
	size_t deserialized_len;
	uint32 num_attributes=0, type=0, kem_key_len=0;
	FENC_ERROR result = FENC_ERROR_UNKNOWN, err_code;
	unsigned char *buf_ptr = buffer;
	
	deserialized_len = 0;
	deserialized_len += sizeof(uint32);								/* ciphertext type	*/
	if (deserialized_len <= buf_len) {
		IMPORT_INT32(type, buf_ptr);
		buf_ptr = buffer + deserialized_len;
	}
	
	if (type == FENC_CIPHERTEXT_TYPE_KEM_CPA)	{					/* KEM session key size */
		deserialized_len += sizeof(uint32);							/* only in KEM mode		*/
		if (deserialized_len <= buf_len) {
			IMPORT_INT32(kem_key_len, buf_ptr);
			buf_ptr = buffer + deserialized_len;
		}
	}
	
	deserialized_len += sizeof(num_attributes);						/* num_attributes	*/
	if (deserialized_len <= buf_len) {
		IMPORT_INT32(num_attributes, buf_ptr);
		buf_ptr = buffer + deserialized_len;
	}
	
	/* Sanity check: make sure the number of attributes is non-zero, but not too big. */
	if (num_attributes < 1 || num_attributes > MAX_CIPHERTEXT_ATTRIBUTES) {
		return FENC_ERROR_INVALID_CIPHERTEXT;
	}
	
	/* Initialize the elements of the LSW ciphertext data structure.  This allocates all of the group elements
	 * and sets the num_attributes member.		*/
	err_code = fenc_ciphertext_LSW_initialize(ciphertext, num_attributes, type, scheme_context);
	if (err_code != FENC_ERROR_NONE) {
		/* Couldn't allocate the structure.  Don't even try to cleanup --- this is a really bad situation! */
		LOG_ERROR("lifenc_deserialize_ciphertext_LSW: couldn't initialize ciphertext");
		return err_code;
	}
	ciphertext->kem_key_len = kem_key_len;
	
	/* Initialize the attribute list.	*/
	err_code = fenc_attribute_list_initialize(&(ciphertext->attribute_list), num_attributes);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("lifenc_deserialize_ciphertext_LSW: couldn't initialize attribute list");
		return err_code;
	}
	
	/* Read in the ciphertext components.								*/	
	if (ciphertext->type == FENC_CIPHERTEXT_TYPE_CPA)	{
		deserialized_len += element_from_bytes(ciphertext->E1T, buf_ptr);				/* E1T				*/
		if (deserialized_len > buf_len) {											
			result = FENC_ERROR_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		buf_ptr = buffer + deserialized_len;
	}
	
	deserialized_len += element_from_bytes_compressed(ciphertext->E2TWO, buf_ptr);	/* E2TWO			*/
	if (deserialized_len > buf_len) {											
		result = FENC_ERROR_BUFFER_TOO_SMALL;
		goto cleanup;
	}
	buf_ptr = buffer + deserialized_len;
	
	/* For every attribute in the ciphertext... */
	for ( i = 0; i < ciphertext->attribute_list.num_attributes; i++) {
		memset(&(ciphertext->attribute_list.attribute[i]), 0, sizeof(fenc_attribute));
		element_init_Zr(ciphertext->attribute_list.attribute[i].attribute_hash, scheme_context->global_params->pairing);
		deserialized_len += element_from_bytes(ciphertext->attribute_list.attribute[i].attribute_hash, buf_ptr);			/* attribute[i]		*/
		if (deserialized_len > buf_len) {											
			result = FENC_ERROR_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		ciphertext->attribute_list.attribute[i].is_hashed = TRUE;
		buf_ptr = buffer + deserialized_len;
		
		deserialized_len += element_from_bytes(ciphertext->E3ONE[i], buf_ptr);	/* E3ONE[i]			*/
		if (deserialized_len > buf_len) {											
			result = FENC_ERROR_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		buf_ptr = buffer + deserialized_len;
		
		deserialized_len += element_from_bytes(ciphertext->E4ONE[i], buf_ptr);	/* E4ONE[i]			*/
		if (deserialized_len > buf_len) {											
			result = FENC_ERROR_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		buf_ptr = buffer + deserialized_len;
		
		deserialized_len += element_from_bytes(ciphertext->E5ONE[i], buf_ptr);	/* E5ONE[i]			*/
		if (deserialized_len > buf_len) {											
			result = FENC_ERROR_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		buf_ptr = buffer + deserialized_len;
	}
	
	/* Success!	*/
	result = FENC_ERROR_NONE;
	
cleanup:
	/* If the deserialization failed, de-allocate any elements we initialized. */
	if (result != FENC_ERROR_NONE) {
		fenc_ciphertext_LSW_clear(ciphertext);
	}
	
	/* Return the result. */
	return result;
}

/*!
 * Utility function to allocate the internals of a fenc_ciphertext_LSW structure.  
 *
 * @param ciphertext		Pointer to fenc_ciphertext_LSW struct.
 * @param num_attributes	Number of attributes.
 * @param scheme_context	Pointer to a fenc_scheme_context_LSW struct.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
fenc_ciphertext_LSW_initialize(fenc_ciphertext_LSW *ciphertext, uint32 num_attributes, FENC_CIPHERTEXT_TYPE type,
							   fenc_scheme_context_LSW *scheme_context)
{
	unsigned int i;
	
	memset(ciphertext, 0, sizeof(fenc_ciphertext_LSW));
	element_init_GT(ciphertext->E1T, scheme_context->global_params->pairing);
	element_set1(ciphertext->E1T);
	element_init_G2(ciphertext->E2TWO, scheme_context->global_params->pairing);
	for ( i = 0; i < num_attributes; i++) {
		element_init_G1(ciphertext->E3ONE[i], scheme_context->global_params->pairing);
		element_init_G1(ciphertext->E4ONE[i], scheme_context->global_params->pairing);
		element_init_G1(ciphertext->E5ONE[i], scheme_context->global_params->pairing);
	}
	ciphertext->type = type;
	
	return FENC_ERROR_NONE;
}

/*!
 * Utility function to release the internals of a fenc_ciphertext_LSW structure.  
 *
 * @param ciphertext		Pointer to fenc_ciphertext_LSW struct.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
fenc_ciphertext_LSW_clear(fenc_ciphertext_LSW *ciphertext)
{
	unsigned int i;
	
	/* Make sure the number of attributes is reasonable (if not, this is an invalid ciphertext).	*/
	if (ciphertext->attribute_list.num_attributes < 1 || ciphertext->attribute_list.num_attributes > MAX_CIPHERTEXT_ATTRIBUTES) {
		LOG_ERROR("fenc_ciphertext_LSW_clear: ciphertext has an invalid number of attributes"); 
		return FENC_ERROR_UNKNOWN;
	}
	
	/* Release all of the internal elements.  Let's hope the ciphertext was correctly inited! */
	element_clear(ciphertext->E1T);
	element_clear(ciphertext->E2TWO);
	for ( i = 0; i < ciphertext->attribute_list.num_attributes; i++) {
		element_clear(ciphertext->E3ONE[i]);
		element_clear(ciphertext->E4ONE[i]);
		element_clear(ciphertext->E5ONE[i]);
	}
	
	/* Release the attribute list if one has been allocated. */
	fenc_attribute_list_clear(&(ciphertext->attribute_list));

	memset(ciphertext, 0, sizeof(fenc_ciphertext_LSW));
	
	return FENC_ERROR_NONE;
}

/*!
 * Initialize and allocate a fenc_global_params_LSW structure.
 *
 * @param	group_params		A fenc_group_params structure.
 * @param	global_params		An allocated fenc_global_params_LSW or NULL if one should be allocated.
 * @return	An allocated fenc_global_params_LSW structure.
 */

fenc_global_params_LSW*
initialize_global_params_LSW(fenc_group_params *group_params, fenc_global_params_LSW *global_params)
{
	FENC_ERROR err_code;
	
	/* If we need to, allocate a new set of global params for the LSW scheme.	*/
	if (global_params == NULL) {	
		global_params = SAFE_MALLOC(sizeof(fenc_global_params_LSW));
		if (global_params == NULL) {
			LOG_ERROR("initialize_global_params_LSW: out of memory");
			return NULL;
		}
	}
	
	err_code = libfenc_copy_group_params(group_params, &(global_params->group_params));
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("libfenc_gen_params_LSW: could not copy parameters");
		return NULL;
	}
	
	err_code = libfenc_get_pbc_pairing(group_params, global_params->pairing);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("libfenc_gen_params_LSW: could not obtain pairing structure");
		return NULL;
	}
	
	return global_params;
}

/*!
 * Process an attribute list, ensuring that all attributes are hashed.
 *
 * @param attribute_list	The attribute list.
 * @param pairing			A pairing structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
attribute_list_compute_hashes(fenc_attribute_list *attribute_list, pairing_t pairing) 
{
	int i;
	
	for (i = 0; i < (int) attribute_list->num_attributes; i++) {
		hash_attribute(&(attribute_list->attribute[i]), pairing);
	}
	
	return FENC_ERROR_NONE;
}

/*!
 * Process an attribute tree, ensuring that all attributes are hashed.
 *
 * @param subtree			The attribute subtree.
 * @param pairing			A pairing structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
attribute_tree_compute_hashes(fenc_attribute_subtree *subtree, pairing_t pairing) 
{
	FENC_ERROR err_code;
	uint32 i;
	
	if (subtree == NULL) { return FENC_ERROR_UNKNOWN;	}
	
	if (subtree->node_type == FENC_ATTRIBUTE_POLICY_NODE_LEAF) {
		hash_attribute(&(subtree->attribute), pairing);
	} else {
		for (i = 0; i < subtree->num_subnodes; i++) {
			err_code = attribute_tree_compute_hashes(subtree->subnode[i], pairing);
		}
	}

	return FENC_ERROR_NONE;
}

/*!
 * Hash an attribute structure.  This entails initializing the attribute_hash member
 * with the pairing structure and hashing the attribute_str into it as an element
 * of Zr.  This function does nothing if is_hashed is already set.
 *
 * @param attribute			The fenc_attribute structure.
 * @param pairing			A pairing_t structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
hash_attribute(fenc_attribute *attribute, pairing_t pairing)
{
	/* If there's no string and the attribute hash isn't present, that's an error.	*/
	if (attribute->is_hashed == FALSE && attribute->attribute_str[0] == 0) {
		return FENC_ERROR_INVALID_INPUT;
	}
	
	/* If there is an attribute string and no hash is present, perform the hashing.	*/
	if (attribute->attribute_str[0] != 0 && attribute->is_hashed == FALSE) {
		element_init_Zr(attribute->attribute_hash, pairing);
		hash1_attribute_string_to_Zr((uint8*)attribute->attribute_str, &(attribute->attribute_hash));
		attribute->is_hashed = TRUE;
	}
	
	return FENC_ERROR_NONE;
}

/*!
 * Hash an attribute string to an element of Zr.  This is modeled as a collision-resistant hash.
 * Although this hash function is not explicitly described in LSW09, this is a standard way to
 * map strings Zr, which is the domain of attributes in the scheme.
 *
 * @param attribute_str		The attribute string.
 * @param hashed_attr		Pointer to an (initialized) element of Zr.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
hash1_attribute_string_to_Zr(uint8 *attribute_str, element_t *hashed_attr)
{
	FENC_ERROR err_code;
	uint8	hash_buf[HASH_TARGET_LEN];
	
	/* TODO: HASH_TARGET_LEN must be replaced with something more sophisticated.	*/
	err_code = hash_to_bytes(attribute_str, strlen((char*)attribute_str), HASH_TARGET_LEN, hash_buf, HASH_FUNCTION_STR_TO_Zr_CRH);
	if (err_code != FENC_ERROR_NONE) { return err_code; }
	element_from_hash(*hashed_attr, hash_buf, HASH_TARGET_LEN); 
	
	return FENC_ERROR_NONE;
}

/*!
 * Hash an element of Zr to an element of G1.  In the LSW09 scheme this hash function is 
 * modeled as a random oracle.
 *
 * @param attribute_elt		The attribute as an element of Zr.
 * @param hashed_attr		Pointer to an (initialized) element of G1.
 * @return					FENC_ERROR_NONE or an error code.
 */
	
FENC_ERROR
hash2_attribute_element_to_G1(element_t *attribute_elt, element_t *hashed_attr)
{
	FENC_ERROR err_code;
	uint8	hash_buf[HASH_TARGET_LEN];
		
	/* TODO: HASH_TARGET_LEN must be replaced with something more sophisticated.	*/
	/* Use the hash function index HASH_FUNCTION_Zr_TO_G1_ROM.	*/
	// TODO : unused parameter... reused
	err_code = hash_element_to_bytes(attribute_elt, HASH_TARGET_LEN, hash_buf, HASH_FUNCTION_Zr_TO_G1_ROM);
	if (err_code != FENC_ERROR_NONE) { return err_code; }
	element_from_hash(*hashed_attr, hash_buf, HASH_TARGET_LEN); 
	
	return FENC_ERROR_NONE;
}

/*!
 * Hash an attribute string first to an element of Zr using hash1_attribute_string_to_Zr.
 * Then process the result directly into an element of G1 using hash2_attribute_element_to_G1.
 * This is just a shortcut routine to avoid making separate function calls.
 *
 * @param attribute_elt		The attribute as an element of Zr.
 * @param hashed_attr		Pointer to an (initialized) element of G1.
 * @param temp_elt			Initialized element of Zr used for temporary storage.
 * @return					FENC_ERROR_NONE or an error code.
 */
	
FENC_ERROR
hash2_attribute_string_to_G1(uint8 *attribute_str, element_t *hashed_attr, element_t *temp_elt)
{
	FENC_ERROR err_code;
	
	err_code = hash1_attribute_string_to_Zr(attribute_str, temp_elt);
	if (err_code != FENC_ERROR_NONE) { return err_code; }		
	err_code = hash2_attribute_element_to_G1(temp_elt, hashed_attr);
	if (err_code != FENC_ERROR_NONE) { return err_code; }

	return FENC_ERROR_NONE;
}

/*!
 * Allocates and initializes a fenc_key_LSW structure.
 *
 * @param key_LSW			The fenc_key_LSW structure.
 * @param attribute_list	Pointer to a fenc_attribute_list structure.
 * @param policy			Pointer to a fenc_policy structure (the internals are /not/ duplicated).
 * @param copy_attr_list	If set to TRUE, duplicates the internals of the attribute list (original can be cleared).
 * @param global_params		Pointer to the group params (necessary for allocating internal elements).
 * @return					The fenc_key_LSW structure or NULL.
 */

fenc_key_LSW*
fenc_key_LSW_initialize(fenc_attribute_list *attribute_list, fenc_attribute_policy *policy, Bool copy_attr_list, 
				   fenc_global_params_LSW *global_params)
{
	FENC_ERROR err_code;
	unsigned int i;
	fenc_key_LSW *key_LSW;
				
	/* Initialize and wipe the key structure.	*/
	key_LSW = (fenc_key_LSW*)SAFE_MALLOC(sizeof(fenc_key_LSW));
	if (key_LSW == NULL) {
		LOG_ERROR("%s: out of memory", __func__);
		return NULL;
	}
	memset(key_LSW, 0, sizeof(fenc_key_LSW));
	key_LSW->reference_count = 1;
	
	/* Copy the attribute list structure into the key.  If copy_attr_list is TRUE we
	 * call fenc_attribute_list_copy() to duplicate all of the internals.  Otherwise
	 * we just copy the top-level structure.	*/
	if (copy_attr_list == FALSE) {
		memcpy(&(key_LSW->attribute_list), attribute_list, sizeof(fenc_attribute_list));
		key_LSW->attribute_list.num_attributes = attribute_list->num_attributes;
	} else {
		err_code = fenc_attribute_list_copy(&(key_LSW->attribute_list), attribute_list, global_params->pairing);
		if (err_code != FENC_ERROR_NONE) {
			return NULL;
		}
	}
						   
	/* Copy the policy structure into the key.	*/
	key_LSW->policy = policy;
	
	/* Allocate the internal group elements.	*/
	key_LSW->num_components = attribute_list->num_attributes;
	for ( i = 0; i < key_LSW->attribute_list.num_attributes; i++) {
		element_init_G1(key_LSW->D1ONE[i], global_params->pairing);
		element_init_G2(key_LSW->D2TWO[i], global_params->pairing);
		element_init_G1(key_LSW->D3ONE[i], global_params->pairing);
		element_init_G2(key_LSW->D4TWO[i], global_params->pairing);
		element_init_G2(key_LSW->D5TWO[i], global_params->pairing);
	}
	
	return key_LSW;
}


/*!
 * Deallocate and clear the internals of a fenc_key_LSW structure.
 *
 * @param key_LSW			The fenc_key_LSW structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
key_LSW_clear(fenc_key_LSW *key_LSW)
{	
	unsigned int i;
	
	for ( i = 0; i < key_LSW->attribute_list.num_attributes; i++) {
		element_clear(key_LSW->D1ONE[i]);
		element_clear(key_LSW->D2TWO[i]);
		element_clear(key_LSW->D3ONE[i]);
		element_clear(key_LSW->D4TWO[i]);
		element_clear(key_LSW->D5TWO[i]);
	}
	
	if (key_LSW->reference_count <= 1) {
		SAFE_FREE(key_LSW);
	} else {
		key_LSW->reference_count--;
	}
	
	return FENC_ERROR_NONE;
}

/*!
 * Initialize a fenc_public_params_LSW structure.  This requires initializing
 * a series of group element structures.
 *
 * @param params			Pointer to a fenc_public_params_LSW data structure.
 * @param pairing			Pairing structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
public_params_initialize_LSW(fenc_public_params_LSW *params, pairing_t pairing)
{
	memset(params, 0, sizeof(fenc_public_params_LSW));
	
	element_init_G1(params->gONE, pairing);
	element_init_G2(params->gTWO, pairing);
	element_init_G1(params->hbONE, pairing);
	element_init_G1(params->gbONE, pairing);
	element_init_G1(params->gb2ONE, pairing);
	element_init_GT(params->eggalphaT, pairing);
	
	return FENC_ERROR_NONE;
}

/*!
 * Initialize a fenc_secret_params_LSW structure.  This requires initializing
 * a series of group element structures.
 *
 * @param params			Pointer to a fenc_secret_params_LSW data structure.
 * @param pairing			Pairing structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
secret_params_initialize_LSW(fenc_secret_params_LSW *params, pairing_t pairing)
{
	memset(params, 0, sizeof(fenc_secret_params_LSW));

	element_init_G1(params->hONE, pairing);
	element_init_G2(params->hTWO, pairing);
	element_init_Zr(params->alphaprimeZ, pairing);
	element_init_Zr(params->alphaprimeprimeZ, pairing);
	element_init_Zr(params->bZ, pairing);
	
	return FENC_ERROR_NONE;
}

/*!
 * Print a ciphertext to a file as ASCII.
 *
 * @param ciphertext		The ciphertext to serialize.
 * @param out_file			The file to write to.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_fprint_ciphertext_LSW(fenc_ciphertext_LSW *ciphertext, FILE* out_file)
{
	unsigned int i;
	
	fprintf(out_file, "number of attributes = %d\n", ciphertext->attribute_list.num_attributes);

	element_fprintf(out_file, "E1T = %B\n", ciphertext->E1T);
	element_fprintf(out_file, "E2TWO = %B\n", ciphertext->E2TWO);
	
	/* For every attribute in the ciphertext... */
	for ( i = 0; i < ciphertext->attribute_list.num_attributes; i++) {
		fprintf(out_file, "Attribute #%d:\n", i);
		if (strlen((char*)ciphertext->attribute_list.attribute[i].attribute_str) > 0) {
			fprintf(out_file, "\tAttribute = \"%s\"\n", ciphertext->attribute_list.attribute[i].attribute_str);
		}
		element_fprintf(out_file, "\tAttribute Hash = %B\n", ciphertext->attribute_list.attribute[i].attribute_hash);
		
		element_fprintf(out_file, "\tE3ONE[%d] = %B\n", i, ciphertext->E3ONE[i]);
		element_fprintf(out_file, "\tE4ONE[%d] = %B\n", i, ciphertext->E4ONE[i]);
		element_fprintf(out_file, "\tE5ONE[%d] = %B\n", i, ciphertext->E5ONE[i]);
	}
	
	/* Return success. */
	return FENC_ERROR_NONE;
}
