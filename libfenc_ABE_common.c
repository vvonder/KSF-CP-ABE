/*!	\file libfenc_abe_common.c
 *
 *	\brief Routines supporting Attribute Based Encryption.
 *	
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <math.h>
#include <pbc/pbc.h>
#include "libfenc.h"
#include "libfenc_group_params.h"
#include "libfenc_ABE_common.h"
#include "libfenc_LSW.h"
#include "abe_policy.h"

/*!
 * Generate a set of global (elliptic curve) parameters.  Caller is responsible
 * for allocating the global_params buffer.
 *
 * @param global_params	The pre-allocated global params data structure.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	
libfenc_generate_global_params_COMMON(fenc_global_params *global_params, fenc_group_params *group_params)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	
	/* If some group parameters already exist, wipe them out and re-use the group_params buffer. */
	if (global_params->group_params != NULL) {
		result = libfenc_destroy_group_params(global_params->group_params);
		if (result != FENC_ERROR_NONE) {
			/* Unable to destroy previous group parameters... */
			LOG_ERROR("libfenc_generate_global_params_COMMON: unable to destroy group parameters");
			return result;
		}
	} else {
		/* Otherwise we need to allocate a buffer for the group_params. */
		global_params->group_params = (fenc_group_params*)SAFE_MALLOC(sizeof(fenc_group_params));
		if (global_params->group_params == NULL) {
			return FENC_ERROR_OUT_OF_MEMORY;
		}
	}
	
	/* Copy the given group params.		*/
	result = libfenc_copy_group_params(group_params, global_params->group_params);
	
	return result;
}

/*!
 * Destroy a set of global parameters.
 *
 * @param global_params	The pre-allocated global params data structure.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	
libfenc_destroy_global_params_COMMON(fenc_global_params *global_params)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	
	/* If group parameters exist, wipe them out. */
	if (global_params->group_params != NULL) {
		result = libfenc_destroy_group_params(global_params->group_params);
		if (result != FENC_ERROR_NONE) {
			/* Unable to destroy previous group parameters... */
			return result;
		}
	}
	
	memset(global_params, 0, sizeof (fenc_global_params) );
	
	return result;
}

/*!
 * Parse a function input as an attribute list.  This will involve some memory allocation in the
 * fenc_attribute_list structure, which must be cleared using the fenc_attribute_list_clear call.
 *
 * @param input				Attribute list
 * @param num_attributes	Number of attributes is written here
 * @param attribute_list	fenc_attribute_list structure
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_parse_input_as_attribute_list(fenc_function_input *input, fenc_attribute_list *attribute_list, pairing_t pairing)
{
	FENC_ERROR result;
	
	if (attribute_list == NULL) {
		return FENC_ERROR_INVALID_INPUT;
	}
	
	/* Wipe the attribute list structure clean.	*/
	memset(attribute_list, 0, sizeof(fenc_attribute_list));
	
	/* Can't parse invalid inputs.	*/
	if (input->input_type != FENC_INPUT_ATTRIBUTE_LIST) {
		return FENC_ERROR_INVALID_INPUT;
	}
	
	if (attribute_list == NULL || input->scheme_input == NULL) {
		LOG_ERROR("libfenc_parse_input_as_attribute_list: could not parse function input as an attribute list");
		return FENC_ERROR_INVALID_INPUT;
	}
	
	/* Clear the attribute list data structure and copy the scheme input.	*/
	memset(attribute_list, 0, sizeof(fenc_attribute_list));
	result = fenc_attribute_list_copy(attribute_list, (fenc_attribute_list*)input->scheme_input, pairing);
	
	return FENC_ERROR_NONE;
}

/*!
 * Parse a function input as an attribute policy.  This will involve some memory allocation in the
 * fenc_attribute_poliy structure, which must be cleared using the fenc_attribute_policy_clear call.
 *
 * @param input				Attribute list
 * @param num_attributes	Number of attributes is written here
 * @param attribute_list	fenc_attribute_list structure
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_parse_input_as_attribute_policy(fenc_function_input *input, fenc_attribute_policy *policy)
{
	if (policy == NULL) {
		return FENC_ERROR_UNKNOWN;
	}
	
	if (input->input_type != FENC_INPUT_NM_ATTRIBUTE_POLICY) {
		return FENC_ERROR_INVALID_INPUT;
	}
	
	/* Clear the attribute list data structure.	*/
	// TODO: Do we still need a copy here?
	// LOG_ERROR("libfenc_parse_input_as_attribute_policy: need to add a copy");
	memcpy(policy, (fenc_attribute_policy*)(input->scheme_input), sizeof(fenc_attribute_policy));
		
	return FENC_ERROR_NONE;
}

/*!
 * Convert an array of attribute strings into a fenc_function_input.  The input
 * structure must be initialized, although some additional memory allocation will
 * occur.
 *
 * @param input				Pointer to an allocated fenc_function_input structure
 * @param attribute_list	Array of char* strings containing attributes
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
fenc_create_func_input_for_attributes(char *attributes, fenc_function_input *input)
{
	FENC_ERROR err_code = FENC_ERROR_NONE;
	fenc_attribute_list *attribute_list = NULL;
	
	/* Allocate an attribute list data structure.	*/
	attribute_list = (fenc_attribute_list*)SAFE_MALLOC(sizeof(fenc_attribute_list));
	if (attribute_list == NULL) {
		LOG_ERROR("%s: could not allocate attribute list", __func__);
		return FENC_ERROR_OUT_OF_MEMORY;
	}
	
	/* Construct attribute list from string */
	err_code = fenc_buffer_to_attribute_list(&attributes, attribute_list);
	if(err_code != FENC_ERROR_NONE) {
		free(attribute_list);
		LOG_ERROR("%s: invalid attribute string", __func__);		
		return err_code;
	}
	
	input->scheme_input = (void*)attribute_list;
	input->input_type = FENC_INPUT_ATTRIBUTE_LIST;
	
	return err_code;
}

/*!
 * Convert an policy string into a fenc_function_input.  The input
 * structure must be initialized, although some additional memory allocation will
 * occur.
 *
 * @param input				Pointer to an allocated fenc_function_input structure
 * @param policy			char* strings containing policy using attributes
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
fenc_create_func_input_for_policy(char *policy, fenc_function_input *input)
{
	FENC_ERROR err_code = FENC_ERROR_NONE;
	fenc_attribute_policy *fenc_policy = NULL;
	
	/* Allocate an fenc_attribute_policy data structure */
	fenc_policy = (fenc_attribute_policy *) SAFE_MALLOC(sizeof(fenc_attribute_policy));
	if(fenc_policy == NULL) {
		LOG_ERROR("%s: could not allocate fenc policy", __func__);
		return FENC_ERROR_OUT_OF_MEMORY;			
	}
	memset(fenc_policy, 0, sizeof(fenc_attribute_policy));
	
	/* Construct/parse policy string into a structure */
	err_code = fenc_policy_from_string(fenc_policy, policy);
	if(err_code != FENC_ERROR_NONE) {
		free(fenc_policy);
		LOG_ERROR("%s: invalid fenc policy string", __func__);
		return err_code;
	}
	
	input->scheme_input = (void *) fenc_policy;
	input->input_type = FENC_INPUT_NM_ATTRIBUTE_POLICY;

	return FENC_ERROR_NONE;
}

/*!
 * Convert an array of attribute strings into a fenc_function_input.  The input
 * structure must be initialized, although some additional memory allocation will
 * occur.
 *
 * @param input				Pointer to an allocated fenc_function_input structure
 * @param attribute_list	Array of char* strings containing attributes
 * @param num_attributes	Number of attributes in list
 * @return					FENC_ERROR_NONE or an error code.
 * @DEPRECATED
 */
FENC_ERROR
libfenc_create_attribute_list_from_strings(fenc_function_input *input, char **attributes, uint32 num_attributes)
{
	FENC_ERROR err_code;
	fenc_attribute_list *attribute_list;
	uint32 i;
	
	/* Allocate an attribute list data structure.	*/
	attribute_list = (fenc_attribute_list*)SAFE_MALLOC(sizeof(fenc_attribute_list));
	if (attribute_list == NULL) {
		LOG_ERROR("libfenc_create_attribute_list_from_strings: could not allocate attribute list");
		return FENC_ERROR_OUT_OF_MEMORY;
	}
	
	/* Initialize the structure.	*/
	memset(attribute_list, 0, sizeof(fenc_attribute_list));
	err_code = fenc_attribute_list_initialize(attribute_list, num_attributes);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("libfenc_create_attribute_list_from_strings: could not initialize attribute list");
		return err_code;
	}

	/* Copy the strings into the attribute list.	*/
	for (i = 0; i < num_attributes; i++) {
		strcpy((char *) attribute_list->attribute[i].attribute_str, (const char *) attributes[i]);
	}
	
	input->scheme_input = (void*)attribute_list;
	input->input_type = FENC_INPUT_ATTRIBUTE_LIST;
	
	return FENC_ERROR_NONE;
}

/*!
 * Apply the N() function (from Goyal et al.) to an attribute list.
 *
 * @param result_list		Resulting attribute list
 * @param input_list		Input attribute list
 * @param input_policy		Input policy structure
 * @param group_params		Group parameters.
 * @return					FENC_ERROR_NONE or an error code
 */
// TODO : unused parameter 'policy'.
FENC_ERROR
fenc_apply_N_function_to_attributes(fenc_attribute_list *result_list, fenc_attribute_list *input_list,
									/*fenc_attribute_policy *policy,*/ pairing_t pairing)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	
	/* This function isn't properly implemented yet.  For the moment we just spit out
	 * the input list, unmodified. */
	LOG_ERROR("%s: warning, NM access structures are not supported yet", __func__);
	result = fenc_attribute_list_copy(result_list, input_list, pairing);
	
	return result;
}

/*!
 * Allocate the internals of an attribute list of num_attributes attributes.
 *
 * @param attribute_list	fenc_attribute_list structure
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	
fenc_attribute_list_initialize(fenc_attribute_list *attribute_list, uint32 num_attributes)
{
	uint32 i;
	
	/* Sanity check.	*/
	if (num_attributes < 1 || num_attributes > MAX_CIPHERTEXT_ATTRIBUTES) {
		return FENC_ERROR_INVALID_INPUT;
	}
	
	/* Initialize the structure and allocate memory for the attribute structures.	*/
	memset(attribute_list, 0, sizeof(fenc_attribute_list));
	attribute_list->num_attributes = num_attributes;
	attribute_list->attribute = SAFE_MALLOC(sizeof(fenc_attribute) * num_attributes);
	if (attribute_list->attribute == NULL) {
		return FENC_ERROR_OUT_OF_MEMORY;
	}
	
	/* Wipe the attribute structures clean.	*/
	for (i = 0; i < num_attributes; i++) {
		attribute_list->attribute[i].is_hashed = FALSE;
		attribute_list->attribute[i].attribute_str[0] = 0;
		attribute_list->attribute[i].is_negated = FALSE;	// must check string for '!' to set this to TRUE
	}

	return FENC_ERROR_NONE;
}

/*!
 * Clear an fenc_function_input structure for attributes or policy and deallocates memory.
 *
 * @param input				functional input structure
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
fenc_func_input_clear(fenc_function_input *input)
{	
	if(input->input_type == FENC_INPUT_ATTRIBUTE_LIST) {
		fenc_attribute_list *attribute_list = (fenc_attribute_list *) input->scheme_input;
		fenc_attribute_list_clear(attribute_list);
	}
	else if(input->input_type == FENC_INPUT_NM_ATTRIBUTE_POLICY) {
		fenc_attribute_policy *attribute_policy = (fenc_attribute_policy *) input->scheme_input;
		free(attribute_policy->string);
		free(attribute_policy->root);
		free(attribute_policy);
	}
	
	return FENC_ERROR_NONE;
}

/*!
 * Clear an attribute list data structure, deallocating memory.
 *
 * @param attribute_list	fenc_attribute_list structure
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
fenc_attribute_list_clear(fenc_attribute_list *attribute_list)
{
	int i;
	
	/* Clear out the attributes in the list.	*/
	for (i = 0; (unsigned) i < attribute_list->num_attributes; i++) {
		fenc_attribute_clear(&(attribute_list->attribute[i]));
	}

	memset(attribute_list, 0, sizeof(fenc_attribute_list));
	
	return FENC_ERROR_NONE;
}

/*!
 * Duplicate an attribute list data structure.	Assumes that the incoming attribute
 * list structure is /not/ previously allocated.  This function allocates the new
 * attribute list: the user must call fenc_attribute_list_clear() when done with it.
 *
 * @param attribute_list_DST	fenc_attribute_list structure destination.
 * @param attribute_list_SRC	fenc_attribute_list structure source.
 * @param group_params			fenc_group_params structure.
 * @return						FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
fenc_attribute_list_copy(fenc_attribute_list *attribute_list_DST, fenc_attribute_list *attribute_list_SRC, pairing_t pairing)
{
	FENC_ERROR err_code;
	int i;
	
	err_code = fenc_attribute_list_initialize(attribute_list_DST, attribute_list_SRC->num_attributes);
	if (err_code != FENC_ERROR_NONE) {
		return err_code;
	}

	/* Duplicate the contents of each fenc_attribute structure.	*/
	for (i = 0; (unsigned) i < attribute_list_SRC->num_attributes; i++) {
		/* Copy attribute #i	*/		
		err_code = fenc_attribute_copy((fenc_attribute*)&(attribute_list_DST->attribute[i]), (fenc_attribute*)&(attribute_list_SRC->attribute[i]), pairing);
		if (err_code != FENC_ERROR_NONE) {
			fenc_attribute_list_clear(attribute_list_DST);
			return err_code;
		}
	}
	
	return FENC_ERROR_NONE;
}

/*!
 * Serialize an attribute list structure.  If "buffer" is NULL this returns the necessary length
 * only.
 *
 * @param attribute_list		fenc_attribute_list pointer.
 * @param buffer				Buffer or "NULL" to get length.
 * @param buf_len				Size of the buffer in bytes.
 * @param result_len			Result length.
 * @return						FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
fenc_attribute_list_to_buffer(fenc_attribute_list *attribute_list, uint8 *buffer, size_t buf_len, size_t *result_len)
{
	// TODO: JAA cleanup.
	uint32 i;
	uint8 *buf_ptr = buffer;
	char token[300];
	
	*result_len = 0;	
	
	if (attribute_list == NULL) {
		return FENC_ERROR_INVALID_INPUT;
	}
	
	/* Begin with a paren.	*/
	(*result_len)++;
	if (buffer != NULL) {	buf_ptr += snprintf((char*)buf_ptr, (buf_len - *result_len), "(");	}
	
	/* Serialize all of the elements.	*/
	for (i = 0; i < attribute_list->num_attributes; i++) {
		// printf("%i:%s\n", i, attribute_list->attribute[i].attribute_str);
		/* We prefer the attribute string.	*/
			if (i != 0) {
				if (buffer != NULL) {	
					/* MDG: 7/4/2010 commented out what look like unnecessary arguments. i.e. ');'	*/
					buf_ptr += snprintf((char*) buf_ptr, (buf_len - *result_len), ",", attribute_list->attribute[i].attribute_str);
				}
				(*result_len)++;
			}

		if (attribute_list->attribute[i].attribute_str[0] != 0)	{
			if (buffer != NULL) {	buf_ptr += snprintf((char *) buf_ptr, (buf_len - *result_len), "%s", attribute_list->attribute[i].attribute_str);	}
			
			/* JAA removed quotes around attributes to make parsing straightforward */
			*result_len += strlen((char *) attribute_list->attribute[i].attribute_str);  // + 2;
		} else if (attribute_list->attribute[i].is_hashed == TRUE) {
			element_snprintf(token, 300, "{%B}", attribute_list->attribute[i].attribute_hash);
			if (buffer != NULL) {	buf_ptr += snprintf((char *) buf_ptr, (buf_len - *result_len), "%s", token);	}
			*result_len += strlen(token) + 2;
		} else {
			return FENC_ERROR_INVALID_INPUT;
		}
	}
	
	/* End with another paren.	*/
	(*result_len)++;
	if (buffer != NULL) {	buf_ptr += snprintf((char *) buf_ptr, (buf_len - *result_len), ")");	}
	
	return FENC_ERROR_NONE;
}


/*!
 * Parse a string of attributes into an fenc_attribute_list structure.
 * 
 * @param str_list				Buffer to attribute list string.
 * @param attribute_list		fenc_attribute_list pointer (not pre-allocated).
 * @return						FENC_ERROR_NONE or an error code.
 */
FENC_ERROR 
fenc_buffer_to_attribute_list(char **str_list, fenc_attribute_list *attribute_list)
{
	// form "( 'ATTR1' , 'ATTRX' )" => token '(' ','
	FENC_ERROR err_code = FENC_ERROR_NONE;
	int i = 0, j, token_len, str_list_len = strlen(*str_list);
	uint32 num_attributes = 0;
	
	char *str_list_pretty = (char *)malloc(str_list_len+1);
	char t;
	int psrc = 0, pdest = 0;
	for(psrc=0; psrc<str_list_len; psrc++)
		if((t=(*str_list)[psrc]) != ' ')
			str_list_pretty[pdest++] = t;
	str_list_pretty[pdest] = '\0';

	int str_list_pretty_len = strlen(str_list_pretty);
	char *list_cpy = (char *)malloc(str_list_pretty_len+1);
	strncpy(list_cpy , str_list_pretty, str_list_pretty_len);
	list_cpy[str_list_pretty_len] = '\0';

	char delims[] = "(,)", tmp[BITS+1];
	char *token = strtok(list_cpy, delims);
	char *s;	
	memset(tmp, 0, BITS+1);
	
	/* count the number of attributes in the list */
	do {
		/* check for '=' => numerical attributes */
		if((s = strchr(token, '=')) != NULL) {
			int len = strlen(s+1);		  
			char *value = malloc(len+1);
			strncpy(value, s+1, len);
			value[len] = '\0';
			if(strchr(value, '-') != NULL) {
				LOG_ERROR("%s: cannot have negative non-numerical attributes",value);
				free(value);
				return FENC_ERROR_INVALID_INPUT;
			}
			
			char *end;
			uint64_t val = strtoull(value, &end, 10);

			uint64_t limit = BITS>=64 ? ULLONG_MAX : ((uint64_t)1<<BITS) - 1;
			if(val >= limit) {
				LOG_ERROR("%s: reach maximum non-numerical limit",value);
				free(value);
				return FENC_ERROR_INVALID_INPUT;
			}

			num_attributes += BITS + 1;		
			free(value);
		}
		else {
			num_attributes++;
		}
		token = strtok(NULL, delims);
	} while(token != NULL);
		
	/* Initialize the structure.	*/
	if(attribute_list == NULL) {
		/* malloc in case the pointer is NULL */
		attribute_list = (fenc_attribute_list *) malloc(sizeof(fenc_attribute_list));
	}
	memset(attribute_list, 0, sizeof(fenc_attribute_list));
	err_code = fenc_attribute_list_initialize(attribute_list, num_attributes);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("%s: could not initialize attribute list", __func__);
		return err_code;
	}	
	
	/* tokenize and store in fenc_attribute_list */
	token = strtok(str_list_pretty, delims);
	// printf("%s: %i = token = '%s'?\n", __func__, i, token);
	while (token != NULL && i <= MAX_CIPHERTEXT_ATTRIBUTES) {
		token_len = strlen(token);

		/* check for '=' => numerical attributes */
		if((s = strchr(token, '=')) != NULL) {
			int len;
			len = s-token;
			char *attr = malloc(len+1);
			strncpy(attr, token, len);
			attr[len] = '\0';

			len = strlen(s+1);
			char *value = malloc(len+1);
			strncpy(value, s+1, len);
			value[len] = '\0';

			char *end;
			uint64_t val = strtoull(value, &end, 10);

			int str_len = token_len + 13;
			int num = BITS;
			
			if(str_len < MAX_ATTRIBUTE_STR) {
				//memset(attribute_list->attribute[i].attribute_str, 0, MAX_ATTRIBUTE_STR);
				//sprintf((char *)attribute_list->attribute[i].attribute_str, "%s_flexint_uint", attr);
				//i++;
				
				memset(attribute_list->attribute[i].attribute_str, 0, MAX_ATTRIBUTE_STR);
				sprintf((char *)attribute_list->attribute[i].attribute_str, "%s_flexint_%llu", attr, val);
				i++;
			}
			
			str_len = strlen(attr) + strlen(tmp) + 9;
			for(j = 0; j < num; j++) {
				memset(tmp, 'x', BITS);
				if (val & ((uint64_t)1 << j))
					tmp[BITS-j-1] = '1';
				else
					tmp[BITS-j-1] = '0';
				if(str_len < MAX_ATTRIBUTE_STR) {
					memset(attribute_list->attribute[i+j].attribute_str, 0, MAX_ATTRIBUTE_STR);
					sprintf((char *)attribute_list->attribute[i+j].attribute_str, "%s_flexint_%s", attr, tmp);
				}
			}
			i += num - 1;
			free(attr);
			free(value);
		}		
		else { /* regular attributes */
			if (token_len < MAX_ATTRIBUTE_STR) {
				memset(attribute_list->attribute[i].attribute_str, 0, MAX_ATTRIBUTE_STR);
				strncpy((char *) attribute_list->attribute[i].attribute_str, token, token_len);
			}
		
			// determine if it includes a NOT '!'
			if(token[0] == '!') {
				// printf("negated token\n");
				attribute_list->attribute[i].is_negated = TRUE;
			}
		}
		
		/* retrieve next token */
		token = strtok(NULL, delims);
		i++;
	}
		
	attribute_list->num_attributes = i;
	free(list_cpy);
	free(str_list_pretty);
	return err_code;
}

/*!
 * Find the index of an attribute within the list.	This searches on either the
 * attribute_hash or the attribute_str value (in that order) depending
 * on which is available.  
 *
 * @param attribute			Pointer to a fenc_attribute structure
 * @param attribute_list	Pointer to a fenc_attribute_list structure
 * @return					The index or -1 if not found.
 */

int32
libfenc_get_attribute_index_in_list(fenc_attribute *attribute, fenc_attribute_list *attribute_list)
{
	int32 i;
	
	//if (attribute->is_hashed) { element_printf("looking for: %B\n", attribute->attribute_hash); }
	for (i = 0; i < (int32) attribute_list->num_attributes; i++) {
		/* Start by looking for matching attribute strings (if both attributes have a string.) */
		if (attribute->attribute_str[0] != 0 && attribute_list->attribute[i].attribute_str[0] != 0) {
			//printf("found: %s\n", attribute->attribute_str);
			/* If both contain a string, look for a match in the attribute string.	*/
			if (strcmp((char *) attribute->attribute_str, (char *) attribute_list->attribute[i].attribute_str) == 0) {
				/* Found a match.	*/
				return i;
			}
		}
		/* If both don't have a string, but /do/ have hashes, compare them.		*/
		else if (attribute->is_hashed == TRUE && attribute_list->attribute[i].is_hashed == TRUE) {
			if (attribute->is_hashed) { DEBUG_ELEMENT_PRINTF("\tfound: %B\n", attribute_list->attribute[i].attribute_hash); }
			if (element_cmp(attribute->attribute_hash, attribute_list->attribute[i].attribute_hash) == 0) {
				/* Found a match.	*/
				return i;
			}
		} 
		/* If one has a hash and one has a string, compute the hash.			*/
		else if (attribute->is_hashed == TRUE && attribute_list->attribute[i].is_hashed == FALSE) {
			/* This is more of an error case.	*/
			LOG_ERROR("PROBLEM: MATCH ISSUE");
		}
		else if (attribute->is_hashed == FALSE && attribute_list->attribute[i].is_hashed == TRUE) {
			/* This is more of an error case.	*/
			LOG_ERROR("PROBLEM: MATCH ISSUE");
		}	
	}
	
	/* Not found.	*/
	return -1;
}

/*!
 * Clear an attribute data structure, deallocating memory.
 *
 * @param subtree		fenc_attribute_subtree structure
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
fenc_attribute_clear(fenc_attribute *attribute)
{ 
	if (attribute == NULL) {
		return FENC_ERROR_UNKNOWN;
	}
	
	/* Clear the hashed elements of Zr (and optionally the shares), and clear out the attribute strings.	*/
	if (attribute->is_hashed == TRUE) {
		element_clear(attribute->attribute_hash);
	}
 
	if (attribute->contains_share == TRUE) {
		element_clear(attribute->share);
	}		
 
	memset(attribute->attribute_str, 0, sizeof(MAX_ATTRIBUTE_STR));
	
	return FENC_ERROR_NONE;
}

/*!
 * Clear an attribute subtree data structure, deallocating memory.
 *
 * @param subtree		fenc_attribute_subtree structure
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
fenc_attribute_subtree_clear(fenc_attribute_subtree *subtree)
{
	FENC_ERROR err_code;
	uint32 i;
	
	/* Leaf nodes.							*/
	if (subtree->node_type == FENC_ATTRIBUTE_POLICY_NODE_LEAF) {
		/* Clear the attribute.			*/
		fenc_attribute_clear(&(subtree->attribute));
		return FENC_ERROR_NONE;
	}
	
	/* Otherwise clear out the subnodes.	*/
	if (subtree->subnode != NULL) {
		/* Recurse.	 Ignore the error codes.	*/
		for (i = 0; i < subtree->num_subnodes; i++) {
			err_code = fenc_attribute_subtree_clear(subtree->subnode[i]);
		}
		
		/* Deallocate the list.		*/
		SAFE_FREE(subtree->subnode);
	}
	
	return FENC_ERROR_NONE;
}

/*!
 * Duplicate an attribute.	The destination structure should be uninitialized.
 *
 * @param attribute_DST			fenc_attribute structure destination.
 * @param attribute_SRC			fenc_attribute structure source.
 * @return						FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
fenc_attribute_copy(fenc_attribute *attribute_DST, fenc_attribute *attribute_SRC, pairing_t pairing)
{
	// FENC_ERROR err_code;
	element_t test;
	
	memset(attribute_DST, 0, sizeof(fenc_attribute));
	
	/* Copy the contents of the structure over.	*/
	memcpy(attribute_DST->attribute_str, attribute_SRC->attribute_str, MAX_ATTRIBUTE_STR);
	attribute_DST->is_hashed = attribute_SRC->is_hashed;
	attribute_DST->is_negated = attribute_SRC->is_negated;
	
	if (attribute_SRC->is_hashed) {
		/* TODO: we're currently assuming that hashes are of Zr.  This may be a bad assumption
		 * going forward.	*/
		element_init_Zr(test, pairing);
		element_init_Zr(attribute_DST->attribute_hash, pairing);
		element_set(attribute_DST->attribute_hash, attribute_SRC->attribute_hash);
	}
	
	return FENC_ERROR_NONE;
}

/***********************************************************************************
 * Utility functions
 ***********************************************************************************/

/*!
 * Recursively print a policy tree into an ASCII string.
 *
 * @param fenc_attribute_subtree	Pointer to a fenc_attribute_subtree structure.
 * @param output_str				Pointer to a character string.
 * @param index						Pointer to a size_t indexing the current position in the string.
 * @param str_len					Maximum length of the string (excluding zero termination!)
 * @return							FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
fenc_attribute_policy_to_string(fenc_attribute_subtree *subtree, char *output_str, size_t buf_len)
{
	FENC_ERROR err_code;
	uint32 len = MAX_ATTRIBUTE_STR;
	char token[len], tmp[len];
	uint32 i;
	// ssize_t start = *str_index;
	Bool use_hash = FALSE;
	memset(token, '\0', len);
	memset(tmp, '\0', len);
	/* Base case (leaf)	*/
	if (subtree->node_type == FENC_ATTRIBUTE_POLICY_NODE_LEAF) {
		// printf("Parsing a leaf node\n");
		/* Is it negated? 
		 if (subtree->attribute.is_negated == TRUE )	{
		 if (output_str != NULL) {	snprintf((output_str+*str_index), buf_len - *str_index, "!");	}
		 (*str_index) += 1;
		 } */

		/* Use either the hash or the attribute string, whichever is shortest.	
		 if (subtree->attribute.is_hashed == TRUE) {
		 if (element_snprintf(token, 400, "{%B}", subtree->attribute.attribute_hash) == 0) {
		 LOG_ERROR("fenc_attribute_policy_to_string: element is too large");
		 return FENC_ERROR_UNKNOWN;
		 }
		 
		 if (strlen(token) < (strlen(subtree->attribute.attribute_str) + 2)) {
		 use_hash = TRUE;
		 } 
		 } */
		
		if (use_hash == TRUE) {
			if (output_str != NULL) {	
				// snprintf((output_str+*str_index), buf_len - *str_index, "%s", token);
				sprintf(tmp, "%s", token);
				strncat(output_str, tmp, strlen(tmp));
			}
			// (*str_index) += strlen(token) + 2;
		} else if (strlen((char *)subtree->attribute.attribute_str) > 0) {
			if (output_str != NULL)	{	
				// snprintf((output_str+*str_index), buf_len - *str_index, "\"%s\"", subtree->attribute.attribute_str);
				sprintf(tmp, "%s", subtree->attribute.attribute_str);
				strncat(output_str, tmp, strlen(tmp));
			}
			// (*str_index) += strlen(subtree->attribute.attribute_str) + 2;
		} else {
			/* Element has neither name nor hash, can't serialize it.	*/
			return FENC_ERROR_INVALID_INPUT;
		}
		
		return FENC_ERROR_NONE;
	}
	
	// printf("Parsing a OPERATOR node\n");
	/* Recursive case.	*/
	switch (subtree->node_type) {
		case FENC_ATTRIBUTE_POLICY_NODE_AND:
			sprintf(token, "and");
			break;
		case FENC_ATTRIBUTE_POLICY_NODE_OR:
			sprintf(token, "or");
			break;
		case FENC_ATTRIBUTE_POLICY_NODE_THRESHOLD:
			// sprintf(token, "th{%d}", subtree->threshold_k);
			sprintf(token, "%d of ", subtree->threshold_k);
			strncat(output_str, token, strlen(token));
			break;
		default:
			return FENC_ERROR_INVALID_INPUT;
	}
	memset(tmp, '\0', len);
	/* Print the token to the output string.	*/
	if (output_str != NULL)	{	
		// snprintf((output_str+*str_index), buf_len - *str_index, "(%s ", token);	
		sprintf(tmp, "(");
		strncat(output_str, tmp, strlen(tmp));
	}
	// (*str_index) += (strlen(token) + 2);
	
	/* Recurse from left to right, spitting out the leaves.	*/
	for (i = 0; i < subtree->num_subnodes; i++) {
		if (i > 0) {			
			if (output_str != NULL && subtree->node_type == FENC_ATTRIBUTE_POLICY_NODE_THRESHOLD) {
				strcat(output_str, ",");
			}			
			else {
				if (output_str != NULL)	{	
				// snprintf(output_str + *str_index, buf_len - *str_index, ",");	
					sprintf(tmp, " %s ", token);
					strncat(output_str, tmp, strlen(tmp));
				}
			}
			// (*str_index) += 1;
		}
		
		err_code = fenc_attribute_policy_to_string(subtree->subnode[i], output_str, buf_len);
		if (err_code != FENC_ERROR_NONE) {
			return err_code;
		}
	}
	
	if (output_str != NULL) {	
		// snprintf(output_str + *str_index, buf_len - *str_index, ")");
		strncat(output_str, ")", 1);	
	}
	// (*str_index) += 1;
	
	return FENC_ERROR_NONE;
}

/*!
 * This recursive function counts the number of leaves
 * under a given subtree.
 *
 * @param fenc_attribute_subtree	Pointer to a fenc_attribute_subtree structure.
 * @param attribute_list			Pointer to a fenc_attribute_list structure.
 * @return							Total number of satisfied leaves or 0 if there's a problem
 */

uint32
fenc_count_policy_leaves(fenc_attribute_subtree *subtree)
{
	uint32 count, i, num_leaves;
	
	if (subtree == NULL) {
		LOG_ERROR("fenc_count_policy_leaves: encountered NULL policy subtree");
		return 0;
	}			  

	/* If it's a leaf, return 1.	*/
	if (subtree->node_type == FENC_ATTRIBUTE_POLICY_NODE_LEAF) {
		return 1;
	}
	
	/* If it's not a leaf node, there should be something under it.  Sanity check.	*/
	if (subtree->num_subnodes < 1) {
		LOG_ERROR("fenc_count_policy_leaves: encountered non-leaf subtree with no children");
		return 0;
	}
	
	/* Otherwise recurse on all subnodes and return a total.	*/
	count = 0;
	for (i = 0; i < subtree->num_subnodes; i++) {
		num_leaves = fenc_count_policy_leaves(subtree->subnode[i]);
		if (num_leaves == 0) {
			return 0;	/* error case.	*/
		} else {
			count += num_leaves;
		}
	}
	
	return count;
}

/***************************************************************************
 * Policy manipulation
 ***************************************************************************/

/*!
 * Create a policy leaf subnode from an attribute string.
 *
 * @param attribute_str			Attribute string.
 * @return						Allocated policy subnode.
 */

fenc_attribute_subtree*
fenc_policy_create_leaf(char *attribute_str)
{
	fenc_attribute_subtree *leaf;
	
	/* Make sure there's room for the string.	*/
	if ((strlen(attribute_str) + 1) > MAX_ATTRIBUTE_STR) {
		return NULL;
	}
	
	/* Allocate and clear the subtree.		*/
	leaf = SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	if (leaf == NULL) {
		return NULL;
	}
	memset(leaf, 0, sizeof(fenc_attribute_subtree));
	
	/* Copy the string into the attribute and set up the node.	*/
	strcpy((char*)leaf->attribute.attribute_str, attribute_str);
	
	/* look for presence of '!' (not) */
	if(attribute_str[0] == '!') {
		leaf->attribute.is_negated = TRUE;
	}
	
	leaf->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	
	return leaf;
}

/*!
 * Create a policy subnode from an array of subnodes.
 *
 * @param node_type			FENC_ATTRIBUTE_NODE_TYPE value.
 * @param num_subnodes		Number of subnodes in the array.
 * @param threshold_k		Threshold value k.
 * @param subnodes			Array of fenc_attribute_subtree pointers.
 * @return					Allocated policy subnode.
 */

fenc_attribute_subtree*
fenc_policy_create_node(FENC_ATTRIBUTE_NODE_TYPE node_type, uint32 num_subnodes, uint32 threshold_k, fenc_attribute_subtree **subnodes)
{
	fenc_attribute_subtree *node;
	uint32 i;
	
	/* Allocate and clear the subtree.		*/
	node = SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	if (node == NULL) {
		return NULL;
	}
	memset(node, 0, sizeof(fenc_attribute_subtree));
	
	/* Copy the string into the attribute and set up the node.	*/
	node->node_type = node_type;
	node->num_subnodes = num_subnodes;
	node->threshold_k = threshold_k;
	
	if (num_subnodes > 0) {
		node->subnode = SAFE_MALLOC(num_subnodes * sizeof(fenc_attribute_subtree *));
		if (node->subnode == NULL) {
			return NULL;
		}
	
		for (i = 0; i < num_subnodes; i++) {
			node->subnode[i] = subnodes[i];
		}
	}
			
	return node;
}

/*!
 * Recursively compact a tree structure.  This consists of combining parent
 * and child nodes where appropriate. 
 *
 * The process is nicked from John Bethencourt's library, though the code isn't.
 *
 * @param subtree			The subtree.
 */

void
fenc_policy_compact(fenc_attribute_subtree* subtree)
{
	uint32 i;
	
	/* First compact all of the subnodes.				*/
	for (i = 0; i < subtree->num_subnodes; i++) {
		fenc_policy_compact(subtree->subnode[i]);
	}
	
	/* Initiate merging if this is an OR or AND node.	*/
	if (subtree->node_type == FENC_ATTRIBUTE_POLICY_NODE_AND ||
		subtree->node_type == FENC_ATTRIBUTE_POLICY_NODE_OR)	{
		/* Merge every subnode that has the same node type.		*/
		for (i = 0; i < subtree->num_subnodes; i++) {
			if (subtree->subnode[i]->node_type == subtree->node_type) {
				/* Merge the parent with this subnode.	*/
				fenc_policy_merge_child(subtree, i);
			}
		}
	}
}

/*!
 * Merge a child into the subtree.	Only works if the parent and child
 * node are both OR nodes or both AND nodes.
 *
 * @param subtree			The subtree.
 * @param child_num			Index of the child.
 */

void
fenc_policy_merge_child(fenc_attribute_subtree* subtree, uint32 child_num)
{
	uint32 new_num_nodes, i;
	fenc_attribute_subtree *child_subtree;
	
	if (subtree->node_type != subtree->subnode[child_num]->node_type) {
		LOG_ERROR("fenc_policy_compact: Node types don't match");
	}
	
	/* Merge the attribute list from the child into the parent node;
	 * remove the child from the parent node's list.
	 * 
	 * This is ugly.  Would be so much easier if we used a proper structured
	 * array type.	*/
	new_num_nodes = (subtree->num_subnodes + subtree->subnode[child_num]->num_subnodes) - 1;
	child_subtree = subtree->subnode[child_num];
	
	/* Re-allocate the array to contain the correct number of elements.	*/
	subtree->subnode = fenc_policy_extend_array(subtree->subnode, subtree->num_subnodes, new_num_nodes);
	
	/* Move all of the subnodes from the child into the parent node.	*/
	for (i = 0; i < child_subtree->num_subnodes; i++) {
		/* Put the first of the child's subnode in the slot where the child used to live.	*/
		if (i == 0) {
			subtree->subnode[child_num] = child_subtree->subnode[i];
		} else {			
			/* Put the rest into the high end of the array.					*/
			subtree->subnode[subtree->num_subnodes + (i - 1)] = child_subtree->subnode[i];
		}
	}
	subtree->num_subnodes = new_num_nodes;
	
	/* Now get rid of the child subnode.	*/
	child_subtree->num_subnodes = 0;
	fenc_attribute_subtree_clear(child_subtree);
	SAFE_FREE(child_subtree);
}

/*!
 * Extend an array of fenc_attribute_subtree pointers.
 *
 * @param attributes		The original array.
 * @param old_nodes			Number of nodes in the original array.
 * @param new_nodes			Desired number of nodes.
 */

fenc_attribute_subtree **
fenc_policy_extend_array(fenc_attribute_subtree **attributes, uint32 old_nodes, uint32 new_nodes)
{
	uint32 i;
	fenc_attribute_subtree **new_attributes;
	
	if (new_nodes <= old_nodes) {
		return attributes;
	}
	
	new_attributes = SAFE_MALLOC(new_nodes * sizeof(fenc_attribute_subtree*));
	memset(new_attributes, 0, new_nodes * sizeof(fenc_attribute_subtree*));
	
	for (i = 0; i < old_nodes; i++) {
		new_attributes[i] = attributes[i];
	}
	
	if (old_nodes > 0) {
		SAFE_FREE(attributes);
	}
	
	return new_attributes;
}

/*!
 * Parse a string to obtain an attribute policy.
 *
 * @param policy		A fenc_attribute_policy structure.
 * @param policy_str	The policy string.
 * @param FENC_ERROR_NONE or an error code
 */

FENC_ERROR
fenc_policy_from_string(fenc_attribute_policy *policy, char *policy_str)
{
	fenc_attribute_subtree* subtree = NULL;

	memset(policy, 0, sizeof(fenc_attribute_policy));
	
	subtree = parse_policy_lang( policy_str );
	if(!subtree) return FENC_ERROR_UNKNOWN;
	policy->root = subtree;
	policy->string = strdup(policy_str);
	return FENC_ERROR_NONE;
}

/*!
 * Parse attribute policy to obtain the string.
 *
 * @param policy		A fenc_attribute_policy structure.
 * @param string or NULL if policy structure is empty.
 */

char*
fenc_get_policy_string(fenc_attribute_policy *policy)
{
	if(policy == NULL) {
		goto cleanup;
	}
	else if(policy->string != NULL)
		/* if string pointer set already, just return */
		return policy->string;
	else {
		/* TODO: parse the policy structure and convert into a string */
	}
cleanup:
	return NULL;
}

/*!
 * Hash an attribute string to a value in Zr.  The result is stored within the
 * attribute structure.  Note that this hash may already have been stored,
 * in which case this routine will avoid redundant computation.
 *
 * @param attribute			Pointer to a fenc_attribute data structure.
 * @param global_params		Pointer to a fenc_group_parameters data structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
hash_attribute_string_to_Zr(fenc_attribute *attribute, pairing_t pairing)
{
	FENC_ERROR err_code;
	
	if (attribute->is_hashed == FALSE) {
		element_init_Zr(attribute->attribute_hash, pairing);
		err_code = hash1_attribute_string_to_Zr(attribute->attribute_str, &(attribute->attribute_hash));
		DEBUG_ELEMENT_PRINTF("Hashed %s to %B\n", attribute->attribute_str, attribute->attribute_hash);
		if (err_code != FENC_ERROR_NONE) {
			element_clear(attribute->attribute_hash);
			return err_code;
		}
		attribute->is_hashed = TRUE;
	}
	
	return FENC_ERROR_NONE;
}

void debug_print_policy(fenc_attribute_policy *policy)
{
	int len = MAX_POLICY_STR * 2;
	char *pol_str = (char *) malloc(len);
	memset(pol_str, 0, len);
	fenc_attribute_policy_to_string(policy->root, pol_str, len);
	printf("DEBUG: Policy -- '%s'\n", pol_str);
	free(pol_str);
}

void debug_print_attribute_list(fenc_attribute_list *attribute_list)
{
	size_t len = MAX_POLICY_STR * 2;
	char *attr_str = (char *) malloc(len);
	memset(attr_str, 0, len);
	size_t result_len;
	fenc_attribute_list_to_buffer(attribute_list, (unsigned char*)attr_str, len, &result_len);
	printf("DEBUG: Attribute list -- '%s'\n", attr_str);
	free(attr_str);
}

