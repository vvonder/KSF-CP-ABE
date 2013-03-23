/*!	\file libfenc_group_params.c
 *
 *	\brief Routines relating to group parameters.
 *  
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pbc/pbc.h>
#include "libfenc.h"
#include "libfenc_group_params.h"

/********************************************************************************
 * Utility functions
 ********************************************************************************/

/*!
 * Set up a group parameters structure from a collection of PBC-formatted parameters.
 * Eventually we'd like to re-implement some portion of this to be library-agnostic.
 *
 * @param param_buf				Buffer containing parameters
 * @return						FENC_ERROR_NONE or an error code.
 */

// TODO : unused parameter.
FENC_ERROR
libfenc_setup_from_pbc_params(/*fenc_group_params *group_params, 
				char *param_buf, size_t param_len*/)
{
	// FENC_ERROR result;
	
	LOG_ERROR("libfenc_setup_from_pbc_params: function not implemented");
	return FENC_ERROR_NOT_IMPLEMENTED;
	
#if 0
	memset(group_params, 0, sizeof(fenc_group_params));
	if (pairing_init_set_buf(group_params->pairing, param_buf, param_len) == 0) {
		group_params->initialized = TRUE;
		result = FENC_ERROR_NONE;
	} else {
		result = FENC_ERROR_INVALID_GROUP_PARAMS;
	} 
	
	return result;
#endif
}

/*!
 * Load parameters from file.
 *
 * @param group_params		parameters data structure
 * @param fp				file pointer
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_load_group_params_from_file(fenc_group_params *group_params, FILE *fp)
{
	FENC_ERROR result;
	char param_buf[16384];
	size_t count;
	
	count = fread(param_buf, 1, 16384, fp);
	if (count == 0) { 
		return FENC_ERROR_INVALID_GROUP_PARAMS;
	}
	
	memset(group_params, 0, sizeof(fenc_group_params));
	
	if (pbc_param_init_set_buf(group_params->params, param_buf, count) == 0) {
		/* We store the parameters into a buffer when we import them, then give back (a copy of) that buffer
		 * on export.  This should always work since libfenc doesn't currently support
		 * parameter generation.														*/
		group_params->param_buf = SAFE_MALLOC(count);
		group_params->param_buf_len = count;
		memcpy(group_params->param_buf, param_buf, count);
		
		group_params->initialized = TRUE;
		result = FENC_ERROR_NONE;
	} else {
		result = FENC_ERROR_INVALID_GROUP_PARAMS;
	} 
	
	return result;
}

/*!
 * Load parameters from a buffer.
 *
 * @param group_params		parameters data structure
 * @param fp				file pointer
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_load_group_params_from_buf(fenc_group_params *group_params, uint8 *param_buf, size_t buf_len)
{
	FENC_ERROR result;
	
	memset(group_params, 0, sizeof(fenc_group_params));

	if (pbc_param_init_set_buf(group_params->params, (char *) param_buf, (unsigned) buf_len) == 0) {
		/* We store the parameters into a buffer when we import them, then give back (a copy of) that buffer
		 * on export.  This should always work since libfenc doesn't currently support
		 * parameter generation.														*/
		group_params->param_buf = SAFE_MALLOC(buf_len);
		group_params->param_buf_len = buf_len;
		memcpy(group_params->param_buf, param_buf, buf_len);
		
		group_params->initialized = TRUE;
		result = FENC_ERROR_NONE;
	} else {
		result = FENC_ERROR_INVALID_GROUP_PARAMS;
	} 
	
	return result;
}

/*!
 * Duplicate a group parameters structure.  This will involve memory allocation for
 * any internal structures; the duplicate structure must be destroyed to reclaim
 * this memory.  Caller must allocate the destination data structure.
 *
 * @param src_group_params		Input group parameters.
 * @param dest_group_params		Pre-allocated buffer for the destination parameters.
 * @return						FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_copy_group_params(fenc_group_params *src_group_params, 
									  fenc_group_params *dest_group_params)
{
	/* TODO: MDG got this. :) */
	// LOG_ERROR("libfenc_copy_group_params: this copy function may not be safe as implemented.");

	if (src_group_params == NULL || dest_group_params == NULL) {
		return FENC_ERROR_INVALID_GROUP_PARAMS;
	}
	
	/* Copy the binary buffer containing the parameters as a string.	*/
	if (src_group_params->param_buf != NULL) {
		dest_group_params->param_buf = SAFE_MALLOC(src_group_params->param_buf_len);
		memcpy(dest_group_params->param_buf, src_group_params->param_buf, src_group_params->param_buf_len);
		dest_group_params->param_buf_len = src_group_params->param_buf_len;
	}
	
	/* Copy the PBC params structure.  This part may not be safe.	*/
	memcpy(dest_group_params->params, src_group_params->params, sizeof(pbc_param_t));
	dest_group_params->initialized = src_group_params->initialized;
	
	return FENC_ERROR_NONE;
}

/*!
 * Destroy a group parameters structure.  This will de-allocate internal data
 * structures.  It does not de-allocate the structure itself.
 *
 * @param group_params		Group parameters.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_destroy_group_params(fenc_group_params *group_params)
{
	if (group_params->param_buf != NULL) {
		SAFE_FREE(group_params->param_buf);
		group_params->param_buf = NULL;
	}
	
	/* TODO: This may not be the safest */
	memset(group_params->params, 0, sizeof(pbc_param_t));
		   
	return FENC_ERROR_NONE;
}

/*!
 * Check that a group parameters structure has been initialized with a valid set
 * of parameters.
 *
 * @param group_params		Group parameters.
 * @return					FENC_ERROR_NONE if the parameters are acceptable, or an error code.
 */

FENC_ERROR
libfenc_validate_group_params(fenc_group_params *group_params)
{
	if (group_params->initialized == TRUE) {
		return FENC_ERROR_NONE;
	} else {
		return FENC_ERROR_INVALID_GROUP_PARAMS;
	}
}

/*!
 * Get a pairing from the params.
 *
 * @param group_params		Group parameters.
 * @return					PBC pairing data structure.
 */

FENC_ERROR
libfenc_get_pbc_pairing(fenc_group_params *group_params, pairing_t pairing)
{
	if (group_params->initialized == FALSE) {
		return FENC_ERROR_INVALID_GROUP_PARAMS;
	}
	
	pairing_init_pbc_param(pairing, group_params->params);
	
	return FENC_ERROR_NONE;
}

/*!
 * Serialize a group parameters structure to a buffer.  If buffer is set to NULL this routine 
 * will return the necessary size of the group parameters.
 *
 * @param group_param			Input group parameters.
 * @param buffer				Pre-allocated buffer for the serialized parameters.
 * @param max_len				Maximum size of the buffer.
 * @param result_len			Pointer to a size_t that will contain the result.
 * @return						FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_export_group_params(fenc_group_params *group_params, uint8 *buffer, size_t max_len,
							size_t *result_len)
{	
	if (group_params->initialized == FALSE) {
		LOG_ERROR("libfenc_export_group_params: group parameters are not set");
		return FENC_ERROR_INVALID_GROUP_PARAMS;
	}
	
	/* Unfortunately PBC only allows us to export group params to a file.  In libfenc
	 * we've chosen to avoid file IO as much as possible.
	 * 
	 * For Linux we could use a memstream to export to a buffer, but that functionality
	 * isn't implemented on many OSes.  So our approach is just to store the parameters
	 * into a buffer when we import them, then give back (a copy of) that buffer
	 * on export.  This should always work since libfenc doesn't currently support
	 * parameter generation.														*/
	if (group_params->param_buf == FALSE) {
		LOG_ERROR("libfenc_export_group_params: valid parameters, but could not find a serialized version");
		return FENC_ERROR_INVALID_GROUP_PARAMS;
	}
	
	*result_len = group_params->param_buf_len;

	if (buffer == NULL) {
		/* All done, just return the length.	*/
		return FENC_ERROR_NONE;
	}
	
	if (group_params->param_buf_len > max_len) {
		/* Provided buffer is too small.		*/
		LOG_ERROR("libfenc_export_group_params: parameters are too large.");
		return FENC_ERROR_INVALID_GROUP_PARAMS;
	}
	
	memcpy(buffer, group_params->param_buf, group_params->param_buf_len);

	return FENC_ERROR_NONE;
}
