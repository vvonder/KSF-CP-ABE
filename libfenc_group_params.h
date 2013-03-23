/*!	\file libfenc_group_params.h
 *
 *	\brief Routines relating to group parameters.
 *  
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#ifndef __LIBFENC_GROUP_PARAMS_H__
#define __LIBFENC_GROUP_PARAMS_H__

#include "libfenc.h"
#include <pbc/pbc.h>
/*#include "pbc_fieldmpz.h"*/
#include <pbc/pbc_fp.h>
#include <pbc/pbc_utils.h>

#define	MAX_PBC_PARAM_STRING	5000

/*!
 * Abstract data structure for group parameters.
 */

typedef struct _fenc_group_params {
	Bool			initialized;
	pbc_param_t		params;
	uint8*			param_buf;
	size_t			param_buf_len;
} fenc_group_params;

/********************************************************************************
 * Utility functions
 ********************************************************************************/

/*!
 * Set up a group parameters structure from a collection of PBC-formatted parameters.
 * Eventually we'd like to re-implement some portion of this to be library-agnostic.
 *
 * @param group_params			Group parameters
 * @param param_buf				Buffer containing raw parameter info
 * @param param_len				Number of bytes in the buffer
 * @return						FENC_ERROR_NONE or an error code.
 */
// TODO : unused parameters.
FENC_ERROR	libfenc_setup_from_pbc_params(/*fenc_group_params *group_params, 
									  char *param_buf, size_t param_len*/);

/*!
 * Load parameters from a buffer.
 *
 * @param group_params		parameters data structure
 * @param param_buf			buffer containing the parameters.
 * @param buf_len			buffer length
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_load_group_params_from_buf(fenc_group_params *group_params, uint8 *param_buf, size_t buf_len);

/*!
 * Load parameters from file.
 *
 * @param group_params		parameters data structure
 * @param fp				file pointer
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_load_group_params_from_file(fenc_group_params *global_params, FILE *fp);

/*!
 * Duplicate a group parameters structure.  This will involve memory allocation for
 * any internal structures; the duplicate structure must be destroyed to reclaim
 * this memory.  Caller must allocate the destination data structure.
 *
 * @param src_group_params		Input group parameters.
 * @param dest_group_params		Pre-allocated buffer for the destination parameters.
 * @return						FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_copy_group_params(fenc_group_params *src_group_params, 
									  fenc_group_params *dest_group_params);

/*!
 * Destroy a group parameters structure.  This will de-allocate internal data
 * structures.  It does not de-allocate the structure itself.
 *
 * @param group_params		Group parameters.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_destroy_group_params(fenc_group_params *group_params);

/*!
 * Check that a group parameters structure has been initialized with a valid set
 * of parameters.
 *
 * @param group_params		Group parameters.
 * @return					FENC_ERROR_NONE if the parameters are acceptable, or an error code.
 */

FENC_ERROR	libfenc_validate_group_params(fenc_group_params *group_params);

/*!
 * Get a pairing from the params.
 *
 * @param group_params		Group parameters.
 * @param pairing			PBC pairing data structure.
 * @return					FENC_ERROR_NONE if the parameters are acceptable, or an error code.
 */

FENC_ERROR	libfenc_get_pbc_pairing(fenc_group_params *group_params, pairing_t pairing);

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

FENC_ERROR	libfenc_export_group_params(fenc_group_params *group_params, uint8 *buffer, size_t max_len,
							size_t *result_len);

#endif /* ifdef __LIBFENC_GROUP_PARAMS_H__ */
