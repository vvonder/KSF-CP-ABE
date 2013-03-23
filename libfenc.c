
/*!	\file libfenc.c
 *
 *	\brief Main file for the Functional Encryption Library.
 *  
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#define __LIBFENC_C__

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#define PBC_DEBUG
#include <pbc/pbc.h>
#include "libfenc.h"
#include "libfenc_group_params.h"
#include "libfenc_utils.h"
#include "libfenc_ABE_common.h"
#include "libfenc_LSW.h"
#include "libfenc_WatersCP.h"
#include "libfenc_WatersSimpleCP.h"

/********************************************************************************
 * Library global variables
 ********************************************************************************/

FILE			*global_error_file = NULL;

/********************************************************************************
 * Core API
 ********************************************************************************/

/*!
 * Global initialization for the library.  This routine must be called before 
 * any others.
 *
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_init()
{
	FENC_ERROR result = FENC_ERROR_LIBRARY_NOT_INITIALIZED;
	
	/* If the library is in a pre-initialized state, we can initialize it and go.
	 * Otherwise return an error. */
	if (libfenc_global_state == FENC_STATE_NOT_INITIALIZED) {
		libfenc_global_state = FENC_STATE_READY;
		result = FENC_ERROR_NONE;
	}
	
	/* Set the error file to stderr.	*/
	global_error_file = stderr;
	
	/* Future library pre-processing, self-checks, etc. go here. */
	
	return result;
}

/*!
 * Global shutdown for the library.  This routine should be called prior to application
 * exit.
 *
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_shutdown()
{
	FENC_ERROR result = FENC_ERROR_NONE;
	
	libfenc_global_state = FENC_STATE_NOT_INITIALIZED;
	
	/* Future library shutdown, key  destruction, etc. go here. */
	
	return result;
}
	

/*!
 * Initialize a fenc_context data structure for use with a particular scheme type.  
 * Any number of fenc_context structures may be simultaneously used, with the same
 * or different schemes.  The caller assumes responsible for allocating the context
 * buffer.
 *
 * @param context		Pre-allocated buffer for the fenc_context data structure.
 * @param scheme_type	Identifier of the functional encryption scheme to use.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_create_context(fenc_context *context, FENC_SCHEME_TYPE scheme_type)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	
	/* Wipe the context buffer. */
	memset(context, 0, sizeof(fenc_context));
	
	/* Depending on the scheme, set up the context using the appropriate constructor.
	 * This will set  appropriate function pointers within the context so the other
	 * calls won't require a switch statement. */
	switch(scheme_type) {
		case FENC_SCHEME_LSW:
			result = libfenc_create_context_LSW(context);
			break;
		case FENC_SCHEME_WATERSCP:
			result = libfenc_create_context_WatersCP(context);
			break;
		case FENC_SCHEME_WATERSSIMPLECP:
			result = libfenc_create_context_WatersSimpleCP(context);
			break;
		default:
			result = FENC_ERROR_UNKNOWN_SCHEME;
	}
	
	/* Record the scheme type. */
	if (result == FENC_ERROR_NONE) {
		context->scheme_type = scheme_type;
	}
	
	return result;
}

/*!
 * Generate public and secret parameters.  This is equivalent to the "Setup" algorithm in most 
 * functional encryption schemes.  All relevant global parameters will 
 *
 * @param context		The fenc_context data structure
 * @param global_params	Global params (scheme-specific).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_gen_params(fenc_context *context, fenc_global_params *global_params)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	
	/* Validate the context. */
	if (context->scheme_type == FENC_SCHEME_NONE || context->gen_params == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
	}

	/* Check that the functionality is implemented for this particular scheme.	*/
	if (context->gen_params == NULL) {
		result = FENC_ERROR_NOT_IMPLEMENTED;
	}
	
	/* Clear flags in the context. */
	context->contains_public_params = FALSE;
	context->contains_secret_params = FALSE;
	
	/* Call the appropriate function pointer to generate the parameters. */
	if (result == FENC_ERROR_NONE) {
		result = context->gen_params(context, global_params);
	}
	
	/* If parameter generation was successful, mark the appropriate flags in the context. */
	if (result == FENC_ERROR_NONE) {
		context->contains_public_params = TRUE;
		context->contains_secret_params = TRUE;
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
// TODO : unused parameters.
FENC_ERROR	libfenc_set_params(/*fenc_context *context, fenc_public_params *public_params, fenc_secret_params *secret_params*/)
{
	return FENC_ERROR_NOT_IMPLEMENTED;
}

/*!
 * Load global parameters into the context.  All relevant global
 * parameters are embedded within the public_params data structure.
 *
 * @param context					The fenc_context data structure
 * @param fenc_global_params		Public scheme parameters.
 * @return							FENC_ERROR_NONE or an error code.
 */
// TODO : unused parameters.
FENC_ERROR	libfenc_set_global_params(/*fenc_context *context, fenc_global_params *global_params*/)
{
	return FENC_ERROR_NOT_IMPLEMENTED;
} 

/*!
 * Extract a secret key representing a given function input.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input from which this key will be built.
 * @param key			A pre-allocated buffer for the resulting key
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	
libfenc_extract_key(fenc_context *context, fenc_function_input *input, fenc_key *key)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	
	/* Validate the context. */
	if (context->scheme_type == FENC_SCHEME_NONE || context->gen_params == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Check that the functionality is implemented for this particular scheme.	*/
	if (context->extract_key == NULL) {
		result = FENC_ERROR_NOT_IMPLEMENTED;
	}
	
	/* Make sure that the secret parameters are available. */
	if (context->contains_secret_params == FALSE) {
		result = FENC_ERROR_NO_SECRET_PARAMS;
	}
	
	/* Call the appropriate function pointer. */
	if (result == FENC_ERROR_NONE) {
		result = context->extract_key(context, input, key);
	}
	
	return result;
}

/*!
 * Encrypt a plaintext under a given function input.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input under which which the ciphertext will be encrypted.
 * @param plaintext		The plaintext message.
 * @param ciphertext	A pre-allocated buffer for the returned fenc_ciphertext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_encrypt(fenc_context *context, fenc_function_input *input, fenc_plaintext *plaintext,
							fenc_ciphertext *ciphertext)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	
	/* Validate the context. */
	if (context->scheme_type == FENC_SCHEME_NONE || context->gen_params == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Check that the functionality is implemented for this particular scheme.	*/
	if (context->encrypt == NULL) {
		result = FENC_ERROR_NOT_IMPLEMENTED;
	}
	
	/* Make sure this context contains public parameters.	*/
	if (context->contains_public_params == FALSE) {
		result = FENC_ERROR_NO_PUBLIC_PARAMS;
	}
	
	/* Call the appropriate function pointer. */
	if (result == FENC_ERROR_NONE) {
		result = context->encrypt(context, input, plaintext, ciphertext);
	}
	
	return result;
}

/*!
 * Key encapsulation variant of encryption.  Generate an encryption key and encapsulate it under 
 * a given function input.  Returns the encapsulated key as well as the ciphertext.
 * Note that this may not be supported for all schemes.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input under which which the ciphertext will be encrypted.
 * @param key_len		Desired key size (in bytes).  Will be overwritten with the actual key size.
 * @param key			Pointer to an initialized buffer into which the key will be written.
 * @param ciphertext	A pre-allocated buffer for the returned fenc_ciphertext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	
libfenc_kem_encrypt(fenc_context *context, fenc_function_input *input, size_t key_len,
								uint8* key, fenc_ciphertext *ciphertext)
{
	FENC_ERROR result = FENC_ERROR_NONE;
		
	/* Validate the context. */
	if (context->scheme_type == FENC_SCHEME_NONE || context->gen_params == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
	}
		
	/* Check that the functionality is implemented for this particular scheme.	*/
	if (context->kem_encrypt == NULL) {
		result = FENC_ERROR_NOT_IMPLEMENTED;
	}
		
	/* Make sure this context contains public parameters.	*/
	if (context->contains_public_params == FALSE) {
		result = FENC_ERROR_NO_PUBLIC_PARAMS;
	}
		
	/* Call the appropriate function pointer. */
	if (result == FENC_ERROR_NONE) {
		result = context->kem_encrypt(context, input, key_len, key, ciphertext);
	}
		
	return result;
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

FENC_ERROR	libfenc_decrypt(fenc_context *context, fenc_ciphertext *ciphertext, fenc_key *key,
							fenc_plaintext *plaintext)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	
	/* Validate the context. */
	if (context->scheme_type == FENC_SCHEME_NONE || context->gen_params == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Check that the functionality is implemented for this particular scheme.	*/
	if (context->decrypt == NULL) {
		result = FENC_ERROR_NOT_IMPLEMENTED;
	}
	
	/* Make sure this context contains public parameters.	*/
	if (context->contains_public_params == FALSE) {
		result = FENC_ERROR_NO_PUBLIC_PARAMS;
	}
	
	/* Call the appropriate function pointer. */
	if (result == FENC_ERROR_NONE) {
		result = context->decrypt(context, ciphertext, key, plaintext);
	}
	
	return result;
}

/*!
 * Export a context's public parameters (MPK) to a binary buffer.  Calling this function with buffer 
 * set to NULL will return the length of the exported material.
 *
 * @param context		The fenc_context data structure
 * @param buffer		A pre-allocated buffer for the resulting export.
 * @param buf_len		The maximum allocated size of the buffer (in bytes).
 * @param result_len	The size of the resulting export (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	
libfenc_export_public_params(fenc_context *context, uint8 *buffer, size_t buf_len, size_t *result_len,
										 Bool include_global_params)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	size_t global_params_len = 0;
	uint8* global_params_len_buf = buffer;
	
	/* Validate the context. */
	if (context->scheme_type == FENC_SCHEME_NONE || context->gen_params == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Check that the functionality is implemented for this particular scheme.	*/
	if (context->export_public_params == NULL) {
		result = FENC_ERROR_NOT_IMPLEMENTED;
	}
	
	/* Make sure this context actually contains public parameters.	*/
	if (context->contains_public_params == FALSE) {
		result = FENC_ERROR_NO_PUBLIC_PARAMS;
	}
	
	/* If requested, export the global parameters.		*/
	if (result == FENC_ERROR_NONE && include_global_params == TRUE) {
		if (buffer != NULL) {
			buffer += sizeof(int32);
			buf_len -= 4;
		}
		
		result = libfenc_export_global_params(context, buffer, buf_len, &global_params_len);
		if (result != FENC_ERROR_NONE) {
			return result;
		}
		
		if (buffer != NULL) {
			buffer += global_params_len;
			buf_len -= global_params_len;
		}
	}
	
	/* Export the global parameters length into the first few bytes.	*/
	global_params_len += sizeof(int32);
	if (buffer != NULL) {
		EXPORT_INT32(global_params_len_buf, global_params_len);
	}
	
	/* Call the appropriate function pointer. */
	if (result == FENC_ERROR_NONE) {
		result = context->export_public_params(context, buffer, buf_len, result_len);
		*result_len += global_params_len;
	}
	
	return result;
}

/*!
 * Export a context's secret parameters (MSK) to a binary buffer.  Calling this function with buffer 
 * set to NULL will return the length of the exported material.  If an optional password parameter is
 * provided, the parameters will be encrypted under the specified password.
 *
 * @param context		The fenc_context data structure
 * @param buffer		A pre-allocated buffer for the resulting export.
 * @param buf_len		The maximum allocated size of the buffer (in bytes).
 * @param result_len	The size of the resulting export (in bytes).
 * @param password		Optional passphrase (set to NULL to skip parameter encryption).
 * @param password_len	Length of the passphrase (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_export_secret_params(fenc_context *context, uint8 *buffer, size_t buf_len, size_t *result_len,
							 uint8* password, size_t password_len)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	
	/* Validate the context. */
	if (context->scheme_type == FENC_SCHEME_NONE || context->gen_params == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Check that the functionality is implemented for this particular scheme.	*/
	if (context->export_secret_params == NULL) {
		result = FENC_ERROR_NOT_IMPLEMENTED;
	}
	
	/* Make sure this context actually contains secret parameters.	*/
	if (context->contains_secret_params == FALSE) {
		result = FENC_ERROR_NO_SECRET_PARAMS;
	}
	
	/* Call the appropriate function pointer to serialize the parameters. */
	if (result == FENC_ERROR_NONE) {
		result = context->export_secret_params(context, buffer, buf_len, result_len);
	}
	
	/* Optionally encrypt the resulting buffer under the supplied passphrase. */
	if (result == FENC_ERROR_NONE && password != NULL && password_len > 0) {
		result = fenc_encrypt_with_password(buffer, buf_len, result_len, password, password_len);
	}
	
	return result;
}

/*!
 * Import a context's public parameters (MPK) from a binary buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param buf_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_import_public_params(fenc_context *context, uint8 *buffer, size_t buf_len)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	
	/* Validate the context. */
	if (context->scheme_type == FENC_SCHEME_NONE || context->gen_params == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Check that the functionality is implemented for this particular scheme.	*/
	if (context->import_public_params == NULL) {
		result = FENC_ERROR_NOT_IMPLEMENTED;
	}

#if 0
	uint32 global_params_len = 0;

	/* First four bytes contain the length of the global params, or 0 if they're not present.	*/
	if (buf_len < sizeof(int32)) {
		return FENC_ERROR_INVALID_GROUP_PARAMS;
	}
	IMPORT_INT32(global_params_len, buffer);
	buffer += sizeof(int32);
	buf_len -= sizeof(int32);
	
	/* Import the global parameters.		*/
	if (global_params_len > 0) {
		result = libfenc_import_global_params(context, buffer, global_params_len);
		buffer += global_params_len;
	}
#endif
	
	/* Call the appropriate function pointer to deserialize the remaining parameters. */
	if (result == FENC_ERROR_NONE) {
		result = context->import_public_params(context, buffer, buf_len, NULL);
	}
	
	/* Note that the public params are available.	*/
	if (result == FENC_ERROR_NONE) {
		context->contains_public_params = TRUE;
	}
	
	return result;
}

/*!
 * Import a context's secret parameters (MSK) from a binary buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param buf_len		The size of the buffer (in bytes).
 * @param password		Optional passphrase (set to NULL to skip parameter decryption).
 * @param password_len	Length of the passphrase (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_import_secret_params(fenc_context *context, uint8 *buffer, size_t buf_len,
							 uint8* password, size_t password_len)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	size_t result_len;
	
	/* Validate the context. */
	if (context->scheme_type == FENC_SCHEME_NONE || context->gen_params == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Check that the functionality is implemented for this particular scheme.	*/
	if (context->import_secret_params == NULL) {
		result = FENC_ERROR_NOT_IMPLEMENTED;
	}
	
	/* Optionally decrypt the resulting buffer using the supplied passphrase. */
	if (result == FENC_ERROR_NONE && password != NULL && password_len > 0) {
		result = fenc_decrypt_with_password(buffer, buf_len, &result_len, password, password_len);
	}
	
	/* Call the appropriate function pointer to deserialize the parameters. */
	if (result == FENC_ERROR_NONE) {
		result = context->import_secret_params(context, buffer, buf_len);
	}
	
	/* Note that the public params are available.	*/
	if (result == FENC_ERROR_NONE) {
		context->contains_secret_params = TRUE;
	}
	
	return result;
}

/*!
 * Export a context's global parameters to a buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		A pre-allocated buffer for the resulting export.
 * @param buf_len		The maximum allocated size of the buffer (in bytes).
 * @param result_len	The size of the resulting export (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_export_global_params(fenc_context *context, uint8 *buffer, size_t buf_len, size_t *result_len)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	
	/* Validate the context. */
	if (context->scheme_type == FENC_SCHEME_NONE || context->gen_params == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Check that the functionality is implemented for this particular scheme.	*/
	if (context->export_global_params == NULL) {
		result = FENC_ERROR_NOT_IMPLEMENTED;
	}
	
	/* Make sure this context actually contains public parameters.	*/
	if (context->contains_public_params == FALSE) {
		result = FENC_ERROR_NO_PUBLIC_PARAMS;
	}
		
	/* Call the appropriate function pointer. */
	if (result == FENC_ERROR_NONE) {
		result = context->export_global_params(context, buffer, buf_len, result_len);
	}
	
	return result;
}

/*!
 * Import a context's global parameters from a buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param buf_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_import_global_params(fenc_context *context, uint8 *buffer, size_t buf_len)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	
	/* Validate the context. */
	if (context->scheme_type == FENC_SCHEME_NONE || context->gen_params == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Check that the functionality is implemented for this particular scheme.	*/
	if (context->import_global_params == NULL) {
		result = FENC_ERROR_NOT_IMPLEMENTED;
	}
	
	/* Call the appropriate function pointer to deserialize the parameters. */
	if (result == FENC_ERROR_NONE) {
		result = context->import_global_params(context, buffer, buf_len);
	}
	
	return result;
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
libfenc_export_secret_key(fenc_context *context, fenc_key *key, uint8 *buffer, size_t buf_len, size_t *result_len)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	/* Validate the context. */
	if (context->scheme_type == FENC_SCHEME_NONE || context->gen_params == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
	}

	/* Check that the functionality is implemented for this particular scheme.	*/
	if (context->export_secret_key == NULL) {
		result = FENC_ERROR_NOT_IMPLEMENTED;
	}
		
	/* TODO: Any other checks necessary to export keys? */
	/* Call the appropriate function pointer to deserialize the parameters. */
	if (result == FENC_ERROR_NONE) {
		result = context->export_secret_key(context, key, buffer, buf_len, result_len);
	}
	
	return result;
}

/*!
 * Deserialize an ABE key structure.
 *
 * @param context		The fenc_context data structure
 * @param key			The fenc_key data structure (pre-allocated).
 * @param buffer		The buffer which contains the binary contents of key?
 * @param buf_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	
libfenc_import_secret_key(fenc_context *context, fenc_key *key, uint8 *buffer, size_t buf_len)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	/* Validate the context. */
	if (context->scheme_type == FENC_SCHEME_NONE || context->gen_params == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Check that the functionality is implemented for this particular scheme.	*/
	if (context->import_secret_key == NULL) {
		result = FENC_ERROR_NOT_IMPLEMENTED;
	}
	
	/* TODO: Any other checks necessary to export keys? */
	// check contents of key?
	
	/* Call the appropriate function pointer to deserialize the parameters. */
	if (result == FENC_ERROR_NONE) {
		result = context->import_secret_key(context, key, buffer, buf_len);
	}	
	return result;
}

/*!
 * Destroy the internal contents of a fenc_context structure.  The caller is responsible for
 * de-allocating the context buffer itself.
 *
 * @param context		The fenc_context data structure.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_destroy_context(fenc_context *context)
{
	FENC_ERROR result = FENC_ERROR_UNKNOWN;
	
	if (context == NULL) {
		return FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Validate the context. */
	if (context->scheme_type == FENC_SCHEME_NONE || context->destroy_context == NULL) {
		return FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Check that the functionality is implemented for this particular scheme.	*/
	if (context->destroy_context == NULL) {
		result = FENC_ERROR_NOT_IMPLEMENTED;
	}
	
	/* Call the "destroy_context" function pointer to destroy the 
	 scheme-specific context data structure. */
	result = context->destroy_context(context);
	
	/* Wipe out the context data structure. */
	memset(context, 0, sizeof(fenc_context) );
	
	return result;
}

/*!
 * Allows the application to specify a FILE structure into which the library will 
 * write its error messages.  A NULL value deactivates logging.  
 * stderr is default.  Application is responsible for opening and closing
 * files.
 *
 * @param error_file	Pointer to a FILE structure or NULL.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_set_error_file(FILE* error_file)
{
	global_error_file = error_file;
	
	return FENC_ERROR_NONE;
}

/**************************************************************************************
 * Utility functions
 **************************************************************************************/

/*!
 * Destroy the internal contents of a global parameters structure.  The caller is responsible for
 * de-allocating the context buffer itself.
 *
 * @param context		The context.
 * @return				FENC_ERROR_NONE or an error code.
 */
// TODO : unused parameter.
FENC_ERROR
libfenc_destroy_global_params(/*fenc_context *context*/)
{
	return FENC_ERROR_NOT_IMPLEMENTED;
}

/*!
 * Get the group parameters structure from the global parameters structure.
 *
 * @param global_params	The global parameters.
 * @return				FENC_ERROR_NONE or an error code.
 */

fenc_group_params* 
libfenc_get_group_params(fenc_global_params *global_params)
{
	return global_params->group_params;
}

/*!
 * Initialize a fenc_plaintext structure.
 *
 * @param plaintext		A pointer to a fenc_plaintext struct.
 * @param data_len		Length in bytes of the plaintext (to allocate).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_plaintext_initialize(fenc_plaintext *plaintext, unsigned int data_len)
{
	memset(plaintext, 0, sizeof(fenc_plaintext));
	plaintext->data = (unsigned char*)SAFE_MALLOC(data_len);
	if (plaintext->data == NULL) {
		LOG_ERROR("libfenc_ciphertext_initialize: unable to allocate buffer");
		return FENC_ERROR_OUT_OF_MEMORY;
	}
	plaintext->max_len = data_len;

	return FENC_ERROR_NONE;
}

/*!
 * Get the data buffer from a fenc_plaintext structure.
 *
 * @param plaintext		A pointer to a fenc_plaintext struct.
 * @return				Data buffer or NULL.
 */

uint8*	libfenc_plaintext_get_buf(fenc_plaintext *plaintext)
{
	return plaintext->data;
}

/*!
 * Initialize a fenc_ciphertext structure.
 *
 * @param ciphertext	A pointer to a fenc_ciphertext struct.
 * @param data_len		Length in bytes of the serialized ciphertext.
 * @param scheme_type	Identifier of the scheme.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_ciphertext_initialize(fenc_ciphertext *ciphertext, unsigned int data_len, FENC_SCHEME_TYPE scheme_type)
{
	memset(ciphertext, 0, sizeof(fenc_ciphertext));
	ciphertext->data = (unsigned char*)SAFE_MALLOC(data_len);
	if (ciphertext->data == NULL) {
		LOG_ERROR("libfenc_ciphertext_initialize: unable to allocate buffer");
		return FENC_ERROR_OUT_OF_MEMORY;
	}
	ciphertext->max_len = data_len;
	ciphertext->scheme_type = scheme_type;
	
	return FENC_ERROR_NONE;
}

/*!
 * Clear a fenc_ciphertext structure.
 *
 * @param ciphertext	A pointer to a fenc_ciphertext struct.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_ciphertext_clear(fenc_ciphertext *ciphertext)
{
	if (ciphertext->data != NULL) {
		SAFE_FREE(ciphertext->data);
	}
	memset(ciphertext, 0, sizeof(fenc_ciphertext));
	
	return FENC_ERROR_NONE;
}

/*!
 * Set a fenc_plaintext structure to a buffer of bytes.
 *
 * @param plaintext		A pointer to a fenc_plaintext struct.
 * @param buf			Byte buffer.
 * @param buf_size		Buffer size in bytes.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_set_plaintext_bytes(fenc_plaintext *plaintext, uint8* buf, size_t buf_size)
{
	if (plaintext == NULL) {
		return FENC_ERROR_INVALID_PLAINTEXT;
	}
	
	if (plaintext->data != NULL) {
		SAFE_FREE(plaintext->data);
	}
	memset(plaintext, 0, sizeof(fenc_plaintext));
	
	plaintext->data = SAFE_MALLOC(buf_size);
	memcpy(plaintext->data, buf, buf_size);
	plaintext->data_len = buf_size;
	plaintext->max_len = buf_size;
	plaintext->valid = TRUE;
	
	return FENC_ERROR_NONE;
}

/*!
 * Get the byte buffer from a fenc_plaintext structure.
 *
 * @param plaintext		A pointer to a fenc_plaintext struct.
 * @param buf			Pointer to a pointer to a byte buffer (this is set by the routine).
 * @param buf_size		Pointer to the buffer size in bytes (this is set by the routine).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	
libfenc_get_plaintext_bytes(fenc_plaintext *plaintext, uint8** buf, size_t *buf_size)
{
	if (plaintext == NULL) {
		return FENC_ERROR_INVALID_PLAINTEXT;
	}
	
	if (plaintext->data == NULL) {
		return FENC_ERROR_INVALID_PLAINTEXT;
	}
	
	*buf = plaintext->data;
	*buf_size = plaintext->data_len;
	
	return FENC_ERROR_NONE;
}

/*!
 * Clear a fenc_plaintext structure.
 *
 * @param plaintext		A pointer to a fenc_plaintext struct.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_plaintext_clear(fenc_plaintext *plaintext)
{
	if (plaintext == NULL) {
		return FENC_ERROR_INVALID_PLAINTEXT;
	}
	
	if (plaintext->data != NULL) {
		SAFE_FREE(plaintext->data);
	}
	memset(plaintext, 0, sizeof(fenc_plaintext));
	
	return FENC_ERROR_NONE;
}

/*!
 * Convert an error code into a string.
 *
 * @param global_params	The global parameters.
 * @return				FENC_ERROR_NONE or an error code.
 */

const char*
libfenc_error_to_string(FENC_ERROR error)
{
	switch(error) {
		case FENC_ERROR_NONE:
			return "No error";
			break;
		case FENC_ERROR_INVALID_CONTEXT:
			return "Invalid encryption context";
			break;
		case FENC_ERROR_INVALID_CIPHERTEXT:
			return "Invalid ciphertext";
			break;
		case FENC_ERROR_INVALID_GROUP_PARAMS:
			return "Invalid group parameters";
			break; 
		case FENC_ERROR_INVALID_GLOBAL_PARAMS:
			return "Invalid global parameters";
			break;
		case FENC_ERROR_INVALID_KEY:
			return "Invalid key";
			break;
		case FENC_ERROR_OUT_OF_MEMORY:
			return "Out of memory";
			break;
		case FENC_ERROR_INVALID_INPUT:
			return "Invalid function input";
			break;
		case FENC_ERROR_INVALID_PLAINTEXT:
			return "Invalid plaintext";
			break;
		case FENC_ERROR_UNKNOWN_SCHEME:
			return "Unknown scheme";
			break;
		case FENC_ERROR_LIBRARY_NOT_INITIALIZED:
			return "Library not initialized or shut down due to critical error";
			break;
		case FENC_ERROR_NO_SECRET_PARAMS:
			return "Secret parameters are not available";
			break;
		case FENC_ERROR_NO_PUBLIC_PARAMS:
			return "Public parameters (MPK) are not available";
			break;
		case FENC_ERROR_NOT_IMPLEMENTED:
			return "Functionality has not been implemented";
			break;
		case FENC_ERROR_BUFFER_TOO_SMALL:
			return "Buffer is too small for the requested operation";
			break;
		case FENC_ERROR_UNKNOWN:	
			return "Unknown error";
			break;
		default:
			return "Unrecognized error code";
			break;
	}
}
