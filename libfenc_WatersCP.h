/*!	\file libfenc_WatersCP.h
 *
 *	\brief Header file for the Waters CP scheme.
 *  
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#ifndef __LIBFENC_WATERSCP_H__
#define __LIBFENC_WATERSCP_H__

/*!
 *  Scheme-specific public parameters data structure.
 */

typedef struct _fenc_public_params_WatersCP {
	element_t gONE;
	element_t gTWO;
	element_t gaONE;
	element_t gaTWO;
	element_t eggalphaT;
	
} fenc_public_params_WatersCP;

/*!
 *  Scheme-specific group parameters parameters data structure.
 */

typedef struct _fenc_global_params_WatersCP {
	fenc_group_params	group_params;
	pairing_t			pairing;
} fenc_global_params_WatersCP;

/*!
 *  Scheme-specific secret parameters data structure.
 */

typedef struct _fenc_secret_params_WatersCP {

	element_t alphaZ;
	element_t aZ;
} fenc_secret_params_WatersCP;

/*!
 *  Scheme-specific context data structure.
 */

typedef struct _fenc_scheme_context_WatersCP {
	fenc_global_params_WatersCP	*global_params;
	fenc_public_params_WatersCP	public_params;
	fenc_secret_params_WatersCP	secret_params;
} fenc_scheme_context_WatersCP;

/*!
 *  Scheme-specific ciphertext data structure.
 */

typedef struct _fenc_ciphertext_WatersCP {
	FENC_CIPHERTEXT_TYPE	type;
	fenc_attribute_list		attribute_list;
	char					policy_str[MAX_POLICY_STR];
	size_t					kem_key_len;

	element_t				CT;
	element_t				CprimeONE;
	element_t				CONE[MAX_CIPHERTEXT_ATTRIBUTES];
	element_t				DTWO[MAX_CIPHERTEXT_ATTRIBUTES];
} fenc_ciphertext_WatersCP;

/*!
 *  Scheme-specific decryption key data structure.
 */

typedef struct _fenc_key_WatersCP {
	uint32					reference_count;
	
//	fenc_attribute_policy	*policy;
	fenc_attribute_list		attribute_list;
	uint32					num_components;
	element_t				KTWO;
	element_t				LTWO;
	element_t				KXONE[MAX_CIPHERTEXT_ATTRIBUTES];
} fenc_key_WatersCP;

/********************************************************************************
 * Main routines
 ********************************************************************************/

/*!
 * Initialize a Sahai-Waters context.  
 *
 * @param context		Pre-allocated buffer for the fenc_context data structure.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_create_context_WatersCP(fenc_context *context);

/*!
 * Generate public and secret parameters.
 *
 * @param context		The fenc_context data structure
 * @param global_params	Global params (scheme-specific).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_gen_params_WatersCP(fenc_context *context, fenc_global_params *global_params);

/*!
 * Load public and (optionally) secret parameters into the context.  All relevant global
 * parameters are embedded within the public_params data structure.
 *
 * @param context		The fenc_context data structure
 * @param public_params	Public scheme parameters.
 * @param secret_params	Secret scheme parameters (optional).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_set_params_WatersCP(fenc_context *context, fenc_public_params *public_params, fenc_secret_params *secret_params);

/*!
 * Extract a secret key representing a given function input.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input from which this key will be built.
 * @param key			A pre-allocated buffer for the resulting key
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_extract_key_WatersCP(fenc_context *context, fenc_function_input *input, fenc_key *key);

/*!
 * Encrypt a plaintext under a given function input.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input under which which the ciphertext will be encrypted.
 * @param plaintext		The plaintext message.
 * @param ciphertext	A pre-allocated buffer for the returned fenc_ciphertext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_encrypt_WatersCP(fenc_context *context, fenc_function_input *input, fenc_plaintext *plaintext,
							fenc_ciphertext *ciphertext);

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

FENC_ERROR	libfenc_kem_encrypt_WatersCP(fenc_context *context, fenc_function_input *input, size_t key_len,
								uint8* key, fenc_ciphertext *ciphertext);


/*!
 * Decrypt a ciphertext using a specified secret key.
 *
 * @param context		The fenc_context data structure
 * @param ciphertext	The ciphertext to decrypt.
 * @param key			The secret key to use.
 * @param plaintext		A pre-allocated buffer for the resulting plaintext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_decrypt_WatersCP(fenc_context *context, fenc_ciphertext *ciphertext, fenc_key *key,
							fenc_plaintext *plaintext);

/*!
 *	For demo purposes only.
 */
FENC_ERROR
libfenc_retrieve_attribute_policy(fenc_context *context, fenc_ciphertext *ciphertext, uint8 *buffer, size_t buf_len);

/*!
 * Export the public parameters (MPK) to a binary buffer.  Calling this function with buffer 
 * set to NULL will return the length of the exported material.
 *
 * @param context		The fenc_context data structure
 * @param buffer		A pre-allocated buffer for the resulting export.
 * @param buf_len		The maximum allocated size of the buffer (in bytes).
 * @param result_len	The size of the resulting export (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_export_public_params_WatersCP(fenc_context *context, uint8 *buffer, size_t buf_len, size_t *result_len);

/*!
 * Export a context's secret parameters (MSK) to a binary buffer.  Calling this function with buffer 
 * set to NULL will return the length of the exported material.
 *
 * @param context		The fenc_context data structure
 * @param buffer		A pre-allocated buffer for the resulting export.
 * @param buf_len		The maximum allocated size of the buffer (in bytes).
 * @param result_len	The size of the resulting export (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_export_secret_params_WatersCP(fenc_context *context, uint8 *buffer, size_t buf_len, size_t *result_len);

/*!
 * Import the public parameters (MPK) from a binary buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param max_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_import_public_params_WatersCP(fenc_context *context, uint8 *buffer, size_t buf_len, fenc_global_params *global_params);

/*!
 * Import the secret parameters (MPK) from a binary buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param max_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_import_secret_params_WatersCP(fenc_context *context, uint8 *buffer, size_t buf_len);

/*!
 * Import the global parameters (MPK) from a binary buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param max_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_import_global_params_WatersCP(fenc_context *context, uint8 *buffer, size_t buf_len);

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

FENC_ERROR	libfenc_export_global_params_WatersCP(fenc_context *context, uint8 *buffer, size_t max_len, size_t *result_len);

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
FENC_ERROR  libfenc_export_secret_key_WatersCP(fenc_context *context, fenc_key *key, uint8 *buffer, size_t buf_len, size_t *result_len);

/*!
 * Deserialize an ABE key structure.
 *
 * @param context		The fenc_context data structure
 * @param key			The fenc_key data structure (pre-allocated).
 * @param buffer		The buffer which contains the binary contents of key?
 * @param buf_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR  libfenc_import_secret_key_WatersCP(fenc_context *context, fenc_key *key, uint8 *buffer, size_t buf_len);


/**************************************************************************************
 * Utility functions
 **************************************************************************************/

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

FENC_ERROR	encrypt_WatersCP_internal(fenc_context *context, fenc_function_input *input, fenc_plaintext *plaintext,
					 Bool kem_mode, uint8* kem_key_buf, size_t kem_key_len, fenc_ciphertext *ciphertext);

/*!
 * Destroy the internal contents of a fenc_context structure.  The caller is responsible for
 * de-allocating the context buffer itself.
 *
 * @param context		The fenc_context data structure.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_destroy_context_WatersCP(fenc_context *context);

/*!
 * Destroy the internal contents of a fenc_context structure.  The caller is responsible for
 * de-allocating the context buffer itself.
 *
 * @param global_params	The global parameters.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_destroy_global_params_WatersCP(fenc_global_params *global_params);

/*!
 * Validate a set of global parameters for the LSW scheme.
 *
 * @param global_params	The global parameters.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR libfenc_validate_global_params_WatersCP(fenc_global_params *global_params);

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

FENC_ERROR	libfenc_serialize_key_WatersCP(fenc_key_WatersCP *key, unsigned char *buffer, size_t max_len, size_t *serialized_len);

/*!
 * Deserialize a decryption key from a binary buffer.  Accepts an LSW key, buffer, and buffer length.
 * If the buffer is large enough, the serialized result is written to the buffer and returns the
 * length in "serialized_len".  Calling with a NULL buffer returns the length /only/ but does
 * not actually serialize the structure.
 *
 * @param key				The key to serialize.
 * @param buffer			Pointer to a buffer, or NULL to get the length only.
 * @param buf_len			The maximum size of the buffer (in bytes).
 * @param serialized_len	Total size of the serialized structure (in bytes).
 * @return					FENC_ERROR_NONE or FENC_ERROR_BUFFER_TOO_SMALL.
 */

FENC_ERROR	libfenc_deserialize_key_WatersCP(fenc_key_WatersCP *key, unsigned char *buffer, size_t buf_len);

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

FENC_ERROR libfenc_serialize_ciphertext_WatersCP(fenc_ciphertext_WatersCP *ciphertext, unsigned char *buffer, size_t max_len, size_t *serialized_len);

/*!
 * Deserialize a ciphertext from a binary buffer.  Accepts a buffer and buffer length and
 * transcribes the result into an LSW ciphertext data structure.  
 *
 * Note: this routine uses deserialization functionality from the PBC library; this could
 * fail catastrophically when given an invalid ciphertext.
 *
 * @param buffer			Pointer to a buffer from which to deserialize.
 * @param buf_len			The size of the buffer (in bytes).
 * @param ciphertext		The fenc_ciphertext_WatersCP structure.
 * @param scheme_context	The scheme context which contains the group parameters.
 * @return					FENC_ERROR_NONE or FENC_ERROR_BUFFER_TOO_SMALL.
 */

FENC_ERROR libfenc_deserialize_ciphertext_WatersCP(unsigned char *buffer, size_t buf_len, fenc_ciphertext_WatersCP *ciphertext, fenc_scheme_context_WatersCP *scheme_context);

/*!
 * Utility function to allocate the internals of a fenc_ciphertext_WatersCP structure.  
 *
 * @param ciphertext		Pointer to fenc_ciphertext_WatersCP struct.
 * @param num_attributes	Number of attributes.
 * @param scheme_context	Pointer to a fenc_scheme_context_WatersCP struct.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_ciphertext_WatersCP_initialize(fenc_ciphertext_WatersCP *ciphertext, fenc_attribute_list *attribute_list, fenc_attribute_policy* policy, FENC_CIPHERTEXT_TYPE type,
									fenc_scheme_context_WatersCP *scheme_context);

/*!
 * Utility function to release the internals of a fenc_ciphertext_WatersCP structure.  
 *
 * @param ciphertext		Pointer to fenc_ciphertext_WatersCP struct.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR fenc_ciphertext_WatersCP_clear(fenc_ciphertext_WatersCP *ciphertext);

/*!
 * Initialize and allocate a fenc_global_params_WatersCP structure.
 *
 * @param	group_params		A fenc_group_params structure.
 * @param	global_params		An allocated fenc_global_params_WatersCP or NULL if one should be allocated.
 * @return	An allocated fenc_global_params_WatersCP structure.
 */

fenc_global_params_WatersCP*	initialize_global_params_WatersCP(fenc_group_params *group_params, fenc_global_params_WatersCP *global_params);

/*!
 * Allocates and initializes a fenc_key_WatersCP structure.
 *
 * @param key_WatersCP			The fenc_key_WatersCP structure.
 * @param attribute_list	Pointer to a fenc_attribute_list structure.
 * @param policy			Pointer to a fenc_policy structure (the internals are /not/ duplicated).
 * @param copy_attr_list	If set to TRUE, duplicates the internals of the attribute list (original can be cleared).
 * @param global_params		Pointer to the group params (necessary for allocating internal elements).
 * @return					The fenc_key_WatersCP structure or NULL.
 */

fenc_key_WatersCP*
fenc_key_WatersCP_initialize(fenc_attribute_list *attribute_list, Bool copy_attr_list, 
				   fenc_global_params_WatersCP *global_params);

/*!
 * Clear the internals of a fenc_key_WatersCP structure.
 *
 * @param key_WatersCP			The fenc_key_WatersCP structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_key_WatersCP_clear(fenc_key_WatersCP *key_WatersCP);

/*!
 * Initialize a fenc_public_params_WatersCP structure.  This requires initializing
 * a series of group element structures.
 *
 * @param params			Pointer to a fenc_public_params_WatersCP data structure.
 * @param pairing			Pairing structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	public_params_initialize_WatersCP(fenc_public_params_WatersCP *params, pairing_t pairing);

/*!
 * Initialize a fenc_secret_params_WatersCP structure.  This requires initializing
 * a series of group element structures.
 *
 * @param params			Pointer to a fenc_secret_params_WatersCP data structure.
 * @param pairing			Pairing structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	secret_params_initialize_WatersCP(fenc_secret_params_WatersCP *params, pairing_t pairing);

/*!
 * Print a ciphertext to a file as ASCII.
 *
 * @param ciphertext		The ciphertext to serialize.
 * @param out_file			The file to write to.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_fprint_ciphertext_WatersCP(fenc_ciphertext_WatersCP *ciphertext, FILE* out_file);

#endif /* ifndef __LIBFENC_WATERSCP_H__ */