/*!	\file libfenc_KSFCP.h
 *
 *	\brief Header file for the Waters CP scheme.
 *
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#ifndef __LIBFENC_KSFCP_H__
#define __LIBFENC_KSFCP_H__

/*!
 *  Scheme-specific public parameters data structure.
 */

typedef struct _fenc_public_params_KSFCP {
	element_t gONE;
	element_t gTWO;
	element_t gaONE;
	element_t gaTWO;
	element_t eggalphaT;

	/* for KSF */
	element_t eggbetaT;
	element_t hTWO;
	element_t ggammaONE;

} fenc_public_params_KSFCP;

/*!
 *  Scheme-specific group parameters parameters data structure.
 */

typedef struct _fenc_global_params_KSFCP {
	fenc_group_params	group_params;
	pairing_t			pairing;
} fenc_global_params_KSFCP;

/*!
 *  Scheme-specific secret parameters data structure.
 */

typedef struct _fenc_secret_params_KSFCP {

	element_t alphaZ;
	element_t aZ;

	/* for KSF */
	element_t betaZ;
	element_t gammaZ;
} fenc_secret_params_KSFCP;

/*!
 *  Scheme-specific context data structure.
 */

typedef struct _fenc_scheme_context_KSFCP {
	fenc_global_params_KSFCP	*global_params;
	fenc_public_params_KSFCP	public_params;
	fenc_secret_params_KSFCP	secret_params;

	/* for KSF */
	element_t 					sZ; /* Encrypt secret s */
} fenc_scheme_context_KSFCP;

/*!
 *  Scheme-specific ciphertext data structure.
 */

typedef struct _fenc_ciphertext_KSFCP {
	FENC_CIPHERTEXT_TYPE	type;
	fenc_attribute_list		attribute_list;
	char					policy_str[MAX_POLICY_STR];
	size_t					kem_key_len;

	element_t				CT;
	element_t				CprimeONE;
	element_t				CONE[MAX_CIPHERTEXT_ATTRIBUTES];
	element_t				DTWO[MAX_CIPHERTEXT_ATTRIBUTES];

	/* for KSF */
	element_t				CgammaONE;
} fenc_ciphertext_KSFCP;

/* for KSF */
typedef struct _fenc_index_KSFCP {
	uint32					num_components;
    element_t				HKeggT[MAX_INDEX_KEYWORDS];
} fenc_index_KSFCP;

/* for KSF */
typedef struct _fenc_index_HK_KSFCP {
	uint32					len;
    uint8					*buffer;
} fenc_index_HK_KSFCP;

/*!
 *  Scheme-specific decryption key data structure.
 */

typedef struct _fenc_key_KSFCP {
	uint32					reference_count;
	fenc_attribute_list		attribute_list;
	uint32					num_components;
	element_t				KTWO;
	element_t				LTWO;
	element_t				KXONE[MAX_CIPHERTEXT_ATTRIBUTES];
} fenc_key_KSFCP;

/* for KSF */
typedef struct _fenc_KSF_key_KSFCP {
	element_t				KgammaTWO;
	element_t				KbetaTWO;
} fenc_KSF_key_KSFCP;

/* for KSF */
typedef struct _fenc_USK_KSFCP {
	element_t				uZ;
} fenc_USK_KSFCP;

/* for KSF */
typedef struct _fenc_UPK_KSFCP {
	element_t				gu_1TWO;
} fenc_UPK_KSFCP;

/* for KSF */
typedef struct _fenc_trapdoor_KSFCP {
	uint32					reference_count;
	fenc_attribute_list		attribute_list;
	uint32					num_components;
	element_t				TgammaTWO;
	element_t				TbetaTWO;
	element_t				LprimeTWO;
	element_t				TTWO;
	element_t				KXprimeONE[MAX_CIPHERTEXT_ATTRIBUTES];
} fenc_trapdoor_KSFCP;

/* for KSF */
typedef struct _fenc_Q_KSFCP {
	element_t				QeggT;
} fenc_Q_KSFCP;

/********************************************************************************
 * Main routines
 ********************************************************************************/

/*!
 * Initialize a Sahai-Waters context.
 *
 * @param context		Pre-allocated buffer for the fenc_context data structure.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_create_context_KSFCP(fenc_context *context);

/*!
 * Generate public and secret parameters.
 *
 * @param context		The fenc_context data structure
 * @param global_params	Global params (scheme-specific).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_gen_params_KSFCP(fenc_context *context, fenc_global_params *global_params);

/*!
 * Load public and (optionally) secret parameters into the context.  All relevant global
 * parameters are embedded within the public_params data structure.
 *
 * @param context		The fenc_context data structure
 * @param public_params	Public scheme parameters.
 * @param secret_params	Secret scheme parameters (optional).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_set_params_KSFCP(fenc_context *context, fenc_public_params *public_params, fenc_secret_params *secret_params);

/*!
 * Extract a secret key representing a given function input.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input from which this key will be built.
 * @param key			A pre-allocated buffer for the resulting key
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_extract_key_KSFCP(fenc_context *context, fenc_function_input *input, fenc_key *key);

/*!
 * Encrypt a plaintext under a given function input.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input under which which the ciphertext will be encrypted.
 * @param plaintext		The plaintext message.
 * @param ciphertext	A pre-allocated buffer for the returned fenc_ciphertext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_encrypt_KSFCP(fenc_context *context, fenc_function_input *input, fenc_plaintext *plaintext,
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

FENC_ERROR	libfenc_kem_encrypt_KSFCP(fenc_context *context, fenc_function_input *input, size_t key_len,
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

FENC_ERROR	libfenc_decrypt_KSFCP(fenc_context *context, fenc_ciphertext *ciphertext, fenc_key *key,
							fenc_plaintext *plaintext);

/*!
 *	For demo purposes only.
 */
FENC_ERROR
libfenc_retrieve_attribute_policy_KSFCP(fenc_context *context, fenc_ciphertext *ciphertext, uint8 *buffer, size_t buf_len);

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

FENC_ERROR	libfenc_export_public_params_KSFCP(fenc_context *context, uint8 *buffer, size_t buf_len, size_t *result_len);

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

FENC_ERROR	libfenc_export_secret_params_KSFCP(fenc_context *context, uint8 *buffer, size_t buf_len, size_t *result_len);

/*!
 * Import the public parameters (MPK) from a binary buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param max_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_import_public_params_KSFCP(fenc_context *context, uint8 *buffer, size_t buf_len, fenc_global_params *global_params);

/*!
 * Import the secret parameters (MPK) from a binary buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param max_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_import_secret_params_KSFCP(fenc_context *context, uint8 *buffer, size_t buf_len);

/*!
 * Import the global parameters (MPK) from a binary buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param max_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_import_global_params_KSFCP(fenc_context *context, uint8 *buffer, size_t buf_len);

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

FENC_ERROR	libfenc_export_global_params_KSFCP(fenc_context *context, uint8 *buffer, size_t max_len, size_t *result_len);

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
FENC_ERROR  libfenc_export_secret_key_KSFCP(fenc_context *context, fenc_key *key, uint8 *buffer, size_t buf_len, size_t *result_len);

/*!
 * Deserialize an ABE key structure.
 *
 * @param context		The fenc_context data structure
 * @param key			The fenc_key data structure (pre-allocated).
 * @param buffer		The buffer which contains the binary contents of key?
 * @param buf_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR  libfenc_import_secret_key_KSFCP(fenc_context *context, fenc_key *key, uint8 *buffer, size_t buf_len);


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

FENC_ERROR	encrypt_KSFCP_internal(fenc_context *context, fenc_function_input *input, fenc_plaintext *plaintext,
					 Bool kem_mode, uint8* kem_key_buf, size_t kem_key_len, fenc_ciphertext *ciphertext);

/*!
 * Destroy the internal contents of a fenc_context structure.  The caller is responsible for
 * de-allocating the context buffer itself.
 *
 * @param context		The fenc_context data structure.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_destroy_context_KSFCP(fenc_context *context);

/*!
 * Destroy the internal contents of a fenc_context structure.  The caller is responsible for
 * de-allocating the context buffer itself.
 *
 * @param global_params	The global parameters.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_destroy_global_params_KSFCP(fenc_global_params *global_params);

/*!
 * Validate a set of global parameters for the LSW scheme.
 *
 * @param global_params	The global parameters.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR libfenc_validate_global_params_KSFCP(fenc_global_params *global_params);

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

FENC_ERROR	libfenc_serialize_key_KSFCP(fenc_key_KSFCP *key, unsigned char *buffer, size_t max_len, size_t *serialized_len);

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

FENC_ERROR	libfenc_deserialize_key_KSFCP(fenc_key_KSFCP *key, unsigned char *buffer, size_t buf_len);

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

FENC_ERROR libfenc_serialize_ciphertext_KSFCP(fenc_ciphertext_KSFCP *ciphertext, unsigned char *buffer, size_t max_len, size_t *serialized_len);

/*!
 * Deserialize a ciphertext from a binary buffer.  Accepts a buffer and buffer length and
 * transcribes the result into an LSW ciphertext data structure.
 *
 * Note: this routine uses deserialization functionality from the PBC library; this could
 * fail catastrophically when given an invalid ciphertext.
 *
 * @param buffer			Pointer to a buffer from which to deserialize.
 * @param buf_len			The size of the buffer (in bytes).
 * @param ciphertext		The fenc_ciphertext_KSFCP structure.
 * @param scheme_context	The scheme context which contains the group parameters.
 * @return					FENC_ERROR_NONE or FENC_ERROR_BUFFER_TOO_SMALL.
 */

FENC_ERROR libfenc_deserialize_ciphertext_KSFCP(unsigned char *buffer, size_t buf_len, fenc_ciphertext_KSFCP *ciphertext, fenc_scheme_context_KSFCP *scheme_context);

/*!
 * Utility function to allocate the internals of a fenc_ciphertext_KSFCP structure.
 *
 * @param ciphertext		Pointer to fenc_ciphertext_KSFCP struct.
 * @param num_attributes	Number of attributes.
 * @param scheme_context	Pointer to a fenc_scheme_context_KSFCP struct.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_ciphertext_KSFCP_initialize(fenc_ciphertext_KSFCP *ciphertext, fenc_attribute_list *attribute_list, fenc_attribute_policy* policy, FENC_CIPHERTEXT_TYPE type,
									fenc_scheme_context_KSFCP *scheme_context);

/*!
 * Utility function to release the internals of a fenc_ciphertext_KSFCP structure.
 *
 * @param ciphertext		Pointer to fenc_ciphertext_KSFCP struct.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR fenc_ciphertext_KSFCP_clear(fenc_ciphertext_KSFCP *ciphertext);

/*!
 * Initialize and allocate a fenc_global_params_KSFCP structure.
 *
 * @param	group_params		A fenc_group_params structure.
 * @param	global_params		An allocated fenc_global_params_KSFCP or NULL if one should be allocated.
 * @return	An allocated fenc_global_params_KSFCP structure.
 */

fenc_global_params_KSFCP*	initialize_global_params_KSFCP(fenc_group_params *group_params, fenc_global_params_KSFCP *global_params);

/*!
 * Allocates and initializes a fenc_key_KSFCP structure.
 *
 * @param key_KSFCP			The fenc_key_KSFCP structure.
 * @param attribute_list	Pointer to a fenc_attribute_list structure.
 * @param policy			Pointer to a fenc_policy structure (the internals are /not/ duplicated).
 * @param copy_attr_list	If set to TRUE, duplicates the internals of the attribute list (original can be cleared).
 * @param global_params		Pointer to the group params (necessary for allocating internal elements).
 * @return					The fenc_key_KSFCP structure or NULL.
 */

fenc_key_KSFCP*
fenc_key_KSFCP_initialize(fenc_attribute_list *attribute_list, Bool copy_attr_list,
				   fenc_global_params_KSFCP *global_params);

/*!
 * Clear the internals of a fenc_key_KSFCP structure.
 *
 * @param key_KSFCP			The fenc_key_KSFCP structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_key_KSFCP_clear(fenc_key_KSFCP *key_KSFCP);

/*!
 * Initialize a fenc_public_params_KSFCP structure.  This requires initializing
 * a series of group element structures.
 *
 * @param params			Pointer to a fenc_public_params_KSFCP data structure.
 * @param pairing			Pairing structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	public_params_initialize_KSFCP(fenc_public_params_KSFCP *params, pairing_t pairing);

/*!
 * Initialize a fenc_secret_params_KSFCP structure.  This requires initializing
 * a series of group element structures.
 *
 * @param params			Pointer to a fenc_secret_params_KSFCP data structure.
 * @param pairing			Pairing structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	secret_params_initialize_KSFCP(fenc_secret_params_KSFCP *params, pairing_t pairing);

/*!
 * Print a ciphertext to a file as ASCII.
 *
 * @param ciphertext		The ciphertext to serialize.
 * @param out_file			The file to write to.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_fprint_ciphertext_KSFCP(fenc_ciphertext_KSFCP *ciphertext, FILE* out_file);


/* for KSF */
FENC_ERROR
libfenc_gen_ukey_KSFCP(fenc_context *context, fenc_USK_KSFCP *usk, fenc_UPK_KSFCP *upk);

FENC_ERROR
libfenc_import_usk_KSFCP(fenc_context *context, fenc_USK_KSFCP *usk, uint8 *buffer, size_t buf_len);

FENC_ERROR
libfenc_import_upk_KSFCP(fenc_context *context, fenc_UPK_KSFCP *upk, uint8 *buffer, size_t buf_len);

FENC_ERROR
libfenc_export_usk_KSFCP(fenc_context *context, fenc_USK_KSFCP *usk, uint8 *buffer, size_t buf_len, size_t *result_len);

FENC_ERROR
libfenc_export_upk_KSFCP(fenc_context *context, fenc_UPK_KSFCP *upk, uint8 *buffer, size_t buf_len, size_t *result_len);

FENC_ERROR
libfenc_extract_ksfkey_KSFCP(fenc_context *context, fenc_KSF_key_KSFCP *ksfkey, fenc_key *key, fenc_UPK_KSFCP *upk);

FENC_ERROR
libfenc_import_ksfkey_KSFCP(fenc_context *context, fenc_KSF_key_KSFCP *ksfkey, uint8 *buffer, size_t buf_len);

FENC_ERROR
libfenc_export_ksfkey_KSFCP(fenc_context *context, fenc_KSF_key_KSFCP *ksfkey, uint8 *buffer, size_t buf_len, size_t *result_len);

FENC_ERROR
libfenc_gen_trapdoor_KSFCP(fenc_context *context, fenc_key *key, fenc_KSF_key_KSFCP *ksfkey, fenc_USK_KSFCP *usk, char *keyword, fenc_trapdoor_KSFCP *trapdoor);

FENC_ERROR
fenc_trapdoor_KSFCP_initialize(fenc_trapdoor_KSFCP *trapdoor, fenc_attribute_list *attribute_list, fenc_global_params_KSFCP *global_params);

FENC_ERROR
libfenc_import_trapdoor_KSFCP(fenc_context *context, fenc_trapdoor_KSFCP *trapdoor, uint8 *buffer, size_t buf_len);

FENC_ERROR
libfenc_export_trapdoor_KSFCP(fenc_context *context, fenc_trapdoor_KSFCP *trapdoor, uint8 *buffer, size_t buf_len, size_t *export_result_len);

FENC_ERROR
libfenc_build_index_KSFCP(fenc_context *context, char keywords[][KEYWORD_SIZE], size_t num_keywords, fenc_index_KSFCP *index);

FENC_ERROR
libfenc_export_index_KSFCP(fenc_context *context, fenc_index_KSFCP *index, fenc_index_HK_KSFCP *hk_buffer);

/* Search decryptable CT */
FENC_ERROR
libfenc_match_KSFCP(fenc_context *context, fenc_ciphertext *ciphertext, fenc_trapdoor_KSFCP *trapdoor, fenc_Q_KSFCP *Q);

FENC_ERROR
libfenc_import_Q_KSFCP(fenc_context *context, fenc_Q_KSFCP *Q, uint8 *buffer, size_t buf_len);

FENC_ERROR
libfenc_export_Q_KSFCP(fenc_context *context, fenc_Q_KSFCP *Q, uint8 *buffer, size_t buf_len, size_t *result_len);

#endif /* ifndef __LIBFENC_KSFCP_H__ */
