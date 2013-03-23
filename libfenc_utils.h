/*!	\file libfenc_utils.h
 *
 *	\brief Utility routines shared among the schemes in the Functional Encryption Library.
 *  
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#ifndef __LIBFENC_UTILS_H__
#define __LIBFENC_UTILS_H__

#define EXPORT_INT32(dest_buf, src_int)  *((uint32*)dest_buf) = src_int
#define IMPORT_INT32(dest_int, src_buf)  dest_int = *((uint32*)src_buf)

/* Index numbers for different hash functions.  These are all implemented as SHA1(index || message).	*/
#define HASH_FUNCTION_STR_TO_Zr_CRH		0
#define HASH_FUNCTION_Zr_TO_G1_ROM		1
#define HASH_FUNCTION_KEM_DERIVE		2

#define HASH_TARGET_LEN	20					/* We hardcode a 20-byte hash (SHA1) throughout the library */

/*!
 * Import a collection of parameters from a buffer.
 *
 * @param buffer		A pointer to the buffer.
 * @param buf_len		Length of the buffer (in bytes).
 * @param imported_len	Pointer to an optional return value specifying num bytes read (can be set to NULL)
 * @param fmt			A format string containing %E, %C, %s, %d (elements, compressed elements, strings and ints)
 * @param ...			Variable-length argument list containing values for the import.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	import_components_from_buffer(uint8* buffer, size_t buf_len, size_t *imported_len, char* fmt, ...);

/*!
 * Export a collection of parameters to a buffer.
 *
 * @param buffer		A pointer to the buffer.
 * @param max_len		Maximum size of the buffer (in bytes).
 * @param result_len	Pointer to the resulting size of the serialized data.
 * @param ...			Variable-length argument list containing values for the import.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	export_components_to_buffer(uint8* buffer, size_t max_len, size_t *result_len, char* fmt, ...);

/*!
 * Encode a plaintext as an element of GT.
 *
 * @param plaintext		A fenc_plaintext structure.
 * @param plaintextT	A pre-initialized element_t structure into which we encode the plaintext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	encode_plaintext_GT(fenc_plaintext* plaintext, element_t *plaintextT, pairing_t pairing);

/*!
 * Decode a plaintext from an element of GT.
 *
 * @param plaintext		A fenc_plaintext structure.
 * @param plaintextT	An element_t structure containing the plaintext element.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	decode_plaintext_GT(fenc_plaintext* plaintext, element_t *plaintextT, pairing_t pairing);

/*!
 * Derives a session key from a group element, placing the result into a fenc_plaintext
 * structure.
 *
 * @param plaintext		A fenc_plaintext structure.
 * @param element		An element_t containing the group element.
 * @param key_bytes		Number of bytes to derive.
 * @param pairing		Pairing structure.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	derive_session_key_from_element(fenc_plaintext *plaintext, element_t element, size_t key_bytes, pairing_t pairing);

/*!
 * Derive a symmetric key (bitstring) from a group element.
 *
 * @param plaintext		A fenc_plaintext structure.
 * @param plaintextT	A pre-initialized element_t structure into which we encode the plaintext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_derive_key_from_element(element_t element, size_t key_bytes, uint8 *key_buf);

/*!
 * Hash a null-terminated string to a byte array.
 *
 * @param input_buf		The input buffer.
 * @param input_len		The input buffer length (in bytes).
 * @param hash_len		Desired length of the output hash (in bytes).
 * @param output_buf	A pre-allocated output buffer.
 * @param hash_num		Index number of the hash function to use (changes the output).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	hash_to_bytes(uint8 *input_buf, int input_len, int hash_size, unsigned char* output_buf, uint32 hash_num);

/*!
 * Hash a group element to a byte array.  This calls hash_to_bytes().
 *
 * @param element		The input element.
 * @param hash_len		Desired length of the output hash (in bytes).
 * @param output_buf	A pre-allocated output buffer.
 * @param hash_num		Index number of the hash function to use (changes the output).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	hash_element_to_bytes(element_t *element, int hash_size, unsigned char* output_buf, uint32 hash_num);

/*!
 * Encrypt a buffer with a user-supplied passphrase.  The encryption is in-place, and the
 * resulting ciphertext is returned in the supplied buffer.  When buffer is NULL, this routine
 * will simply calculate the necessary buffer length and return it in result_len.
 *
 * @param buffer		The input buffer to be encrypted, also holds the resulting encryption.
 * @param buf_max		The maximum size of the supplied buffer.
 * @param data_len		Pointer to the data length; this is updated on return.
 * @param password		A buffer containing the passphrase.
 * @param password_len	Passphrase length in bytes.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_encrypt_with_password(uint8 *buffer, size_t buf_max, size_t *data_len, uint8 *password, 
									   size_t password_len);

/*!
 * Decrypt a buffer with a user-supplied passphrase.  The decryption is in-place, and the
 * resulting ciphertext is returned in the supplied buffer.  When buffer is NULL, this routine
 * will simply calculate the necessary buffer length and return it in result_len.
 *
 * @param buffer		The input buffer to be encrypted, also holds the resulting encryption.
 * @param data_len		Pointer to the data length; this is updated on return.
 * @param password		A buffer containing the passphrase.
 * @param password_len	Passphrase length in bytes.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_decrypt_with_password(uint8 *buffer, size_t data_len, size_t *result_len, uint8 *password, 
						   size_t password_len);

#endif /* ifdef __LIBFENC_UTILS_H__ */
