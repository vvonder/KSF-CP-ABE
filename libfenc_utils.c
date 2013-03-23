/*!	\file libfenc_utils.c
 *
 *	\brief Utility routines shared across many different schemes.
 *  
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pbc/pbc.h>
#include "libfenc.h"
#include "libfenc_group_params.h"
#include "libfenc_ABE_common.h"
#include "libfenc_utils.h"
#include "sha1.h"

/********************************************************************************
 * Utilities
 ********************************************************************************/

void printf_buffer_as_hex(uint8* data, size_t len);

void printf_buffer_as_hex(uint8* data, size_t len)
{
	size_t i;
	
	for (i = 0; i < len; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n");
}

/*!
 * Import a collection of parameters from a buffer.
 *
 * @param buffer		A pointer to the buffer.
 * @param buf_len		Length of the buffer (in bytes).
 * @param ...			Variable-length argument list containing values for the import.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
import_components_from_buffer(uint8* buffer, size_t buf_len, size_t *imported_len, char* fmt, ...)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	va_list comp_list;
	uint32 deserialized_len = 0;
	fenc_attribute_list *attr_list = NULL;
	fenc_attribute_policy *pol_tree = NULL;
	char *attrs;
	size_t len;
	int32 temp_int;
	uint8* buf_ptr;
	char* fmt_ptr; 
	element_t *elt;
	
	/* Iterate through the variable-length argument list.	*/
	va_start(comp_list, fmt);
	
	for(fmt_ptr = fmt; *fmt_ptr != '\0'; fmt_ptr++)	{
		if(*fmt_ptr != '%')	{
			continue;
		}

		buf_ptr = (uint8*)(buffer + deserialized_len);
		switch(*++fmt_ptr)	{
			case 'E':
				/* Uncompressed element.	*/
				elt = va_arg(comp_list, element_t*);
				deserialized_len += element_from_bytes(*elt, buf_ptr);
				break;
				
			case 'C':
				/* Compressed element.		*/
				elt = va_arg(comp_list, element_t*);
				deserialized_len += element_from_bytes_compressed(*elt, buf_ptr);
				break;
				
			case 's':
				strcpy(va_arg(comp_list, char *), (const char *) buf_ptr);
				deserialized_len += strlen((char *)buf_ptr) + 1;
				break;
				
			case 'd':
				IMPORT_INT32(temp_int, buf_ptr);
				*(va_arg(comp_list, int32*)) = temp_int;
				deserialized_len += sizeof(int32);
				break;
			case 'A':
				len = strlen((char *)buf_ptr); /* assume attribute list is NULL terminated */
				attrs = SAFE_MALLOC(len+1);
				memset(attrs, 0, len+1);
				strncpy(attrs, (const char *) buf_ptr, len);
				// printf("Raw list: '%s'\n", attrs);
				deserialized_len += len + 1;
				
				attr_list =  va_arg(comp_list, fenc_attribute_list*);
				/* tokenize the string and place in attribute_list */
				fenc_buffer_to_attribute_list(&attrs, attr_list);
				free(attrs);
				break;
			case 'P':
				len = strlen((char *) buf_ptr); /* assume policy is NULL terminated */
				pol_tree = va_arg(comp_list, fenc_attribute_policy *); /* get the users ptr to fenc_attribute_policy */
				fenc_policy_from_string(pol_tree, (char *) buf_ptr); /* store policy into given policy structure */
				deserialized_len += len + 1;	/* increment pointer to next component */
				break;
			default:
				/* Unrecognized symbol.	*/
				result = FENC_ERROR_INVALID_INPUT;
				break;
		}
		
		if (deserialized_len > buf_len) {
			/* Return the length we read.	*/
			if (imported_len != NULL) {
				*imported_len = deserialized_len;
			}
			
			return FENC_ERROR_BUFFER_TOO_SMALL;
		}
	}
	
	va_end(comp_list);

	/* Return the length we read.	*/
	if (imported_len != NULL) {
		*imported_len = deserialized_len;
	}
	
	return result;
}

/*!
 * Export a collection of parameters to a buffer.
 *
 * @param buffer		A pointer to the buffer.
 * @param max_len		Maximum size of the buffer (in bytes).
 * @param result_len	Pointer to the resulting size of the serialized data.
 * @param ...			Variable-length argument list containing values for the import.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
export_components_to_buffer(uint8* buffer, size_t max_len, size_t *result_len, char* fmt, ...)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	va_list comp_list;
	uint8* buf_ptr = buffer;

	char* fmt_ptr;
	element_t *elt;
	fenc_attribute_policy *policy;
	fenc_attribute_list *attribute_list;
	size_t i_index=0, tmp_len=0;
	
	*result_len = 0;

	/* Iterate through the variable-length argument list.	*/
	va_start(comp_list, fmt);
	
	for(fmt_ptr = fmt; *fmt_ptr != '\0'; fmt_ptr++)	{
		if(*fmt_ptr != '%')	{
			continue;
		}
		
		/* Point buf_ptr to the correct offset, unless the buffer is NULL.	*/
		if (buffer != NULL) {
			buf_ptr = (uint8*)(buffer + *result_len);
		}
		
		switch(*++fmt_ptr)	{
			case 'E':
				/* Uncompressed element.	*/
				elt = va_arg(comp_list, element_t*);
				*result_len += element_length_in_bytes(*elt);
				if (buffer != NULL && *result_len <= max_len) {
					element_to_bytes(buf_ptr, *elt);
				}
				break;
				
			case 'C':
				/* Compressed element.		*/
				elt = va_arg(comp_list, element_t*);
				tmp_len = element_length_in_bytes_compressed(*elt);
				*result_len += tmp_len;
				if (buffer != NULL && *result_len < max_len) {
					element_to_bytes_compressed(buf_ptr, *elt);
				}
				// printf("len of C = '%zu'\n", *result_len);
				// printf_buffer_as_hex(buf_ptr, tmp_len);
				break;
				
			case 'P':
				policy = va_arg(comp_list, fenc_attribute_policy*);
				result = fenc_attribute_policy_to_string(policy->root, (char *)buf_ptr, (max_len - *result_len));
				i_index = strchr((char *) buf_ptr, 0) - (char *) buf_ptr;
				*result_len += i_index + 1;
				// printf("policy_root: '%s', strlen: '%d', index: '%d'\n", (char *) buf_ptr, strlen((char *) buf_ptr), i_index);
				break;
				
			case 'A':
				attribute_list = va_arg(comp_list, fenc_attribute_list*);
				fenc_attribute_list_to_buffer(attribute_list, buf_ptr, (max_len - *result_len), &i_index);
				*result_len += i_index + 1;
				// printf("attribute_list: '%s'\n\tlength: '%zu'\n", (char *)buf_ptr, strlen((char *)buf_ptr));
				break;
				
			case 's':
				*result_len += strlen(va_arg(comp_list, char *)) + 1;
				if (buffer != NULL && *result_len <= max_len) {
					strcpy((char *)buf_ptr, va_arg(comp_list, char *));
				}
				break;
				
			case 'd':
				*result_len += sizeof(int32);
				if (buffer != NULL && *result_len < max_len) {
					EXPORT_INT32(buf_ptr, va_arg(comp_list, int32));
				}
				break;				

			default:
				/* Unrecognized symbol.	*/
				result = FENC_ERROR_INVALID_INPUT;
				break;
		}

		if (buffer != NULL && *result_len > max_len) {
			return FENC_ERROR_BUFFER_TOO_SMALL;
		}
	}
	
	return result;
}

/*!
 * Encode a plaintext as an element of GT.
 *
 * @param plaintext		A fenc_plaintext structure.
 * @param plaintextT	A pre-initialized element_t structure into which we encode the plaintext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
encode_plaintext_GT(fenc_plaintext* plaintext, element_t *plaintextT, pairing_t pairing)
{
	FENC_ERROR err_code;
	mpz_t plaintextInt;
	uint8 *plaintext_data;
	size_t plaintext_len;
	
	//element_set_str(*plaintextT, "[[9882350185216559099620728107541180757801968079488054432788959567594, 13944520348592609168382783508329518298245689745619156863608695792833, 12197163330915190734665648766899322447891514594965450638546058828602], [2917363296457165291849055051224360600107115434305264336863861604298, 11989107583075951953075574136812449493637517189559770644124056280837, 3045866228068198662389081411868036989760015934466596901165843475558]]", 10);
	
	//element_printf("plaintextT=%B\n", *plaintextT);
	LOG_ERROR("encode_plaintext_GT: NOT WORKING RIGHT");
	//return FENC_ERROR_NONE;
	
	err_code = libfenc_get_plaintext_bytes(plaintext, &plaintext_data, &plaintext_len);

	/* Make sure the data fits.	 
	 * TODO: This is very crude and probably not safe.	*/
	if (plaintext_len > (unsigned)pairing_length_in_bytes_Zr(pairing)) {
		return FENC_ERROR_BUFFER_TOO_SMALL;
	}
	
	/* Initialize a gmp integer from a buffer.			*/
	mpz_init(plaintextInt);
	mpz_import(plaintextInt, plaintext_len, 1, sizeof(plaintext_data[0]), 0, 0, plaintext_data);
		
	/* Set the field element plaintextT to the integer.	*/
	element_set_mpz(*plaintextT, plaintextInt);
	
	/* Release memory for the plaintext integer.		*/
	mpz_clear(plaintextInt);
	
	return FENC_ERROR_NONE;
}

/*!
 * Decode a plaintext from an element of GT.
 *
 * @param plaintext		A fenc_plaintext structure.
 * @param plaintextT	An element_t structure containing the plaintext element.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
decode_plaintext_GT(fenc_plaintext* plaintext, element_t *plaintextT, pairing_t pairing)
{
	FENC_ERROR result = FENC_ERROR_NONE;
	mpz_t plaintextInt;
	uint8 plaintextBuf[500]; /* TODO: fix this	*/
	size_t count = 0;
	
	/* First convert the element to an mpz integer.		*/
	mpz_init(plaintextInt);
	element_to_mpz(plaintextInt, *plaintextT);
		
	/* Now export that integer into a raw buffer.	*/
	mpz_export(plaintextBuf, &count, 1, sizeof(plaintextBuf[0]), 0, 0, plaintextInt);
	if (count > 0) {
		result = libfenc_set_plaintext_bytes(plaintext, plaintextBuf, count);
	} else {
		result = FENC_ERROR_UNKNOWN;
	}
	
	mpz_clear(plaintextInt);
	return result;
}

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

FENC_ERROR
derive_session_key_from_element(fenc_plaintext *plaintext, element_t element, size_t key_bytes, pairing_t pairing)
{
	FENC_ERROR err_code;
	
	/* Initialize the plaintext structure.		*/
	err_code = libfenc_plaintext_initialize(plaintext, key_bytes);
	if (err_code != FENC_ERROR_NONE) {
		return err_code;
	}
	
	/* Hash the key into the plaintext.			*/
	err_code = fenc_derive_key_from_element(element, key_bytes, libfenc_plaintext_get_buf(plaintext));
	if (err_code != FENC_ERROR_NONE) {
		return err_code;
	}
	
	plaintext->data_len = key_bytes;
	
	return err_code;
}


/*!
 * Derive a symmetric key (bitstring) from a group element.
 *
 * @param plaintext		A fenc_plaintext structure.
 * @param plaintextT	A pre-initialized element_t structure into which we encode the plaintext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
fenc_derive_key_from_element(element_t element, size_t key_bytes, uint8 *key_buf)
{
	


	return hash_element_to_bytes((element_t *)element, key_bytes, key_buf, HASH_FUNCTION_KEM_DERIVE);
}

/*!
 * Hash a null-terminated string to a byte array.
 *
 * @param input_buf		The input buffer.
 * @param input_len		The input buffer length (in bytes).
 * @param hash_len		Length of the output hash (in bytes).
 * @param output_buf	A pre-allocated output buffer.
 * @param hash_num		Index number of the hash function to use (changes the output).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
hash_to_bytes(uint8 *input_buf, int input_len, int hash_size, unsigned char* output_buf, uint32 hash_num)
{
	SHA1Context sha_context;

	uint32 block_hdr[2];
	
	/* Compute an arbitrary number of SHA1 hashes of the form:
	 * output_buf[0...19] = SHA1(hash_num || 0 || input_buf)
	 * output_buf[20..39] = SHA1(hash_num || 1 || output_buf[0...19])
	 * ...
	 */
	block_hdr[0] = hash_num;
	for (block_hdr[1] = 0; hash_size > 0; (block_hdr[1])++) {
		/* Initialize the SHA1 function.	*/
		SHA1Reset(&sha_context);
		
		SHA1Input(&sha_context, (unsigned char*)&(block_hdr[0]), sizeof(block_hdr));
		SHA1Input(&sha_context, input_buf, input_len);
		
		SHA1Result(&sha_context);
		if (hash_size <= 20) {
			memcpy(output_buf, sha_context.Message_Digest, hash_size);
			hash_size = 0;
		} else {
			memcpy(output_buf, sha_context.Message_Digest, 20);
			input_buf = output_buf;
			hash_size -= 20;
			output_buf += 20;
		}
	}

	return FENC_ERROR_NONE;
}

/*!
 * Hash a group element to a byte array.  This calls hash_to_bytes().
 *
 * @param element		The input element.
 * @param hash_len		Length of the output hash (in bytes).
 * @param output_buf	A pre-allocated output buffer.
 * @param hash_num		Index number of the hash function to use (changes the output).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
hash_element_to_bytes(element_t *element, int hash_size, unsigned char* output_buf, uint32 hash_num)
{
	FENC_ERROR result;
	unsigned int buf_len;
	
	buf_len = element_length_in_bytes(*element);
	uint8 *temp_buf = (uint8*)SAFE_MALLOC(buf_len);
	if (temp_buf == NULL) {
		return FENC_ERROR_INVALID_INPUT;
	}
	
	element_to_bytes(temp_buf, *element);
	result = hash_to_bytes(temp_buf, buf_len, hash_size, output_buf, 2);
	
	SAFE_FREE(temp_buf);
	
	return result;
}

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

FENC_ERROR
fenc_encrypt_with_password(uint8 *buffer, size_t buf_max, size_t *data_len, uint8 *password, 
									   size_t password_len)
{
	LOG_ERROR("fenc_encrypt_with_password: password encryption is not implemented in this version");
	return FENC_ERROR_NOT_IMPLEMENTED;
}

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

FENC_ERROR
fenc_decrypt_with_password(uint8 *buffer, size_t data_len, size_t *result_len, uint8 *password, 
						   size_t password_len)
{
	LOG_ERROR("fenc_encrypt_with_password: password encryption is not implemented in this version");
	return FENC_ERROR_NOT_IMPLEMENTED;
}

