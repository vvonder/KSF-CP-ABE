/*!	\file libfenc.h
 *
 *	\brief Main header file for the Functional Encryption Library.
 *  
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#ifndef __LIBFENC_H__
#define __LIBFENC_H__

#define SAFE_MALLOC(size)	malloc(size)
#define SAFE_FREE(val)		free(val)
#define LOG_ERROR(...)		if (global_error_file != NULL) ( fprintf (global_error_file, __VA_ARGS__), fprintf(global_error_file, " (%s:%d)\n" , __FILE__, __LINE__))

#ifdef DEBUG
#define DEBUG_ELEMENT_PRINTF(...)	element_printf(__VA_ARGS__)
#else
#define DEBUG_ELEMENT_PRINTF(...) 
#endif

/* 
 * Library globals (extern)
 */

#ifndef __LIBFENC_C__
extern	FILE	*global_error_file;
#endif

/*
 * Constants
 */

#define TRUE	1
#define FALSE	0

typedef enum _FENC_SCHEME_TYPE {
	FENC_SCHEME_NONE = 0,
	FENC_SCHEME_LSW,
	FENC_SCHEME_WATERSCP,
	FENC_SCHEME_WATERSSIMPLECP
} FENC_SCHEME_TYPE;

typedef enum _FENC_CIPHERTEXT_TYPE	{
	FENC_CIPHERTEXT_TYPE_UNDEFINED,
	FENC_CIPHERTEXT_TYPE_CPA,
	FENC_CIPHERTEXT_TYPE_KEM_CPA
} FENC_CIPHERTEXT_TYPE;

typedef enum _FENC_INPUT_TYPE {
	FENC_INPUT_NONE = 0,
	FENC_INPUT_ATTRIBUTE_LIST,
	FENC_INPUT_NM_ATTRIBUTE_POLICY
} FENC_INPUT_TYPE;

typedef enum _FENC_ERROR {
	FENC_ERROR_NONE = 0,
	FENC_ERROR_INVALID_CONTEXT,
	FENC_ERROR_INVALID_CIPHERTEXT,
	FENC_ERROR_INVALID_GROUP_PARAMS,
	FENC_ERROR_INVALID_GLOBAL_PARAMS,
	FENC_ERROR_INVALID_KEY,
	FENC_ERROR_OUT_OF_MEMORY,
	FENC_ERROR_INVALID_INPUT,
	FENC_ERROR_INVALID_PLAINTEXT,
	FENC_ERROR_UNKNOWN_SCHEME,
	FENC_ERROR_LIBRARY_NOT_INITIALIZED,
	FENC_ERROR_NOT_IMPLEMENTED,
	FENC_ERROR_NO_SECRET_PARAMS,
	FENC_ERROR_NO_PUBLIC_PARAMS,
	FENC_ERROR_BUFFER_TOO_SMALL,
	FENC_ERROR_UNKNOWN
} FENC_ERROR;

typedef enum _FENC_LIBRARY_STATE {
	FENC_STATE_READY = 0,
	FENC_STATE_MEMORY_ERROR,
	FENC_STATE_NOT_INITIALIZED
} FENC_LIBRARY_STATE;

/*
 * Data Structures
 */

typedef unsigned int uint32;
typedef unsigned short uint16;
typedef int	int32;
typedef short int16;
typedef unsigned char uint8;
typedef char int8;
typedef int Bool;

//typedef struct _struct _fenc_group_params struct _fenc_group_params; /*!< defined in libstruct _fenc_group_params.h */
struct _fenc_group_params; /*!< defined in libstruct _fenc_group_params.h */

/**
 *  Global parameters data structure.
 */

typedef struct _fenc_global_params {
	struct _fenc_group_params	*group_params;
} fenc_global_params;

/**
 *  Public parameters data structure.
 */

typedef struct _fenc_public_params {
	FENC_SCHEME_TYPE		scheme_type;
} fenc_public_params;

/**
 *  Secret parameters data structure.
 */

typedef struct _fenc_secret_params {
	FENC_SCHEME_TYPE		scheme_type;
} fenc_secret_params;

/**
 *  Abstract data structure describing a function input.
 */

typedef struct _fenc_function_input {
	FENC_INPUT_TYPE			input_type;
	void*					scheme_input;
} fenc_function_input;

/**
 *  Abstract class containing a plaintext message.
 */

typedef struct _fenc_plaintext {
	Bool					valid;
	uint8*					data;
	unsigned int			max_len;
	unsigned int			data_len;
} fenc_plaintext;

/**
 *  Abstract class containing a ciphertext.
 */

typedef struct _fenc_ciphertext {
	FENC_SCHEME_TYPE		scheme_type;
	uint8*					data;
	size_t					max_len;
	size_t					data_len;
} fenc_ciphertext;

/**
 *  Abstract class containing an extracted secret key.
 */

typedef struct _fenc_key {
	FENC_SCHEME_TYPE		scheme_type;
	Bool					valid;
	void*					scheme_key;
} fenc_key;

/*!
 *  Main context data structure.  Contains scheme-specific data including keys and parameters.
 */

typedef struct _fenc_context {
	FENC_SCHEME_TYPE		scheme_type;
	void					*scheme_context;	/*!< Scheme-specific context data structure */

	/* Flags	*/
	Bool					contains_public_params;
	Bool					contains_secret_params;
	
	/* Function pointers */
	FENC_ERROR				(*gen_params)(struct _fenc_context*, fenc_global_params*);
	FENC_ERROR				(*set_params)(struct _fenc_context *, fenc_public_params *, fenc_secret_params *);
	FENC_ERROR				(*extract_key)(struct _fenc_context *, fenc_function_input *, fenc_key *);	
	FENC_ERROR				(*encrypt)(struct _fenc_context *, fenc_function_input *, fenc_plaintext *,
											 fenc_ciphertext *);
	FENC_ERROR				(*kem_encrypt)(struct _fenc_context *, fenc_function_input *, size_t, uint8 *,
									   fenc_ciphertext *);
	FENC_ERROR				(*decrypt)(struct _fenc_context *, fenc_ciphertext *, fenc_key *,
											 fenc_plaintext *);
	FENC_ERROR				(*destroy_context)(struct _fenc_context*);
	FENC_ERROR				(*generate_global_params)(fenc_global_params*, struct _fenc_group_params*);
	FENC_ERROR				(*destroy_global_params)(fenc_global_params *);
	FENC_ERROR				(*export_public_params)(struct _fenc_context *context, uint8 *buffer, size_t buf_len, size_t *result_len);
	FENC_ERROR				(*export_secret_params)(struct _fenc_context *context, uint8 *buffer, size_t buf_len, size_t *result_len);
	FENC_ERROR				(*import_public_params)(struct _fenc_context *context, uint8 *buffer, size_t buf_len, struct _fenc_global_params *group_params);
	FENC_ERROR				(*import_secret_params)(struct _fenc_context *context, uint8 *buffer, size_t buf_len);
	FENC_ERROR				(*export_global_params)(struct _fenc_context *context, uint8 *buffer, size_t buf_len, size_t *result_len);
	FENC_ERROR				(*import_global_params)(struct _fenc_context *context, uint8 *buffer, size_t buf_len);
	FENC_ERROR				(*export_secret_key)(struct _fenc_context *context, fenc_key *key, uint8 *buffer, size_t buf_len, size_t *result_len);
	FENC_ERROR				(*import_secret_key)(struct _fenc_context *context, fenc_key *key, uint8 *buffer, size_t buf_len);
} fenc_context;


/*
 * Pre-processor macros
 */

#define CHECK_LIBRARY_STATE		if (libfenc_global_state != FENC_STATE_READY) { return FENC_ERROR_LIBRARY_NOT_INITIALIZED; }

/*!
 * Library state global.  Main declaration in libfenc.c, defined as "extern" everywhere else.  This 
 * value should not be directly manipulated.
 */

#ifdef __LIBFENC_C__
FENC_LIBRARY_STATE	libfenc_global_state = FENC_STATE_NOT_INITIALIZED;
#else
extern FENC_LIBRARY_STATE	libfenc_global_state;
#endif

/********************************************************************************
 * Core API
 ********************************************************************************/

/*!
 * Global initialization for the library.  This routine must be called before 
 * any others.
 *
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_init();

/*!
 * Global shutdown for the library.  This routine should be called prior to application
 * exit.
 *
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_shutdown();

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

FENC_ERROR	libfenc_create_context(fenc_context *context, FENC_SCHEME_TYPE scheme_type);

/*!
 * Generate public and secret parameters.  This is equivalent to the "Setup" algorithm in most 
 * functional encryption schemes.  All relevant global parameters will 
 *
 * @param context		The fenc_context data structure
 * @param global_params	Global params (scheme-specific).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_gen_params(fenc_context *context, fenc_global_params *global_params);

/*!
 * Load public and (optionally) secret parameters into the context.  All relevant global
 * parameters are embedded within the public_params data structure.
 *
 * @param context		The fenc_context data structure
 * @param public_params	Public scheme parameters.
 * @param secret_params	Secret scheme parameters (optional).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_set_params(/*fenc_context *context, fenc_public_params *public_params, fenc_secret_params *secret_params*/);

/*!
 * Load global parameters into the context.  All relevant global
 * parameters are embedded within the public_params data structure.
 *
 * @param context		The fenc_context data structure
 * @param global_oarams	Public scheme parameters.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_set_global_params(/*fenc_context *context, fenc_global_params *global_params*/);

/*!
 * Extract a secret key representing a given function input.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input from which this key will be built.
 * @param key			A pre-allocated buffer for the resulting key
 * @return				FENC_ERROR_NONE or an error code.
 */


FENC_ERROR	libfenc_extract_key(fenc_context *context, fenc_function_input *input, fenc_key *key);

/*!
 * Encrypt a plaintext under a given function input.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input under which which the ciphertext will be encrypted.
 * @param plaintext		The plaintext message.
 * @param ciphertext	A pre-allocated buffer for the returned fenc_ciphertext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_encrypt(fenc_context *context, fenc_function_input *input, fenc_plaintext *plaintext,
							fenc_ciphertext *ciphertext);

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

FENC_ERROR	libfenc_kem_encrypt(fenc_context *context, fenc_function_input *input, size_t key_len,
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

FENC_ERROR	libfenc_decrypt(fenc_context *context, fenc_ciphertext *ciphertext, fenc_key *key,
							fenc_plaintext *plaintext);

/*!
 * Export a context's public parameters (MPK) to a binary buffer.  Calling this function with buffer 
 * set to NULL will return the length of the exported material.
 *
 * @param context				The fenc_context data structure
 * @param buffer				A pre-allocated buffer for the resulting export.
 * @param buf_len				The maximum allocated size of the buffer (in bytes).
 * @param result_len			The size of the resulting export (in bytes).
 * @param include_global_params	Set to "TRUE" if the global parameters should also be exported.
 * @return						FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_export_public_params(fenc_context *context, uint8 *buffer, size_t buf_len, size_t *result_len,
										 Bool include_global_params);

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

FENC_ERROR	libfenc_export_secret_params(fenc_context *context, uint8 *buffer, size_t buf_len, size_t *result_len,
							 uint8* password, size_t password_len);

/*!
 * Import a context's public parameters (MPK) from a binary buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param buf_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_import_public_params(fenc_context *context, uint8 *buffer, size_t buf_len);

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

FENC_ERROR	libfenc_import_secret_params(fenc_context *context, uint8 *buffer, size_t buf_len,
							 uint8* password, size_t password_len);

/*!
 * Export a context's global parameters to a buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		A pre-allocated buffer for the resulting export.
 * @param buf_len		The maximum allocated size of the buffer (in bytes).
 * @param result_len	The size of the resulting export (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_export_global_params(fenc_context *context, uint8 *buffer, size_t buf_len, size_t *result_len);

/*!
 * Import a context's global parameters from a buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param buf_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_import_global_params(fenc_context *context, uint8 *buffer, size_t buf_len);

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

FENC_ERROR	libfenc_export_secret_key(fenc_context *context, fenc_key *key, uint8 *buffer, size_t buf_len, size_t *result_len);

/*!
 * Deserialize an ABE key structure.
 *
 * @param context		The fenc_context data structure
 * @param key			The fenc_key data structure (pre-allocated).
 * @param buffer		The buffer.
 * @param buf_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_import_secret_key(fenc_context *context, fenc_key *key, uint8 *buffer, size_t buf_len);

/*!
 * Destroy the internal contents of a fenc_context structure.  The caller is responsible for
 * de-allocating the context buffer itself.
 *
 * @param context		The fenc_context data structure.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_destroy_context(fenc_context *context);

/*!
 * Allows the application to specify a FILE structure into which the library will 
 * write its error messages.  A NULL value deactivates logging.  
 * stderr is default.  Application is responsible for opening and closing
 * files.
 *
 * @param error_file	Pointer to a FILE structure or NULL.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_set_error_file(FILE* error_file);

/**************************************************************************************
 * Utility functions
 **************************************************************************************/



/*!
 * Destroy the internal contents of a fenc_context structure.  The caller is responsible for
 * de-allocating the context buffer itself.
 *
 * @param global_params	The global parameters.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_destroy_global_params(/*fenc_context *context*/);

/*!
 * Get the group parameters structure from the global parameters structure.
 *
 * @param global_params	The global parameters.
 * @return				FENC_ERROR_NONE or an error code.
 */

struct _fenc_group_params* libfenc_get_group_params(fenc_global_params *global_params);

/*!
 * Initialize a fenc_plaintext structure.
 *
 * @param plaintext	A pointer to a fenc_plaintext struct.
 * @param data_len		Length in bytes of the plaintext (to allocate).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_plaintext_initialize(fenc_plaintext *plaintext, unsigned int data_len);

/*!
 * Get the data buffer from a fenc_plaintext structure.
 *
 * @param plaintext		A pointer to a fenc_plaintext struct.
 * @return				Data buffer or NULL.
 */

uint8*	libfenc_plaintext_get_buf(fenc_plaintext *plaintext);

/*!
 * Initialize a fenc_ciphertext structure.
 *
 * @param ciphertext	A pointer to a fenc_ciphertext struct.
 * @param data_len		Length in bytes of the serialized ciphertext.
 * @param scheme_type	Identifier of the scheme.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_ciphertext_initialize(fenc_ciphertext *ciphertext, unsigned int data_len, FENC_SCHEME_TYPE scheme_type);

/*!
 * Clear a fenc_ciphertext structure.
 *
 * @param ciphertext	A pointer to a fenc_ciphertext struct.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_ciphertext_clear(fenc_ciphertext *ciphertext);

/*!
 * Set a fenc_plaintext structure to a buffer of bytes.
 *
 * @param plaintext		A pointer to a fenc_plaintext struct.
 * @param buf			Byte buffer.
 * @param buf_size		Buffer size in bytes.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_set_plaintext_bytes(fenc_plaintext *plaintext, uint8* buf, size_t buf_size);

/*!
 * Get the a fenc_plaintext structure to a buffer of bytes.
 *
 * @param plaintext		A pointer to a fenc_plaintext struct.
 * @param buf			Pointer to a pointer to a byte buffer (this is set by the routine).
 * @param buf_size		Pointer to the buffer size in bytes (this is set by the routine).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_get_plaintext_bytes(fenc_plaintext *plaintext, uint8** buf, size_t *buf_size);

/*!
 * Clear a fenc_plaintext structure.
 *
 * @param plaintext		A pointer to a fenc_plaintext struct.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_plaintext_clear(fenc_plaintext *plaintext);

/*!
 * Convert an error code into a string.
 *
 * @param		error	The error code.
 * @return				A string containing the error code.
 */

const char* libfenc_error_to_string(FENC_ERROR error);

#endif /* ifdef __LIBFENC_H__ */