/*!	\file libfenc_abe_common.h
 *
 *	\brief Routines that are shared among the schemes in the Functional Encryption Library.
 *  
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#ifndef __LIBFENC_ABE_COMMON_H__
#define __LIBFENC_ABE_COMMON_H__

/**
 * Constants
 */

typedef enum _FENC_ATTRIBUTE_NODE_TYPE {
	FENC_ATTRIBUTE_POLICY_NODE_NULL = 0,
	FENC_ATTRIBUTE_POLICY_NODE_LEAF,
	FENC_ATTRIBUTE_POLICY_NODE_AND,
	FENC_ATTRIBUTE_POLICY_NODE_OR,
	FENC_ATTRIBUTE_POLICY_NODE_THRESHOLD
} FENC_ATTRIBUTE_NODE_TYPE;

/* Number of ciphertext attributes (maximum)	*/
#define	MAX_CIPHERTEXT_ATTRIBUTES	1024

/* Maximum attribute string length in bytes (this includes a NULL termination byte.) */
#define MAX_ATTRIBUTE_STR	256

/* Maximum serialized policy string in bytes (this includes a NULL termination byte.) */
#define	MAX_POLICY_STR		32768

#define BITS 32

/**
 *  Attribute structure.  Contains a null-terminated string (or NULL) and/or a hashed attribute
 *	typically an element of Zr.  The attribute_hash member should only be accessed if the
 *	is_hashed flag is TRUE.
 */

typedef struct _fenc_attribute {
	uint8			attribute_str[MAX_ATTRIBUTE_STR];	/* Attribute as string.	*/
	element_t		attribute_hash;						/* Optional: attribute hashed to an element.	*/
	Bool			is_hashed;
	Bool			is_negated;
	element_t		share;								/* Optional: secret share value.	*/
	Bool			contains_share;
} fenc_attribute;
	
/**
 *  Attribute list data structure.
 */

typedef struct _fenc_attribute_list {
	uint32					num_attributes;
	struct _fenc_attribute	*attribute;		/* Array of fenc_attribute structures.	*/
} fenc_attribute_list;

/**
 *  Attribute subtree data structure.
 */

typedef struct _fenc_attribute_subtree {
	FENC_ATTRIBUTE_NODE_TYPE		node_type;
	fenc_attribute					attribute;
	Bool							is_negated;
	uint32							num_subnodes;
	uint32							threshold_k;
	Bool							use_subnode;
	struct _fenc_attribute_subtree	**subnode;
} fenc_attribute_subtree;

/*!
 *  Attribute policy data structure.
 */

typedef struct _fenc_attribute_policy {
	fenc_attribute_subtree		*root;
	char 						*string;
} fenc_attribute_policy;

/* Prototypes			*/

/*!
 * Generate a set of global (elliptic curve) parameters.  Caller is responsible
 * for allocating the global_params buffer.
 *
 * @param global_params	The pre-allocated global params data structure.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_generate_global_params_COMMON(fenc_global_params *global_params, fenc_group_params *group_params);

/*!
 * Destroy a set of global parameters.
 *
 * @param global_params	The pre-allocated global params data structure.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_destroy_global_params_COMMON(fenc_global_params *global_params);

/*!
 * Parse a function input as an attribute list.  This will involve some memory allocation in the
 * fenc_attribute_list structure, which must be cleared using the fenc_attribute_list_clear call.
 *
 * @param input				Attribute list
 * @param num_attributes	Number of attributes is written here
 * @param attribute_list	fenc_attribute_list structure
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_parse_input_as_attribute_list(fenc_function_input *input, fenc_attribute_list *attribute_list,
									  pairing_t pairing);

/*!
 * Parse a function input as an attribute policy.  This will involve some memory allocation in the
 * fenc_attribute_poliy structure, which must be cleared using the fenc_attribute_policy_clear call.
 *
 * @param input				Attribute list
 * @param num_attributes	Number of attributes is written here
 * @param attribute_list	fenc_attribute_list structure
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_parse_input_as_attribute_policy(fenc_function_input *input, fenc_attribute_policy *policy);

/*!
 * Convert an array of attribute strings into a fenc_function_input.  The input
 * structure must be initialized, although some additional memory allocation will
 * occur.
 *
 * @param input				Pointer to an allocated fenc_function_input structure
 * @param attribute_list	Array of char* strings containing attributes
 * @param num_attributes	Number of attributes in list
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_create_attribute_list_from_strings(fenc_function_input *input, char **attributes, uint32 num_attributes);

/*!
 * This recursive function counts the number of leaves under a given subtree.
 *
 * @param fenc_attribute_subtree	Pointer to a fenc_attribute_subtree structure.
 * @param attribute_list			Pointer to a fenc_attribute_list structure.
 * @return							Total number of satisfied leaves
 */

uint32	fenc_count_policy_leaves(fenc_attribute_subtree *subtree);

/*!
 * Apply the N() function (from Goyal et al.) to an attribute list.
 *
 * @param result_list		Resulting attribute list
 * @param input_list		Input attribute list
 * @param input_policy		Input policy structure
 * @param group_params		Group parameters.
 * @return					FENC_ERROR_NONE or an error code
 */

FENC_ERROR	fenc_apply_N_function_to_attributes(fenc_attribute_list *result_list, fenc_attribute_list *input_list,
									/*fenc_attribute_policy *policy,*/ pairing_t pairing);

/*!
 * Allocate memory for an attribute list of num_attributes attributes.
 *
 * @param attribute_list	fenc_attribute_list structure
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_attribute_list_initialize(fenc_attribute_list *attribute_list, uint32 num_attributes);

/*!
 * Find the index of an attribute within the list.  This searches on either the
 * attribute_hash or the attribute_str value (in that order) depending
 * on which is available.  
 *
 * @param attribute			Pointer to a fenc_attribute structure
 * @param attribute_list	Pointer to a fenc_attribute_list structure
 * @return					The index or -1 if not found.
 */

int32	libfenc_get_attribute_index_in_list(fenc_attribute *attribute, fenc_attribute_list *attribute_list);

/*!
 * Convert an array of attribute strings into a fenc_function_input.  The input
 * structure must be initialized, although some additional memory allocation will
 * occur.
 *
 * @param input				Pointer to an allocated fenc_function_input structure
 * @param attribute_list	Array of char* strings containing attributes
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_create_func_input_for_attributes(char *attributes, fenc_function_input *input);

/*!
 * Convert an policy string into a fenc_function_input.  The input
 * structure must be initialized, although some additional memory allocation will
 * occur.
 *
 * @param input				Pointer to an allocated fenc_function_input structure
 * @param policy			char* strings containing policy using attributes
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_create_func_input_for_policy(char *policy, fenc_function_input *input);

/*!
 * Clear an fenc_function_input structure for attributes or policy and deallocates memory.
 *
 * @param input				functional input structure
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_func_input_clear(fenc_function_input *input);

/*!
 * Clear an attribute list data structure, deallocating memory.
 *
 * @param attribute_list	fenc_attribute_list structure
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_attribute_list_clear(fenc_attribute_list *attribute_list);

/*!
 * Duplicate an attribute list data structure.  Assumes that the incoming attribute
 * list structure is /not/ previously allocated.  This function allocates the new
 * attribute list: the user must call fenc_attribute_list_clear() when done with it.
 *
 * @param attribute_list_DST	fenc_attribute_list structure destination.
 * @param attribute_list_SRC	fenc_attribute_list structure source.
 * @param group_params			fenc_group_params structure.
 * @return						FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_attribute_list_copy(fenc_attribute_list *attribute_list_DST, fenc_attribute_list *attribute_list_SRC, pairing_t pairing);

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

FENC_ERROR	fenc_attribute_list_to_buffer(fenc_attribute_list *attribute_list, uint8 *buffer, size_t buf_len, size_t *result_len);

/*!
 * Parse a string of attributes into an fenc_attribute_list structure.
 * 
 * @param str_list				Buffer to attribute list string.
 * @param attribute_list		fenc_attribute_list pointer.
 */
FENC_ERROR  fenc_buffer_to_attribute_list(char **str_list, fenc_attribute_list *attribute_list);

/*!
 * Clear an attribute data structure, deallocating memory.
 *
 * @param subtree		fenc_attribute_subtree structure
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_attribute_clear(fenc_attribute *attribute);

/*!
 * Clear an attribute subtree data structure, deallocating internal memory.
 *
 * @param subtree		fenc_attribute_subtree structure
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_attribute_subtree_clear(fenc_attribute_subtree *subtree);

/*!
 * Duplicate an attribute.  The destination structure should be uninitialized.
 *
 * @param attribute_DST			fenc_attribute structure destination.
 * @param attribute_SRC			fenc_attribute structure source.
 * @return						FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_attribute_copy(fenc_attribute *attribute_DST, fenc_attribute *attribute_SRC, pairing_t pairing);

/*!
 * Recursively print a policy tree into an ASCII string.
 *
 * @param fenc_attribute_subtree	Pointer to a fenc_attribute_subtree structure.
 * @param output_str				Pointer to a character string.
 * @param str_len					Maximum length of the buffer
 * @return							FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_attribute_policy_to_string(fenc_attribute_subtree *subtree, char *output_str, size_t buf_len);

/***************************************************************************
 * Policy manipulation
 ***************************************************************************/

/*!
 * Create a policy leaf subnode from an attribute string.
 *
 * @param attribute_str			Attribute string.
 * @return						Allocated policy subnode.
 */

fenc_attribute_subtree*	fenc_policy_create_leaf(char *attribute_str);

/*!
 * Create a policy subnode from an array of subnodes.
 *
 * @param node_type			FENC_ATTRIBUTE_NODE_TYPE value.
 * @param num_subnodes		Number of subnodes in the array.
 * @param threshold_k		Threshold value k.
 * @param subnodes			Array of fenc_attribute_subtree pointers.
 * @return					Allocated policy subnode.
 */

fenc_attribute_subtree*	fenc_policy_create_node(FENC_ATTRIBUTE_NODE_TYPE node_type, uint32 num_subnodes, uint32 threshold_k, fenc_attribute_subtree **subnodes);

/*!
 * Recursively compact a tree structure.  This consists of combining parent
 * and child nodes where appropriate. 
 *
 * The process is nicked from John Bethencourt's library, though the code isn't.
 *
 * @param subtree			The subtree.
 */

void	fenc_policy_compact(fenc_attribute_subtree* subtree);

/*!
 * Merge a child into the subtree.  Only works if the parent and child
 * node are both OR nodes or both AND nodes.
 *
 * @param subtree			The subtree.
 * @param child_num			Index of the child.
 */

void	fenc_policy_merge_child(fenc_attribute_subtree* subtree, uint32 child_num);

/*!
 * Extend an array of fenc_attribute_subtree pointers.
 *
 * @param attributes		The original array.
 * @param old_nodes			Number of nodes in the original array.
 * @param new_nodes			Desired number of nodes.
 */

fenc_attribute_subtree **fenc_policy_extend_array(fenc_attribute_subtree **attributes, uint32 old_nodes, uint32 new_nodes);

/*!
 * Parse a string to obtain an attribute policy.
 *
 * @param policy		A fenc_attribute_policy structure.
 * @param policy_str	The policy string.
 * @param FENC_ERROR_NONE or an error code
 */

FENC_ERROR	fenc_policy_from_string(fenc_attribute_policy *policy, char *policy_str);

/*!
 * Parse attribute policy to obtain the string.
 *
 * @param policy		A fenc_attribute_policy structure.
 * @param string or NULL if policy structure is empty.
 */

char* fenc_get_policy_string(fenc_attribute_policy *policy);

/*!
 * Hash an attribute string to a value in Zr.  The result is stored within the
 * attribute structure.  Note that this hash may already have been stored,
 * in which case this routine will avoid redundant computation.
 *
 * @param attribute			Pointer to a fenc_attribute data structure.
 * @param global_params		Pointer to a fenc_group_parameters data structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR hash_attribute_string_to_Zr(fenc_attribute *attribute, pairing_t pairing);

int num_bits(int value);

void debug_print_policy(fenc_attribute_policy *policy_tree);

void debug_print_attribute_list(fenc_attribute_list *attribute_list);

#endif /* ifdef __LIBFENC_ABE_COMMON_H__ */
