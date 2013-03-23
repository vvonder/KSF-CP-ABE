/*!	\file libfenc_LSSS.h
 *
 *	\brief Routines that support Linear Secret Sharing.
 *  
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#ifndef __LIBFENC_LSSS_H__
#define __LIBFENC_LSSS_H__

typedef struct _fenc_lsss_coefficient {
	Bool			is_set;
	element_t		coefficient;
	fenc_attribute	*attribute;
} fenc_lsss_coefficient;

typedef struct _fenc_lsss_coefficient_list {
	uint32							num_coefficients;
	struct _fenc_lsss_coefficient	*coefficients;
} fenc_lsss_coefficient_list;

/*!
 * Generate a set of secret shares from the master secret and a tree-based policy.
 * This routine generates a fenc_attribute_list structure containing each labeled
 * attribute as well as its share.
 *
 * @param secret			Pointer to the secret (an element of Zr).
 * @param policy			Pointer to a fenc_attribute_policy structure.
 * @param attribute_list	Pointer to a fenc_attribute_list that will contain the result.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_LSSS_calculate_shares_from_policy(element_t *secret, fenc_attribute_policy *policy, fenc_attribute_list *attribute_list,
												   pairing_t pairing);

/*!
 * Given a policy and an attribute list containing N(ciphertext attributes)
 * compute the coefficients of the secret sharing scheme and place them into
 * the attribute list.  
 *
 * At a lower lever, this routine does a number of things:
 *   - Identifies the smallest subset of leaf nodes that satisfy the policy
 *     (or if there is no such subset, returns this result)
 *   - "Prunes" the tree down to the smallest such subset
 *   - Calculates the coefficients for the pruned tree, placing the
 *     result into a fenc_attribute_list structure
 *
 * @param policy			Pointer to a fenc_attribute_policy structure.
 * @param attribute_list	Pointer to a fenc_attribute_list that will contain the result. 
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	fenc_LSSS_calculate_coefficients_from_policy(fenc_attribute_policy *policy, fenc_attribute_list *ciphertext_attributes, 
														 fenc_lsss_coefficient_list *coefficients, pairing_t pairing);

/*!
 * Utility function to allocate a coefficient list.
 *
 * @param coefficient_list	Pointer to an allocated fenc_lsss_coefficient_list structure.
 * @param num_coefficients	number of coefficients to allocate
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	LSSS_allocate_coefficient_list(fenc_lsss_coefficient_list *coefficient_list, uint32 num_coefficients, pairing_t pairing);

/*!
 * Utility function to clear out a coefficient list.
 *
 * @param coefficient_list	Pointer to an allocated fenc_lsss_coefficient_list structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	LSSS_clear_coefficients_list(fenc_lsss_coefficient_list *coefficient_list);

/*!
 * Given a fenc_attribute_subtree structure, recursively compute the secret shares.  The only shares we
 * retain are the ones on the leaf nodes, which are added from left to right to the attribute list.
 *
 * @param secret			Pointer to the secret element to be shared.
 * @param subtree			Pointer to a fenc_attribute_subtree structure.
 * @param attribute_list	Pointer to the fenc_attribute_list that will contain the result. 
 * @param attribute_index	Index into the attribute list.
 * @param pairing			Group parameters (used to initialize elements).
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	LSSS_compute_shares_on_subtree(element_t *secret, fenc_attribute_subtree *subtree, fenc_attribute_list *attribute_list,
										   uint32 *list_index, pairing_t pairing);

/*!
 * Given a fenc_attribute_subtree structure, recursively compute the recovery coefficients.
 *
 * @param in_coef			Pointer to the secret element to be shared.
 * @param subtree			Pointer to a fenc_attribute_subtree structure.
 * @param active_subtree	If set to FALSE, all subnodes will be added to the list
 * @param attribute_list	Pointer to the fenc_attribute_list that will contain the result. 
 * @param list_index		Index into the attribute list.
 * @param pairing			Group parameters (used to initialize elements).
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	LSSS_compute_coefficients_on_subtree(element_t *in_coef, Bool active_subtree, fenc_attribute_subtree *subtree, fenc_lsss_coefficient_list *coefficient_list,
									 uint32 *list_index, pairing_t pairing);

/*!
 * Evaluate a polynomial on a point, given a list of coefficients.
 *
 * @param x					Pointer to the secret element to be shared.
 * @param coefficients		A list of element_t values containing the coefficients (low to high)
 * @param num_coefs			Number of coefficients
 * @param shareZ			Pointer to an element_t for the result (must be allocated)
 */

void	LSSS_evaluate_polynomial(uint32 x, element_t *coefficients, uint32 num_coefs, element_t *shareZ,
								 element_t *tempZ, element_t *temp2Z, element_t *temp3Z, element_t *temp4Z);

/***********************************************************************************
 * Utility functions
 ***********************************************************************************/

/*!
 * This recursive function determines the minimum number of leaf nodes
 * that must be satisfied in order for the policy tree to be satisfied.
 * Along the way it marks all of the subtrees that must also be evaluated
 * to achieve this result.
 *
 * This function has side effects (marking the tree), so it's not thread safe.
 *
 * @param fenc_attribute_subtree	Pointer to a fenc_attribute_subtree structure.
 * @param attribute_list			Pointer to a fenc_attribute_list structure.
 * @return							Total number of satisfied leaves
 */

uint32	prune_tree(fenc_attribute_subtree *subtree, fenc_attribute_list *attribute_list);

/*!
 * Utility function to compute a coefficient of the Lagrange basis polynomial,
 * \ell_{index}(0).
 *
 * Note: we could pre-compute many of these to speed things up.
 *
 * @return					FENC_ERROR_NONE or an error code.
 */
FENC_ERROR	compute_lagrange(uint32 k, uint32 point_index, fenc_attribute_subtree *subtree, element_t *result, 
				 element_t *temp2Z, element_t *temp3Z);

/*!
 * Utility function to determine whether an attribute is contained within an array
 * of attributes.
 *
 * @param subtree			fenc_attribute_subtree structure containing the attribute
 * @param attribute_list	array of attribute elements
 * @param num_attributes	number of attributes in the array
 * @return					true if the attribute is in the list, false if it isn't
 */

Bool	LSSS_element_in_attribute_list(fenc_attribute_subtree *subtree, fenc_attribute_list *attribute_list);

#endif /* ifdef __LIBFENC_LSSS_H__ */