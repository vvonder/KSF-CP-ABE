/*!	\file libfenc_LSSS.c
 *
 *	\brief Routines supporting Linear Secret Sharing.
 *  
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pbc/pbc.h>
#include "libfenc.h"
#include "libfenc_group_params.h"
#include "libfenc_ABE_common.h"
#include "libfenc_utils.h"
#include "libfenc_LSSS.h"

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

FENC_ERROR	
fenc_LSSS_calculate_shares_from_policy(element_t *secret, fenc_attribute_policy *policy, fenc_attribute_list *attribute_list,
										pairing_t pairing)
{
	FENC_ERROR result = FENC_ERROR_UNKNOWN, err_code;
	uint32 num_leaves, list_index = 0;
	
	/* Count the total number of leaf nodes in the policy tree.	*/
	num_leaves = fenc_count_policy_leaves(policy->root);
	if (num_leaves == 0 || num_leaves > MAX_CIPHERTEXT_ATTRIBUTES) {
		LOG_ERROR("fenc_LSSS_calculate_shares_from_policy: too many or too few leaf nodes in policy");
		result = FENC_ERROR_INVALID_INPUT;
		goto cleanup;
	}
	
	/* Allocate a new attribute list structure with num_leaves elements in it.	*/
	err_code = fenc_attribute_list_initialize(attribute_list, num_leaves);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("fenc_LSSS_calculate_shares_from_policy: could not initialize attribute list");
		result = err_code;
		goto cleanup;
	}
		
	/* Recursively compute the share list, placing each into the attribute list.	*/
	err_code = LSSS_compute_shares_on_subtree(secret, policy->root, attribute_list, &list_index, pairing);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("fenc_LSSS_calculate_shares_from_policy: could not compute shares");
		result = err_code;
		goto cleanup;
	}
	
	/* Success!	*/
	result = FENC_ERROR_NONE;
	
cleanup:
	return result;
}

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

FENC_ERROR
fenc_LSSS_calculate_coefficients_from_policy(fenc_attribute_policy *policy, fenc_attribute_list *ciphertext_attributes, 
											 fenc_lsss_coefficient_list *coefficients, pairing_t pairing)
{
	FENC_ERROR err_code = FENC_ERROR_NONE, result = FENC_ERROR_NONE;
	element_t identityZ;
	uint32 list_index, num_leaves, i;
	
	/* First, we prune the tree.  This applies the ciphertext's attribute list to identify the minimal
	 * subset of leaves that must be satisfied to satisfy the policy.  The markup from this process
	 * is placed within the policy tree.  (This approach is not thread safe.)			*/
	num_leaves = prune_tree(policy->root, ciphertext_attributes);
	if (num_leaves == 0) {
		/* This policy is not satisfied.  Return an error.	*/
		return FENC_ERROR_INVALID_INPUT;
	}
	
	/* Clear out the coefficients list.				*/
	for (i = 0; i < coefficients->num_coefficients; i++) {
		coefficients->coefficients[i].is_set = FALSE;
	}
	
	/* Now compute the coefficients.  Each one corresponds to a leaf of the policy
	 * tree, harvested from left to right.  The recursive function accepts the identity
	 * element and passes calculated coefficients down the tree.
	 *
	 * This should produce one coefficient for every element of the decryption key.
	 * The only way this won't happen is if the key is somehow inconsistent (e.g.,
	 * was not deserialized correctly).  If that happens, we'll reap the whirlwind.	*/
	
	element_init_Zr(identityZ, pairing);
	element_set1(identityZ);
	list_index = 0;
	err_code = LSSS_compute_coefficients_on_subtree(&identityZ, TRUE, policy->root, coefficients, &list_index, pairing);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("fenc_LSSS_calculate_coefficients_from_policy: unable to recover coefficients");
		result = err_code;
	}

	/* Clean up after ourselves.	*/
	element_clear(identityZ);
	
	return result;
}

/*!
 * Given a fenc_attribute_subtree structure, recursively compute the secret shares.  The only shares we
 * retain are the ones on the leaf nodes, which are added from left to right to the attribute list.
 *
 * @param secret			Pointer to the secret element to be shared.
 * @param subtree			Pointer to a fenc_attribute_subtree structure.
 * @param attribute_list	Pointer to the fenc_attribute_list that will contain the result. 
 * @param list_index		Index into the attribute list.
 * @param pairing			Group parameters (used to initialize elements).
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
LSSS_compute_shares_on_subtree(element_t *secret, fenc_attribute_subtree *subtree, fenc_attribute_list *attribute_list,
							   uint32 *list_index, pairing_t pairing)
{
	FENC_ERROR err_code, result = FENC_ERROR_NONE;
	uint32 threshold_k = 0, num_coefs, i;
	element_t *coefficients = NULL, shareZ, tempZ, temp2Z, temp3Z, temp4Z;
	
	/* Process the subtree differently depending on whether it's a leaf or an AND/OR/THRESHOLD-k gate.	*/
	switch(subtree->node_type) {
		case FENC_ATTRIBUTE_POLICY_NODE_LEAF:
			/* Leaf node: the share is the passed-in secret.  Store it into the attribute list.	*/
			element_init_Zr(attribute_list->attribute[*list_index].attribute_hash, pairing);
			element_init_Zr(attribute_list->attribute[*list_index].share, pairing);
			attribute_list->attribute[*list_index].is_hashed = subtree->attribute.is_hashed;
			attribute_list->attribute[*list_index].contains_share = TRUE;
			// attribute_list->attribute[*list_index].is_negated = subtree->is_negated;	/* TODO: make this block cleaner.	*/
			element_set(attribute_list->attribute[*list_index].share, *secret);
			if (subtree->attribute.is_hashed == TRUE) {
				element_set(attribute_list->attribute[*list_index].attribute_hash, subtree->attribute.attribute_hash);
			}
			if (subtree->attribute.attribute_str[0] != 0) {
				memcpy(attribute_list->attribute[*list_index].attribute_str, subtree->attribute.attribute_str, MAX_ATTRIBUTE_STR);
			}
			if (subtree->attribute.attribute_str[0] == '!') {
				attribute_list->attribute[*list_index].is_negated = TRUE;
			}
			else {
				attribute_list->attribute[*list_index].is_negated = FALSE;
			}
			(*list_index)++;
			// LOG_ERROR("%s: found the missing negated attribute? '%s' => '%d'", __func__, subtree->attribute.attribute_str, subtree->is_negated);
			
			/* No need to recurse.	*/
			return FENC_ERROR_NONE;
			
		case FENC_ATTRIBUTE_POLICY_NODE_AND:
			/* AND gate: we'll recurse as though it's an N-of-N threshold gate. */
			threshold_k = subtree->num_subnodes;
			break;
			
		case FENC_ATTRIBUTE_POLICY_NODE_OR:
			/* OR gate: we'll recurse as though it's a 1-of-N threshold gate. */
			threshold_k = 1;
			break;
			
		case FENC_ATTRIBUTE_POLICY_NODE_THRESHOLD:
			/* THRESHOLD gate: it's a specified k-of-N threshold gate.	*/
			threshold_k = subtree->threshold_k;
			break;
			
		default:
			/* Unknown subtree type, just fail.	*/
			LOG_ERROR("LSSS_compute_shares_on_subtree: unrecognized node type, index = %d", *list_index);
			return FENC_ERROR_INVALID_INPUT;
	}
	
	/* Recursive case: perform a k-of-N secret sharing on the secret, then recurse on each share. */
	
	/* Allocate coefficients for a random polynomial P.  We'll place the secret at index 0, and  select k-1 coefficients at random. */
	num_coefs = threshold_k;
	coefficients = (element_t*)SAFE_MALLOC(sizeof(element_t) * num_coefs);
	if (coefficients == NULL)	{ return FENC_ERROR_OUT_OF_MEMORY;	}
	memset(coefficients, 0, sizeof(element_t) * num_coefs);
	element_init_Zr(shareZ, pairing);
	element_init_Zr(tempZ, pairing);
	element_init_Zr(temp2Z, pairing);
	element_init_Zr(temp3Z, pairing);
	element_init_Zr(temp4Z, pairing);

	/* Select coefficients for a P s.t. P(0) = secret.	*/
	for (i = 0; i < num_coefs; i++) {
		element_init_Zr(coefficients[i], pairing);
		
		if (i == 0) {
			element_set(coefficients[i], *secret);
		} else {
			element_random(coefficients[i]);
		}
	}
	
	/* Evaluate the polynomial at points 1 ... N to obtain each share, then recurse on the corresponding subtrees.	*/
	for (i = 0; i < subtree->num_subnodes; i++) {
		/* Evaluate at point i+1, place result into shareZ.	*/
		LSSS_evaluate_polynomial((i+1), coefficients, threshold_k, &shareZ, &tempZ, &temp2Z, &temp3Z, &temp4Z);
		
		/* Recurse.	*/
		err_code = LSSS_compute_shares_on_subtree(&shareZ, subtree->subnode[i], attribute_list, list_index, pairing);
		
		if (err_code != FENC_ERROR_NONE) {
			LOG_ERROR("LSSS_compute_shares_on_subtree: could not recurse");
			result = err_code;
			goto cleanup;
		}
	}
	
	/* Success!	*/
	result = FENC_ERROR_NONE;
	
cleanup:
	/* Wipe out the coefficients list.	*/
	if (coefficients != NULL) {
		for (i = 0; i < num_coefs; i++) {
			element_clear(coefficients[i]);
		}
		
		SAFE_FREE(coefficients);
		element_clear(shareZ);
		element_clear(tempZ);
		element_clear(temp2Z);
		element_clear(temp3Z);
		element_clear(temp4Z);
	}
	
	return result;
}

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

FENC_ERROR
LSSS_compute_coefficients_on_subtree(element_t *in_coef, Bool active_subtree, fenc_attribute_subtree *subtree, fenc_lsss_coefficient_list *coefficient_list,
							   uint32 *list_index, pairing_t pairing)
{
	FENC_ERROR err_code, result = FENC_ERROR_NONE;

	uint32 threshold_k = 0, i;
	element_t shareZ, tempZ, temp2Z, temp3Z;
	Bool elements_initialized = FALSE;
	
	/* Process the subtree differently depending on whether it's a leaf or an AND/OR/THRESHOLD-k gate.	*/
	switch(subtree->node_type) {
		case FENC_ATTRIBUTE_POLICY_NODE_LEAF:
			/* TODO: We should add a sanity check to make sure that this list matches
			 * up with the attribute list provided in the key.	*/
			
			/* If it's a leaf, we add it to the coefficients list.			*/
			if (active_subtree == TRUE) {
				if (subtree->attribute.is_hashed == TRUE) {
					//element_printf("added coefficient %d, attribute hash=%B\n", *list_index, subtree->attribute.attribute_hash);
				} else {
					//printf("added coefficient %d, attribute string=\"%s\"\n", *list_index, subtree->attribute.attribute_str);
				}
				
				/* Non-pruned node: in_coef contains is the passed-in coefficient.  Store it into the coefficients list.	*/
				coefficient_list->coefficients[*list_index].is_set = TRUE;
				element_set(coefficient_list->coefficients[*list_index].coefficient, *in_coef);

			} else {
				/* Pruned leaf node: we add a blank entry to the coefficient list, marked as unused.	*/
				coefficient_list->coefficients[*list_index].is_set = FALSE;
			}
			
			(*list_index)++;
			
			/* No need to recurse.	*/
			return FENC_ERROR_NONE;
			
		case FENC_ATTRIBUTE_POLICY_NODE_AND:
			threshold_k = subtree->num_subnodes;
			break;
			
		case FENC_ATTRIBUTE_POLICY_NODE_OR:
			threshold_k = 1;
			break;
			
		case FENC_ATTRIBUTE_POLICY_NODE_THRESHOLD:
			threshold_k = subtree->threshold_k;
			break;
			
		default:
			/* Unknown subtree type, just fail.	*/
			LOG_ERROR("LSSS_compute_shares_on_subtree: unrecognized node type, index = %d", *list_index);
			return FENC_ERROR_INVALID_INPUT;
	}
	
	/* Recursive case.  Allocate temporary variables. */
	elements_initialized = TRUE;
	element_init_Zr(shareZ,	pairing);
	element_init_Zr(tempZ, pairing);
	element_init_Zr(temp2Z, pairing);
	element_init_Zr(temp3Z, pairing);
	
	/* Go through all of the subnodes that are marked as being satisfied and recursively
	 * compute the appropriate coefficients.  This assumes that the marking function has previously
	 * been executed and has labeled exactly "k" subnodes of this subtree.  If that hasn't
	 * happened, this function will fail catastrophically.											*/
	for (i = 0; i < subtree->num_subnodes; i++) {
		/* Check if this subnode is marked.	*/
		if (active_subtree == TRUE && subtree->subnode[i]->use_subnode == TRUE) {
			/* If so, we'll compute the lagrange basis polynomial coefficient
			 * \ell_{i+1}(0)*in_coef which we'll use to recover the secret.  Note that this
			 * node corresponds to a share with x=(i+1) in the LSSS.		*/
			err_code = compute_lagrange(threshold_k, i, subtree, &tempZ, &temp2Z, &temp3Z);
			if (err_code != FENC_ERROR_NONE) {
				LOG_ERROR("LSSS_compute_coefficients_on_subtree: could not compute Lagrange polynomial");
				result = err_code;
				goto cleanup;
			}
			
			/* Multiply the calculated coefficient by in_coef.  (temp2Z = tempZ * in_coef).	*/
			element_mul(temp2Z, tempZ, *in_coef);
			
			/* Recurse, passing the calculated coefficient down to this lower subtree.	*/
			err_code = LSSS_compute_coefficients_on_subtree(&temp2Z, TRUE, subtree->subnode[i], coefficient_list,
															list_index, pairing);
			if (err_code != FENC_ERROR_NONE) {
				LOG_ERROR("LSSS_compute_coefficients_on_subtree: recursion failed (%s)", libfenc_error_to_string(err_code));
				result = err_code;
				goto cleanup;
			}
		} else {
			/* Inactive subnode.  Recursing on it makes sure that we get one "blank" entry in the coefficients
			 * list for each of its leaves.	*/
			err_code = LSSS_compute_coefficients_on_subtree(in_coef, FALSE, subtree->subnode[i], coefficient_list,
																list_index, pairing);
			if (err_code != FENC_ERROR_NONE) {
				LOG_ERROR("LSSS_compute_coefficients_on_subtree: recursion failed with error %d", err_code);
				result = err_code;
				goto cleanup;
			}
		}
	}
	
	/* Success!	*/
	result = FENC_ERROR_NONE;
	
cleanup:
	/* Wipe out the coefficients list.	*/
	if (elements_initialized == TRUE) {
		element_clear(shareZ);
		element_clear(tempZ);
		element_clear(temp2Z);
		element_clear(temp3Z);
	}
	
	return result;
}


/*!
 * Evaluate a polynomial on a point, given a list of coefficients.
 *
 * @param x					Pointer to the secret element to be shared.
 * @param coefficients		A list of element_t values containing the coefficients (low to high)
 * @param num_coefs			Number of coefficients
 * @param shareZ			Pointer to an element_t for the result (must be allocated)
 */

void
LSSS_evaluate_polynomial(uint32 x, element_t *coefficients, uint32 num_coefs, element_t *shareZ,
						 element_t *tempZ, element_t *temp2Z, element_t *temp3Z, element_t *temp4Z)
{
	uint32 i;
	signed int xN;
	
	element_set(*shareZ, coefficients[0]);
	
	xN = (signed int)x;
	element_set_si(*tempZ, xN);
	element_set_si(*temp4Z, (signed int)x);
	for (i = 1; i < num_coefs; i++) {
		element_mul(*temp2Z, *tempZ, coefficients[i]);
		
		element_add(*temp3Z, *temp2Z, *shareZ);
		element_set(*shareZ, *temp3Z);
		
		/*	xN *= x;	*/
		element_mul(*temp2Z, *tempZ, *temp4Z);
		element_set(*tempZ, *temp2Z);
	}
}


/***********************************************************************************
 * Utility functions
 ***********************************************************************************/

/*!
 * This recursive function counts the total number of leaves in a policy.
 *
 * @param fenc_attribute_subtree	Pointer to a fenc_attribute_subtree structure.
 * @return							Total number of leaves.
 */

uint32
prune_tree(fenc_attribute_subtree *subtree, fenc_attribute_list *attribute_list)
{
	uint32 k, i, j, result=0;
	int32 attribute_index;
	uint32 num_satisfied_subnodes;
	uint32 *satisfied_leaves = NULL;
	uint32 smallest_node, smallest_node_count;
	
	if (subtree == NULL) {
		LOG_ERROR("prune_tree: encountered NULL policy subtree");
		return 0;
	}			  
	
	/* There are four different cases we must deal with: leaf nodes, and three types of gate.	*/
	switch(subtree->node_type) {
		case FENC_ATTRIBUTE_POLICY_NODE_LEAF:
			/* Search the attribute list for a match.	*/
			attribute_index = libfenc_get_attribute_index_in_list(&(subtree->attribute), attribute_list);
			
			/* If the node is /not/ primed (negated), return whether or not it was found.  Otherwise return
			 * the opposite. Either way this will end the recursion. */
			result = 0;
			if ((attribute_index >= 0) && !(subtree->is_negated)) { result = 1; }
			if ((attribute_index < 0) && subtree->is_negated) { result = 1; }
			
			return result;
			
		case FENC_ATTRIBUTE_POLICY_NODE_AND:
			/* AND gates are N-of-N threshold gates */
			k = subtree->num_subnodes;
			break;
			
		case FENC_ATTRIBUTE_POLICY_NODE_OR:
			/* OR gates are 1-of-N threshold gates	*/
			k = 1;
			break;
			
		case FENC_ATTRIBUTE_POLICY_NODE_THRESHOLD:
			/* THRESHOLD gates have a k parameter associated with them. */
			k = subtree->threshold_k;
			break;
			
		default:
			LOG_ERROR("prune_tree: encountered unknown gate type");
			return FALSE;
	}
	
	satisfied_leaves = (uint32*)SAFE_MALLOC(sizeof(uint32) * subtree->num_subnodes);
	
	/* Recurse on each subnode to determine the number of satisfied leaves hanging underneath it.	*/
	num_satisfied_subnodes = 0;
	for (i = 0; i < subtree->num_subnodes; i++) {
		/* Recurse on each subnode.  This will record the number of satisfied leaves inside of the node.
		 * At this point we also initialize each subnode as unused --- we'll mark the ones we
		 * /do/ want to use a bit later.	*/
		satisfied_leaves[i] = prune_tree(subtree->subnode[i], attribute_list);
		subtree->subnode[i]->use_subnode = FALSE;
		
		/* Count the total number satisfied.	*/
		if (satisfied_leaves[i] > 0) {
			num_satisfied_subnodes++;
		}
	}
	
	/* Make sure at least k of the subnodes are satisfied. 	*/
	if (num_satisfied_subnodes < k) {
		/* Not enough; mark this subtree as a dud.	*/
		subtree->use_subnode = FALSE;
		goto cleanup;
	}
	
	/* Consider the following cases:		*/
	result = 0;
	if (k == subtree->num_subnodes) {
		/* 1. k==N (AND gate): we need all of the subnodes.	
		 * Mark all of the subnodes as necessary, and total them up.	*/
		for (i = 0; i < subtree->num_subnodes; i++) {
			subtree->subnode[i]->use_subnode = TRUE;
			result += satisfied_leaves[i];
		}
	} else {
		/* 2. OR or generic threshold gate.		*/		
		/* Hunt for the k values with the smallest number of leaves.	*/
		for (j = 0; j < k; j++) {
			/* Find the smallest non-zero value in the list.	*/
			smallest_node = 0;
			smallest_node_count = 400000;
			for (i = 0; i < subtree->num_subnodes; i++) {
				if (satisfied_leaves[i] != 0 && satisfied_leaves[i] <= smallest_node_count)	{
					smallest_node_count = satisfied_leaves[i];
					smallest_node = i;
				}	
			}
			
			/* Sanity check.	*/
			if (smallest_node_count >= 400000) {
				result = 0;
				goto cleanup;
			}
			
			/* Mark the node.	*/
			subtree->subnode[smallest_node]->use_subnode = TRUE;
			satisfied_leaves[smallest_node] = 0;
			result += smallest_node_count;
		}
	}
	
cleanup:
	if (satisfied_leaves != NULL) {
		SAFE_FREE(satisfied_leaves);
	}
	
	return result;
}

/*!
 * Utility function to compute a coefficient of the Lagrange basis polynomial,
 * \ell_{index}(0).
 *
 * Note: we could pre-compute many of these to speed things up.
 *
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
compute_lagrange(uint32 k, uint32 subnode_index, fenc_attribute_subtree *subtree, element_t *result, 
				 element_t *temp2Z, element_t *temp3Z)
{
	signed int i, total_comp = 0;
	
	element_set1(*result);			/* result = 1	*/
	
	/* Product for all k marked subnodes (excluding subnode_index) of ( (0 - (X(i))) / (X(subnode_index) - (X(i))) )	
	 * Note that X(i) = i+1.	*/
	for (i = 0; i < (signed int)subtree->num_subnodes; i++) {
		/* Check if this subnode is being used for the recovery.	*/
		if (subtree->subnode[i]->use_subnode == TRUE) {
			total_comp++;

			if (i != (signed int)subnode_index) {
				/* This block is a little crazy, but was designed to reduce the need for temporary
				 * variables (since PBC may not do in-place operations.)						*/
				element_set_si(*temp2Z,  (signed int)0 - (signed int)(i+1));	/* temp2Z = 0-(i+1)			*/
				element_mul(*temp3Z, *temp2Z, *result);							/* temp3Z = result * temp2Z	*/
							
				element_set_si(*temp2Z, (signed int)(subnode_index+1) - (signed int)(i+1));	/* temp2Z = (subnode_index+1) - (i+1)	*/
				element_invert(*result, *temp2Z);								/* result = 1/temp2Z		*/
				element_mul(*temp2Z, *result, *temp3Z);							/* temp2Z = result * temp3Z	*/
				element_set(*result, *temp2Z);									/* result = temp2Z			*/
			}
		}
	}
	
	/* Make sure there weren't too many marked nodes.	*/
	if (total_comp > (signed) k) {
		LOG_ERROR("compute_lagrange: too many child nodes (%d nodes, threshold = %d)", total_comp, k);
		return FENC_ERROR_UNKNOWN;
	}
		
	return FENC_ERROR_NONE;
}

/*!
 * Utility function to determine whether an attribute is contained within an array
 * of attributes.
 *
 * @param subtree			fenc_attribute_subtree structure containing the attribute
 * @param attribute_list	array of attribute elements
 * @param num_attributes	number of attributes in the array
 * @return					true if the attribute is in the list, FALSE if it isn't
 */

Bool
LSSS_element_in_attribute_list(fenc_attribute_subtree *subtree, fenc_attribute_list *attribute_list)
{
	uint32 i;
	
	for (i = 0; i < attribute_list->num_attributes; i++) {
		if (attribute_list->attribute[i].is_hashed == TRUE) {
			/* If it's hashed, let's look at the hash value.	*/
			if (element_cmp(subtree->attribute.attribute_hash, attribute_list->attribute[i].attribute_hash) == 0) {
				/* Found a match!	*/
				return TRUE;
			} 
		} else {
			/* If it's not hashed, compare the attribute strings (NOTE: We should be more careful.)	*/
			if (strcmp((char*)subtree->attribute.attribute_str, (char*)attribute_list->attribute[i].attribute_str) == 0) {
				/* Found a match!	*/
				return TRUE;
			}
		}
	}
	
	/* No match.	*/
	return FALSE;
}

/*!
 * Utility function to allocate a coefficient list.
 *
 * @param coefficient_list	Pointer to an allocated fenc_coefficient_list structure.
 * @param num_coefficients	number of coefficients to allocate
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
LSSS_allocate_coefficient_list(fenc_lsss_coefficient_list *coefficient_list, uint32 num_coefficients, pairing_t pairing)
{	
	uint32 i;
	
	/* Clear out the top-level structure.	*/
	memset(coefficient_list, 0, sizeof(fenc_lsss_coefficient_list));
	
	/* Allocate the list memory.	*/
	coefficient_list->coefficients = (fenc_lsss_coefficient*)SAFE_MALLOC(sizeof(fenc_lsss_coefficient) * num_coefficients);
	if (coefficient_list->coefficients == NULL) {
		return FENC_ERROR_OUT_OF_MEMORY;
	}
	
	coefficient_list->num_coefficients = num_coefficients;
	
	for (i = 0; i < coefficient_list->num_coefficients; i++) {
		coefficient_list->coefficients[i].is_set = FALSE;
		element_init_Zr(coefficient_list->coefficients[i].coefficient, pairing);
	}
	
	return FENC_ERROR_NONE;
}

/*!
 * Utility function to clear out a coefficient list.
 *
 * @param coefficient_list	Pointer to an allocated fenc_coefficient_list structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
LSSS_clear_coefficients_list(fenc_lsss_coefficient_list *coefficient_list)
{
	uint32 i;
	
	if (coefficient_list->coefficients != NULL) {	
		for (i = 0; i < coefficient_list->num_coefficients; i++) {
			element_clear(coefficient_list->coefficients[i].coefficient);
		}
		
		SAFE_FREE(coefficient_list->coefficients);
	}
	
	return FENC_ERROR_NONE;
}
