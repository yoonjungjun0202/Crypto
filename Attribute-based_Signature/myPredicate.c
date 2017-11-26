#include "myPredicate.h"

/*
 * Setup predicate.
 */
void element_init_predicate(pairing_t _pairing, pred_t _pred, int _c, int _k)
{
	_pred->k = _k;
	element_init_vector_Zr(_pairing, _pred->predS, _c);
}

/*
 * Get random predicate.
 */
void element_get_random_in_attrSet(pred_t _pred, vecter_t _attrS, vecter_t _univS)
{
	int i, j, flag, pos=_pred->k;

	element_get_random_in_vector(_pred->predS, _attrS, _pred->k);
	for(i=0; i<_univS->size; ++i)
	{
		flag = 0;
		for(j=0; j<_attrS->size; ++j)
		{
			if(0 == element_cmp(_univS->val[i], _attrS->val[j]))
			{
				flag = 1;
				break;
			}
		}

		if(1 == flag)
			continue;

		if(_pred->predS->size <= pos)
			break;

		element_set(_pred->predS->val[pos], _univS->val[i]);
		++pos;
	}
}

/*
 * Copy _attrS to _pred.
 */
void element_set_attrSet(pred_t _pred, vecter_t _attrS)
{
	int i;

	if(_pred->predS->size > _attrS->size)
	{
		printf("source vector size error\n");
		return;
	}

	element_copy_vector(_pred->predS, _attrS);
}

/*
 * Clear memory.
 */
void element_clear_predicate(pred_t _pred)
{
	int i;
	for(i=0; i<_pred->predS->size; ++i)
		element_clear(_pred->predS->val[i]);
}
