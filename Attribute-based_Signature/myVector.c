#include "myVector.h"

/*
 * Initialize vector in G1.
 */
void element_init_vector_G1(pairing_t _pairing, vecter_t _v, int _size)
{
	int i;
	_v->size = _size;
	_v->val = (element_t *) malloc (_size * sizeof(element_t));
	for(i=0; i<_size; ++i)
		element_init_G1(_v->val[i], _pairing);
}


/*
 * Initialize vector in Zr.
 */
void element_init_vector_Zr(pairing_t _pairing, vecter_t _v, int _size)
{   
	int i;
	_v->size = _size; 
	_v->val = (element_t *) malloc (_size * sizeof(element_t));
	for(i=0; i<_size; ++i)
		element_init_Zr(_v->val[i], _pairing);
}


/*
 * Generate random value.
 */
void element_random_vector(vecter_t _v)
{
	int i;
	for(i=0; i<_v->size; ++i)
		element_random(_v->val[i]);
}

/*
 * Generate random value from input vector.
 */
void element_get_random_in_vector(vecter_t _vo, vecter_t _vi, int _cnt)
{
	int i=0, j, pos, flag;

	if(_cnt > _vi->size)
	{
		printf("input vector size error\n");
		return;
	}


	srand(time(NULL));
	while(i < _cnt)
	{
		flag = 0;
		pos = rand() % _vi->size;
		for(j=0; j<i; ++j)
		{
			if(0 == element_cmp(_vo->val[j], _vi->val[pos]))
			{
				flag = 1;
				break;
			}
		}
		
		if(1 == flag)
			continue;

		element_set(_vo->val[i], _vi->val[pos]);
		i++;
	}
}

/*
 * Copy source to destination.
 */
void element_copy_vector(vecter_t _vo, vecter_t _vi)
{
	int i, size = (_vi->size < _vo->size) ? _vi->size : _vo->size;
	for(i=0; i<size; i++)
		element_set(_vo->val[i], _vi->val[i]);
}

/*
 * Clear memory.
 */
void element_clear_vector(vecter_t _v)
{   
	int i;
	for(i=0; i<_v->size; ++i)
		element_clear(_v->val[i]);
} 

/*
 * Get intersection between v0 and v1.
 */
vecter_ptr element_get_intersection_vector_Zr(pairing_t _pairing, vecter_t _v0, vecter_t _v1)
{
	int i, j, pos=0, tmpCnt = (_v0->size < _v1->size) ? (_v0->size) : (_v1->size);
	vecter_ptr intersection;
	vecter_t tmp;

	element_init_vector_Zr(_pairing, tmp, tmpCnt);
	for(i=0; i<_v0->size; ++i)
	{
		for(j=0; j<_v1->size; ++j)
		{
			if(0 == element_cmp(_v0->val[i], _v1->val[j]))
			{
				element_set(tmp->val[pos], _v0->val[i]);
				++pos;
				break;
			}
		}
	}

	if(0 == pos)
		return NULL;

	intersection = (vecter_ptr) malloc (sizeof(struct vecter_s));
	element_init_vector_Zr(_pairing, intersection, pos);
	element_copy_vector(intersection, tmp);

	element_clear_vector(tmp);

	return intersection;
}
