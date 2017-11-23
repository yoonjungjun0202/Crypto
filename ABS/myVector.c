#include "myVector.h"

/*
 * Initialize vector in G1.
 */
void element_init_vector_G1(pairing_t _pairing, vecter_t _v, int _size)
{
	int i;
	_v->size = _size;
	_v->val = (element_t *) malloc (_size * sizeof(element_t));
	for(i=0; i<_size; i++)
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
	for(i=0; i<_size; i++)
		element_init_Zr(_v->val[i], _pairing);
}


/*
 * Generate random value.
 */
void element_random_vector(vecter_t _v)
{
	int i;
	for(i=0; i<_v->size; i++)
		element_random(_v->val[i]);
}
