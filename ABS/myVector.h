#ifndef __MY_VECTOR_H__
#define __MY_VECTOR_H__

#include <pbc/pbc.h>

/* Start of defined structures. */
struct vecter_s
{
	int size;
	element_t *val;
};

typedef struct vecter_s vecter_t[1];
typedef struct vecter_s *vecter_ptr;
/* End of defined structures. */


/* Start of defined function. */
void element_init_vector_G1(pairing_t _pairing, vecter_t _v, int _size);
void element_init_vector_Zr(pairing_t _pairing, vecter_t _v, int _size);
void element_random_vector(vecter_t _v);
/* End of defined function. */

#endif
