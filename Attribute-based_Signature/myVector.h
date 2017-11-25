#ifndef __MY_VECTOR_H__
#define __MY_VECTOR_H__

#include <pbc/pbc.h>
#include <stdlib.h>
#include <time.h>

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
void element_get_random_in_vector(vecter_t _vo, vecter_t _vi, int _cnt);
void element_copy_vector(vecter_t _vo, vecter_t _vi);
void element_clear_vector(vecter_t _v);
vecter_ptr element_get_intersection_vector_Zr(pairing_t _pairing, vecter_t _v0, vecter_t _v1);
/* End of defined function. */

#endif
