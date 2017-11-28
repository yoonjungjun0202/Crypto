#ifndef __MY_POLY_H__
#define __MY_POLY_H__

#include "myVector.h"

/* Start of defined structures. */
struct poly_s
{
	int degree;
	element_t *coef;
};

typedef struct poly_s poly_t[1];
typedef struct poly_s *poly_ptr;
/* End of defined structures. */


/* Start of defined function. */
void element_init_poly_Zr(pairing_t _pairing, poly_t _q, int _degree);
void element_random_poly(poly_t _q);
int element_set_coef_poly(poly_t _q, element_t _coef, int _idx);
void element_get_y_poly(pairing_t _pairing, element_t _y, poly_t _q, element_t _x);
void element_lagrange_interpolation(pairing_t _pairing, element_t _coef, vecter_t _s, element_t _j, element_t _i);
void element_clear_poly(poly_t _q);
/* End of defined function. */

#endif
