#include "myPoly.h"

void element_init_poly_Zr(pairing_t _pairing, poly_t _q, int _degree)
{
	vecter_ptr tmp = (vecter_ptr) _q;
	element_init_vector_Zr(_pairing, tmp, _degree);
}

void element_random_poly(poly_t _q)
{
	vecter_ptr tmp = (vecter_ptr) _q;
	element_random_vector(tmp);
}

void element_set_coef_poly(poly_t _q, element_t _coef, int _idx)
{
	element_set(_q->val[_idx], _coef);
}

void element_get_y_poly(pairing_t _pairing, element_t _y, poly_t _q, element_t _x)
{
	int i;
	element_t tmp;
	
	element_init_Zr(tmp, _pairing);
	element_set(_y, _q->coef[0]);
	for(i=1; i<_q->degree; ++i)
	{
		element_mul(tmp, _q->coef[i], _x);
		element_add(_y, _y, tmp);
	}

	element_clear(tmp);
}

void element_lagrange_interpolation(pairing_t _pairing, element_t _coef, vecter_t _s, element_t _j, element_t _i)
{
	int i;
	element_t tmp;
	element_t numerator;
	element_t denominator;

	element_init_Zr(tmp, _pairing);
	element_init_Zr(numerator, _pairing);
	element_init_Zr(denominator, _pairing);


	element_set1(numerator);
	element_set1(denominator);
	for(i=0; i<_s->size; ++i)
	{
		if(0 == element_cmp(_s->val[i], _j))
			continue;

		element_sub(tmp, _i, _s->val[i]);
		element_mul(numerator, numerator, tmp);
		element_sub(tmp, _j, _s->val[i]);
		element_mul(denominator, denominator, tmp);
	}
	element_div(_coef, numerator, denominator);


	element_clear(tmp);
	element_clear(numerator);
	element_clear(denominator);
}
