#ifndef __MY_PREDICATE_H__
#define __MY_PREDICATE_H__

#include "myVector.h"

/* Start of defined structures. */
struct predicate_s
{   
	int k;
	vecter_t predS;
};

typedef struct predicate_s pred_t[1];
typedef struct predicate_s *pred_ptr;
/* End of defined structures. */

/* Start of defined functions. */
void element_init_predicate(pairing_t _pairing, pred_t _pred, int _c, int _k);
void element_get_random_in_attrSet(pred_t _pred, vecter_t _attrS, vecter_t _univS);
void element_set_attrSet(pred_t _pred, vecter_t _attrS);
void element_clear_predicate(pred_t _pred);
/* End of defined functions. */

#endif
