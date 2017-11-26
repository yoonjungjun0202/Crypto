#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pbc/pbc.h>
#include <openssl/sha.h>

#include "myVector.h"
#include "myPoly.h"
#include "myPredicate.h"

#define ELAPSEDTIME(x, y) ((float)(y-x)/CLOCKS_PER_SEC)
#define BASE 8
#define GET_BIT(data, index, base) ( ((*(data+(index/base)) & (1 << index % base)) == 0) ? 0 : 1 )
time_t startTime;
time_t endTime;


/* Start of defined constant/global variables. */
const int l = 10;	// Universal count.
const int d = 5;	// Dummy count.
const int n = SHA256_DIGEST_LENGTH * BASE;	// 256 bit = 32 * 8.
const int k = 3;	// Treshhold.
const int predSCnt = 5;
const int userSCnt = 5;

const char *kDefaultFilename = "./param/a.param";
vecter_t univS;	// Universal set.
vecter_t dummyS;	// Dummy set.
vecter_t userS;	// User set.
poly_t q;		// Polynomial.
/* End of defined constant variables. */


/* Start of defined structures. */
struct publickey_s
{
	element_t g;
	element_t g1;
	element_t g2;
	element_t u;
	element_t Z;
	vecter_t H;
	vecter_t U;
};

struct masterkey_s
{
	element_t x;
};

struct privatekey_s
{
	vecter_t d0;
	vecter_t d1;
	vecter_ptr attrS;
};

struct signatures_s
{
	element_t sig0;
	element_t sig1;
	vecter_t sigi;
	vecter_ptr attrS;
};

typedef struct publickey_s pk_t[1];
typedef struct masterkey_s mk_t[1];
typedef struct privatekey_s ask_t[1];
typedef struct signatures_s sig_t[1];
typedef struct publickey_s *pk_ptr;
typedef struct masterkey_s *mk_ptr;
typedef struct privatekey_s *ask_ptr;
typedef struct signatures_s *sig_ptr;
/* End of defined structures. */


/* Start of defined functions. */
/*
 * Initialize pairing.
 * Read file to initialize pairing.
 * Returns 0 on success, 1 on failure.
 */
int init_pairing(pairing_t _pairing, const char *_filename)
{
	FILE *fp = NULL;
	char param[1024];
	size_t count;
	int res;

	if (NULL == (fp = fopen(_filename, "r"))) pbc_die("file open error");
	count = fread(param, 1, 1024, fp);
	if (!count) pbc_die("input error");
	res = pairing_init_set_buf(_pairing, param, count);
	fclose(fp);

	return res;
}


/*
 * Setup algorithm.
 * Generate PK, MK.
 * Attribute set setup.
 */
void abs_setup(pairing_t _pairing, pk_t _pk, mk_t _mk)
{
	int i, j;

	// Allocate parameters.
	element_init_G1(_pk->g, _pairing);
	element_init_G1(_pk->g1, _pairing);
	element_init_G1(_pk->g2, _pairing);
	element_init_G1(_pk->u, _pairing);
	element_init_Zr(_mk->x, _pairing);
	element_init_GT(_pk->Z, _pairing);
	element_init_vector_G1(_pairing, _pk->H, l+d-1);
	element_init_vector_G1(_pairing, _pk->U, n);
	element_init_vector_Zr(_pairing, univS, l);
	element_init_vector_Zr(_pairing, dummyS, d-1);

	// Set attribute set.
	for(i=0; i<l; ++i) element_set_si(univS->val[i], i);
	for(j=0; j<d-1; ++j) element_set_si(dummyS->val[j], i+j); 

	// Generate master key.
	element_random(_mk->x);

	// Generate params.
	element_random(_pk->g);
	element_pow_zn(_pk->g1, _pk->g, _mk->x);
	element_random(_pk->g2);
	element_random(_pk->u);
	element_random_vector(_pk->H);
	element_random_vector(_pk->U);
	element_pairing(_pk->Z, _pk->g1, _pk->g2);
}

/*
 * Extract algorithm.
 * Generate attribute private key.
 */
void abs_extract(pairing_t _pairing, ask_t _ask, mk_t _mk, pk_t _pk, vecter_t _userSet)
{
	int i, j;
	element_t y, r, gh;

	// Set polynomial.
	element_init_poly_Zr(_pairing, q, d-1);
	element_random_poly(q, _mk->x);

	// Generate attribute private key.
	_ask->attrS = element_get_union_vector_Zr(_pairing, _userSet, dummyS);
//	element_init_vector_Zr(_pairing, _ask->attrS, _userSet->size + dummyS->size);
//	for(i=0; i<dummyS->size; ++i) element_set(_ask->attrS->val[i], dummyS->val[i]);
//	for(j=0; j<_userSet->size; ++j) element_set(_ask->attrS->val[i+j], _userSet->val[j]);

	element_init_Zr(y, _pairing);
	element_init_Zr(r, _pairing);
	element_init_G1(gh, _pairing);
	element_init_vector_G1(_pairing, _ask->d0, _ask->attrS->size);
	element_init_vector_G1(_pairing, _ask->d1, _ask->attrS->size);
	for(i=0; i<_ask->attrS->size; ++i)
	{
		element_get_y_poly(_pairing, y, q, _ask->attrS->val[i]);

		element_random(r);
		element_mul(gh, _pk->g1, _pk->H->val[i]);
		element_pow2_zn(_ask->d0->val[i], _pk->g2, y, gh, r);

		element_pow_zn(_ask->d1->val[i], _pk->g, r);
	}


	element_clear(y);
	element_clear(r);
	element_clear(gh);
}

/*
 * Sign algorithm.
 * Generate signature.
 */
void abs_sign(pairing_t _pairing, sig_t _sig, char *_msg, ask_t _ask, pred_t _pred, pk_t _pk)
{
	// msg = (u0, u1, u2, ..., un)
	int i, j, flag, idx;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	vecter_t ddS;
	vecter_ptr inter_ddS = NULL;
	vecter_ptr intersection = NULL;
	element_t s, u, r, coef, zero, tmp;
	SHA256_CTX ctx;
	mpz_t z;
   
	// Check doest intersection exist.
	// If exist, get intersection.
	// Otherwise, abort;
	intersection = element_get_intersection_vector_Zr(_pairing, _pred->predS, userS);
	if(NULL == intersection)
	{
		printf("There is no intersection.\n");
		return;
	}

	if(intersection->size < _pred->k)
	{
		printf("Intersection is not enough.\n");
		goto INTER_CLEAR;
		return;
	}

	// Set dummy set.
	element_init_vector_Zr(_pairing, ddS, d - _pred->k);
	element_get_random_in_vector(ddS, dummyS, ddS->size);

	// Hashing the message.
	SHA256_Init(&ctx); 
	SHA256_Update(&ctx, (unsigned char *) _msg, strlen(_msg)); 
	SHA256_Final(hash, &ctx);


	// Generate signature.
	// sig0.
	element_init_G1(_sig->sig0, _pairing);
	element_init_Zr(s, _pairing);
	element_init_Zr(u, _pairing);
	element_set(u, _pk->u);
	element_random(s);
	for(i=0; i<n; i++)
		if(1 == GET_BIT(hash, i, BASE))
			element_mul(u, u, _pk->U->val[i]);
	element_pow_zn(_sig->sig0, u, s);


	// sig0 & sigi.
	mpz_init(z);
	element_init_Zr(r, _pairing);
	element_init_Zr(tmp, _pairing);
	element_init_Zr(zero, _pairing);
	element_init_Zr(coef, _pairing);
	element_set0(zero);
	_sig->attrS = element_get_union_vector_Zr(_pairing, _pred->predS, ddS);
	inter_ddS = element_get_union_vector_Zr(_pairing, intersection, ddS);
	element_init_vector_G1(_pairing, _sig->sigi, _sig->attrS->size);
	for(i=0; i<_sig->attrS->size; ++i)
	{
		flag = 0;

		element_random(r);
		// sig0.
		element_to_mpz(z, _sig->attrS->val[i]);
		idx = mpz_get_ui(z);

		element_pow2_zn(tmp, _pk->g1, r, _pk->H->val[idx], r);
		element_mul(_sig->sig0, _sig->sig0, tmp);


		// sigi.
		element_pow_zn(_sig->sigi->val[i], _pk->g, r);


		for(j=0; j<intersection->size; ++j)
		{
			if(0 == element_cmp(_ask->attrS->val[i], intersection->val[j]))
			{
				//sig0.
				element_lagrange_interpolation(_pairing, coef, inter_ddS, intersection->val[j], zero);
				element_pow_zn(tmp, _ask->d0->val[i], coef);
				element_mul(_sig->sig0, _sig->sig0, tmp);


				//sigi.
				element_lagrange_interpolation(_pairing, coef, inter_ddS, intersection->val[j], zero);
				element_pow_zn(tmp, _ask->d1->val[i], coef);
				element_mul(_sig->sigi->val[i], _sig->sigi->val[i], tmp);

				flag = 1;
				break;
			}
		}

		if(1 == flag)
			continue;

		for(j=0; j<ddS->size; ++j)
		{
			if(0 == element_cmp(_ask->attrS->val[i], ddS->val[j]))
			{
				// sig0.
				element_lagrange_interpolation(_pairing, coef, inter_ddS, ddS->val[j], zero);
				element_pow_zn(tmp, _ask->d0->val[i], coef);
				element_mul(_sig->sig0, _sig->sig0, tmp);


				// sigi.
				element_lagrange_interpolation(_pairing, coef, inter_ddS, ddS->val[j], zero);
				element_pow_zn(tmp, _ask->d0->val[i], coef);
				element_mul(_sig->sigi->val[i], _sig->sigi->val[i], tmp);
				break;
			}
		}
	}


	// sig1.
	element_init_G1(_sig->sig1, _pairing);
	element_pow_zn(_sig->sig1, _pk->g, s);


	mpz_clear(z);
	element_clear(s);
	element_clear(u);
	element_clear(r);
	element_clear(tmp);
	element_clear(coef);
	element_clear(zero);
	element_clear_vector(ddS);
	element_clear_vector(inter_ddS);
	free(inter_ddS);
INTER_CLEAR:
	element_clear_vector(intersection);
	free(intersection);
}

/*
 * Clear algorithm.
 */
void abs_clear(pk_t _pk, mk_t _mk, ask_t _ask, sig_t _sig)
{
	// Public key clear.
	element_clear(_pk->g);
	element_clear(_pk->g1);
	element_clear(_pk->g2);
	element_clear(_pk->u);
	element_clear(_pk->Z);
	element_clear_vector(_pk->H);
	element_clear_vector(_pk->U);

	// Master key clear.
	element_clear(_mk->x);

	// Attribute private key clear.
	element_clear_vector(_ask->d0);
	element_clear_vector(_ask->d1);

	// Signature clear.
	/*
	element_clear(_sig->sig0);
	element_clear(_sig->sig1);
	element_clear_vector(_sig->sigi);
	*/
}
/* End of defined functions. */


/* Start of main function. */
int main(int argc, char *argv[])
{
	// Declare local variables of main function.
	pairing_t pairing;
	pk_t pk;
	mk_t mk;
	ask_t ask;
	sig_t sig;
	pred_t pred;
	char *msg = "Attribute-based Signature and its Applications.";


	// Initailize Pairing.
	if (2 == argc) init_pairing(pairing, argv[1]);
	else init_pairing(pairing, kDefaultFilename);


	// Test ABS algorithm.
	// 1. Generate public/master key.
	abs_setup(pairing, pk, mk);

	// 2. Initialize user attribute set & Extract attribute private key.
	element_init_vector_Zr(pairing, userS, userSCnt);
	element_get_random_in_vector(userS, univS, userS->size);
	abs_extract(pairing, ask, mk, pk, userS);

	// 3. Initialize predicate & Generate Signature.
	element_init_predicate(pairing, pred, predSCnt, k);
	element_get_random_in_attrSet(pred, userS, univS);
	abs_sign(pairing, sig, msg, ask, pred, pk);

	// 4. Verify signature.


	
	printf("\n## univS: \n");
	for(int i=0; i<univS->size; i++) element_printf("%B, ", univS->val[i]);
	printf("\n## dummyS: \n");
	for(int i=0; i<dummyS->size; i++) element_printf("%B, ", dummyS->val[i]);
	printf("\n## userS: \n");
	for(int i=0; i<userS->size; i++) element_printf("%B, ", userS->val[i]);
	printf("\n## predicateS: \n");
	for(int i=0; i<pred->predS->size; i++) element_printf("%B, ", pred->predS->val[i]);
	printf("\n## dummyS/userS union: \n");
	for(int i=0; i<ask->attrS->size; i++) element_printf("%B, ", ask->attrS->val[i]);
	printf("\n## user/pred inter: \n");
	vecter_ptr inter = element_get_intersection_vector_Zr(pairing, pred->predS, userS);
	for(int i=0; i<inter->size; i++) element_printf("%B, ", inter->val[i]);
	printf("\n");
	element_clear_vector(inter);
	free(inter);
	printf("\n## union: \n");
	vecter_ptr uni = element_get_union_vector_Zr(pairing, pred->predS, userS);
	for(int i=0; i<uni->size; i++) element_printf("%B, ", uni->val[i]);
	printf("\n");
	for(int i=0; i<uni->size; i++)
	{
		mpz_t z;
		mpz_init(z);
		element_to_mpz(z, uni->val[i]);
		printf("%d, ", mpz_get_ui(z));
		mpz_clear(z);
	}
	printf("\n");
	element_clear_vector(uni);
	free(uni);


	// clean memory.
	abs_clear(pk, mk, ask, sig);
	pairing_clear(pairing);
	element_clear_predicate(pred);
	element_clear_vector(univS);
	element_clear_vector(dummyS);
	element_clear_vector(userS);

	return 0;
}
/* End of main function. */
