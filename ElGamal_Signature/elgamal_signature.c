#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>


/* Start of defined constant/global variables. */
#define BASE 8
const int n = SHA256_DIGEST_LENGTH * BASE;  // 256 bit = 32 * 8.
const int l = 1024;
const char seed[] = "random seed";
const int seedSize = sizeof(seed)/sizeof(seed[0]);
/* End of defined constant variables. */


/* Start of defined structures. */
struct publickey_s
{
	BIGNUM *p;
	BIGNUM *g;
	BIGNUM *y;
};

struct secretkey_s
{
	BIGNUM *x;
};

struct signature_s
{
	BIGNUM *r;
	BIGNUM *s;
};

typedef struct publickey_s pk_t[1];
typedef struct publickey_s *pk_ptr;
typedef struct secretkey_s sk_t[1];
typedef struct secretkey_s *sk_ptr;
typedef struct signature_s sig_t[1];
typedef struct signature_s *sig_ptr;
/* End of defined structures. */


#define GET8_HBIT(x) ( (x >> 4) & 0x0f )
#define GET8_LBIT(x) ( x & 0x0f )
/* Start of defined function */
void BN_ext_euclid(BIGNUM *_inv_a, const BIGNUM *_a, const BIGNUM *_n, BN_CTX *_ctx)
{
    BIGNUM *r = BN_new();
    BIGNUM *r1 = BN_dup(_a);
    BIGNUM *r2 = BN_dup(_n);
    BIGNUM *x = BN_new();
    BIGNUM *x1 = BN_new();
    BIGNUM *x2 = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *temp = BN_new();

    BN_zero(x2);
    BN_one(x1);

    while(0 == BN_is_zero(r2))
    {
        BN_div(q, temp, r1, r2, _ctx);
        BN_mul(temp, q, r2, _ctx);
        BN_sub(r, r1, temp);
        BN_copy(r1, r2);
        BN_copy(r2, r);

        BN_mul(temp, q, x2, _ctx);
        BN_sub(x, x1, temp);
        BN_copy(x1, x2);
        BN_copy(x2, x);
    }
    BN_copy(_inv_a, x1);

    BN_clear_free(temp);
    BN_clear_free(r);
    BN_clear_free(r1);
    BN_clear_free(r2);
    BN_clear_free(x);
    BN_clear_free(x1);
    BN_clear_free(x2);
    BN_clear_free(q);
}

void BN_hash(BIGNUM **_hash, unsigned char *_msg)
{
	int i, hBit, lBit;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char tmp[SHA256_DIGEST_LENGTH*2+1];

	SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, _msg, strlen(_msg));
    SHA256_Final(hash, &sha256_ctx);
	for(i=0; i<SHA256_DIGEST_LENGTH; ++i)
	{
		hBit = GET8_HBIT(hash[i]);
		lBit = GET8_LBIT(hash[i]);
		tmp[i*2] = hBit + ((0 <= hBit && hBit < 10) ? (48) : (55));
		tmp[i*2+1] = lBit + ((0 <= lBit && lBit < 10) ? (48) : (55));
	}
	tmp[i*2] = '\0';
	BN_hex2bn(_hash, tmp);
}

void elgamal_keygen(BN_CTX *_ctx, pk_t _pk, sk_t _sk)
{
	BIGNUM *tmp;

	// Initialize parameters.
	tmp = BN_new();

	_pk->p = BN_new();
	_pk->g = BN_new();
	_pk->y = BN_new();

	_sk->x = BN_new();


	// Generate l bit prime.
	RAND_seed(seed, seedSize);
	while(0 == BN_generate_prime_ex(_pk->p, l, 0, NULL, NULL, NULL));

	// Genearte generator g.
	BN_copy(tmp, _pk->p);
	BN_sub_word(tmp, 1);
	BN_rand_range(_pk->g, tmp);	// 0 <= tmp < p-1.
	BN_add_word(_pk->g, 1);		// 1 <= tmp < p.

	// Generate x. (1 < x < p-1)
	BN_sub_word(tmp, 3);
	BN_rand_range(_sk->x, tmp);	// 0 <= tmp < p-3.
	BN_add_word(_sk->x, 2);		// 2 <= tmp < p-1.

	// Generate y.
	BN_mod_exp(_pk->y, _pk->g, _sk->x, _pk->p, _ctx);


	// clear.
	BN_clear_free(tmp);
}

void elgamal_sign(BN_CTX *_ctx, unsigned char *_msg, sig_t _sig, sk_t _sk, pk_t _pk)
{
	BIGNUM *k;
	BIGNUM *k_inv;
	BIGNUM *xr;
	BIGNUM *p1;
	BIGNUM *gcd;
	BIGNUM *tmp;
	BIGNUM *hash;

	// Initialize parameters.
	k = BN_new();
	k_inv = BN_new();
	xr = BN_new();
	p1 = BN_new();
	gcd = BN_new();
	tmp = BN_new();
	hash = BN_new();

	_sig->r = BN_new();
	_sig->s = BN_new();

	// Hash the message.
	BN_hash(&hash, _msg);

	// Generate k. (0 < k < p-1)
	BN_copy(p1, _pk->p);
	BN_sub_word(p1, 1);		// p1 = p-1.
	while(1)
	{
		BN_copy(tmp, _pk->p);
		BN_sub_word(tmp, 2);	// tmp = p-2.
		while(1)
		{
			BN_rand_range(k, tmp);	// 0 <= k < p-2.
			BN_add_word(k, 1);		// 1 <= k < p-1.

			BN_gcd(gcd, k, p1, _ctx);
			if(1 == BN_is_one(gcd))	// gcd(k, p-1) = 1.
				break;
		}

		// Compute r.
		BN_mod_exp(_sig->r, _pk->g, k, _pk->p, _ctx);

		// Compute s.
		BN_mod_inverse(k_inv, k, p1, _ctx);
		BN_mod_mul(tmp, k, k_inv, p1, _ctx);
		if(0 == BN_is_one(tmp))
		{
			printf("Finding inverse of k breaks error.\n");
			exit(0);
		}

		BN_mod_mul(xr, _sk->x, _sig->r, p1, _ctx);
		BN_mod_sub(tmp , hash, xr, p1, _ctx);
		BN_mod_mul(_sig->s, tmp, k_inv, p1, _ctx);

		if(0 == BN_is_zero(_sig->s))
			break;
	}

	// clear.
	BN_clear_free(k);
	BN_clear_free(k_inv);
	BN_clear_free(xr);
	BN_clear_free(p1);
	BN_clear_free(gcd);
	BN_clear_free(tmp);
	BN_clear_free(hash);
}

int elgamal_verify()
{
    BIGNUM *hash;

}

void elgamal_clear(pk_t _pk, sk_t _sk, sig_t _sig)
{
	// Pulbic key clear.
	BN_clear_free(_pk->p);
	BN_clear_free(_pk->g);
	BN_clear_free(_pk->y);

	// Secret key clear.
	BN_clear_free(_sk->x);

	// Signature clear.
	BN_clear_free(_sig->r);
	BN_clear_free(_sig->s);
}
/* End of defined function */

/* Start of main function. */
int main(int argc, char *argv[])
{
	BN_CTX *ctx;
	pk_t pk;
	sk_t sk;
	sig_t sig;

	char *msg = "Elgamal Signature.";
	char *str = NULL;
	int isValid;

    // 1. Generate public/master key.
	ctx = BN_CTX_new();
	elgamal_keygen(ctx, pk, sk);

	// 2. Generate signature.
	elgamal_sign(ctx, msg, sig, sk, pk);

	// 3. Verify signature.
	// elgamal_verify(msg, sig, pk);

	// clean memory.
	BN_CTX_free(ctx);
	// elgamal_clear(pk, sk, sig);

	return 0;
}
/* End of main function. */
