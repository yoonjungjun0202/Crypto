#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>


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
	BIGNUM *two;

	// Initialize parameters.
	tmp = BN_new();
	two = BN_new();

	_pk->p = BN_new();
	_pk->g = BN_new();
	_pk->y = BN_new();

	_sk->x = BN_new();

	// Generate l bit prime.
	RAND_seed(seed, seedSize);
	while(0 == BN_generate_prime_ex(_pk->p, l, 0, NULL, NULL, NULL));

	// Generate x. (1 < x < p-1)
	BN_set_word(two, 2);
	BN_copy(tmp, _pk->p);
	BN_sub_word(tmp, 3);
	BN_rand_range(_sk->x, tmp);
	BN_add(_sk->x, _sk->x, two);

	// Genearte generator g.
	BN_set_word(tmp, 17);
	BN_exp(_pk->g, two, tmp, _ctx);

	// Generate y.
	BN_mod_exp(_pk->y, _pk->g, _sk->x, _pk->p, _ctx);


	// clear.
	BN_clear_free(tmp);
	BN_clear_free(two);
}
/* End of defined function */

void elgamal_sign(BN_CTX *_ctx, unsigned char *_msg, sig_t _sig, sk_t _sk, pk_t _pk)
{
	BIGNUM *k;
	BIGNUM *k_inv;
	BIGNUM *xr;
	BIGNUM *gcd;
	BIGNUM *tmp;
	BIGNUM *hash;

	// Initialize parameters.
	k = BN_new();
	k_inv = BN_new();
	xr = BN_new();
	gcd = BN_new();
	tmp = BN_new();
	hash = BN_new();

	_sig->r = BN_new();
	_sig->s = BN_new();

	// Generate k. (0 < k < p-1)
	while(1)
	{
		BN_copy(tmp, _pk->p);
		BN_sub_word(tmp, 2);
		BN_rand_range(k, tmp);
		BN_add_word(k, 1);

		BN_copy(tmp, _pk->p);
		BN_sub_word(tmp, 1);
		BN_gcd(gcd, k, tmp, _ctx);
		if(0 == BN_cmp(gcd, BN_value_one()))
			break;
	}

	// Compute r.
	BN_mod_exp(_sig->r, _pk->g, k, _pk->p, _ctx);
	
	// Compute s.
	// Hashing the message.
	BN_hash(&hash, _msg);

	BN_mod_inverse(k_inv, k, _pk->p, _ctx);
	BN_mod_mul(xr, _sk->x, _sig->r, _pk->p, _ctx);


	// clear.
	BN_clear_free(k);
	BN_clear_free(k_inv);
	BN_clear_free(xr);
	BN_clear_free(gcd);
	BN_clear_free(tmp);
	BN_clear_free(hash);
}

int elgamal_verify()
{
	/*
	// Hashing the message.
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (unsigned char *) _msg, strlen(_msg));
    SHA256_Final(hash, &ctx);
	*/
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
