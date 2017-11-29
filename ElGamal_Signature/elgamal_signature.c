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


/* Start of defined function */
void elgamal_keygen(BN_CTX *_ctx, pk_t _pk, sk_t _sk)
{
	BIGNUM *tmp;
	BIGNUM *two;
	BIGNUM *three;

	// Initialize parameters.
	tmp = BN_new();
	two = BN_new();
	three = BN_new();

	_pk->p = BN_new();
	_pk->g = BN_new();
	_pk->y = BN_new();

	_sk->x = BN_new();

	// Generate l bit prime.
	RAND_seed(seed, seedSize);
	while(0 == BN_generate_prime_ex(_pk->p, l, 0, NULL, NULL, NULL));

	// Generate x. (1 < x < p-1).
	BN_set_word(two, 2);
	BN_set_word(three, 3);

	BN_copy(tmp, _pk->p);
	BN_sub(tmp, tmp, three);
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
	BN_clear_free(three);
}
/* End of defined function */

void elgamal_sign()
{
	/*
	// Hashing the message.
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (unsigned char *) _msg, strlen(_msg));
    SHA256_Final(hash, &ctx);
	*/
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
	// elgamal_sign(msg, sk);

	// 3. Verify signature.
	// elgamal_verify(msg, sig, pk);

	// clean memory.
	BN_CTX_free(ctx);
	// elgamal_clear(pk, sk, sig);

	return 0;
}
/* End of main function. */
