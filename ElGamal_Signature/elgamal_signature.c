#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>


/* Start of defined constant/global variables. */
#define BASE 8
const int n = SHA256_DIGEST_LENGTH * BASE;  // 256 bit = 32 * 8.
const int l = 1024;
/* End of defined constant variables. */


/* Start of defined structures. */
struct publickey_s
{
	BIGNUM p;
	BIGNUM g;
	BIGNUM y;
};

struct secretkey_s
{
	BIGNUM x;
};

struct signature_s
{
	BIGNUM r;
	BIGNUM s;
};

typedef struct publickey_s pk_t[1];
typedef struct publickey_s *pk_ptr;
typedef struct secretkey_s sk_t[1];
typedef struct secretkey_s *sk_ptr;
typedef struct signature_s sig_t[1];
typedef struct signature_s *sig_ptr;
/* End of defined structures. */


/* Start of defined function */
/* End of defined function */


/* Start of main function. */
int main(int argc, char *argv[])
{
	

	return 0;
}
/* End of main function. */
