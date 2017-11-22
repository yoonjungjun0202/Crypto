#include <pbc/pbc.h>


/* Start of defined constant/global variables. */
const char *kDefaultFilename = "./param/a.param"
element_t *universalAttributeSet;
element_t *DummyAttributeSet;
/* End of defined constant variables. */


/* Start of defined structures. */
// will make vecter file.
struct vecter_s
{
	int size;
	element_t *data;
}

typedef struct vecter_s vecter_t[1];
typedef struct vecter_s *vecter_ptr;

struct publickey_s
{
	element_t g;
	element_t g1;
	element_t g2;
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
};

struct signatures_s
{
	element_t sig0;
	element_t sig1;
	vecter_t sigi;
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
int init_pairing(pairing_t _pairing, char *filename)
{
	FILE *fp = NULL;
	char param[1024];
	size_t count;
	int res;

	if (NULL == (fp = fopen(filename, "r"))) pbc_die("file open error");
	count = fread(param, 1, 1024, stdin);
	if (!count) pbc_die("input error");
	res = pairing_init_set_buf(pairing, param, count);
	fclose(fp);

	return res;
}
/* End of defined functions. */


/* Start of main function. */
int main(int argc, char *argv[])
{
	// Declare local variables of main function.
	pairing_t pairing;

	element_t g, h;
	element_t public_key, secret_key;
	element_t sig;
	element_t temp1, temp2;


	// Initailize Pairing.
	if (2 == argc) init_pairing(pairing, argv[1]);
	else init_pairing(pairing, kDefaultFilename)


	return 0;
}
/*
	element_init_G2(g, pairing);
	element_init_G2(public_key, pairing);
	element_init_G1(h, pairing);
	element_init_G1(sig, pairing);
	element_init_GT(temp1, pairing);
	element_init_GT(temp2, pairing);
	element_init_Zr(secret_key, pairing);

	element_random(g);
	element_random(secret_key);
	element_pow_zn(public_key, g, secret_key);

	element_from_hash(h, "ABCDEF", 6);
	element_pow_zn(sig, h, secret_key);

	pairing_apply(temp1, sig, g, pairing);
	pairing_apply(temp2, h, public_key, pairing);
	if (!element_cmp(temp1, temp2)) {
		    printf("signature verifies\n");
	} else {
		    printf("signature does not verify\n");
	}
*/
/* End of main function. */
