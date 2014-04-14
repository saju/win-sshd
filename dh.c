/*
  Diffie Hellman key exchange algorithm - RFC 2631
*/

#include <stdlib.h>
#include "log.h"
#include "ssh.h"

#define CRYPTO_INTERNAL
#include "crypto.h"

/* Well known oakley group 2 & 14 primes (rfc 3526 & 2049) */
const char *oakley2_prime = 
	"FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	"29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	"EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	"E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	"EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE65381"
	"FFFFFFFF" "FFFFFFFF";

const char *oakley14_prime = 
	"FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	"29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	"EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	"E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	"EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
	"C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
	"83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
	"670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
	"E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
	"DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
	"15728E5A" "8AACAA68" "FFFFFFFF" "FFFFFFFF";

mpz_t oakley_2, oakley_14;

void dh_init() {
	mpz_init(oakley_2);
	mpz_init(oakley_14);

	mpz_set_str(oakley_2, oakley2_prime, 16);
	mpz_set_str(oakley_14, oakley14_prime, 16);
}

/**
   client_public_key - g^a mod p from client

   dh_group - the Diffie Hellman Oakley Group (used to select/preseed, prime & generator)

   cipher   - the symmetric cipher for which keying material has to be generated. The secret
   DH key (g^a mod p)^b should be suitable keying material for the cipher. Knowing the cipher
   to be used allows to select a wide enough private exponent 'b' (cipher key size * 2 bits).
**/
int dh_kex(mpz_t *e, int algo, unsigned long want_keylen, mpz_t *f, mpz_t *K) {
	mpz_t p, y, g;
	gmp_randstate_t *rand = crypto_randctx();
	unsigned long client_keylen;

	if (algo == DH1)
		mpz_init_set(p, oakley_2);
	else if (algo == DH14)
		mpz_init_set(p, oakley_14);
	else
		return 1;

	client_keylen = (unsigned long)mpz_sizeinbase(*e, 2) / 8;
	want_keylen = (client_keylen > want_keylen) ? client_keylen : want_keylen;

	/* generator = 2 */
	mpz_init_set_ui(g, 2UL);
	
	/* private exponent */
	mpz_init(y);
	mpz_urandomb(y, *rand, want_keylen);

	/* f = g^y mod p */
	mpz_powm(*f, g, y, p);
	
	/* K = e^y mod p */
	mpz_powm(*K, *e, y, p);
	
	mpz_clear(p);
	mpz_clear(y);
	mpz_clear(g);
	return 0;
}


	

