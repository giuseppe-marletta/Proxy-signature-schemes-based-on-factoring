#ifndef LIB_PROXYPROTECTED_MULTISIGN_H
#define LIB_PROXYPROTECTED_MULTISIGN_H


#include <gmp.h>
#include <stdio.h>
#include "lib-shared.h"
#include "lib-data.h"




void computeProtMultiSign(message_t message, proxyProtected_multiSign_t multiProtSign,rsa_keysOwner_t keysOwner, signKeyPool_usersProt_t signKeyPoolUsersProt,gmp_randstate_t prng, int hash_out, int fixed_n_signers);
void verifyYK (mpz_t Ri, mpz_t Yi, mpz_t Ki, mpz_t k, int i, signKeyPool_usersProt_t signKeyPoolUsersProt, rsa_keysOwner_t keysOwner, int hash_out);







#endif