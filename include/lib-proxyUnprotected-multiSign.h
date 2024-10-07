#ifndef LIB_PROXYUNPROTECTED_MULTISIGN_H
#define LIB_PROXYUNPROTECTED_MULTISIGN_H


#include <gmp.h>
#include <stdio.h>
#include "lib-shared.h"
#include "lib-data.h"




void computeUnMultiSign(message_t message, proxyUnprotected_multiSign_t multiUnSign,rsa_keysOwner_t keysOwner, signKeyPool_users_t signKeyPoolUsers,gmp_randstate_t prng, int hash_out, int fixed_n_signers);
void verifyY (mpz_t Ri, mpz_t Yi, int i, signKeyPool_users_t signKeyPoolUsers, rsa_keysOwner_t keysOwner, proxyUnprotected_multiSign_t multiUnSign, int hash_out);







#endif