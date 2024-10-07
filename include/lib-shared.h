#ifndef LIB_SHARED_H
#define LIB_SHARED_H


#include <gmp.h>
#include "lib-misc.h"
#include "lib-OwnerSigner.h"
#include "lib-proxyUnprotected-monoSign.h"
#include "lib-data.h"





void randGen(rsa_keysOwner_t keysOwner,gmp_randstate_t prng, mpz_t rannum);
void  computeMpzHash(message_t message, mpz_t r, int hash_out, mpz_t hash_value);
void computeHash(signKey_user_t signKeyUser,rsa_keysOwner_t keysOwner, int hash_out, mpz_t hash_value);
void computeHashProt(signKey_userProt_t signKeyUserProt, int hash_out, mpz_t hash_value);
void compute_hash_by_hash_out(int hash_out,size_t block_size_uno, char* block_to_hash_uno, size_t block_size_due, char* block_to_hash_due, mpz_t hash_value);


#endif