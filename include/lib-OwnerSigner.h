#ifndef LIB_OWNERSIGNER_H
#define LIB_OWNERSIGNER_H

#include <gmp.h>
#include <stdio.h>
#include "lib-rsa-enc.h"
#include "lib-misc.h"
#include <nettle/sha2.h>
#include "lib-data.h"
#include "lib-shared.h"
#include <time.h>









void RsaKeyGeneration(rsa_keysOwner_t keysOwner,gmp_randstate_t prng, int mod_bits);
void SignKeyProxyUsersGeneration(signKey_user_t signKeyUser,rsa_keysOwner_t keysOwner,char* mw, int sn, int hash_out);
void SignKeyProxyUsersMultiGeneration(signKeyPool_users_t signKeyPoolUsers ,rsa_keysOwner_t keysOwner,char* mw, int sn[], int hash_out, int fixed_n_signers);
void SignKeyProxyUsersProtGeneration(signKey_userProt_t signKeyUserProt,rsa_keysOwner_t keysOwner,char* mw, gmp_randstate_t prng, int mod_bits, int hash_out);
void SignKeyProxyUsersProtMultiGeneration(signKeyPool_usersProt_t signKeyPoolUsersProt ,rsa_keysOwner_t keysOwner,char* mw, gmp_randstate_t prng, int mod_bits, int hash_out, int fixed_n_signers);

#endif