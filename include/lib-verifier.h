#ifndef LIB_VERIFIER_H
#define LIB_VERIFIER_H

#include <gmp.h>
#include <stdio.h>
#include "lib-data.h"
#include "lib-OwnerSigner.h"
#include "lib-shared.h"


void verifyProxySignerKey(signKey_user_t signKeyUser,rsa_keysOwner_t keysOwner, int hash_out);
void verifyProxySignerProtKey(signKey_userProt_t signKeyUserProt, rsa_keysOwner_t keysOwner, int hash_out);
void verifyProxyUnprotectedMonoSign(rsa_keysOwner_t keysOwner, proxyUnprotected_monoSign_t monoUnSign,signKey_user_t signKeyUser, int hash_out);
void verifyProxyUnprotectedMultiSign(rsa_keysOwner_t keysOwner, proxyUnprotected_multiSign_t multiUnSign, signKeyPool_users_t signKeyPoolUsers, int hash_out, int fixed_n_signers);
void verifyProxyProtectedMonoSign(rsa_keysOwner_t keysOwner, proxyprotected_monoSign_t monoProtSign,signKey_userProt_t signKeyUserProt, int hash_out);
void verifyProxyProtectedMultiSign(rsa_keysOwner_t keysOwner, proxyProtected_multiSign_t multiProtSign, signKeyPool_usersProt_t signKeyPoolUsersProt, int hash_out, int fixed_n_signers);



#endif
