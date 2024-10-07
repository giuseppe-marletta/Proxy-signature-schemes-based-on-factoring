#ifndef LIB_PROXYPROTECTED_MONOSIGN_H
#define LIB_PROXYPROTECTED_MONOSIGN_H


#include <gmp.h>
#include <stdio.h>
#include "lib-shared.h"
#include "lib-data.h"




void computeProtMonoSign(message_t message, proxyprotected_monoSign_t monoProtSign,rsa_keysOwner_t keysOwner, signKey_userProt_t signKeyUserProt ,gmp_randstate_t prng, int hash_out);






#endif