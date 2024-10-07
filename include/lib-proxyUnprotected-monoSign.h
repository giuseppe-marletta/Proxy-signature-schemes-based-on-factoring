#ifndef LIB_PROXYUNPROTECTED_MONOSIGN_H
#define LIB_PROXYUNPROTECTED_MONOSIGN_H


#include <gmp.h>
#include <stdio.h>
#include "lib-shared.h"
#include "lib-data.h"




void computeUnMonoSign(message_t message, proxyUnprotected_monoSign_t monoUnSign,rsa_keysOwner_t keysOwner, signKey_user_t signKeyUser,gmp_randstate_t prng, int hash_out);






#endif