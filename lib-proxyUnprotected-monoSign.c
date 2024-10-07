#include "lib-proxyUnprotected-monoSign.h"

void computeUnMonoSign(message_t message,proxyUnprotected_monoSign_t monoUnSign,rsa_keysOwner_t keysOwner, signKey_user_t signKeyUser,gmp_randstate_t prng, int hash_out)
{
    monoUnSign->m = message->message;
    monoUnSign->mw = signKeyUser->mw;
    monoUnSign->sn = signKeyUser->sn;

    
    mpz_t t;
    randGen(keysOwner, prng,t);
    mpz_t r;
    mpz_init(r);
    mpz_powm(r,t,keysOwner->e,keysOwner->n);
    mpz_t k; 
    computeMpzHash(monoUnSign,r, hash_out,k);
    mpz_set(monoUnSign->k, k);

    mpz_t y; 
    mpz_t vik;
    mpz_inits(y,vik,NULL);
    mpz_powm(vik,signKeyUser->vi,k,keysOwner->n);
    mpz_mul(y,t,vik);
    mpz_mod(y,y,keysOwner->n);
    mpz_set(monoUnSign->y,y);
    
    pmesg_mpz(msg_verbose, "valore y monofirma proxy non protetto", monoUnSign->y);
    pmesg_mpz(msg_verbose, "valore k monofirma proxy non protetto", monoUnSign->k);
}
