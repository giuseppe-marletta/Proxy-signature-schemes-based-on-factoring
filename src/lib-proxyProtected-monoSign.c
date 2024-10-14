#include "lib-proxyProtected-monoSign.h"

void computeProtMonoSign(message_t message, proxyprotected_monoSign_t monoProtSign,rsa_keysOwner_t keysOwner, signKey_userProt_t signKeyUserProt ,gmp_randstate_t prng, int hash_out)
{
    monoProtSign->m = message->message;
    monoProtSign->mw = signKeyUserProt->mw;
    monoProtSign->id = signKeyUserProt->id;

    
    mpz_t t;
    randGen(keysOwner, prng,t);
    mpz_t r;
    mpz_init(r);
    mpz_powm(r,t,keysOwner->e,keysOwner->n);

    mpz_t k;
    computeMpzHash(monoProtSign,r,hash_out,k);
    mpz_t u;
    mpz_init(u);
    mpz_powm(u,k,signKeyUserProt->d,signKeyUserProt->n);
    mpz_set(monoProtSign->u, u);
    
    mpz_t y; 
    mpz_t vik;
    mpz_inits(y,vik,NULL);
    mpz_powm(vik,signKeyUserProt->vi,k,keysOwner->n);
    mpz_mul(y,t,vik);
    mpz_mod(y,y,keysOwner->n);
    mpz_set(monoProtSign->y,y);
    

    pmesg_mpz(msg_verbose, "valore y monofirma proxy protetto", monoProtSign->y);
    pmesg_mpz(msg_verbose, "valore u monofirma proxy protetto", monoProtSign->u);

}