#include "lib-proxyUnprotected-monoSign.h"

void computeUnMonoSign(message_t message,proxyUnprotected_monoSign_t monoUnSign,rsa_keysOwner_t keysOwner, signKey_user_t signKeyUser,gmp_randstate_t prng, int hash_out)
{
    //assert(monoUnSign);
    //mpz_inits(monoUnSign->k,monoUnSign->y,NULL);
    monoUnSign->m = message->message;
    monoUnSign->mw = signKeyUser->mw;
    monoUnSign->sn = signKeyUser->sn;

    
    mpz_t t;
    randGen(keysOwner, prng,t);
    //gmp_printf("\n Il numero random:\n %Zd", *t);
    mpz_t r;
    mpz_init(r);
    mpz_powm(r,t,keysOwner->e,keysOwner->n);
    //gmp_printf("\nIl valore di r:\n %Zd", r);

    mpz_t k; 
    computeMpzHash(monoUnSign,r, hash_out,k);
    mpz_set(monoUnSign->k, k);
    //gmp_printf("\n Il valore di k:\n %Zd", *k);
    //gmp_printf("\n il valore di k nello struct: \n %Zd", monoUnSign->k);


    mpz_t y; 
    mpz_t vik;
    mpz_inits(y,vik,NULL);
    mpz_powm(vik,signKeyUser->vi,k,keysOwner->n);
    mpz_mul(y,t,vik);
    mpz_mod(y,y,keysOwner->n);
    mpz_set(monoUnSign->y,y);
    //gmp_printf("\n il valore di y: \n %Zd", monoUnSign->y);



    
    pmesg_mpz(msg_verbose, "valore y monofirma proxy non protetto", monoUnSign->y);
    pmesg_mpz(msg_verbose, "valore k monofirma proxy non protetto", monoUnSign->k);



        

}
