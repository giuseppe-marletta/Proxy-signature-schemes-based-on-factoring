#include "lib-proxyProtected-multiSign.h"


void computeProtMultiSign(message_t message, proxyProtected_multiSign_t multiProtSign,rsa_keysOwner_t keysOwner, signKeyPool_usersProt_t signKeyPoolUsersProt,gmp_randstate_t prng, int hash_out, int fixed_n_signers)
{   
    multiProtSign->m = message->message;
    multiProtSign->mw = signKeyPoolUsersProt->signKeys_usersProt[0]->mw;

    mpz_t Ri[fixed_n_signers];
    mpz_t t[fixed_n_signers];
    for(int i = 0; i < fixed_n_signers; i++)
    {
        multiProtSign->id[i] = signKeyPoolUsersProt->signKeys_usersProt[i]->id;
        randGen(keysOwner, prng,t[i]);
        mpz_init(Ri[i]);
        if(i == 0)
        {
            mpz_powm(Ri[i],t[i],keysOwner->e,keysOwner->n);
        }
        else
        {
            mpz_powm(Ri[i],t[i],keysOwner->e,keysOwner->n);
            mpz_mul(Ri[i],Ri[i-1],Ri[i]);
            mpz_mod(Ri[i], Ri[i], keysOwner->n);
        }
    }
    mpz_t k; 
    computeMpzHash(multiProtSign->m,Ri[fixed_n_signers-1], hash_out,k);
    mpz_t Yi[fixed_n_signers];
    mpz_t Ki[fixed_n_signers];


    for(int i = 0; i < fixed_n_signers; i++)
    {
        mpz_init(Yi[i]);
        mpz_init(Ki[i]);
        if(i == 0)
        {
            mpz_powm(Yi[i],signKeyPoolUsersProt->signKeys_usersProt[i]->vi,k,keysOwner->n);
            mpz_mul(Yi[i],t[i],Yi[i]);
            mpz_mod(Yi[i],Yi[i],keysOwner->n);
            mpz_powm(Ki[i], k, signKeyPoolUsersProt->signKeys_usersProt[i]->d, signKeyPoolUsersProt->signKeys_usersProt[i]->n);
        }
        else
        {
            verifyYK(Ri[i-1],Yi[i-1], Ki[i-1], k, i, signKeyPoolUsersProt,keysOwner, hash_out);
            mpz_powm(Yi[i],signKeyPoolUsersProt->signKeys_usersProt[i]->vi,k,keysOwner->n);
            mpz_mul(Yi[i],t[i],Yi[i]);
            mpz_mul(Yi[i],Yi[i-1],Yi[i]);
            mpz_mod(Yi[i],Yi[i],keysOwner->n);
            mpz_powm(Ki[i], Ki[i-1], signKeyPoolUsersProt->signKeys_usersProt[i]->d, signKeyPoolUsersProt->signKeys_usersProt[i]->n);
        } 
    }
    mpz_set(multiProtSign->y, Yi[fixed_n_signers-1]);
    mpz_set(multiProtSign->u, Ki[fixed_n_signers-1]);
}

void verifyYK (mpz_t Ri, mpz_t Yi, mpz_t Ki, mpz_t k, int i, signKeyPool_usersProt_t signKeyPoolUsersProt, rsa_keysOwner_t keysOwner, int hash_out)
{
    mpz_t firstM, secondM;
    mpz_t yie;
    mpz_t kie;
    mpz_inits(firstM, secondM, yie, kie, NULL);
    

    mpz_t hk;
    computeHashProt(signKeyPoolUsersProt->signKeys_usersProt[0], hash_out,hk);
    if(i > 1)
    {
        int j = i;
        while(j > 1)
        {
            j--; 
            mpz_t chash;
            computeHashProt(signKeyPoolUsersProt->signKeys_usersProt[j], hash_out,chash);
            mpz_mul(hk, hk, chash);
        }
    }
    mpz_powm(hk, hk,k,keysOwner->n);
    mpz_powm(yie, Yi, keysOwner->e, keysOwner->n);
    mpz_mul(firstM, hk, yie);
    mpz_mod(firstM, firstM, keysOwner->n); 
    mpz_mod(secondM, Ri, keysOwner->n);

    mpz_powm(kie,Ki,signKeyPoolUsersProt->signKeys_usersProt[i-1]->e,signKeyPoolUsersProt->signKeys_usersProt[i-1]->n);
    if ( i > 1 )
    {
        int j = 2;
        while ( j <= i)
        {
            mpz_powm(kie,kie,signKeyPoolUsersProt->signKeys_usersProt[i-j]->e, signKeyPoolUsersProt->signKeys_usersProt[i-j]->n);
            j++;
        }
    }
    mpz_clears(firstM,secondM, yie,kie, NULL);
}
