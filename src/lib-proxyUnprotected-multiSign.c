#include "lib-proxyUnprotected-multiSign.h"


void computeUnMultiSign(message_t message, proxyUnprotected_multiSign_t multiUnSign,rsa_keysOwner_t keysOwner, signKeyPool_users_t signKeyPoolUsers,gmp_randstate_t prng, int hash_out, int fixed_n_signers)
{
    multiUnSign->m = message->message;
    multiUnSign->mw = signKeyPoolUsers->signKeys_users[0]->mw;
    mpz_t *Ri = malloc(fixed_n_signers * sizeof(mpz_t));
    mpz_t *t = malloc(fixed_n_signers * sizeof(mpz_t));
    for(int i = 0; i < fixed_n_signers; i++)
    {
        multiUnSign->sn[i] = signKeyPoolUsers->signKeys_users[i]->sn;
        mpz_init(t[i]);
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
    mpz_init(k);
    computeMpzHash(multiUnSign->m,Ri[fixed_n_signers-1], hash_out, k);
    mpz_set(multiUnSign->k, k);
    mpz_t *Yi = malloc(fixed_n_signers * sizeof(mpz_t));
    for(int i = 0; i < fixed_n_signers; i++)
    {
        mpz_init(Yi[i]);
        if(i == 0)
        {
            mpz_powm(Yi[i],signKeyPoolUsers->signKeys_users[i]->vi,k,keysOwner->n);
            mpz_mul(Yi[i],t[i],Yi[i]); 
            mpz_mod(Yi[i],Yi[i],keysOwner->n);
        }
        else 
        {
            verifyY(Ri[i-1],Yi[i-1], i,signKeyPoolUsers,keysOwner, multiUnSign, hash_out);
            mpz_powm(Yi[i],signKeyPoolUsers->signKeys_users[i]->vi,k,keysOwner->n);
            mpz_mul(Yi[i],t[i],Yi[i]);
            mpz_mul(Yi[i],Yi[i-1],Yi[i]);
            mpz_mod(Yi[i],Yi[i],keysOwner->n);
        }
    }
    mpz_set(multiUnSign->y,Yi[fixed_n_signers-1]);
    pmesg_mpz(msg_verbose, "valore k multifirma proxy non protetto", multiUnSign->k);
    pmesg_mpz(msg_verbose, "valore y multifirma proxy non protetto", multiUnSign->y);
}



void verifyY (mpz_t Ri, mpz_t Yi, int i, signKeyPool_users_t signKeyPoolUsers, rsa_keysOwner_t keysOwner, proxyUnprotected_multiSign_t multiUnSign, int hash_out )
{
    mpz_t firstM, secondM;
    mpz_t yie;
    mpz_inits(firstM, secondM, yie, NULL);
    
    mpz_t hk; 
    computeHash(signKeyPoolUsers->signKeys_users[0],keysOwner, hash_out, hk);
    if(i > 1)
    {
        int j = i;
        while(j > 1)
        {
            j--; 
            mpz_t chash;
            computeHash(signKeyPoolUsers->signKeys_users[j],keysOwner, hash_out, chash);
            mpz_mul(hk, hk, chash);
        }
    }
    mpz_powm(hk, hk,multiUnSign->k,keysOwner->n);
    mpz_powm(yie, Yi, keysOwner->e, keysOwner->n);
    mpz_mul(firstM, hk, yie);
    mpz_mod(firstM, firstM, keysOwner->n);
        
    mpz_mod(secondM, Ri, keysOwner->n);

    if(mpz_congruent_p(firstM,secondM, keysOwner->n))
    {
        //printf("\n  Il valore y numero %d verificato correttamente\n\n", i);
    }
    else
    {
        printf("\n Il valore y numero %d verificato ma errato\n\n", i);
    }
    mpz_clears(firstM,secondM, yie, NULL);
}




