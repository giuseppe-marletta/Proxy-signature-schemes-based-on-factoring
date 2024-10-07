#include "lib-verifier.h"
#include <stdio.h>



void verifyProxySignerKey(signKey_user_t signKeyUser,rsa_keysOwner_t keysOwner, int hash_out)
{
    mpz_t vie;
    mpz_init(vie);
    mpz_t uno;
    mpz_init(uno);
    mpz_set_ui(uno,1);

    mpz_powm(vie,signKeyUser->vi, keysOwner->e,keysOwner->n);
    mpz_t baseVi;
    computeHash(signKeyUser, keysOwner,hash_out,baseVi);

    mpz_t ver;
    mpz_init(ver);
    

    mpz_mul(ver,vie,baseVi);
    mpz_mod(ver,ver,keysOwner->n);


    if(mpz_congruent_p(ver,uno,keysOwner->n))
    {
        printf("\n Chiave proxy signer non protetta verificata correttamente\n\n");
    }
    else
    {
        printf("\nChiave proxy signer verificata ma errata\n");
    }
}


void verifyProxyUnprotectedMonoSign(rsa_keysOwner_t keysOwner, proxyUnprotected_monoSign_t monoUnSign, signKey_user_t signKeyUser, int hash_out)
{
    mpz_t rver;
    mpz_t hk;
    mpz_t ye;
    mpz_inits(rver,hk,ye,NULL);

    mpz_t baseVi;
    computeHash(signKeyUser, keysOwner, hash_out, baseVi);
    mpz_powm(hk,baseVi,monoUnSign->k,keysOwner->n);
    mpz_powm(ye,monoUnSign->y,keysOwner->e,keysOwner->n);
    mpz_mul(rver,ye,hk);
    mpz_mod(rver,rver,keysOwner->n);

    mpz_t ver;
    computeMpzHash(monoUnSign, rver, hash_out, ver);

    if(mpz_cmp(ver,monoUnSign->k) == 0)
    {
        printf("\n proxyUnprotectedMonoSign verificata correttamente\n\n");
    }
    else
    {
        printf("\n proxyUnprotectedMonoSign verificata ma errata\n\n");
    }


}


void verifyProxyUnprotectedMultiSign(rsa_keysOwner_t keysOwner, proxyUnprotected_multiSign_t multiUnSign, signKeyPool_users_t signKeyPoolUsers, int hash_out, int fixed_n_signers)
{
    mpz_t rver;
    mpz_t hk;
    mpz_t ye;
    mpz_inits(rver,hk,ye,NULL);
    mpz_t baseVi;
    computeHash(signKeyPoolUsers->signKeys_users[0], keysOwner,hash_out, baseVi);
    mpz_set(hk, baseVi);
    for(int i = 1; i < fixed_n_signers; i++)
    {
       mpz_t  baseVi;
       computeHash(signKeyPoolUsers->signKeys_users[i], keysOwner, hash_out, baseVi);
       mpz_mul(hk,hk,baseVi);
    }
    mpz_powm(hk,hk,multiUnSign->k,keysOwner->n);
    mpz_powm(ye,multiUnSign->y,keysOwner->e,keysOwner->n);
    mpz_mul(rver,ye,hk);
    mpz_mod(rver,rver,keysOwner->n);

    mpz_t ver;
    computeMpzHash(multiUnSign, rver, hash_out, ver);

    if(mpz_cmp(ver,multiUnSign->k) == 0)
    {
        printf("\n proxyUnprotectedMultiSign verificata correttamente\n\n");
    }
    else
    {
        printf("\n proxyUnprotectedMultiSign verificata ma errata\n\n");
    }

}


void verifyProxySignerProtKey(signKey_userProt_t signKeyUserProt, rsa_keysOwner_t keysOwner, int hash_out)
{
    
    mpz_t vi, firstM, secondM;
    mpz_inits(vi, firstM, secondM, NULL);
    mpz_mul(firstM, signKeyUserProt->ui, signKeyUserProt->n);
    mpz_powm(secondM, signKeyUserProt->wi, signKeyUserProt->d, signKeyUserProt->n);
    mpz_add(firstM, firstM, secondM);
    mpz_t thirdM,fourthM;
    mpz_inits(thirdM,fourthM,NULL);

    mpz_powm(vi,signKeyUserProt->vi, keysOwner->e, keysOwner->n);
    mpz_t hashc;
    computeHashProt(signKeyUserProt, hash_out, hashc);
    mpz_mul(thirdM, vi, hashc);
    mpz_mod(thirdM, thirdM, keysOwner->n);
    mpz_set_ui(fourthM, 1);
    if(mpz_congruent_p(thirdM,fourthM,keysOwner->n) && mpz_cmp(firstM, signKeyUserProt->vi) == 0)
    {
        printf("\nChiave proxy signer protetta verificata correttamente\n\n");
    }
    else
    {
        printf("\nChiave proxy signer protetta verificata ma errata\n");
    }



}


void verifyProxyProtectedMonoSign(rsa_keysOwner_t keysOwner, proxyprotected_monoSign_t monoProtSign,signKey_userProt_t signKeyUserProt, int hash_out)
{
    mpz_t kver, rver, ye;
    mpz_inits(kver,rver,ye,NULL);
    mpz_powm(kver,monoProtSign->u,signKeyUserProt->e,signKeyUserProt->n);
    mpz_powm(ye,monoProtSign->y,keysOwner->e,keysOwner->n);
    mpz_t hashverone;
    computeHashProt(signKeyUserProt, hash_out, hashverone);
    mpz_powm(rver,hashverone,kver,keysOwner->n);
    mpz_mul(rver,rver,ye);
    mpz_mod(rver, rver, keysOwner->n);
    mpz_t hashvertwo;
    computeMpzHash(monoProtSign,rver, hash_out, hashvertwo);
    if(mpz_cmp(hashvertwo,kver) == 0)
    {
        printf("\n\n ProxyProtectedMonoSign verifica correttamente \n\n");
    }
    else 
    {
        printf("\n\n ProxyProtectedMonoSign verificata ma errata \n\n");
    }


}



void verifyProxyProtectedMultiSign(rsa_keysOwner_t keysOwner, proxyProtected_multiSign_t multiProtSign, signKeyPool_usersProt_t signKeyPoolUsersProt, int hash_out, int fixed_n_signers)
{
    mpz_t rver, kver;
    mpz_t hk;
    mpz_t ye;
    mpz_inits(rver,kver,hk,ye,NULL);
    mpz_powm(kver,multiProtSign->u,signKeyPoolUsersProt->signKeys_usersProt[fixed_n_signers-1]->e,signKeyPoolUsersProt->signKeys_usersProt[fixed_n_signers-1]->n);
    for(int i = fixed_n_signers-2; i >= 0; i--)
    {
       mpz_powm(kver,kver,signKeyPoolUsersProt->signKeys_usersProt[i]->e, signKeyPoolUsersProt->signKeys_usersProt[i]->n);
    }



    mpz_t chash;
    computeHashProt(signKeyPoolUsersProt->signKeys_usersProt[0], hash_out,chash);
    mpz_set(hk,chash);
    for(int i = 1; i < fixed_n_signers; i++)
    {
       mpz_t  chash;
       computeHashProt(signKeyPoolUsersProt->signKeys_usersProt[i], hash_out, chash);
       mpz_mul(hk,hk,chash);
    }
    mpz_powm(hk,hk,kver,keysOwner->n);
    mpz_powm(ye,multiProtSign->y,keysOwner->e,keysOwner->n);
    mpz_mul(rver,ye,hk);
    mpz_mod(rver,rver,keysOwner->n);

    mpz_t ver;
    computeMpzHash(multiProtSign, rver, hash_out, ver);

    if(mpz_cmp(ver,kver) == 0)
    {
        printf("\n proxyProtectedMultiSign verificata correttamente\n\n");
    }
    else
    {
        printf("\n proxyProtectedMultiSign verificata ma errata\n\n");
    } 

}







