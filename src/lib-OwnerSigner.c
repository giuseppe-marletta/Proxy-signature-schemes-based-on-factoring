#include "lib-OwnerSigner.h"

void RsaKeyGeneration(rsa_keysOwner_t keysOwner,gmp_randstate_t prng, int mod_bits)
{
    assert(keysOwner);
    rsa_keys_t keys;
    long int rsa_exp = 0;
    
    pmesg(msg_verbose, "\nGenerazione chiavi di KeysOwner...\n");
    rsa1_generate_keys(keys, mod_bits, rsa_exp, prng, true);

    mpz_inits(keysOwner->n,keysOwner->e, keysOwner->p,keysOwner->q,keysOwner->d,NULL);
    
    mpz_set(keysOwner->n, keys->n);
    mpz_set(keysOwner->e, keys->e);
    mpz_set(keysOwner->p, keys->p);
    mpz_set(keysOwner->q, keys->q);
    mpz_set(keysOwner->d, keys->d);    


}

void SignKeyProxyUsersGeneration(signKey_user_t signKeyUser, rsa_keysOwner_t keysOwner, char* mw, int sn, int hash_out)
{
    signKeyUser->mw = mw;
    signKeyUser->sn = sn;
    mpz_init(signKeyUser->vi); 

    

    mpz_t baseVi;
    computeHash(signKeyUser, keysOwner, hash_out,baseVi);
    
        
    int ecmph = mpz_cmp(keysOwner->e, baseVi);
    if(ecmph < 0)
    {
        printf("\n e0 deve essere maggiore di h()!!! \n");
        exit(1);
    }

    mpz_t d_neg_value;
    mpz_init(d_neg_value);

    mpz_neg(d_neg_value, keysOwner->d);

    mpz_powm(signKeyUser->vi,baseVi, d_neg_value, keysOwner->n);

    pmesg_mpz(msg_very_verbose, "La chiave di firma del proxy signer non protetto", signKeyUser->vi);



}



void SignKeyProxyUsersMultiGeneration(signKeyPool_users_t signKeyPoolUsers ,rsa_keysOwner_t keysOwner,char* mw, int sn[], int hash_out, int fixed_n_signers)
{
    for(int i = 0; i < fixed_n_signers; i++) {
        signKeyPoolUsers->signKeys_users[i]->mw = mw;
        
        signKeyPoolUsers->signKeys_users[i]->sn = sn[i];
        mpz_t baseVi;
        computeHash(signKeyPoolUsers->signKeys_users[i], keysOwner, hash_out,baseVi);
        int ecmph = mpz_cmp(keysOwner->e, baseVi);
        if(ecmph < 0)
        {
            printf("\ne0 deve essere maggiore di h()!!! \n");
            exit(1);
        }
        mpz_t d_neg_value;
        mpz_init(d_neg_value);
        mpz_neg(d_neg_value, keysOwner->d);
        mpz_powm(signKeyPoolUsers->signKeys_users[i]->vi,baseVi, d_neg_value, keysOwner->n);
        mpz_clears(baseVi, d_neg_value,NULL);
        pmesg_mpz(msg_verbose, "La chiave di firma del proxy signer non protetto", signKeyPoolUsers->signKeys_users[i]->vi);
    }
    
}


void SignKeyProxyUsersProtGeneration(signKey_userProt_t signKeyUserProt,rsa_keysOwner_t keysOwner,char* mw, gmp_randstate_t prng, int mod_bits, int hash_out)
{
    signKeyUserProt->mw = mw;
    rsa_keys_t keys;
    long int rsa_exp = 0;
    
    rsa1_generate_keys(keys, mod_bits, rsa_exp, prng,true);
    mpz_inits(signKeyUserProt->n, signKeyUserProt->e,signKeyUserProt->d, signKeyUserProt->ui, signKeyUserProt->vi, signKeyUserProt->wi,NULL);
    mpz_set(signKeyUserProt->n,keys->n);
    mpz_set(signKeyUserProt->e, keys->e);
    mpz_set(signKeyUserProt->d, keys->d);
    srand(time(NULL));
    int id = rand() % 10001;
    signKeyUserProt->id = id;
    mpz_t ui, wi;
    mpz_inits(ui,wi, NULL); 
    mpz_t vi;
    computeHashProt(signKeyUserProt,hash_out,vi);
    mpz_t d_neg_value;
    mpz_init(d_neg_value);
    mpz_neg(d_neg_value, keysOwner->d);
    mpz_powm(vi,vi,d_neg_value, keysOwner->n);
    mpz_fdiv_q(ui,vi,signKeyUserProt->n);
    mpz_powm(wi,vi,signKeyUserProt->e, signKeyUserProt->n);
    mpz_set(signKeyUserProt->vi, vi);
    mpz_set(signKeyUserProt->ui, ui);
    mpz_set(signKeyUserProt->wi, wi);
    pmesg_mpz(msg_verbose, " La chiave di firma del proxy signer protetto", signKeyUserProt->vi);
   
}

void SignKeyProxyUsersProtMultiGeneration(signKeyPool_usersProt_t signKeyPoolUsersProt ,rsa_keysOwner_t keysOwner,char* mw, gmp_randstate_t prng, int mod_bits, int hash_out, int fixed_n_signers)
{
    rsa_keys_t keys;
    long int rsa_exp = 0;
    mpz_t d_neg_value, predN;
    mpz_inits(d_neg_value, predN, NULL);
    mpz_neg(d_neg_value, keysOwner->d);
    srand(time(NULL));
    int j = (fixed_n_signers*2)-2;
    for(int i = 0; i < fixed_n_signers; i++) {
        signKeyPoolUsersProt->signKeys_usersProt[i]->mw = mw;
        rsa1_generate_keys(keys, mod_bits-j, rsa_exp, prng,false);
        j = j-2 ;
        mpz_set(predN,keys->n);
        mpz_set(signKeyPoolUsersProt->signKeys_usersProt[i]->n,keys->n);
        mpz_set(signKeyPoolUsersProt->signKeys_usersProt[i]->e, keys->e);
        mpz_set(signKeyPoolUsersProt->signKeys_usersProt[i]->d, keys->d);
        int id = rand() % 10001;
        signKeyPoolUsersProt->signKeys_usersProt[i]->id = id;
        pmesg_mpz(msg_very_verbose, "Fattore primo", keys->p);
        pmesg_mpz(msg_very_verbose, "Fattore primo", keys->q);
        pmesg_mpz(msg_very_verbose, "Modulo composito", signKeyPoolUsersProt->signKeys_usersProt[i]->n);
        pmesg_mpz(msg_very_verbose, "Esponente pubblico", signKeyPoolUsersProt->signKeys_usersProt[i]->e);
        pmesg_mpz(msg_very_verbose, "Esponente privato", signKeyPoolUsersProt->signKeys_usersProt[i]->d);
        mpz_t ui, wi;
        mpz_inits(ui,wi, NULL);
        mpz_t vi;
        computeHashProt(signKeyPoolUsersProt->signKeys_usersProt[i], hash_out, vi);
        mpz_powm(vi,vi,d_neg_value, keysOwner->n);
        mpz_fdiv_q(ui,vi,signKeyPoolUsersProt->signKeys_usersProt[i]->n);
        mpz_powm(wi,vi,signKeyPoolUsersProt->signKeys_usersProt[i]->e, signKeyPoolUsersProt->signKeys_usersProt[i]->n);
        mpz_set(signKeyPoolUsersProt->signKeys_usersProt[i]->vi, vi);
        mpz_set(signKeyPoolUsersProt->signKeys_usersProt[i]->ui, ui);
        mpz_set(signKeyPoolUsersProt->signKeys_usersProt[i]->wi, wi);
        pmesg_mpz(msg_verbose, " La chiave di firma del proxy signer non protetto", signKeyPoolUsersProt->signKeys_usersProt[i]->vi);
    }
}








