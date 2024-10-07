#include "lib-data.h"


void rsa_keysOwner_clear(rsa_keysOwner_t keysOwner) {
    assert(keysOwner);
    mpz_clears(keysOwner->d,keysOwner->e,keysOwner->n,keysOwner->p,keysOwner->q,NULL);
}
void signKey_user_clear(signKey_user_t signKeyUser) {
    assert(signKeyUser);
    mpz_clears(signKeyUser->vi, NULL);
}
void proxyUnprotected_monoSign_init(proxyUnprotected_monoSign_t monoUnSign) {
    assert(monoUnSign);
    mpz_inits(monoUnSign->k, monoUnSign->y, NULL);
}
void proxyUnprotected_monoSign_clear(proxyUnprotected_monoSign_t monoUnSign) {
    assert(monoUnSign);
    mpz_clears(monoUnSign->k, monoUnSign->y, NULL);
}

void signKeyPool_users_init(signKeyPool_users_t signKeyPoolUsers, int fixed_n_signers) {
    assert(signKeyPoolUsers);
    signKeyPoolUsers->signKeys_users = malloc(fixed_n_signers * sizeof(signKey_user_t));
    for(int i = 0; i < fixed_n_signers; i++)
    {
        mpz_init(signKeyPoolUsers->signKeys_users[i]->vi);
    }
}

void signKeyPool_users_clear(signKeyPool_users_t signKeyPoolUsers, int fixed_n_signers) {
    assert(signKeyPoolUsers);
    for(int i = 0; i < fixed_n_signers; i++)
    {
        mpz_clear(signKeyPoolUsers->signKeys_users[i]->vi);
    }
}

void proxyUnprotected_multiSign_init(proxyUnprotected_multiSign_t multiUnSign, int fixed_n_signers) {
    assert(multiUnSign);
    multiUnSign->sn = malloc(fixed_n_signers * sizeof(proxyUnprotected_multiSign_t));
    mpz_inits(multiUnSign->k, multiUnSign->y, NULL);
}
void proxyUnprotected_multiSign_clear(proxyUnprotected_multiSign_t multiUnSign) {
    assert(multiUnSign);
    mpz_clears(multiUnSign->k, multiUnSign->y, NULL);
}

void signKey_userProt_clear(signKey_userProt_t signKeyUserProt)
{
    assert(signKeyUserProt);
    mpz_clears(signKeyUserProt->vi, signKeyUserProt->e, signKeyUserProt->n, signKeyUserProt->ui, signKeyUserProt->wi, NULL);
}
void signKeyPool_usersProt_init(signKeyPool_usersProt_t signKeyPoolUsersProt, int fixed_n_signers)
{
    assert(signKeyPoolUsersProt);
    signKeyPoolUsersProt->signKeys_usersProt = malloc(fixed_n_signers * sizeof(signKey_userProt_t));
    for(int i = 0; i < fixed_n_signers; i++)
    {
        mpz_init(signKeyPoolUsersProt->signKeys_usersProt[i]->vi);
        mpz_init(signKeyPoolUsersProt->signKeys_usersProt[i]->e);
        mpz_init(signKeyPoolUsersProt->signKeys_usersProt[i]->n);
        mpz_init(signKeyPoolUsersProt->signKeys_usersProt[i]->d);
        mpz_init(signKeyPoolUsersProt->signKeys_usersProt[i]->ui);
        mpz_init(signKeyPoolUsersProt->signKeys_usersProt[i]->wi);
    }
}
void signKeyPool_usersProt_clear(signKeyPool_usersProt_t signKeyPoolUsersProt, int fixed_n_signers) 
{
    assert(signKeyPoolUsersProt);
    for(int i = 0; i < fixed_n_signers; i++)
    {
        mpz_clear(signKeyPoolUsersProt->signKeys_usersProt[i]->vi);
        mpz_clear(signKeyPoolUsersProt->signKeys_usersProt[i]->e);
        mpz_clear(signKeyPoolUsersProt->signKeys_usersProt[i]->n);
        mpz_clear(signKeyPoolUsersProt->signKeys_usersProt[i]->d);
        mpz_clear(signKeyPoolUsersProt->signKeys_usersProt[i]->ui);
        mpz_clear(signKeyPoolUsersProt->signKeys_usersProt[i]->wi);
    }
}

void proxyprotected_monoSign_init(proxyprotected_monoSign_t monoProtSign)
{
    assert(monoProtSign);
    mpz_inits(monoProtSign->u, monoProtSign->y, NULL);
}

void proxyprotected_monoSign_clear(proxyprotected_monoSign_t monoProtSign)
{
    assert(monoProtSign);
    mpz_clears(monoProtSign->u, monoProtSign->y, NULL);
}



void proxyProtected_multiSign_init(proxyProtected_multiSign_t multiProtSign,int fixed_n_signers)
{
    assert(multiProtSign);
    multiProtSign->id = malloc(fixed_n_signers * sizeof(proxyProtected_multiSign_t));
    mpz_inits(multiProtSign->u, multiProtSign->y, NULL);
}

void proxyProtected_multiSign_clear(proxyProtected_multiSign_t multiProtSign)
{
    assert(multiProtSign);
    mpz_clears(multiProtSign->u, multiProtSign->y, NULL);
}
