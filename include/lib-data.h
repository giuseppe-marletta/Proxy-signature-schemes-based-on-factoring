#ifndef LIB_DATA_H
#define LIB_DATA_H

#include <gmp.h>
#include <assert.h>
#include <stdlib.h>



struct rsa_keysOwner_struct {
  
    /* elementi pubblici: */
    mpz_t n;
    mpz_t e;

    /* elementi privati: */
    mpz_t d;
    mpz_t p, q;
};
typedef struct rsa_keysOwner_struct *rsa_keysOwner_ptr;
typedef struct rsa_keysOwner_struct rsa_keysOwner_t[1];


struct signKey_user_struct {
    mpz_t vi;
    char* mw;
    int sn;

};
typedef struct signKey_user_struct *signKey_user_ptr;
typedef struct signKey_user_struct signKey_user_t[1];


struct signKeyPool_users_struct {
    signKey_user_t *signKeys_users;
};
typedef struct signKeyPool_users_struct *signKeyPool_users_ptr;
typedef struct signKeyPool_users_struct signKeyPool_users_t[1];

struct proxyUnprotected_monoSign_struct {
    char* m;
    char* mw;
    int sn;
    mpz_t y;
    mpz_t k;

};
typedef struct proxyUnprotected_monoSign_struct *proxyUnprotected_monoSign_ptr;
typedef struct proxyUnprotected_monoSign_struct proxyUnprotected_monoSign_t[1];


struct proxyUnprotected_multiSign_struct {
    char* m;
    char* mw;
    int *sn;
    mpz_t y;
    mpz_t k;

};
typedef struct proxyUnprotected_multiSign_struct *proxyUnprotected_multiSign_ptr;
typedef struct proxyUnprotected_multiSign_struct proxyUnprotected_multiSign_t[1];



struct message_struct {
    char* message;

};
typedef struct message_struct *message_ptr;
typedef struct message_struct message_t[1];


struct signKey_userProt_struct {
    mpz_t n;
    mpz_t e;
    mpz_t d;
    int id;
    mpz_t vi;
    mpz_t ui;
    mpz_t wi;
    char* mw;
    

};
typedef struct signKey_userProt_struct *signKey_userProt_ptr;
typedef struct signKey_userProt_struct signKey_userProt_t[1];


struct signKeyPool_usersProt_struct {
    signKey_userProt_t *signKeys_usersProt;
};
typedef struct signKeyPool_usersProt_struct *signKeyPool_usersProt_ptr;
typedef struct signKeyPool_usersProt_struct signKeyPool_usersProt_t[1];


struct proxyprotected_monoSign_struct {
    char* m;
    char* mw;
    int id;
    mpz_t y;
    mpz_t u;

};
typedef struct proxyprotected_monoSign_struct *proxyprotected_monoSign_ptr;
typedef struct proxyprotected_monoSign_struct proxyprotected_monoSign_t[1];



struct proxyProtected_multiSign_struct {
    char* m;
    char* mw;
    int *id;
    mpz_t y;
    mpz_t u;

};
typedef struct proxyProtected_multiSign_struct *proxyProtected_multiSign_ptr;
typedef struct proxyProtected_multiSign_struct proxyProtected_multiSign_t[1];






void rsa_keysOwner_clear(rsa_keysOwner_t keysOwner);
void signKey_user_clear(signKey_user_t signKeyUser);
void proxyUnprotected_monoSign_init(proxyUnprotected_monoSign_t monoUnSign);
void proxyUnprotected_monoSign_clear(proxyUnprotected_monoSign_t monoUnSign);
void signKeyPool_users_init(signKeyPool_users_t signKeyPoolUsers, int fixed_n_signers);
void signKeyPool_users_clear(signKeyPool_users_t signKeyPoolUsers, int fixed_n_signers);
void proxyUnprotected_multiSign_init(proxyUnprotected_multiSign_t multiUnSign, int fixed_n_signers);
void proxyUnprotected_multiSign_clear(proxyUnprotected_multiSign_t multiUnSign);
void signKey_userProt_clear(signKey_userProt_t signKeyUserProt);
void signKeyPool_usersProt_init(signKeyPool_usersProt_t signKeyPoolUsersProt, int fixed_n_signers);
void signKeyPool_usersProt_clear(signKeyPool_usersProt_t signKeyPoolUsersProt, int fixed_n_signers);
void proxyprotected_monoSign_init(proxyprotected_monoSign_t monoProtSign);
void proxyprotected_monoSign_clear(proxyprotected_monoSign_t monoProtSign);
void proxyProtected_multiSign_init(proxyProtected_multiSign_t multiProtSign, int fixed_n_signers);
void proxyProtected_multiSign_clear(proxyProtected_multiSign_t multiProtSign);








#endif