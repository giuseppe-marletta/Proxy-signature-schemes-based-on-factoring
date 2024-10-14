#include "lib-shared.h"



#define hashing_macro(STRUCT_CTX, FNC_INIT, FNC_UPDATE, FNC_DIGEST,     \
                             DGST_SIZE, block_size_uno, block_to_hash_uno, block_size_due, block_to_hash_due)                 \
    ({                                                                         \
        struct STRUCT_CTX context;                                             \
        uint8_t digest[DGST_SIZE];                                             \
        FNC_INIT(&context);                                                    \     
        FNC_UPDATE(&context, block_size_uno, block_to_hash_uno);           \
        FNC_UPDATE(&context, block_size_due, block_to_hash_due);            \
        FNC_DIGEST(&context, DGST_SIZE, digest);                       \
        mpz_t* mpzHash = malloc(sizeof(mpz_t));                     \
        mpz_init(*mpzHash);                                         \
        mpz_import(*mpzHash,SHA256_DIGEST_SIZE,1,1,1,0,digest);       \
        mpzHash;                                                                \
    })


void randGen(rsa_keysOwner_t keysOwner, gmp_randstate_t prng, mpz_t rannum)
{
    mpz_init(rannum);
    mpz_set_ui(rannum, 0);
    mpz_urandomm(rannum,prng,keysOwner->n);
}


void computeMpzHash(message_t message, mpz_t r, int hash_out, mpz_t hash_value)
{
    char* rstr;
    rstr = mpz_get_str(NULL,10,r);
    compute_hash_by_hash_out(hash_out,strlen(message->message), message->message, strlen(rstr), rstr, hash_value);
}



void computeHash(signKey_user_t signKeyUser,rsa_keysOwner_t keysOwner, int hash_out, mpz_t hash_value)
{
    char* SN[5];
    sprintf(SN, "%d", signKeyUser->sn);
    return compute_hash_by_hash_out(hash_out,strlen(signKeyUser->mw), signKeyUser->mw, strlen(SN),SN, hash_value);
}


void computeHashProt(signKey_userProt_t signKeyUserProt, int hash_out, mpz_t hash_value)
{
    char* ID[5];
    sprintf(ID, "%d", signKeyUserProt->id);
    return compute_hash_by_hash_out(hash_out,strlen(signKeyUserProt->mw), signKeyUserProt->mw, strlen(ID),ID, hash_value);
}




void compute_hash_by_hash_out(int hash_out, size_t block_size_uno, char* block_to_hash_uno, size_t block_size_due, char* block_to_hash_due, mpz_t hash_value) 
{ 
    mpz_init(hash_value);
    mpz_t *temp_value;
    if (hash_out == 224)
        temp_value = hashing_macro(sha224_ctx, sha224_init, sha224_update, sha224_digest,
                         SHA224_DIGEST_SIZE,block_size_uno, block_to_hash_uno, block_size_due, block_to_hash_due);
    else if (hash_out == 256)
        temp_value = hashing_macro(sha256_ctx, sha256_init, sha256_update, sha256_digest,
                         SHA256_DIGEST_SIZE,block_size_uno, block_to_hash_uno, block_size_due, block_to_hash_due);
    else if (hash_out == 384)
        temp_value = hashing_macro(sha384_ctx, sha384_init, sha384_update, sha384_digest,
                         SHA384_DIGEST_SIZE,block_size_uno, block_to_hash_uno, block_size_due, block_to_hash_due);
    else 
        temp_value = hashing_macro(sha512_ctx, sha512_init, sha512_update, sha512_digest,
                         SHA512_DIGEST_SIZE,block_size_uno, block_to_hash_uno, block_size_due, block_to_hash_due);
    mpz_set(hash_value, *temp_value);
}

