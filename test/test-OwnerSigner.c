#include <stdio.h>
#include <stdlib.h>
#include "lib-OwnerSigner.h"
#include <gmp.h>
#include <libgen.h>
#include "lib-mesg.h"
#include "lib-verifier.h"
#include "lib-shared.h"
#include "lib-proxyUnprotected-monoSign.h"
#include "lib-data.h"
#include "lib-proxyUnprotected-multiSign.h"
#include "lib-proxyProtected-monoSign.h"
#include "lib-proxyProtected-multiSign.h"


#define prng_sec_level 80
#define default_mod_bits 1024
#define default_hash_out 256


#define bench_sampling_time 2 /* secondi */
#define max_samples (bench_sampling_time * 1000)


int main(int argc, char *argv[])
{
    rsa_keysOwner_t keysOwner;
    signKey_user_t signKeyUser;
    signKey_userProt_t signKeyUserProt;
    signKeyPool_users_ptr signKeyPoolUsers = malloc(sizeof(struct signKeyPool_users_struct));
    signKeyPool_usersProt_t signKeyPoolUsersProt;
    proxyUnprotected_monoSign_t monoUnSign;
    proxyUnprotected_multiSign_t multiUnSign;
    proxyprotected_monoSign_t monoProtSign;
    proxyProtected_multiSign_t multiProtSign;
    message_t text;
    gmp_randstate_t prng;
    char* fixed_msg = "."; //messaggio predefinito
    int fixed_n_signers = 5; //numero di signers multipli predefinito
    int mod_bits = default_mod_bits;
    int sec_level = prng_sec_level;
    int hash_out = default_hash_out;
    bool do_bench = false;
    stats_t timing;
    elapsed_time_t time;
    long int applied_sampling_time = 0;


    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "verbose") == 0)
            set_messaging_level(msg_very_verbose);
        else if (strcmp(argv[i], "quiet") == 0)
            set_messaging_level(msg_silence);
        else if (strcmp(argv[i], "bench") == 0) {
            applied_sampling_time = bench_sampling_time;
            do_bench = true; }
        else if (strcmp(argv[i], "message") == 0) {
            if (i + 1 >= argc) {
                printf("argomento mancante!\n");
                exit(1);
            }
            assert(argv[i + 1]);
            fixed_msg = argv[i + 1];
            i++;
        }
        else if (strcmp(argv[i], "signers") == 0) {
            if (i + 1 >= argc) {
                printf("argomento mancante!\n");
                exit(1);
            }
            assert(argv[i+1]);
            fixed_n_signers = atoi(argv[i+1]);
            i++;
        } 
        else if (strcmp(argv[i], "sec-lev") == 0) {
            if( i +1 >= argc) {
                printf("argomento mancante!\n");
                exit(1);
            }
            assert(argv[i+1]);
            sec_level = atoi(argv[i+1]);
            mod_bits = non_generic_dlog_secure_size_by_security_level(sec_level);
            hash_out = hash_secure_size_by_security_level(sec_level);
            if ( sec_level < 16 ) {
                printf("livello di sicurezza non valido!\n");
                exit(1);
            }
            i++;
        }
         else {
            printf(
                "utilizzo: %s [verbose|quiet|bench] [sec-lev <n>] [message <n>] [signers <n>] \n",
                basename(argv[0]));
            exit(1);
        }
    }
    if (do_bench)
        set_messaging_level(msg_silence);

    printf("Calibrazione strumenti per il timing...\n");
    calibrate_timing_methods();

   
    printf("\n Inizializzazione PRNG...\n\n");
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, prng_sec_level);


     if( strcmp(fixed_msg,".") != 0 )
        {
            text->message = fixed_msg;
        }
    else
        {
            mpz_t randMsg;
            mpz_t mpzN;
            mpz_inits(randMsg,mpzN,NULL);
            mpz_set_ui(randMsg, 0);
            mpz_set_ui(mpzN, mod_bits);
            mpz_urandomb(randMsg,prng,mod_bits);
            text->message = mpz_get_str(NULL,10, randMsg);
        }

    printf("\n il numero di signer multipli: %d \n", fixed_n_signers);
    printf("\n Il valore del modulo: %d \n", mod_bits);
    printf("\n Il valore dell'output hash: %d \n", hash_out);

    printf("\n Il messaggio scritto:\n %s\n\n", text->message);
    
    
    perform_wc_time_sampling_period(
            timing, applied_sampling_time, max_samples, tu_millis,
            { RsaKeyGeneration(keysOwner,prng,mod_bits); }, {});
        if (do_bench)
            printf_short_stats(" RsaKeyGeneration_OriginalSigner", timing, "");

    printf("\n Generazioni delle chiavi dell'original signer effettuata con successo! \n\n");


    char* mw = "Mandatory";
    int sn[fixed_n_signers];
    for(int i = 0; i < fixed_n_signers; i++){
        sn[i] = i;
    }


    printf("\n Generazione della chiave di firma del proxy signer non protetto...\n");
    perform_wc_time_sampling_period(
            timing, applied_sampling_time, max_samples, tu_millis,
            { SignKeyProxyUsersGeneration(signKeyUser, keysOwner,mw,sn[0], hash_out); }, {});
        if (do_bench)
            printf_short_stats(" SignKeyProxyUsersGeneration", timing, "");
    printf("\n Generazione della chiave di firma del proxy signer non protetto effettuata con successo!\n");


    verifyProxySignerKey(signKeyUser,keysOwner,hash_out);


    proxyUnprotected_monoSign_init(monoUnSign);

    perform_wc_time_sampling_period(
            timing, applied_sampling_time, max_samples, tu_millis,
            { computeUnMonoSign(text,monoUnSign,keysOwner,signKeyUser,prng, hash_out); }, {});
        if (do_bench)
            printf_short_stats(" ComputeUnMonoSign", timing, "");
    


    verifyProxyUnprotectedMonoSign(keysOwner, monoUnSign, signKeyUser, hash_out);


    signKeyPool_users_init(signKeyPoolUsers,fixed_n_signers);
    printf("\n Generazione delle chiavi di firma dei proxy signer multipili non protetti... \n");
    perform_wc_time_sampling_period(
            timing, applied_sampling_time, max_samples, tu_millis,
            {SignKeyProxyUsersMultiGeneration(signKeyPoolUsers, keysOwner, mw, sn, hash_out, fixed_n_signers);}, {});
        if (do_bench)
            printf_short_stats(" SignKeyProxyUsersMultiGeneration", timing, "");
    printf("\n Generazione delle chiavi di firma dei proxy signer multipli non protetti effettuata con successo!\n\n");


    proxyUnprotected_multiSign_init(multiUnSign,fixed_n_signers);
     perform_wc_time_sampling_period(
            timing, applied_sampling_time, max_samples, tu_millis,
            {computeUnMultiSign(text, multiUnSign, keysOwner, signKeyPoolUsers,prng,hash_out,fixed_n_signers);}, {});
        if (do_bench)
            printf_short_stats(" computeUnMultiSign", timing, "");
    
    verifyProxyUnprotectedMultiSign(keysOwner, multiUnSign, signKeyPoolUsers, hash_out, fixed_n_signers);

    printf("\nGenerazione delle chiavi e della chiave di firma del proxy signer protetto...\n");
    perform_wc_time_sampling_period(
            timing, applied_sampling_time, max_samples, tu_millis,
            { SignKeyProxyUsersProtGeneration(signKeyUserProt,keysOwner,mw,prng,mod_bits, hash_out); }, {});
        if (do_bench)
            printf_short_stats(" SignKeyProxyUsersProtGeneration", timing, "");
    printf("\n Generazione delle chiavi e della chiave di firma del proxy signer protetto effettuata con successo! \n");



    verifyProxySignerProtKey(signKeyUserProt, keysOwner, hash_out);



    proxyprotected_monoSign_init(monoProtSign);
    perform_wc_time_sampling_period(
            timing, applied_sampling_time, max_samples, tu_millis,
            {computeProtMonoSign(text,monoProtSign,keysOwner,signKeyUserProt,prng, hash_out);}, {});
        if (do_bench)
            printf_short_stats(" computerProtMonoSign", timing, "");
    verifyProxyProtectedMonoSign(keysOwner, monoProtSign, signKeyUserProt, hash_out);


    printf("\nGenerazione delle chiavi e delle chiavi di firma dei proxy signer multipli protetti...\n");
    signKeyPool_usersProt_init(signKeyPoolUsersProt, fixed_n_signers);
     perform_wc_time_sampling_period(
            timing, applied_sampling_time, max_samples, tu_millis,
            {SignKeyProxyUsersProtMultiGeneration(signKeyPoolUsersProt, keysOwner, mw, prng, mod_bits, hash_out, fixed_n_signers);}, {});
        if (do_bench)
            printf_short_stats(" SignKeyPRoxyUsersProtMultiGeneration", timing, "");
    printf("\n Generazione delle chiavi e delle chiavi di firma dei proxy signer multipli protetti effettuata con successo! \n");
    


    proxyProtected_multiSign_init(multiProtSign,fixed_n_signers);
    perform_wc_time_sampling_period(
            timing, applied_sampling_time, max_samples, tu_millis,
            {computeProtMultiSign(text, multiProtSign, keysOwner, signKeyPoolUsersProt, prng, hash_out,fixed_n_signers);}, {});
        if (do_bench)
            printf_short_stats(" computeProtMultiSign", timing, "");
    
    verifyProxyProtectedMultiSign(keysOwner, multiProtSign, signKeyPoolUsersProt, hash_out, fixed_n_signers);

    
    proxyUnprotected_monoSign_clear(monoUnSign);
    proxyUnprotected_multiSign_clear(multiUnSign);
    rsa_keysOwner_clear(keysOwner);
    signKey_user_clear(signKeyUser);
    signKey_userProt_clear(signKeyUserProt);
    signKeyPool_users_clear(signKeyPoolUsers, fixed_n_signers); 
    signKeyPool_usersProt_clear(signKeyPoolUsersProt,fixed_n_signers);
    proxyprotected_monoSign_clear(monoProtSign);
    proxyProtected_multiSign_clear(multiProtSign);

    gmp_randclear(prng);



}