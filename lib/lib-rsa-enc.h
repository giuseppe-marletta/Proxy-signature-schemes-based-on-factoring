/*
 *  Copyright 2016 Mario Di Raimondo <diraimondo@dmi.unict.it>
 *
 *  This source code is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This source code is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIB_RSA_ENC_H
#define LIB_RSA_ENC_H

#include "lib-mesg.h"
#include <assert.h>
#include <gmp.h>
#include <stdio.h>
#include <strings.h>

#define rsa_mr_iterations 12

typedef enum { rsa_public_key_type, rsa_secret_key_type } rsa_key_type_t;

struct rsa_keys_struct {
    rsa_key_type_t type;
    unsigned int n_bits;

    /* elementi pubblici: */
    mpz_t n;
    mpz_t e;

    /* elementi privati: */
    mpz_t d;
    mpz_t p, q;
    mpz_t d_p, d_q;
    mpz_t q_inv;
};
typedef struct rsa_keys_struct *rsa_keys_ptr;
typedef struct rsa_keys_struct rsa_keys_t[1];

struct rsa_plaintext_struct {
    mpz_t m;
};
typedef struct rsa_plaintext_struct *rsa_plaintext_ptr;
typedef struct rsa_plaintext_struct rsa_plaintext_t[1];

struct rsa_ciphertext_struct {
    mpz_t c;
};
typedef struct rsa_ciphertext_struct *rsa_ciphertext_ptr;
typedef struct rsa_ciphertext_struct rsa_ciphertext_t[1];

#define rsa_generate_keys(KEYS, N_BITS, PRNG)                                  \
    (rsa2_generate_keys(KEYS, N_BITS, ((1 << 16) + 1), PRNG))
#define rsa_decrypt(PLAINTEXT, CIPHERTEXT, KEYS)                               \
    (rsa2_decrypt(PLAINTEXT, CIPHERTEXT, KEYS))

void rsa1_generate_keys(rsa_keys_t keys, unsigned int n_bits,
                        unsigned long int fixed_exp, gmp_randstate_t prng, bool isLog);
void rsa_keys_clear(rsa_keys_t keys);
void rsa_plaintext_init(rsa_plaintext_t plaintext);
void rsa_plaintext_clear(rsa_plaintext_t plaintext);
void rsa_ciphertext_init(rsa_ciphertext_t ciphertext);
void rsa_ciphertext_clear(rsa_ciphertext_t ciphertext);
void rsa_encrypt(rsa_ciphertext_t ciphertext, const rsa_plaintext_t plaintext,
                 const rsa_keys_t keys);
void rsa1_decrypt(rsa_plaintext_t plaintext, const rsa_ciphertext_t ciphertext,
                  const rsa_keys_t keys);

void rsa2_generate_keys(rsa_keys_t keys, unsigned int n_bits,
                        unsigned long int fixed_exp, gmp_randstate_t prng);
void rsa2_decrypt(rsa_plaintext_t plaintext, const rsa_ciphertext_t ciphertext,
                  const rsa_keys_t keys);

#endif /* LIB_RSA_ENC_H */
