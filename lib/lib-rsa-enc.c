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

/*
 * libreria con versioni elementari dello schema di cifratura RSA
 *
 * nota: per puri fini didattici, gli schemi qui implementati presentano
 *       deliberatamente dei controlli mitigati sui parametri e problemi di
 *       sicurezza che non li rendono idonei ad un ambiente di produzione
 */

#include "lib-rsa-enc.h"

/* generazione delle chiavi RSA con possibilità di scegliere l'esponente
 * pubblico */
void rsa1_generate_keys(rsa_keys_t keys, unsigned int n_bits,
                        unsigned long int fixed_exp, gmp_randstate_t prng, bool isLog) {
    mpz_t p, q, phi, tmp1, tmp2;
    unsigned int p_bits, q_bits;

    assert(keys);
    assert(n_bits > 1);
    assert((fixed_exp == 0) || (fixed_exp % 2 == 1));
    assert(prng);
    p_bits = n_bits >> 1;
    q_bits = n_bits - p_bits;

    mpz_inits(tmp1, tmp2, NULL);

    mpz_inits(p, q, phi, NULL);
    mpz_inits(keys->e, keys->d, keys->n, NULL);
    keys->n_bits = n_bits;
    keys->type = rsa_secret_key_type;

    /* per semplicità inizializziamo anche gli elementi non usati da questa
     * variante */
    mpz_inits(keys->p, keys->q, keys->d_p, keys->d_q, keys->q_inv, NULL);

    do {
        /* p e q */
        do
            mpz_urandomb(p, prng, p_bits);
        while ((mpz_sizeinbase(p, 2) < p_bits) ||
               !mpz_probab_prime_p(p, rsa_mr_iterations));
        do
            mpz_urandomb(q, prng, q_bits);
        while ((mpz_sizeinbase(q, 2) < q_bits) ||
               !mpz_probab_prime_p(q, rsa_mr_iterations));

        /* phi(n) */
        mpz_sub_ui(tmp1, p, 1L);
        mpz_sub_ui(tmp2, q, 1L);
        mpz_mul(phi, tmp1, tmp2);
    } while ((fixed_exp > 0) && (mpz_gcd_ui(NULL, phi, fixed_exp) != 1L));

    /* esponente e: 1<e<phi, gcd(e, phi)=1 */
    if (fixed_exp > 0) {
        mpz_set_ui(keys->e, fixed_exp);
        /* abbiamo già testato che gcd(e, phi)=1 */
    } else {
        do {
            mpz_urandomm(keys->e, prng, phi);
            mpz_gcd(tmp2, keys->e, phi);
        } while ((mpz_cmp_ui(keys->e, 0L) == 0) || (mpz_cmp_ui(tmp2, 1L) != 0));
    }

    /* esponente d: ed=1 mod phi(n) */
    mpz_invert(keys->d, keys->e, phi);

    /* modulo n */
    mpz_mul(keys->n, p, q);

    //gmp_printf("\nIl valore di p: \n %Zx \n", p);
    //gmp_printf("\nIl valore di q: \n %Zx \n", q);

    mpz_set(keys->p, p);
    mpz_set(keys->q,q);

    if(isLog == true)
    {
        pmesg_mpz(msg_very_verbose, "fattore primo", p);
        pmesg_mpz(msg_very_verbose, "fattore primo", q);
        pmesg_mpz(msg_very_verbose, "modulo composito", keys->n);
        pmesg_mpz(msg_very_verbose, "esponente pubblico", keys->e);
        pmesg_mpz(msg_very_verbose, "esponente privato", keys->d);
    }
    mpz_clears(p, q, phi, tmp1, tmp2, NULL);

    
}

void rsa_keys_clear(rsa_keys_t keys) {
    assert(keys);
    mpz_clears(keys->n, keys->e, keys->d, keys->p, keys->q, keys->d_p,
               keys->d_q, keys->q_inv, NULL);
}

void rsa_plaintext_init(rsa_plaintext_t plaintext) {
    assert(plaintext);
    mpz_init(plaintext->m);
}

void rsa_plaintext_clear(rsa_plaintext_t plaintext) {
    assert(plaintext);
    mpz_clear(plaintext->m);
}

void rsa_ciphertext_init(rsa_ciphertext_t ciphertext) {
    assert(ciphertext);
    mpz_init(ciphertext->c);
}

void rsa_ciphertext_clear(rsa_ciphertext_t ciphertext) {
    assert(ciphertext);
    mpz_clear(ciphertext->c);
}

/* cifratura (unica) */
void rsa_encrypt(rsa_ciphertext_t ciphertext, const rsa_plaintext_t plaintext,
                 const rsa_keys_t keys) {
    pmesg(msg_verbose, "cifratura...");

    assert(ciphertext);
    assert(plaintext);
    assert(keys);
    assert((keys->type == rsa_secret_key_type) ||
           (keys->type == rsa_public_key_type));

    /* controlli deboli per didattica, dovrebbe essere: 1 < m < n-1 */
    assert(mpz_cmp_ui(plaintext->m, 0L) > 0);
    assert(mpz_cmp(plaintext->m, keys->n) < 0);
    pmesg_mpz(msg_very_verbose, "testo in chiaro", plaintext->m);

    mpz_powm(ciphertext->c, plaintext->m, keys->e, keys->n);
    pmesg_mpz(msg_very_verbose, "testo cifrato", ciphertext->c);
}

/* decifratura semplice */
void rsa1_decrypt(rsa_plaintext_t plaintext, const rsa_ciphertext_t ciphertext,
                  const rsa_keys_t keys) {
    pmesg(msg_verbose, "decifratura...");

    assert(plaintext);
    assert(ciphertext);
    assert(keys);
    assert(keys->type == rsa_secret_key_type);

    pmesg_mpz(msg_very_verbose, "testo cifrato", ciphertext->c);
    mpz_powm(plaintext->m, ciphertext->c, keys->d, keys->n);
    pmesg_mpz(msg_very_verbose, "testo in chiaro", plaintext->m);
}

/* generazione delle chiavi RSA con supporto al metodo CRT e con possibilità di
 * scegliere l'esponente pubblico */
void rsa2_generate_keys(rsa_keys_t keys, unsigned int n_bits,
                        unsigned long int fixed_exp, gmp_randstate_t prng) {
    mpz_t phi, tmp1, tmp2;
    unsigned int p_bits, q_bits;

    pmesg(msg_verbose, "generazione chiavi...");

    assert(keys);
    assert(n_bits > 1);
    assert((fixed_exp == 0) || (fixed_exp % 2 == 1));
    assert(prng);
    p_bits = n_bits >> 1;
    q_bits = n_bits - p_bits;

    mpz_inits(phi, tmp1, tmp2, NULL);
    mpz_inits(keys->e, keys->d, keys->n, keys->p, keys->q, keys->d_p, keys->d_q,
              keys->q_inv, NULL);
    keys->n_bits = n_bits;
    keys->type = rsa_secret_key_type;

    do {
        /* p e q*/
        do
            mpz_urandomb(keys->p, prng, p_bits);
        while ((mpz_sizeinbase(keys->p, 2) < p_bits) ||
               !mpz_probab_prime_p(keys->p, rsa_mr_iterations));
        do
            mpz_urandomb(keys->q, prng, q_bits);
        while ((mpz_sizeinbase(keys->q, 2) < q_bits) ||
               !mpz_probab_prime_p(keys->q, rsa_mr_iterations));

        /* phi(n) */
        mpz_sub_ui(tmp1, keys->p, 1L);
        mpz_sub_ui(tmp2, keys->q, 1L);
        mpz_mul(phi, tmp1, tmp2);
    } while ((fixed_exp > 0) && (mpz_gcd_ui(NULL, phi, fixed_exp) != 1L));

    /* esponente e: 1<e<phi, gcd(e, phi)=1 */
    if (fixed_exp > 0) {
        mpz_set_ui(keys->e, fixed_exp);
        /* abbiamo già testato che gcd(e, phi)=1 */
    } else {
        do {
            mpz_urandomm(keys->e, prng, phi);
            mpz_gcd(tmp2, keys->e, phi);
        } while ((mpz_cmp_ui(keys->e, 0L) == 0) || (mpz_cmp_ui(tmp2, 1L) != 0));
    }

    /* esponente d: ed=1 mod phi(n) */
    mpz_invert(keys->d, keys->e, phi);

    /* modulo n */
    mpz_mul(keys->n, keys->p, keys->q);

    /* d_p = d mod (p-1) ; d_q = d mod (q-1) */
    mpz_sub_ui(tmp1, keys->p, 1L);
    mpz_mod(keys->d_p, keys->d, tmp1);
    mpz_sub_ui(tmp1, keys->q, 1L);
    mpz_mod(keys->d_q, keys->d, tmp1);

    /* q_inv = q^-1 mod p */
    mpz_invert(keys->q_inv, keys->q, keys->p);

    pmesg_mpz(msg_very_verbose, "fattore primo", keys->p);
    pmesg_mpz(msg_very_verbose, "fattore primo", keys->q);
    pmesg_mpz(msg_very_verbose, "modulo composito", keys->n);
    pmesg_mpz(msg_very_verbose, "ordine gruppo", phi);
    pmesg_mpz(msg_very_verbose, "esponente pubblico", keys->e);
    pmesg_mpz(msg_very_verbose, "esponente privato", keys->d);
    pmesg_mpz(msg_very_verbose, "esponente privato (mod p-1)", keys->d_p);
    pmesg_mpz(msg_very_verbose, "esponente privato (mod q-1)", keys->d_q);

    mpz_clears(phi, tmp1, tmp2, NULL);
}

/* decifratura con CRT */
void rsa2_decrypt(rsa_plaintext_t plaintext, const rsa_ciphertext_t ciphertext,
                  const rsa_keys_t keys) {
    mpz_t m_p, m_q, tmp;
    pmesg(msg_verbose, "decifratura...");

    assert(plaintext);
    assert(ciphertext);
    assert(keys);
    assert(keys->type == rsa_secret_key_type);

    mpz_inits(m_p, m_q, tmp, NULL);

    pmesg_mpz(msg_very_verbose, "testo cifrato", ciphertext->c);

    /* m_p = (c mod p)^(d_p) mod p ; m_q = (c mod q)^(d_q) mod q */
    mpz_mod(tmp, ciphertext->c, keys->p);
    mpz_powm(m_p, tmp, keys->d_p, keys->p);
    mpz_mod(tmp, ciphertext->c, keys->q);
    mpz_powm(m_q, tmp, keys->d_q, keys->q);

    /* m = m_q + ( (m_p - m_q)*(q_inv) mod p ) * q */
    mpz_sub(tmp, m_p, m_q);
    mpz_mul(tmp, tmp, keys->q_inv);
    mpz_mod(tmp, tmp, keys->p);
    mpz_mul(tmp, tmp, keys->q);
    mpz_add(plaintext->m, tmp, m_q);

    pmesg_mpz(msg_very_verbose, "testo in chiaro", plaintext->m);

    mpz_clears(m_p, m_q, tmp, NULL);
}
