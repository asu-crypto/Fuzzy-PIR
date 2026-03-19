#pragma once

#include <gmpxx.h>
#include "cryptoTools/Crypto/PRNG.h"
#include <stdint.h>

struct pal_sk {
    mpz_class p;
    mpz_class q;
    mpz_class d;
};

struct pal_pk {    
    mpz_class N;
    mpz_class N_squared;
    mpz_class N_plus_1;
};

void pal_keygen(size_t blum_int_bitlen, 
                size_t miller_rabin_rounds_per_prime,
                osuCrypto::PRNG& prg, 
                pal_sk& sk_out, 
                pal_pk& pk_out);

void pal_encrypt(const mpz_class& plaintext, const pal_pk& pk, osuCrypto::PRNG& prg, mpz_class& ciphertext_out);
void pal_decrypt(const mpz_class& ciphertext, const pal_sk& sk, const pal_pk& pk, mpz_class& plaintext_out);

void hom_ct_add(const mpz_class& ct0, const mpz_class& ct1, const pal_pk& pk, mpz_class& ct_sum_out);
// This function does the same has hom_ct_add but stores the result in ct0_and_out to save memory. ct1 is not modified.
void hom_ct_add(mpz_class& ct0_and_out, const mpz_class& ct1, const pal_pk& pk);

void hom_bit_negate(const mpz_class& ct, const pal_pk& pk, mpz_class& ct_neg_out);
void hom_ct_pt_mul(const mpz_class& ct, const mpz_class& pt_multiplier, const pal_pk& pk, mpz_class& ct_product_out);
