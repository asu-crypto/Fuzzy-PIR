#include "./paillier.hpp"
#include <gmpxx.h>
#include "./rand.hpp"

using osuCrypto::PRNG;

void pal_keygen(size_t blum_int_bitlen, 
                size_t miller_rabin_rounds_per_prime,
                PRNG& prg, 
                pal_sk& sk_out, 
                pal_pk& pk_out) {
    assert(blum_int_bitlen % 2 == 0); // Ensure we can split the bit length evenly for p and q

    // I'M USING UNSAGE PRRIME FOR TESTS, BECAUSE SAFE PRIMES TAKE TOO LONG TO GENERATE AND GENERATES THE PRIMES IS A ONE-TIME COST.
    gen_blum_int_with_unsafe_primes(blum_int_bitlen / 2, miller_rabin_rounds_per_prime, prg, sk_out.p, sk_out.q, pk_out.N);
    
    pk_out.N_squared = pk_out.N * pk_out.N;
    pk_out.N_plus_1 = pk_out.N + 1;

    // The next lines computes the private exponent d such that d ≡ 0 (mod φ(N)) and d ≡ 1 (mod N)
    mpz_class phi_N = (sk_out.p - 1) * (sk_out.q - 1);
    mpz_class g, s, t;
    mpz_gcdext(g.get_mpz_t(), s.get_mpz_t(), t.get_mpz_t(), pk_out.N.get_mpz_t(), phi_N.get_mpz_t());    
    sk_out.d = phi_N*t;

}

void pal_encrypt(const mpz_class& plaintext, const pal_pk& pk, osuCrypto::PRNG& prg, mpz_class& ciphertext_out) {
    
    // Samples a random r in the range [0, N).
    mpz_class r;
    gen_rand_int(mpz_sizeinbase(pk.N.get_mpz_t(), 2), prg, r);

    mpz_class ct_msg_term, ct_rand_term;

    // Compute (N + 1)^m mod N^2
    mpz_powm(ct_msg_term.get_mpz_t(), pk.N_plus_1.get_mpz_t(), plaintext.get_mpz_t(), pk.N_squared.get_mpz_t());

    // Compute r^N mod N^2
    mpz_powm(ct_rand_term.get_mpz_t(), r.get_mpz_t(), pk.N.get_mpz_t(), pk.N_squared.get_mpz_t());

    // Compute final ciphertext
    mpz_mul(ciphertext_out.get_mpz_t(), ct_msg_term.get_mpz_t(), ct_rand_term.get_mpz_t());
    mpz_mod(ciphertext_out.get_mpz_t(), ciphertext_out.get_mpz_t(), pk.N_squared.get_mpz_t());

}

void pal_decrypt(const mpz_class& ciphertext, const pal_sk& sk, const pal_pk& pk, mpz_class& plaintext_out) {
    mpz_class ct_d_mod_N_squared;
    mpz_powm(ct_d_mod_N_squared.get_mpz_t(), ciphertext.get_mpz_t(), sk.d.get_mpz_t(), pk.N_squared.get_mpz_t());

    // Compute m = (ct^d mod N^2 - 1) / N
    mpz_sub_ui(plaintext_out.get_mpz_t(), ct_d_mod_N_squared.get_mpz_t(), 1);
    mpz_divexact(plaintext_out.get_mpz_t(), plaintext_out.get_mpz_t(), pk.N.get_mpz_t());
}

void hom_ct_add(const mpz_class& ct0, const mpz_class& ct1, const pal_pk& pk, mpz_class& ct_sum_out) {
    mpz_mul(ct_sum_out.get_mpz_t(), ct0.get_mpz_t(), ct1.get_mpz_t());
    mpz_mod(ct_sum_out.get_mpz_t(), ct_sum_out.get_mpz_t(), pk.N_squared.get_mpz_t());
}

void hom_ct_add(mpz_class& ct0_and_out, const mpz_class& ct1, const pal_pk& pk) {
    mpz_mul(ct0_and_out.get_mpz_t(), ct0_and_out.get_mpz_t(), ct1.get_mpz_t());
    mpz_mod(ct0_and_out.get_mpz_t(), ct0_and_out.get_mpz_t(), pk.N_squared.get_mpz_t());
}

void hom_bit_negate(const mpz_class& ct, const pal_pk& pk, mpz_class& ct_neg_out) {
    
    // After this step we have ct^{-1} mod N^2, which is the encryption of -m (negation in the plaintext space) with the same randomness as ct.
    mpz_invert(ct_neg_out.get_mpz_t(), ct.get_mpz_t(), pk.N_squared.get_mpz_t());

    // After this step we have (ct^{-1} mod N^2) * (N + 1) over the integers.
    mpz_mul(ct_neg_out.get_mpz_t(), ct_neg_out.get_mpz_t(), pk.N_plus_1.get_mpz_t());

    //After this step we have ct^{-1}* (N + 1) mod N^2, which is the encryption of -m + 1 (negation in the plaintext space plus one) with the same randomness as ct.
    mpz_mod(ct_neg_out.get_mpz_t(), ct_neg_out.get_mpz_t(), pk.N_squared.get_mpz_t());

}

void hom_ct_pt_mul(const mpz_class& ct, const mpz_class& pt_multiplier, const pal_pk& pk, mpz_class& ct_product_out) {
    mpz_powm(ct_product_out.get_mpz_t(), ct.get_mpz_t(), pt_multiplier.get_mpz_t(), pk.N_squared.get_mpz_t());
}
