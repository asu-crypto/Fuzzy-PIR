#include "./hss_hd.hpp"
#include <map>
#include <array>

using osuCrypto::PRNG;
using osuCrypto::BitVector;
using std::vector;
using std::map;
using std::array;

static const map<array<size_t, 2>, uint32_t> ge_poly_prime_map = {
    {{10,4}, 263}
};

static const map<array<size_t, 2>, vector<uint32_t>> ge_poly_coeffs = {
    {{10,4}, {1, 81, 251, 68, 95, 256, 93, 13, 150, 45}}
};

static void precomp_enc_bv_neg(const std::vector<pal_hss::input>& enc_bv,
                               const pal_hss::pk& pk, 
                               vector<pal_hss::input>& bv_neg_out) {
    assert(enc_bv.size() > 0);
    
    bv_neg_out.resize(enc_bv.size());

    for (size_t i = 0; i < enc_bv.size(); i++) {
        pal_hss::hom_neg_input(enc_bv[i], pk, bv_neg_out[i]);
    }

}

void hd_intss(const BitVector& pub_bit_vector, 
              const std::vector<pal_hss::input>& enc_bv,
              const pal_hss::pk& pk, 
              const pal_hss::ek& ek,
              mpz_class& hd_intss_out) {
    assert(enc_bv.size() == pub_bit_vector.size());
    assert(enc_bv.size() > 0);
    
    std::vector<pal_hss::input> bv_neg;
    precomp_enc_bv_neg(enc_bv, pk, bv_neg);

    pal_hss::input acc_hd_input;

    if (pub_bit_vector[0]) {
        acc_hd_input = bv_neg[0];
    } else {
        acc_hd_input = enc_bv[0];
    }

    for (size_t i = 1; i < enc_bv.size(); i++) {
        pal_hss::input neg_enc_bv_i;

        if (pub_bit_vector[i]) {
            pal_hss::hom_add_inputs(acc_hd_input, bv_neg[i], pk);

        } else {
            pal_hss::hom_add_inputs(acc_hd_input, enc_bv[i], pk);
        }

    }

    pal_hss::mem hd_mem;
    pal_hss::input_to_mem(acc_hd_input, pk, ek, hd_mem);

    hd_intss_out = hd_mem.x_intss;
    
}

static bool poly_prime_and_coeffs_exist(size_t bv_len, size_t hd_threshold) {
    array<size_t, 2> key = {bv_len, hd_threshold};

    return ge_poly_prime_map.find(key) != ge_poly_prime_map.end() && ge_poly_coeffs.find(key) != ge_poly_coeffs.end();
}

void hd_threshold_match(const BitVector& pub_bit_vector, 
                        const std::vector<pal_hss::input>& enc_bv,
                        const pal_hss::pk& pk, 
                        const pal_hss::ek& ek,
                        size_t inclusive_hd_threshold,
                        uint32_t& prime_mod,
                        uint32_t& hd_threshold_match_adss_out,
                        bool& hd_threshold_match_bss_out) {
    assert(enc_bv.size() == pub_bit_vector.size());
    assert(enc_bv.size() > 2);
    assert(inclusive_hd_threshold <= pub_bit_vector.size());
    assert(poly_prime_and_coeffs_exist(pub_bit_vector.size(), inclusive_hd_threshold));
    
    size_t n = pub_bit_vector.size();

    const vector<uint32_t>& poly_coeffs = ge_poly_coeffs.at({n, inclusive_hd_threshold});
    const uint32_t poly_prime = ge_poly_prime_map.at({n, inclusive_hd_threshold});

    prime_mod = poly_prime;

    std::vector<pal_hss::input> bv_neg;
    precomp_enc_bv_neg(enc_bv, pk, bv_neg);

    pal_hss::input acc_hd_input;

    if (pub_bit_vector[0]) {
        acc_hd_input = bv_neg[0];
    } else {
        acc_hd_input = enc_bv[0];
    }

    for (size_t i = 1; i < enc_bv.size(); i++) {
        pal_hss::input neg_enc_bv_i;

        if (pub_bit_vector[i]) {
            pal_hss::hom_add_inputs(acc_hd_input, bv_neg[i], pk);
        } else {
            pal_hss::hom_add_inputs(acc_hd_input, enc_bv[i], pk);
        }

    }

    pal_hss::mem carry_pow_mem;
    pal_hss::input_to_mem(acc_hd_input, pk, ek, carry_pow_mem);

    mpz_class carry_pow_mem_x_intss_mod_poly_prime;
    mpz_mod_ui(carry_pow_mem_x_intss_mod_poly_prime.get_mpz_t(), carry_pow_mem.x_intss.get_mpz_t(), poly_prime);

    uint32_t acc_poly_eval_intss = (ek.pidx == 0) ? poly_coeffs[0] : 0;

    acc_poly_eval_intss += (poly_coeffs[1] * carry_pow_mem_x_intss_mod_poly_prime.get_ui()) % poly_prime;

    //std::cout << "acc_poly_eval_intss = " << acc_poly_eval_intss << std::endl;

    for (size_t i = 2; i < poly_coeffs.size(); i++) {

        pal_hss::hom_mult_mem_input(carry_pow_mem, acc_hd_input, pk, ek);

        mpz_mod_ui(carry_pow_mem_x_intss_mod_poly_prime.get_mpz_t(), carry_pow_mem.x_intss.get_mpz_t(), poly_prime);
        acc_poly_eval_intss += poly_coeffs[i] * carry_pow_mem_x_intss_mod_poly_prime.get_ui();
        acc_poly_eval_intss %= poly_prime;

        //std::cout << "acc_poly_eval_intss = " << acc_poly_eval_intss << std::endl;

    }

    hd_threshold_match_adss_out = acc_poly_eval_intss;
    hd_threshold_match_bss_out = 0;

}
