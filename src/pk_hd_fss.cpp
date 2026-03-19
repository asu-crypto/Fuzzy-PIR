#include "./pk_hd_fss.hpp"
#include <map>
#include <array>
#include <cmath>

using osuCrypto::PRNG;
using osuCrypto::BitVector;
using std::vector;
using std::map;
using std::array;

using pk_hd_fss::one_time_setup_sk;
using pk_hd_fss::key;


static const map<array<size_t, 2>, uint32_t> ge_poly_prime_map = {
    {{10,4}, 263}
};

static const map<array<size_t, 2>, vector<uint32_t>> ge_poly_coeffs = {
    {{10,4}, {1, 81, 251, 68, 95, 256, 93, 13, 150, 45}}
};

static bool poly_prime_and_coeffs_exist(size_t bv_len, size_t hd_threshold) {
    array<size_t, 2> key = {bv_len, hd_threshold};

    return ge_poly_prime_map.find(key) != ge_poly_prime_map.end() && ge_poly_coeffs.find(key) != ge_poly_coeffs.end();
}

static uint64_t log2ceil(uint64_t x) {
    return (x > 1) ? static_cast<uint64_t>(std::ceil(std::log2(x))) : 0;
}

static void precomp_enc_bv_neg(const std::vector<pal_hss::input>& enc_bv,
                               const pal_hss::pk& pk, 
                               vector<pal_hss::input>& bv_neg_out) {
    assert(enc_bv.size() > 0);
    
    bv_neg_out.resize(enc_bv.size());

    for (size_t i = 0; i < enc_bv.size(); i++) {
        pal_hss::hom_neg_input(enc_bv[i], pk, bv_neg_out[i]);
    }

}

void pk_hd_fss::one_time_setup(const one_time_setup_opts& opts, 
                               osuCrypto::PRNG& prg,
                               one_time_setup_sk& secret_out) {
    assert(opts.n > 2);
    assert(opts.inclusive_hd_threshold <= opts.n);
    assert(poly_prime_and_coeffs_exist(opts.n, opts.inclusive_hd_threshold));
    assert(opts.eval_out_ss_prime_mod == ge_poly_prime_map.at({opts.n, opts.inclusive_hd_threshold}));

    pal_hss::setup_opts hss_opts;
    hss_opts.blum_int_bitlen = opts.blum_int_bitlen;
    hss_opts.miller_rabin_rounds_per_prime = opts.miller_rabin_rounds_per_prime;
    hss_opts.stat_sec_param = opts.stat_sec_param;
    hss_opts.value_base_bitlen = opts.n * log2ceil(opts.inclusive_hd_threshold + 1);
    
    pal_hss::setup(hss_opts, prg, secret_out.hss_pk, secret_out.hss_sk);

    secret_out.n = opts.n;
    secret_out.inclusive_hd_threshold = opts.inclusive_hd_threshold;

}

void pk_hd_fss::key_gen(const one_time_setup_sk& secret_out,
                        const BitVector& bv, 
                        osuCrypto::PRNG& prg,
                        pk_hd_fss::key& k0,
                        pk_hd_fss::key& k1) {
    assert(bv.size() == secret_out.n);

    size_t n = secret_out.n;
    size_t inclusive_hd_threshold = secret_out.inclusive_hd_threshold;
    
    k0.n = n;
    k0.inclusive_hd_threshold = inclusive_hd_threshold;
    k1.n = n;
    k1.inclusive_hd_threshold = inclusive_hd_threshold;
    
    array<pal_hss::ek, 2> hss_ek;
    pal_hss::gen_eks(secret_out.hss_sk, secret_out.hss_pk, prg, hss_ek);

    k0.hss_pk = secret_out.hss_pk;
    k0.hss_ek = hss_ek[0];
    k1.hss_pk = secret_out.hss_pk;
    k1.hss_ek = hss_ek[1];

    k0.enc_bv.resize(n);
    k1.enc_bv.resize(n);

    for (size_t i = 0; i < n; i++) {

        pal_hss::enc_bin_input(bv[i], secret_out.hss_pk, secret_out.hss_sk, prg, k0.enc_bv[i]);
        k1.enc_bv[i] = k0.enc_bv[i];
        
    }

}

void pk_hd_fss::eval(const pk_hd_fss::key& k,
                      const BitVector& pub_bv,
                      uint32_t& hd_threshold_match_adss_out) {
    assert(pub_bv.size() == k.n);

    size_t n = k.n;
    size_t inclusive_hd_threshold = k.inclusive_hd_threshold;

    uint32_t prime_mod = ge_poly_prime_map.at({n, inclusive_hd_threshold});
    const vector<uint32_t>& poly_coeffs = ge_poly_coeffs.at({n, inclusive_hd_threshold});
    
    std::vector<pal_hss::input> bv_neg;
    precomp_enc_bv_neg(k.enc_bv, k.hss_pk, bv_neg);

    pal_hss::input acc_hd_input;

    if (pub_bv[0]) {
        acc_hd_input = bv_neg[0];
    } else {
        acc_hd_input = k.enc_bv[0];
    }

    for (size_t i = 1; i < n; i++) {
        pal_hss::input neg_enc_bv_i;

        if (pub_bv[i]) {
            pal_hss::hom_add_inputs(acc_hd_input, bv_neg[i], k.hss_pk);
        } else {
            pal_hss::hom_add_inputs(acc_hd_input, k.enc_bv[i], k.hss_pk);
        }

    }

    pal_hss::mem carry_pow_mem;
    pal_hss::input_to_mem(acc_hd_input, k.hss_pk, k.hss_ek, carry_pow_mem);

    mpz_class carry_pow_mem_x_intss_mod_prime;
    mpz_mod_ui(carry_pow_mem_x_intss_mod_prime.get_mpz_t(), carry_pow_mem.x_intss.get_mpz_t(), prime_mod);

    hd_threshold_match_adss_out = (k.hss_ek.pidx == 1) ? poly_coeffs[0] : 0;

    hd_threshold_match_adss_out = (hd_threshold_match_adss_out + (poly_coeffs[1] * carry_pow_mem_x_intss_mod_prime.get_ui())) % prime_mod;

    for (size_t i = 2; i < poly_coeffs.size(); i++) {

        pal_hss::hom_mult_mem_input(carry_pow_mem, acc_hd_input, k.hss_pk, k.hss_ek);

        mpz_mod_ui(carry_pow_mem_x_intss_mod_prime.get_mpz_t(), carry_pow_mem.x_intss.get_mpz_t(), prime_mod);

        hd_threshold_match_adss_out = (hd_threshold_match_adss_out + (poly_coeffs[i] * carry_pow_mem_x_intss_mod_prime.get_ui())) % prime_mod;

    }

    hd_threshold_match_adss_out = (k.hss_ek.pidx == 1) ? hd_threshold_match_adss_out : (prime_mod - hd_threshold_match_adss_out);

}