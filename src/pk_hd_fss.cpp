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
    {{10,4}, 263},
    {{31, 5}, 251},
    {{32,5}, 251},
    {{64,6}, 251},
    {{128,7}, 251}

};

static const map<array<size_t, 2>, vector<uint32_t>> ge_poly_coeffs = {
    {{10,4}, {1, 81, 251, 68, 95, 256, 93, 13, 150, 45}},
    {{32,5}, {1,203,120,228,7,221,32,162,16,194,194,179,15,167,9,96,186,196,246,34,76,199,147,172,130,39,10,243,77,9,55,209,145}},
    {{64,6}, {1,148,187,146,144,88,162,216,37,98,98,83,7,249,146,223,50,180,140,93,177,240,249,201,63,49,164,239,58,110,121,154,77,135,181,231,30,159,197,198,144,32,239,2,153,159,163,43,158,181,225,250,98,173,94,135,22,45,231,143,204,203,154,49,208}},
    {{128,7}, {1,202,40,112,162,75,219,116,59,125,94,184,139,0,95,25,85,167,155,0,169,202,187,217,144,47,131,115,96,73,19,243,63,61,191,93,180,42,1,52,182,65,143,133,182,27,244,177,191,176,98,79,200,108,181,72,106,116,74,139,177,24,232,11,106,11,34,39,112,240,133,114,68,13,239,63,81,99,108,85,243,91,73,250,33,14,207,210,3,90,140,129,76,229,8,76,137,105,110,162,208,221,224,126,116,38,96,122,165,40,191,173,125,144,183,156,42,32,193,124,74,168,198,146,133,93,16,95,221}}
    //{{31,5}, {1,149254738,1866557849,1551169740,633575973,966842048,960478088,307095781,484546730,2000280975,1983312044,760100187,1229459510,924144550,1412802006,178383026,382351911,2038667949,632554322,1881428818,453382756,703282127,1624539408,1609884484,1569120384,1436958617,904826549,324450963,199803047,1274480237,1768519888}}    
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
    //hss_opts.value_base_bitlen = opts.n * log2ceil(opts.inclusive_hd_threshold + 1);
    hss_opts.value_base_bitlen = opts.n * log2ceil(opts.n + 1);

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
    
    //std::cout << "Public BV: " << pub_bv.getSpan<uint32_t>()[0] << std::endl;
    //std::cout << "Carry Pow Mem x mod Prime: " << carry_pow_mem_x_intss_mod_prime.get_ui() << std::endl;

    hd_threshold_match_adss_out = (k.hss_ek.pidx == 1) ? poly_coeffs[0] : 0;

    hd_threshold_match_adss_out += (poly_coeffs[1] * carry_pow_mem_x_intss_mod_prime.get_ui());
    hd_threshold_match_adss_out %= prime_mod;

    for (size_t i = 2; i < poly_coeffs.size(); i++) {

        pal_hss::hom_mult_mem_input(carry_pow_mem, acc_hd_input, k.hss_pk, k.hss_ek);

        mpz_mod_ui(carry_pow_mem_x_intss_mod_prime.get_mpz_t(), carry_pow_mem.x_intss.get_mpz_t(), prime_mod);

        //std::cout << "Carry Pow Mem x mod Prime (iteration " << i << "): " << carry_pow_mem_x_intss_mod_prime.get_ui() << std::endl;

        hd_threshold_match_adss_out += (poly_coeffs[i] * carry_pow_mem_x_intss_mod_prime.get_ui());
        hd_threshold_match_adss_out %= prime_mod;

    }

    hd_threshold_match_adss_out = (k.hss_ek.pidx == 1) ? hd_threshold_match_adss_out : (prime_mod - hd_threshold_match_adss_out);

}