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
    {{128,7}, 251},
    {{16,1}, 251},
    {{32,1}, 251},
    {{64,1}, 251},
    {{128,1}, 251},
    {{16,2}, 251},
    {{32,2}, 251},
    {{64,2}, 251},
    {{128,2}, 251},
    {{16,3}, 251},
    {{32,3}, 251},
    {{64,3}, 251},
    {{128,3}, 251},
    {{16,4}, 251},
    {{32,4}, 251},
    {{64,4}, 251},
    {{128,4}, 251},
};

static const map<array<size_t, 2>, vector<uint32_t>> ge_poly_coeffs = {
    {{10,4}, {1, 81, 251, 68, 95, 256, 93, 13, 150, 45}},
    {{32,5}, {1,203,120,228,7,221,32,162,16,194,194,179,15,167,9,96,186,196,246,34,76,199,147,172,130,39,10,243,77,9,55,209,145}},
    {{64,6}, {1,148,187,146,144,88,162,216,37,98,98,83,7,249,146,223,50,180,140,93,177,240,249,201,63,49,164,239,58,110,121,154,77,135,181,231,30,159,197,198,144,32,239,2,153,159,163,43,158,181,225,250,98,173,94,135,22,45,231,143,204,203,154,49,208}},
    {{128,7}, {1,202,40,112,162,75,219,116,59,125,94,184,139,0,95,25,85,167,155,0,169,202,187,217,144,47,131,115,96,73,19,243,63,61,191,93,180,42,1,52,182,65,143,133,182,27,244,177,191,176,98,79,200,108,181,72,106,116,74,139,177,24,232,11,106,11,34,39,112,240,133,114,68,13,239,63,81,99,108,85,243,91,73,250,33,14,207,210,3,90,140,129,76,229,8,76,137,105,110,162,208,221,224,126,116,38,96,122,165,40,191,173,125,144,183,156,42,32,193,124,74,168,198,146,133,93,16,95,221}},
    //{{31,5}, {1,149254738,1866557849,1551169740,633575973,966842048,960478088,307095781,484546730,2000280975,1983312044,760100187,1229459510,924144550,1412802006,178383026,382351911,2038667949,632554322,1881428818,453382756,703282127,1624539408,1609884484,1569120384,1436958617,904826549,324450963,199803047,1274480237,1768519888}}    
    {{16, 1}, {1,53,30,204,1,17,75,132,129,233,168,109,151,247,188,69,202}},
    {{32, 1}, {1,109,58,7,159,207,113,162,65,114,239,94,51,216,56,179,194,30,162,16,135,204,95,63,183,153,118,3,225,242,235,206,174}},
    {{64, 1}, {1,248,136,93,158,166,230,7,160,84,227,248,56,189,166,37,198,13,196,232,227,39,127,107,114,135,215,192,15,166,0,144,151,83,72,80,8,50,239,111,164,112,39,182,10,153,184,106,162,87,126,238,159,236,79,241,98,169,204,12,172,165,102,146,69}},
    {{128, 1}, {1,50,176,214,34,55,10,31,33,182,24,221,218,24,113,72,175,73,248,123,49,0,177,191,156,215,231,98,41,17,59,208,64,67,219,162,234,86,237,96,196,200,72,80,14,169,115,133,177,233,86,209,10,193,210,121,247,4,132,57,133,121,166,38,155,43,170,134,1,96,248,206,177,51,77,5,36,91,171,5,121,119,77,27,32,55,181,148,21,243,165,188,58,206,178,18,105,121,232,60,245,222,245,70,78,30,69,243,23,110,12,102,59,77,158,13,195,32,51,142,99,163,106,110,65,159,118,44,200}},
    {{16, 2}, {1,244,39,125,61,67,95,0,28,9,58,159,133,120,25,0,92}},
    {{32, 2}, {1,112,165,151,159,134,99,54,26,217,154,140,33,94,228,92,235,237,16,167,233,38,107,60,239,139,68,202,189,196,127,5,151}},
    {{64, 2}, {1,244,151,105,178,38,43,2,243,151,213,26,103,188,173,162,150,157,213,87,143,114,197,127,145,180,52,182,241,239,70,113,78,127,189,96,26,219,241,161,124,210,141,198,145,61,202,226,67,168,152,130,1,248,68,52,123,2,101,45,151,120,22,90,120}},
    {{128, 2}, {1,2,131,199,11,110,122,175,220,7,27,78,6,210,44,150,68,189,116,225,75,214,201,240,206,62,225,37,81,220,34,189,3,186,224,41,20,79,34,11,57,56,108,56,183,138,49,195,80,147,235,149,239,184,78,246,28,230,48,65,148,229,206,178,165,44,156,14,207,160,171,63,82,113,156,105,0,220,136,250,225,90,29,124,40,68,74,178,177,56,104,25,138,157,211,100,135,118,117,53,76,228,24,70,92,134,146,129,63,128,115,73,175,58,153,69,130,188,203,199,55,243,184,67,100,181,191,73,201}},
    {{16, 3}, {1,96,203,49,5,14,65,125,67,4,78,90,188,115,54,166,187}},
    {{32, 3}, {1,92,208,64,108,18,245,23,83,5,73,25,17,89,179,225,218,243,8,177,170,28,56,103,121,45,156,244,186,47,142,237,130}},
    {{64, 3}, {1,76,56,95,177,182,196,5,70,244,6,214,192,109,127,146,189,198,92,42,147,93,49,117,187,178,125,30,187,47,158,215,207,37,133,133,40,83,161,17,107,224,29,113,96,39,38,148,57,207,58,204,92,168,164,158,241,116,73,238,230,36,89,26,70}},
    {{128, 3}, {1,91,163,167,16,174,120,53,55,191,148,232,59,0,243,162,144,70,209,70,54,101,61,245,163,179,47,12,23,13,244,190,23,190,78,20,44,48,4,41,8,34,5,110,153,99,195,10,172,140,44,170,22,223,147,192,111,67,155,123,194,24,195,161,166,240,209,100,234,6,76,29,143,163,0,116,69,143,219,123,115,146,149,39,58,73,158,127,228,214,167,242,39,106,90,150,125,33,171,163,145,227,188,210,165,36,250,83,9,166,173,171,235,226,83,81,228,130,36,6,180,106,162,13,6,191,48,68,159}},
    {{16, 4}, {1,143,134,162,108,45,244,76,124,219,126,208,247,218,5,8,192}},
    {{32, 4}, {1,138,122,217,109,133,54,79,76,20,180,91,116,159,46,70,199,65,112,40,167,140,202,127,172,104,118,197,0,115,27,25,94}},
    {{64, 4}, {1,115,151,169,59,243,30,136,179,54,202,163,82,38,193,76,88,229,134,200,79,2,180,45,27,70,181,194,172,245,226,248,117,14,205,32,231,14,101,89,194,162,187,180,4,222,150,35,34,172,222,107,15,140,9,120,39,90,37,64,207,147,144,133,205}},
    {{128, 4}, {1,217,30,67,16,172,133,139,57,159,75,44,20,165,82,250,110,197,112,44,19,98,184,210,103,192,226,209,248,185,70,242,30,66,143,31,183,134,157,83,162,221,82,114,24,166,109,147,103,80,27,158,249,149,71,205,210,168,164,245,227,192,211,101,183,192,188,109,40,154,54,188,166,148,184,113,43,33,186,163,1,236,181,200,32,137,17,202,159,108,165,103,98,72,9,99,47,249,68,240,81,146,191,156,52,161,247,59,219,161,176,85,169,192,47,91,4,191,108,168,50,245,97,212,80,182,134,219,91}}
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

    const size_t prime_mod = opts.eval_out_ss_prime_mod;

    pal_hss::setup_opts hss_opts;
    hss_opts.blum_int_bitlen = opts.blum_int_bitlen;
    hss_opts.miller_rabin_rounds_per_prime = opts.miller_rabin_rounds_per_prime;
    hss_opts.stat_sec_param = opts.stat_sec_param;
    //hss_opts.value_base_bitlen = opts.n * log2ceil(opts.inclusive_hd_threshold + 1);
    hss_opts.value_base_bitlen = (opts.n + 2) * log2ceil(prime_mod);

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
    uint8_t prime_mod = ge_poly_prime_map.at({n, inclusive_hd_threshold});

    k0.n = n;
    k0.inclusive_hd_threshold = inclusive_hd_threshold;
    k0.ss_mod = prime_mod;
    k1.n = n;
    k1.inclusive_hd_threshold = inclusive_hd_threshold;
    k1.ss_mod = prime_mod;
    
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

    uint8_t prime_mod = k.ss_mod;
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

size_t pk_hd_fss::key_byte_size(const pk_hd_fss::key& k) {
    size_t size = 0;

    size += mpz_sizeinbase(k.hss_pk.pk.N.get_mpz_t(), 2) / 8;

    for (size_t i = 0;i < k.hss_ek.d_slice_intss.size(); i++) {
        size += mpz_sizeinbase(k.hss_ek.d_slice_intss[i].get_mpz_t(), 2) / 8;
    }

    for (size_t i = 0; i < k.enc_bv.size(); i++) {
        size += mpz_sizeinbase(k.enc_bv[i].x_ct.get_mpz_t(), 2) / 8;
        for (size_t j = 0; j < k.enc_bv[i].xd_slices_cts.size(); j++) {
            size += mpz_sizeinbase(k.enc_bv[i].xd_slices_cts[j].get_mpz_t(), 2) / 8;
        }
    }

    return size;

}