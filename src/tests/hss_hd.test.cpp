#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <array>
#include <vector>
#include "../pal_hss.hpp"
#include "../ss.hpp"
#include "../hss_hd.hpp"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <gmpxx.h>

using osuCrypto::PRNG;
using std::array;
using std::vector;
using osuCrypto::BitVector;

TEST_CASE("hss_hd produces the correct hamming distance between the public bit vector and the secret bit vector", "[hss_hd]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pal_hss::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 25;
    opts.stat_sec_param = 40;
    opts.value_base_bitlen = 7; // log2(128)

    pal_hss::pk hss_pk;
    std::array<pal_hss::ek, 2> hss_ek;
    pal_hss::sk hss_sk;

    pal_hss::setup(opts, prg, hss_pk, hss_ek, hss_sk);

    BitVector pub_bit_vector(10);
    pub_bit_vector[1] = true;
    pub_bit_vector[3] = true;
    pub_bit_vector[4] = true;
    pub_bit_vector[7] = true;

    BitVector secret_bit_vector = pub_bit_vector;
    secret_bit_vector[3] = false;
    secret_bit_vector[5] = true;

    vector<pal_hss::input> enc_bv(secret_bit_vector.size());
    for (size_t i = 0; i < secret_bit_vector.size(); i++) {
        pal_hss::enc_bin_input(secret_bit_vector[i], hss_pk, hss_sk, prg, enc_bv[i]);
    }

    mpz_class hd_intss0_out, hd_intss1_out;
    hd_intss(pub_bit_vector, enc_bv, hss_pk, hss_ek[0], hd_intss0_out);
    hd_intss(pub_bit_vector, enc_bv, hss_pk, hss_ek[1], hd_intss1_out);

    mpz_class hd_out;
    intss_reconst(hd_intss0_out, hd_intss1_out, hd_out);

    BitVector expected_hd_bit_vector = pub_bit_vector ^ secret_bit_vector;
    size_t expected_hd = expected_hd_bit_vector.hammingWeight();

    REQUIRE(hd_out == expected_hd);

}

TEST_CASE("hd_threshold_match correctly identifies when the Hamming distance between the public bit vector and the secret bit vector is within the threshold", "[hss_hd]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pal_hss::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 25;
    opts.stat_sec_param = 40;
    opts.value_base_bitlen = 7; // log2(128)

    pal_hss::pk hss_pk;
    std::array<pal_hss::ek, 2> hss_ek;
    pal_hss::sk hss_sk;

    pal_hss::setup(opts, prg, hss_pk, hss_ek, hss_sk);

    BitVector pub_bit_vector(10);
    pub_bit_vector[1] = true;
    pub_bit_vector[3] = true;
    pub_bit_vector[4] = true;
    pub_bit_vector[7] = true;

    BitVector secret_bit_vector = pub_bit_vector;
    secret_bit_vector[3] = false;
    secret_bit_vector[5] = true;

    vector<pal_hss::input> enc_bv(secret_bit_vector.size());
    for (size_t i = 0; i < secret_bit_vector.size(); i++) {
        pal_hss::enc_bin_input(secret_bit_vector[i], hss_pk, hss_sk, prg, enc_bv[i]);
    }

    uint32_t hd_threshold_match_adss0_out, hd_threshold_match_adss1_out;
    bool hd_threshold_match_bss_out;

    size_t inclusive_hd_threshold = 4;
    uint32_t prime_mod;

    hd_threshold_match(pub_bit_vector, 
                       enc_bv, 
                       hss_pk, 
                       hss_ek[0], 
                       inclusive_hd_threshold,
                       prime_mod,
                       hd_threshold_match_adss0_out, 
                       hd_threshold_match_bss_out);
    hd_threshold_match(pub_bit_vector, 
                       enc_bv, 
                       hss_pk, 
                       hss_ek[1], 
                       inclusive_hd_threshold, 
                       prime_mod, 
                       hd_threshold_match_adss1_out, 
                       hd_threshold_match_bss_out);

    uint32_t reconstructed_hd_threshold_match_adss = (hd_threshold_match_adss0_out - hd_threshold_match_adss1_out) % prime_mod;

    std::cout << "expected hamming distance = " << (pub_bit_vector ^ secret_bit_vector).hammingWeight() << std::endl;

    uint32_t expected_hd_threshold_match = (pub_bit_vector ^ secret_bit_vector).hammingWeight() <= inclusive_hd_threshold ? 1 : 0;

    REQUIRE(reconstructed_hd_threshold_match_adss == expected_hd_threshold_match);

}

