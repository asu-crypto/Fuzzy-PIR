#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <array>
#include <vector>
#include "../pk_hd_fss.hpp"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <gmpxx.h>

using osuCrypto::PRNG;
using std::array;
using std::vector;
using osuCrypto::BitVector;

TEST_CASE("pk_hd_fss produces correct hamming distance matching additive shares indicating a match (HD=1) (n=10, hd_threshold=4)", "[pk_hd_fss]") {

     auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pk_hd_fss::one_time_setup_opts one_time_setup_opts;
    one_time_setup_opts.blum_int_bitlen = 1024;
    one_time_setup_opts.miller_rabin_rounds_per_prime = 25;
    one_time_setup_opts.stat_sec_param = 40;
    one_time_setup_opts.eval_out_ss_prime_mod = 263;
    one_time_setup_opts.n = 10;
    one_time_setup_opts.inclusive_hd_threshold = 4;

    pk_hd_fss::one_time_setup_sk one_time_setup_sk;
    pk_hd_fss::one_time_setup(one_time_setup_opts, prg, one_time_setup_sk);

    BitVector secret_bit_vector(one_time_setup_opts.n);
    secret_bit_vector[1] = true;
    secret_bit_vector[3] = true;
    secret_bit_vector[4] = true;
    secret_bit_vector[7] = true;

    pk_hd_fss::key k0, k1;
    pk_hd_fss::key_gen(one_time_setup_sk, secret_bit_vector, prg, k0, k1);

    BitVector pub_bit_vector(one_time_setup_opts.n);
    pub_bit_vector[1] = true;
    pub_bit_vector[3] = true;
    pub_bit_vector[4] = true;
    pub_bit_vector[7] = false;

    uint32_t hd_threshold_match_adss0_out, hd_threshold_match_adss1_out;
    pk_hd_fss::eval(k0, pub_bit_vector, hd_threshold_match_adss0_out);
    pk_hd_fss::eval(k1, pub_bit_vector, hd_threshold_match_adss1_out);

    uint32_t prime_mod = one_time_setup_opts.eval_out_ss_prime_mod;
    uint32_t reconstructed_hd_threshold_match_adss = (hd_threshold_match_adss1_out + hd_threshold_match_adss0_out) % prime_mod;

    REQUIRE(reconstructed_hd_threshold_match_adss == 1);

}


TEST_CASE("pk_hd_fss produces correct hamming distance matching additive shares indicating a match (HD=0) (n=10, hd_threshold=4)", "[pk_hd_fss]") {

     auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pk_hd_fss::one_time_setup_opts one_time_setup_opts;
    one_time_setup_opts.blum_int_bitlen = 1024;
    one_time_setup_opts.miller_rabin_rounds_per_prime = 25;
    one_time_setup_opts.stat_sec_param = 40;
    one_time_setup_opts.eval_out_ss_prime_mod = 263;
    one_time_setup_opts.n = 10;
    one_time_setup_opts.inclusive_hd_threshold = 4;

    pk_hd_fss::one_time_setup_sk one_time_setup_sk;
    pk_hd_fss::one_time_setup(one_time_setup_opts, prg, one_time_setup_sk);

    BitVector secret_bit_vector(one_time_setup_opts.n);
    secret_bit_vector[1] = true;
    secret_bit_vector[3] = true;
    secret_bit_vector[4] = true;
    secret_bit_vector[7] = true;

    pk_hd_fss::key k0, k1;
    pk_hd_fss::key_gen(one_time_setup_sk, secret_bit_vector, prg, k0, k1);

    BitVector pub_bit_vector(one_time_setup_opts.n);
    pub_bit_vector[1] = true;
    pub_bit_vector[3] = true;
    pub_bit_vector[4] = true;
    pub_bit_vector[7] = true;

    uint32_t hd_threshold_match_adss0_out, hd_threshold_match_adss1_out;
    pk_hd_fss::eval(k0, pub_bit_vector, hd_threshold_match_adss0_out);
    pk_hd_fss::eval(k1, pub_bit_vector, hd_threshold_match_adss1_out);

    uint32_t prime_mod = one_time_setup_opts.eval_out_ss_prime_mod;
    uint32_t reconstructed_hd_threshold_match_adss = (hd_threshold_match_adss1_out + hd_threshold_match_adss0_out) % prime_mod;

    REQUIRE(reconstructed_hd_threshold_match_adss == 1);

}

TEST_CASE("pk_hd_fss produces correct hamming distance matching additive shares indicating a match (HD=4) (n=10, hd_threshold=4)", "[pk_hd_fss]") {

     auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pk_hd_fss::one_time_setup_opts one_time_setup_opts;
    one_time_setup_opts.blum_int_bitlen = 1024;
    one_time_setup_opts.miller_rabin_rounds_per_prime = 25;
    one_time_setup_opts.stat_sec_param = 40;
    one_time_setup_opts.eval_out_ss_prime_mod = 263;
    one_time_setup_opts.n = 10;
    one_time_setup_opts.inclusive_hd_threshold = 4;

    pk_hd_fss::one_time_setup_sk one_time_setup_sk;
    pk_hd_fss::one_time_setup(one_time_setup_opts, prg, one_time_setup_sk);

    BitVector secret_bit_vector(one_time_setup_opts.n);
    secret_bit_vector[1] = true;
    secret_bit_vector[3] = true;
    secret_bit_vector[4] = true;
    secret_bit_vector[7] = true;

    pk_hd_fss::key k0, k1;
    pk_hd_fss::key_gen(one_time_setup_sk, secret_bit_vector, prg, k0, k1);

    BitVector pub_bit_vector(one_time_setup_opts.n);
    pub_bit_vector[1] = false;
    pub_bit_vector[3] = false;
    pub_bit_vector[4] = false;
    pub_bit_vector[7] = false;

    uint32_t hd_threshold_match_adss0_out, hd_threshold_match_adss1_out;
    pk_hd_fss::eval(k0, pub_bit_vector, hd_threshold_match_adss0_out);
    pk_hd_fss::eval(k1, pub_bit_vector, hd_threshold_match_adss1_out);

    uint32_t prime_mod = one_time_setup_opts.eval_out_ss_prime_mod;
    uint32_t reconstructed_hd_threshold_match_adss = (hd_threshold_match_adss1_out + hd_threshold_match_adss0_out) % prime_mod;

    REQUIRE(reconstructed_hd_threshold_match_adss == 1);

}

TEST_CASE("pk_hd_fss produces correct hamming distance matching additive shares indicating a non-match (HD=5) (n=10, hd_threshold=4)", "[pk_hd_fss]") {

     auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pk_hd_fss::one_time_setup_opts one_time_setup_opts;
    one_time_setup_opts.blum_int_bitlen = 1024;
    one_time_setup_opts.miller_rabin_rounds_per_prime = 25;
    one_time_setup_opts.stat_sec_param = 40;
    one_time_setup_opts.eval_out_ss_prime_mod = 263;
    one_time_setup_opts.n = 10;
    one_time_setup_opts.inclusive_hd_threshold = 4;

    pk_hd_fss::one_time_setup_sk one_time_setup_sk;
    pk_hd_fss::one_time_setup(one_time_setup_opts, prg, one_time_setup_sk);

    BitVector secret_bit_vector(one_time_setup_opts.n);
    secret_bit_vector[1] = true;
    secret_bit_vector[3] = true;
    secret_bit_vector[4] = true;
    secret_bit_vector[7] = true;

    pk_hd_fss::key k0, k1;
    pk_hd_fss::key_gen(one_time_setup_sk, secret_bit_vector, prg, k0, k1);

    BitVector pub_bit_vector(one_time_setup_opts.n);
    pub_bit_vector[0] = true;
    pub_bit_vector[2] = true;
    pub_bit_vector[5] = true;
    pub_bit_vector[7] = false;
    pub_bit_vector[9] = true;

    uint32_t hd_threshold_match_adss0_out, hd_threshold_match_adss1_out;
    pk_hd_fss::eval(k0, pub_bit_vector, hd_threshold_match_adss0_out);
    pk_hd_fss::eval(k1, pub_bit_vector, hd_threshold_match_adss1_out);

    uint32_t prime_mod = one_time_setup_opts.eval_out_ss_prime_mod;
    uint32_t reconstructed_hd_threshold_match_adss = (hd_threshold_match_adss1_out + hd_threshold_match_adss0_out) % prime_mod;

    REQUIRE(reconstructed_hd_threshold_match_adss == 0);

}
