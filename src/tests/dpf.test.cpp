#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <vector>
#include <cstdint>
#include <array>
#include "../fss.hpp"
#include "cryptoTools/Common/BitVector.h"

using osuCrypto::block;
using osuCrypto::PRNG;
using osuCrypto::BitVector;
using std::vector;
using std::array;

static block random_block(PRNG& prg, size_t n) {
    BitVector bv(n);

    for (size_t i = 0; i < n; i++) {
        bv[i] = prg.get<bool>();
    }

    return bv.blocks()[0];
}

TEST_CASE("DPF Evaluation with Same Root Seed Always Evaluates to Zero  (n=7)", "[correctness][same_root_seed]") {
    auto global_prg = PRNG(osuCrypto::toBlock(5719839740904675739ULL));
    
    const size_t n = 7;
    const size_t domain_size = 1ULL << n;
    block alpha = block(0,108);
    block beta = osuCrypto::toBlock(4341985187325902331ULL,3729205291002859743ULL);

    std::array<dpf_key,2> key_pair;
    dpf_gen(global_prg, n, alpha, beta, key_pair);

    for (size_t i = 0; i < domain_size; i++) {
        block x = block(0, i);
        block eval0 = dpf_eval(key_pair[0], x);
        block eval1 = dpf_eval(key_pair[0], x);

        REQUIRE((eval0 ^ eval1) == block());

        eval0 = dpf_eval(key_pair[1], x);
        eval1 = dpf_eval(key_pair[1], x);

        REQUIRE((eval0 ^ eval1) == block());

    }

    delete key_pair[0].cws;

}

TEST_CASE("DPF CW Gen Algorithm Prodoces the Correct Beta Shares (n=8)", "[correctness][cws][n=8]") {
   auto global_prg = PRNG(osuCrypto::toBlock(5719839740904675739ULL));
    
    const size_t n = 8;
    const size_t domain_size = 1ULL << n;
    block alpha = block(0,108);
    block beta = osuCrypto::toBlock(4341985187325902331ULL,3729205291002859743ULL);

    block p0_root_seed = global_prg.get<block>();
    block p1_root_seed = global_prg.get<block>();

    dpf_cws cws;
    block p0_beta_share, p1_beta_share;
    old_dpf_gen_cws(global_prg, n, p0_root_seed, p1_root_seed, alpha, beta, cws, p0_beta_share, p1_beta_share);

    block eval0 = dpf_eval(0, n, p0_root_seed, cws, alpha);
    block eval1 = dpf_eval(1, n, p1_root_seed, cws, alpha);

    REQUIRE((eval0 ^ eval1) == beta);
    REQUIRE(eval0 == p0_beta_share);
    REQUIRE(eval1 == p1_beta_share);

}

TEST_CASE("DPF Small Full Domain Correctness (n=7)", "[correctness][poly_domain][n=7]") {
    auto global_prg = PRNG(osuCrypto::toBlock(5719839740904675739ULL));
    
    const size_t n = 7;
    const size_t domain_size = 1ULL << n;
    block alpha = block(0,108);
    block beta = osuCrypto::toBlock(4341985187325902331ULL,3729205291002859743ULL);

    std::array<dpf_key,2> key_pair;
    dpf_gen(global_prg, n, alpha, beta, key_pair);

    for (size_t i = 0; i < domain_size; i++) {
        block x = block(0, i);
        block eval0 = dpf_eval(key_pair[0], x);
        block eval1 = dpf_eval(key_pair[1], x);

        if (x != alpha) {
            REQUIRE((eval0 ^ eval1) == block());
        } else {
            REQUIRE((eval0 ^ eval1) == beta);
        }

    }

    delete key_pair[0].cws;

}

TEST_CASE("DPF Small Full Domain Correctness (n=15)", "[correctness][poly_domain][n=15]") {
    auto global_prg = PRNG(osuCrypto::toBlock(14470836026931862485ULL));
    
    const size_t n = 15;
    const size_t domain_size = 1ULL << n;
    block alpha = block(0,25179);
    block beta = osuCrypto::toBlock(6997561703093904935ULL,4863909455133631174ULL);

    std::array<dpf_key,2> key_pair;
    dpf_gen(global_prg, n, alpha, beta, key_pair);

    for (size_t i = 0; i < domain_size; i++) {
        block x = block(0, i);
        block eval0 = dpf_eval(key_pair[0], x);
        block eval1 = dpf_eval(key_pair[1], x);

        if (x != alpha) {
            REQUIRE((eval0 ^ eval1) == block());
        } else {
             REQUIRE((eval0 ^ eval1) == beta);
        }

    }

    delete key_pair[0].cws;

}

TEST_CASE("DPF Large Domain Correctness with Random Trials (n=31)", "[correctness][exp_domain][n=31]") {
    auto global_prg = PRNG(osuCrypto::toBlock(12426442599595151159ULL,14054130607035283804ULL));
    auto test_prg = PRNG(osuCrypto::toBlock(11114520566441717755ULL,4456662723962352921ULL));

    const size_t n = 31;
    const size_t num_rand_trials = 1ULL << 10;
    block alpha = block(0,833558679ULL);
    block beta = osuCrypto::toBlock(4551317306124574518ULL,4913373638789847822ULL);

    std::array<dpf_key,2> key_pair;
    dpf_gen(global_prg, n, alpha, beta, key_pair);

    for (size_t i = 0; i < num_rand_trials; i++) {
        block x = random_block(test_prg, n);
        block eval0 = dpf_eval(key_pair[0], x);
        block eval1 = dpf_eval(key_pair[1], x);

        if (x != alpha) {
            REQUIRE((eval0 ^ eval1) == block());
        } else {
             REQUIRE((eval0 ^ eval1) == beta);
        }

    }

    block eval0 = dpf_eval(key_pair[0], alpha);
    block eval1 = dpf_eval(key_pair[1], alpha);

    REQUIRE((eval0 ^ eval1) == beta);

    delete key_pair[0].cws;

}

TEST_CASE("DPF Large Domain Correctness with Random Trials (n=32)", "[correctness][exp_domain][n=32]") {
    auto global_prg = PRNG(osuCrypto::toBlock(9753745207163285974ULL, 326668278255314955ULL));
    auto test_prg = PRNG(osuCrypto::toBlock(484600121121354243ULL,1069304259247278154ULL));

    const size_t n = 32;
    const size_t num_rand_trials = 1ULL << 10;
    block alpha = block(0,4289011082ULL);
    block beta = osuCrypto::toBlock(2762191533320217582ULL,13328248723039110248ULL);

    std::array<dpf_key,2> key_pair;
    dpf_gen(global_prg, n, alpha, beta, key_pair);

    for (size_t i = 0; i < num_rand_trials; i++) {
        block x = block(0, test_prg.get<uint32_t>());
        block eval0 = dpf_eval(key_pair[0], x);
        block eval1 = dpf_eval(key_pair[1], x);

        if (x != alpha) {
            REQUIRE((eval0 ^ eval1) == block());
        } else {
             REQUIRE((eval0 ^ eval1) == beta);
        }

    }

    block eval0 = dpf_eval(key_pair[0], alpha);
    block eval1 = dpf_eval(key_pair[1], alpha);

    REQUIRE((eval0 ^ eval1) == beta);

    delete key_pair[0].cws;

}

TEST_CASE("DPF Large Domain Correctness with Random Trials (n=77)", "[correctness][exp_domain][n=77]") {
    auto global_prg = PRNG(osuCrypto::toBlock(12426442599595151159ULL,14054130607035283804ULL));
    auto test_prg = PRNG(osuCrypto::toBlock(11114520566441717755ULL,4456662723962352921ULL));

    const size_t n = 77;
    const size_t num_rand_trials = 1ULL << 10;
    block alpha = block(7329ULL,833558679ULL);
    block beta = osuCrypto::toBlock(4551317306124574518ULL,4913373638789847822ULL);

    std::array<dpf_key,2> key_pair;
    dpf_gen(global_prg, n, alpha, beta, key_pair);

    for (size_t i = 0; i < num_rand_trials; i++) {
        block x = random_block(test_prg, n);
        block eval0 = dpf_eval(key_pair[0], x);
        block eval1 = dpf_eval(key_pair[1], x);

        if (x != alpha) {
            REQUIRE((eval0 ^ eval1) == block());
        } else {
             REQUIRE((eval0 ^ eval1) == beta);
        }

    }

    block eval0 = dpf_eval(key_pair[0], alpha);
    block eval1 = dpf_eval(key_pair[1], alpha);

    REQUIRE((eval0 ^ eval1) == beta);

    delete key_pair[0].cws;

}

TEST_CASE("DPF Large Domain Correctness with Random Trials (n=128)", "[correctness][exp_domain][n=128]") {
    auto global_prg = PRNG(osuCrypto::toBlock(12426442599595151159ULL,10692743444359128618ULL));
    auto test_prg = PRNG(osuCrypto::toBlock(1252096824295872404ULL,4456662723962352921ULL));

    const size_t n = 128;
    const size_t num_rand_trials = 1ULL << 10;
    block alpha = block(4975049802475859009ULL,16350662151992695822ULL);
    block beta = osuCrypto::toBlock(15781256119978507379ULL,4386034837013609554ULL);

    std::array<dpf_key,2> key_pair;
    dpf_gen(global_prg, n, alpha, beta, key_pair);

    for (size_t i = 0; i < num_rand_trials; i++) {
        block x = random_block(test_prg, n);
        block eval0 = dpf_eval(key_pair[0], x);
        block eval1 = dpf_eval(key_pair[1], x);

        if (x != alpha) {
            REQUIRE((eval0 ^ eval1) == block());
        } else {
             REQUIRE((eval0 ^ eval1) == beta);
        }

    }

    block eval0 = dpf_eval(key_pair[0], alpha);
    block eval1 = dpf_eval(key_pair[1], alpha);

    REQUIRE((eval0 ^ eval1) == beta);

    delete key_pair[0].cws;

}