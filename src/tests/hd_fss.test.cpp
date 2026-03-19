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
using osuCrypto::AllOneBlock;

static block random_block(PRNG& prg, size_t n) {
    BitVector bv(n);

    for (size_t i = 0; i < n; i++) {
        bv[i] = prg.get<bool>();
    }

    return bv.blocks()[0];
}

static size_t block_hd(const block& a, const block& b, size_t n) {
    BitVector a_bv(n), b_bv(n);
    a_bv.assign(a);
    b_bv.assign(b);

    a_bv.blocks()[0] &= (AllOneBlock ^ (AllOneBlock << n));
    b_bv.blocks()[0] &= (AllOneBlock ^ (AllOneBlock << n));

    return (a_bv ^ b_bv).hammingWeight();
}

TEST_CASE("HD FSS Small Full Domain Correctness (n=8)", "[correctness][poly_domain][n=8]") {
    auto global_prg = PRNG(osuCrypto::toBlock(5719839740904675739ULL));
    
    const size_t n = 8;
    const size_t domain_size = 1ULL << n;
    block alpha = block(0,108);
    block beta = osuCrypto::toBlock(4341985187325902331ULL,3729205291002859743ULL);

    std::array<ddf_key,2> key_pair;
    hw_fss_gen(global_prg, n, alpha, beta, key_pair);

    for (size_t i = 0; i < domain_size; i++) {
        block x = block(0, i);
        block eval0 = hw_fss_eval(key_pair[0], x);
        block eval1 = hw_fss_eval(key_pair[1], x);

        //std::cout << "x: " << x << " eval0: " << eval0 << " eval1: " << eval1 << " hd: " << block_hd(x, alpha, n) << std::endl;

        if (block_hd(x, alpha, n) != 1) {
            REQUIRE((eval0 ^ eval1) == block());
        } else {
            REQUIRE((eval0 ^ eval1) == beta);
        }
    }

    delete[] key_pair[0].cws;
}

TEST_CASE("HD FSS Exponential Domain Correctness with Random Trials (n=128)", "[correctness][exp_domain][n=128]") {
    auto global_prg = PRNG(osuCrypto::toBlock(13500208152607548444ULL, 10437400963745058484ULL));
    auto test_prg = PRNG(osuCrypto::toBlock(12719337631725217092ULL, 9611915535302579427ULL));
    
    const size_t n = 128;
    const size_t num_rand_trials = 1ULL << 10;
    block alpha = block(4577924149022994781ULL, 6451093106684942340ULL);
    block beta = osuCrypto::toBlock(1784850959206460087ULL, 1515347673038214064ULL);

    std::array<ddf_key,2> key_pair;
    hw_fss_gen(global_prg, n, alpha, beta, key_pair);

    for (size_t i = 0; i < num_rand_trials; i++) {
        block x = random_block(test_prg, n);
        block eval0 = hw_fss_eval(key_pair[0], x);
        block eval1 = hw_fss_eval(key_pair[1], x);

        if (block_hd(x, alpha, n) != 1) {
            REQUIRE((eval0 ^ eval1) == block());
        } else {
            REQUIRE((eval0 ^ eval1) == beta);
        }
    }

    for (size_t i = 0; i < 64; i++) {
        block x = alpha ^ block(0, 1ULL << i);
        block eval0 = hw_fss_eval(key_pair[0], x);
        block eval1 = hw_fss_eval(key_pair[1], x);

        REQUIRE((eval0 ^ eval1) == beta);
    }

    for (size_t i = 0;i < 64;i++) {
        block x = alpha ^ block(1ULL << i, 0);
        block eval0 = hw_fss_eval(key_pair[0], x);
        block eval1 = hw_fss_eval(key_pair[1], x);

        REQUIRE((eval0 ^ eval1) == beta);
    }

    delete[] key_pair[0].cws;
}

/*
TEST_CASE("HD FSS Small Full Domain Correctness for beta points (n=8)", "[correctness][poly_domain][n=8]") {
    auto global_prg = PRNG(osuCrypto::toBlock(5719839740904675739ULL));
    
    const size_t n = 8;
    const size_t domain_size = 1ULL << n;
    block alpha = block(0,108);
    block beta = osuCrypto::toBlock(4341985187325902331ULL,3729205291002859743ULL);

    std::array<ddf_key,2> key_pair;
    hw_fss_gen(global_prg, n, alpha, beta, key_pair);

    block alpha_prime = block(0, 108) ^ block(0, 1); // Flip the least significant bit of alpha to get a point that is at Hamming distance 1 from alpha.

    block eval0 = hw_fss_eval(key_pair[0], alpha_prime);
    block eval1 = hw_fss_eval(key_pair[1], alpha_prime);

    REQUIRE((eval0 ^ eval1) == beta);

    delete[] key_pair[0].cws;
}
    */