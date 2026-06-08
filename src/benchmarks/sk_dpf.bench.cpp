#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
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

TEST_CASE("SK DPF key pairs generated with n=128.", "[sk_dpf][n=128]") {
    
    constexpr size_t n = 128; // Length of the input bit vectors for the FSS scheme.
    constexpr size_t num_rand_trials = 1ULL << 4; // Number of random trials to perform for correctness testing.

    PRNG test_prng(osuCrypto::toBlock(18299147406654953957ULL, 17332306228894218771ULL)); // Initialize a pseudorandom generator with a fixed seed for reproducibility.
    
    BENCHMARK_ADVANCED("n=128 online phase")(Catch::Benchmark::Chronometer meter) {

        size_t runs = meter.runs();

        vector<std::array<ddf_key, 2>> key_pairs(runs); // Vector to hold the generated key pairs.
        vector<block> alphas(runs); // Vector to hold the alpha values for each key pair.
        vector<block> betas(runs); // Vector to hold the beta values for each key pair.
        for (size_t i = 0; i < runs; i++) {
            alphas[i] = random_block(test_prng, n); // Generate a random alpha value for the current key pair.
            betas[i] = random_block(test_prng, n); // Generate a random beta value for the current key pair.
        }

        meter.measure([&](int run_id) {
            hw_fss_gen(test_prng, n, alphas[run_id], betas[run_id], key_pairs[run_id]); // Generate the FSS key pair for the current alpha and beta values.
        });

        for (size_t i = 0; i < runs; i++) {
            block alpha = alphas[i];
            block beta = betas[i];
            std::array<ddf_key,2>& key_pair = key_pairs[i];

            for (size_t i = 0; i < num_rand_trials; i++) {
                block x = random_block(test_prng, n);
                block eval0 = hw_fss_eval(key_pair[0], x);
                block eval1 = hw_fss_eval(key_pair[1], x);

                if (block_hd(x, alpha, n) > 1) {
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

            block eval0 = hw_fss_eval(key_pair[0], alpha);
            block eval1 = hw_fss_eval(key_pair[1], alpha);
            REQUIRE((eval0 ^ eval1) == beta);
        }

        // Clean up the generated key pairs to free memory.
        for (size_t i = 0; i < runs; i++) {
            delete[] key_pairs[i][0].cws;
        }

    };
}
