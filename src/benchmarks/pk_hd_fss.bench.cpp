#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
#include <cstdint>
#include <array>
#include <vector>
#include "../pk_hd_fss.hpp"
#include "../pk_fpir.hpp"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <thread>
#include <gmpxx.h>

using osuCrypto::PRNG;
using std::array;
using std::vector;
using osuCrypto::BitVector;

TEST_CASE("PK HD FSS Key Generation for n=16 and hd_threshold = 1", "[pk_hd_fss][n=16][hd_threshold=1]") {
    
    const size_t n = 16;
    const size_t hd_threshold = 1;

    auto prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    pk_hd_fss::one_time_setup_opts one_time_setup_opts;
    one_time_setup_opts.blum_int_bitlen = 2048;
    one_time_setup_opts.miller_rabin_rounds_per_prime = 25;
    one_time_setup_opts.stat_sec_param = 40;
    one_time_setup_opts.eval_out_ss_prime_mod = 251;
    one_time_setup_opts.n = n;
    one_time_setup_opts.inclusive_hd_threshold = hd_threshold;

    pk_hd_fss::one_time_setup_sk one_time_setup_sk;
    pk_hd_fss::one_time_setup(one_time_setup_opts, prg, one_time_setup_sk);
    
    BENCHMARK_ADVANCED("n=16, hd_threshold=1")(Catch::Benchmark::Chronometer meter) {

        size_t run_count = meter.runs();

        vector<BitVector> secret_bit_vectors(run_count);
        vector<array<pk_hd_fss::key, 2>> hd_query_fss_keys_vec(run_count);

        for (size_t i = 0; i < run_count; i++) {
            secret_bit_vectors[i] = BitVector(one_time_setup_opts.n);
            secret_bit_vectors[i].randomize(prg);

            hd_query_fss_keys_vec[i] = array<pk_hd_fss::key, 2>();
        }

        meter.measure([&](int run_idx) {
            pk_hd_fss::key_gen(one_time_setup_sk, secret_bit_vectors[run_idx], prg, hd_query_fss_keys_vec[run_idx][0], hd_query_fss_keys_vec[run_idx][1]);
        });

        for (size_t i = 0; i < run_count; i++) {
            BitVector& secret_bit_vector = secret_bit_vectors[i];
            array<pk_hd_fss::key, 2>& hd_query_fss_keys = hd_query_fss_keys_vec[i];

            BitVector pub_bit_vector(one_time_setup_opts.n);
    
            for (size_t hd = 0; hd <= n; hd++) {
                pub_bit_vector.assign(secret_bit_vector);
                for (size_t i = 0; i < hd; i++) {
                    pub_bit_vector[i] = !pub_bit_vector[i];
                }

                uint32_t hd_threshold_match_adss0_out, hd_threshold_match_adss1_out;
                pk_hd_fss::eval(hd_query_fss_keys[0], pub_bit_vector, hd_threshold_match_adss0_out);
                pk_hd_fss::eval(hd_query_fss_keys[1], pub_bit_vector, hd_threshold_match_adss1_out);

                uint32_t prime_mod = one_time_setup_opts.eval_out_ss_prime_mod;
                uint32_t reconstructed_hd_threshold_match_adss = (hd_threshold_match_adss1_out + hd_threshold_match_adss0_out) % prime_mod;

                if (hd <= hd_threshold) {
                    REQUIRE(reconstructed_hd_threshold_match_adss == 1);
                }
                else {
                    REQUIRE(reconstructed_hd_threshold_match_adss == 0);
                }

            }

        }

    };
}

TEST_CASE("PK HD FSS Key Generation for n=32 and hd_threshold = 1", "[pk_hd_fss][n=32][hd_threshold=1]") {
    
    const size_t n = 32;
    const size_t hd_threshold = 1;

    auto prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    pk_hd_fss::one_time_setup_opts one_time_setup_opts;
    one_time_setup_opts.blum_int_bitlen = 2048;
    one_time_setup_opts.miller_rabin_rounds_per_prime = 25;
    one_time_setup_opts.stat_sec_param = 40;
    one_time_setup_opts.eval_out_ss_prime_mod = 251;
    one_time_setup_opts.n = n;
    one_time_setup_opts.inclusive_hd_threshold = hd_threshold;

    pk_hd_fss::one_time_setup_sk one_time_setup_sk;
    pk_hd_fss::one_time_setup(one_time_setup_opts, prg, one_time_setup_sk);
    
    BENCHMARK_ADVANCED("n=32, hd_threshold=1")(Catch::Benchmark::Chronometer meter) {

        size_t run_count = meter.runs();

        vector<BitVector> secret_bit_vectors(run_count);
        vector<array<pk_hd_fss::key, 2>> hd_query_fss_keys_vec(run_count);

        for (size_t i = 0; i < run_count; i++) {
            secret_bit_vectors[i] = BitVector(one_time_setup_opts.n);
            secret_bit_vectors[i].randomize(prg);

            hd_query_fss_keys_vec[i] = array<pk_hd_fss::key, 2>();
        }

        meter.measure([&](int run_idx) {
            pk_hd_fss::key_gen(one_time_setup_sk, secret_bit_vectors[run_idx], prg, hd_query_fss_keys_vec[run_idx][0], hd_query_fss_keys_vec[run_idx][1]);
        });

        for (size_t i = 0; i < run_count; i++) {
            BitVector& secret_bit_vector = secret_bit_vectors[i];
            array<pk_hd_fss::key, 2>& hd_query_fss_keys = hd_query_fss_keys_vec[i];

            BitVector pub_bit_vector(one_time_setup_opts.n);
    
            for (size_t hd = 0; hd <= hd_threshold + 1; hd++) {
                pub_bit_vector.assign(secret_bit_vector);
                for (size_t i = 0; i < hd; i++) {
                    pub_bit_vector[i] = !pub_bit_vector[i];
                }

                uint32_t hd_threshold_match_adss0_out, hd_threshold_match_adss1_out;
                pk_hd_fss::eval(hd_query_fss_keys[0], pub_bit_vector, hd_threshold_match_adss0_out);
                pk_hd_fss::eval(hd_query_fss_keys[1], pub_bit_vector, hd_threshold_match_adss1_out);

                uint32_t prime_mod = one_time_setup_opts.eval_out_ss_prime_mod;
                uint32_t reconstructed_hd_threshold_match_adss = (hd_threshold_match_adss1_out + hd_threshold_match_adss0_out) % prime_mod;

                if (hd <= hd_threshold) {
                    REQUIRE(reconstructed_hd_threshold_match_adss == 1);
                }
                else {
                    REQUIRE(reconstructed_hd_threshold_match_adss == 0);
                }

            }

        }

    };
}

TEST_CASE("PK HD FSS Key Generation for n=64 and hd_threshold = 1", "[pk_hd_fss][n=64][hd_threshold=1]") {
    
    const size_t n = 64;
    const size_t hd_threshold = 1;

    auto prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    pk_hd_fss::one_time_setup_opts one_time_setup_opts;
    one_time_setup_opts.blum_int_bitlen = 2048;
    one_time_setup_opts.miller_rabin_rounds_per_prime = 25;
    one_time_setup_opts.stat_sec_param = 40;
    one_time_setup_opts.eval_out_ss_prime_mod = 251;
    one_time_setup_opts.n = n;
    one_time_setup_opts.inclusive_hd_threshold = hd_threshold;

    pk_hd_fss::one_time_setup_sk one_time_setup_sk;
    pk_hd_fss::one_time_setup(one_time_setup_opts, prg, one_time_setup_sk);
    
    BENCHMARK_ADVANCED("n=64, hd_threshold=1")(Catch::Benchmark::Chronometer meter) {

        size_t run_count = meter.runs();

        vector<BitVector> secret_bit_vectors(run_count);
        vector<array<pk_hd_fss::key, 2>> hd_query_fss_keys_vec(run_count);

        for (size_t i = 0; i < run_count; i++) {
            secret_bit_vectors[i] = BitVector(one_time_setup_opts.n);
            secret_bit_vectors[i].randomize(prg);

            hd_query_fss_keys_vec[i] = array<pk_hd_fss::key, 2>();
        }

        meter.measure([&](int run_idx) {
            pk_hd_fss::key_gen(one_time_setup_sk, secret_bit_vectors[run_idx], prg, hd_query_fss_keys_vec[run_idx][0], hd_query_fss_keys_vec[run_idx][1]);
        });

        for (size_t i = 0; i < run_count; i++) {
            BitVector& secret_bit_vector = secret_bit_vectors[i];
            array<pk_hd_fss::key, 2>& hd_query_fss_keys = hd_query_fss_keys_vec[i];

            BitVector pub_bit_vector(one_time_setup_opts.n);
    
            for (size_t hd = 0; hd <= hd_threshold + 1; hd++) {
                pub_bit_vector.assign(secret_bit_vector);
                for (size_t i = 0; i < hd; i++) {
                    pub_bit_vector[i] = !pub_bit_vector[i];
                }

                uint32_t hd_threshold_match_adss0_out, hd_threshold_match_adss1_out;
                pk_hd_fss::eval(hd_query_fss_keys[0], pub_bit_vector, hd_threshold_match_adss0_out);
                pk_hd_fss::eval(hd_query_fss_keys[1], pub_bit_vector, hd_threshold_match_adss1_out);

                uint32_t prime_mod = one_time_setup_opts.eval_out_ss_prime_mod;
                uint32_t reconstructed_hd_threshold_match_adss = (hd_threshold_match_adss1_out + hd_threshold_match_adss0_out) % prime_mod;

                if (hd <= hd_threshold) {
                    REQUIRE(reconstructed_hd_threshold_match_adss == 1);
                }
                else {
                    REQUIRE(reconstructed_hd_threshold_match_adss == 0);
                }

            }

        }

    };
}

TEST_CASE("PK HD FSS Key Generation for n=128 and hd_threshold = 1", "[pk_hd_fss][n=128][hd_threshold=1]") {
    
    const size_t n = 128;
    const size_t hd_threshold = 1;

    auto prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    pk_hd_fss::one_time_setup_opts one_time_setup_opts;
    one_time_setup_opts.blum_int_bitlen = 2048;
    one_time_setup_opts.miller_rabin_rounds_per_prime = 25;
    one_time_setup_opts.stat_sec_param = 40;
    one_time_setup_opts.eval_out_ss_prime_mod = 251;
    one_time_setup_opts.n = n;
    one_time_setup_opts.inclusive_hd_threshold = hd_threshold;

    pk_hd_fss::one_time_setup_sk one_time_setup_sk;
    pk_hd_fss::one_time_setup(one_time_setup_opts, prg, one_time_setup_sk);
    
    BENCHMARK_ADVANCED("n=128, hd_threshold=1")(Catch::Benchmark::Chronometer meter) {

        size_t run_count = meter.runs();

        vector<BitVector> secret_bit_vectors(run_count);
        vector<array<pk_hd_fss::key, 2>> hd_query_fss_keys_vec(run_count);

        for (size_t i = 0; i < run_count; i++) {
            secret_bit_vectors[i] = BitVector(one_time_setup_opts.n);
            secret_bit_vectors[i].randomize(prg);

            hd_query_fss_keys_vec[i] = array<pk_hd_fss::key, 2>();
        }

        meter.measure([&](int run_idx) {
            pk_hd_fss::key_gen(one_time_setup_sk, secret_bit_vectors[run_idx], prg, hd_query_fss_keys_vec[run_idx][0], hd_query_fss_keys_vec[run_idx][1]);
        });

        for (size_t i = 0; i < run_count; i++) {
            BitVector& secret_bit_vector = secret_bit_vectors[i];
            array<pk_hd_fss::key, 2>& hd_query_fss_keys = hd_query_fss_keys_vec[i];

            BitVector pub_bit_vector(one_time_setup_opts.n);
    
            for (size_t hd = 0; hd <= hd_threshold + 1; hd++) {
                pub_bit_vector.assign(secret_bit_vector);
                for (size_t i = 0; i < hd; i++) {
                    pub_bit_vector[i] = !pub_bit_vector[i];
                }

                uint32_t hd_threshold_match_adss0_out, hd_threshold_match_adss1_out;
                pk_hd_fss::eval(hd_query_fss_keys[0], pub_bit_vector, hd_threshold_match_adss0_out);
                pk_hd_fss::eval(hd_query_fss_keys[1], pub_bit_vector, hd_threshold_match_adss1_out);

                uint32_t prime_mod = one_time_setup_opts.eval_out_ss_prime_mod;
                uint32_t reconstructed_hd_threshold_match_adss = (hd_threshold_match_adss1_out + hd_threshold_match_adss0_out) % prime_mod;

                if (hd <= hd_threshold) {
                    REQUIRE(reconstructed_hd_threshold_match_adss == 1);
                }
                else {
                    REQUIRE(reconstructed_hd_threshold_match_adss == 0);
                }

            }

        }

    };
}


TEST_CASE("PK HD FSS Key Generation for n=16 and hd_threshold = 2", "[pk_hd_fss][n=16][hd_threshold=2]") {
    
    const size_t n = 16;
    const size_t hd_threshold = 2;

    auto prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    pk_hd_fss::one_time_setup_opts one_time_setup_opts;
    one_time_setup_opts.blum_int_bitlen = 2048;
    one_time_setup_opts.miller_rabin_rounds_per_prime = 25;
    one_time_setup_opts.stat_sec_param = 40;
    one_time_setup_opts.eval_out_ss_prime_mod = 251;
    one_time_setup_opts.n = n;
    one_time_setup_opts.inclusive_hd_threshold = hd_threshold;

    pk_hd_fss::one_time_setup_sk one_time_setup_sk;
    pk_hd_fss::one_time_setup(one_time_setup_opts, prg, one_time_setup_sk);
    
    BENCHMARK_ADVANCED("n=16, hd_threshold=1")(Catch::Benchmark::Chronometer meter) {

        size_t run_count = meter.runs();

        vector<BitVector> secret_bit_vectors(run_count);
        vector<array<pk_hd_fss::key, 2>> hd_query_fss_keys_vec(run_count);

        for (size_t i = 0; i < run_count; i++) {
            secret_bit_vectors[i] = BitVector(one_time_setup_opts.n);
            secret_bit_vectors[i].randomize(prg);

            hd_query_fss_keys_vec[i] = array<pk_hd_fss::key, 2>();
        }

        meter.measure([&](int run_idx) {
            pk_hd_fss::key_gen(one_time_setup_sk, secret_bit_vectors[run_idx], prg, hd_query_fss_keys_vec[run_idx][0], hd_query_fss_keys_vec[run_idx][1]);
        });

        for (size_t i = 0; i < run_count; i++) {
            BitVector& secret_bit_vector = secret_bit_vectors[i];
            array<pk_hd_fss::key, 2>& hd_query_fss_keys = hd_query_fss_keys_vec[i];

            BitVector pub_bit_vector(one_time_setup_opts.n);
    
            for (size_t hd = 0; hd <= n; hd++) {
                pub_bit_vector.assign(secret_bit_vector);
                for (size_t i = 0; i < hd; i++) {
                    pub_bit_vector[i] = !pub_bit_vector[i];
                }

                uint32_t hd_threshold_match_adss0_out, hd_threshold_match_adss1_out;
                pk_hd_fss::eval(hd_query_fss_keys[0], pub_bit_vector, hd_threshold_match_adss0_out);
                pk_hd_fss::eval(hd_query_fss_keys[1], pub_bit_vector, hd_threshold_match_adss1_out);

                uint32_t prime_mod = one_time_setup_opts.eval_out_ss_prime_mod;
                uint32_t reconstructed_hd_threshold_match_adss = (hd_threshold_match_adss1_out + hd_threshold_match_adss0_out) % prime_mod;

                if (hd <= hd_threshold) {
                    REQUIRE(reconstructed_hd_threshold_match_adss == 1);
                }
                else {
                    REQUIRE(reconstructed_hd_threshold_match_adss == 0);
                }

            }

        }

    };
}

TEST_CASE("PK HD FSS Key Generation for n=16 and hd_threshold = 4", "[pk_hd_fss][n=16][hd_threshold=4]") {
    
    const size_t n = 16;
    const size_t hd_threshold = 4;

    auto prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    pk_hd_fss::one_time_setup_opts one_time_setup_opts;
    one_time_setup_opts.blum_int_bitlen = 2048;
    one_time_setup_opts.miller_rabin_rounds_per_prime = 25;
    one_time_setup_opts.stat_sec_param = 40;
    one_time_setup_opts.eval_out_ss_prime_mod = 251;
    one_time_setup_opts.n = n;
    one_time_setup_opts.inclusive_hd_threshold = hd_threshold;

    pk_hd_fss::one_time_setup_sk one_time_setup_sk;
    pk_hd_fss::one_time_setup(one_time_setup_opts, prg, one_time_setup_sk);
    
    BENCHMARK_ADVANCED("n=16, hd_threshold=1")(Catch::Benchmark::Chronometer meter) {

        size_t run_count = meter.runs();

        vector<BitVector> secret_bit_vectors(run_count);
        vector<array<pk_hd_fss::key, 2>> hd_query_fss_keys_vec(run_count);

        for (size_t i = 0; i < run_count; i++) {
            secret_bit_vectors[i] = BitVector(one_time_setup_opts.n);
            secret_bit_vectors[i].randomize(prg);

            hd_query_fss_keys_vec[i] = array<pk_hd_fss::key, 2>();
        }

        meter.measure([&](int run_idx) {
            pk_hd_fss::key_gen(one_time_setup_sk, secret_bit_vectors[run_idx], prg, hd_query_fss_keys_vec[run_idx][0], hd_query_fss_keys_vec[run_idx][1]);
        });

        for (size_t i = 0; i < run_count; i++) {
            BitVector& secret_bit_vector = secret_bit_vectors[i];
            array<pk_hd_fss::key, 2>& hd_query_fss_keys = hd_query_fss_keys_vec[i];

            BitVector pub_bit_vector(one_time_setup_opts.n);
    
            for (size_t hd = 0; hd <= n; hd++) {
                pub_bit_vector.assign(secret_bit_vector);
                for (size_t i = 0; i < hd; i++) {
                    pub_bit_vector[i] = !pub_bit_vector[i];
                }

                uint32_t hd_threshold_match_adss0_out, hd_threshold_match_adss1_out;
                pk_hd_fss::eval(hd_query_fss_keys[0], pub_bit_vector, hd_threshold_match_adss0_out);
                pk_hd_fss::eval(hd_query_fss_keys[1], pub_bit_vector, hd_threshold_match_adss1_out);

                uint32_t prime_mod = one_time_setup_opts.eval_out_ss_prime_mod;
                uint32_t reconstructed_hd_threshold_match_adss = (hd_threshold_match_adss1_out + hd_threshold_match_adss0_out) % prime_mod;

                if (hd <= hd_threshold) {
                    REQUIRE(reconstructed_hd_threshold_match_adss == 1);
                }
                else {
                    REQUIRE(reconstructed_hd_threshold_match_adss == 0);
                }

            }

        }

    };
}

TEST_CASE("PK HD FSS Key Generation for n=16 and hd_threshold = 8", "[pk_hd_fss][n=16][hd_threshold=8]") {
    
    const size_t n = 16;
    const size_t hd_threshold = 8;

    auto prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    pk_hd_fss::one_time_setup_opts one_time_setup_opts;
    one_time_setup_opts.blum_int_bitlen = 2048;
    one_time_setup_opts.miller_rabin_rounds_per_prime = 25;
    one_time_setup_opts.stat_sec_param = 40;
    one_time_setup_opts.eval_out_ss_prime_mod = 251;
    one_time_setup_opts.n = n;
    one_time_setup_opts.inclusive_hd_threshold = hd_threshold;

    pk_hd_fss::one_time_setup_sk one_time_setup_sk;
    pk_hd_fss::one_time_setup(one_time_setup_opts, prg, one_time_setup_sk);
    
    BENCHMARK_ADVANCED("n=16, hd_threshold=1")(Catch::Benchmark::Chronometer meter) {

        size_t run_count = meter.runs();

        vector<BitVector> secret_bit_vectors(run_count);
        vector<array<pk_hd_fss::key, 2>> hd_query_fss_keys_vec(run_count);

        for (size_t i = 0; i < run_count; i++) {
            secret_bit_vectors[i] = BitVector(one_time_setup_opts.n);
            secret_bit_vectors[i].randomize(prg);

            hd_query_fss_keys_vec[i] = array<pk_hd_fss::key, 2>();
        }

        meter.measure([&](int run_idx) {
            pk_hd_fss::key_gen(one_time_setup_sk, secret_bit_vectors[run_idx], prg, hd_query_fss_keys_vec[run_idx][0], hd_query_fss_keys_vec[run_idx][1]);
        });

        for (size_t i = 0; i < run_count; i++) {
            BitVector& secret_bit_vector = secret_bit_vectors[i];
            array<pk_hd_fss::key, 2>& hd_query_fss_keys = hd_query_fss_keys_vec[i];

            BitVector pub_bit_vector(one_time_setup_opts.n);
    
            for (size_t hd = 0; hd <= n; hd++) {
                pub_bit_vector.assign(secret_bit_vector);
                for (size_t i = 0; i < hd; i++) {
                    pub_bit_vector[i] = !pub_bit_vector[i];
                }

                uint32_t hd_threshold_match_adss0_out, hd_threshold_match_adss1_out;
                pk_hd_fss::eval(hd_query_fss_keys[0], pub_bit_vector, hd_threshold_match_adss0_out);
                pk_hd_fss::eval(hd_query_fss_keys[1], pub_bit_vector, hd_threshold_match_adss1_out);

                uint32_t prime_mod = one_time_setup_opts.eval_out_ss_prime_mod;
                uint32_t reconstructed_hd_threshold_match_adss = (hd_threshold_match_adss1_out + hd_threshold_match_adss0_out) % prime_mod;

                if (hd <= hd_threshold) {
                    REQUIRE(reconstructed_hd_threshold_match_adss == 1);
                }
                else {
                    REQUIRE(reconstructed_hd_threshold_match_adss == 0);
                }

            }

        }

    };
}