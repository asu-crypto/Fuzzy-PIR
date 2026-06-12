#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
#include <cstdint>
#include <array>
#include <vector>
#include "../pk_hd_fss.hpp"
#include "../pk_fpir.hpp"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Aligned.h"
#include <thread>
#include <gmpxx.h>
#include <algorithm>
#include <random>    
#include <set>
#include <unordered_set>

using osuCrypto::PRNG;
using std::array;
using std::vector;
using osuCrypto::BitVector;
using osuCrypto::block;
using osuCrypto::AlignedUnVector;
using std::unordered_set;
using std::set;

static size_t db_entry_ss_mod_vec_len(size_t db_entry_bitlen, uint8_t ss_mod) {
    size_t ss_mod_log2_floor = static_cast<size_t>(std::floor(std::log2(ss_mod)));
    return static_cast<size_t>(std::ceil(static_cast<double>(db_entry_bitlen) / static_cast<double>(ss_mod_log2_floor)));
}

template<size_t num_ss_iblt_copies>
static void init_ss_tables(size_t threshold, 
                            double space_mult_fac,
                            size_t num_hash_funcs,
                            uint8_t ss_mod, 
                            size_t element_vec_len,
                            size_t num_runs,
                            PRNG& prg,
                            vector<array<u8_ss_iblt::table, num_ss_iblt_copies>>& ss0_iblt_copies_vec,
                            vector<array<u8_ss_iblt::table, num_ss_iblt_copies>>& ss1_iblt_copies_vec) {

    ss0_iblt_copies_vec.resize(num_runs);
    ss1_iblt_copies_vec.resize(num_runs);
    for (size_t i = 0; i < num_runs; i++) {
        for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
            block hash_funcs_seed = prg.get<block>();

            u8_ss_iblt::init_table(threshold, 
                                   space_mult_fac, 
                                   num_hash_funcs, 
                                   hash_funcs_seed, 
                                   ss_mod, 
                                   element_vec_len, 
                                   ss0_iblt_copies_vec[i][copy_idx]);
            u8_ss_iblt::init_table(threshold, 
                                   space_mult_fac, 
                                   num_hash_funcs, 
                                   hash_funcs_seed, 
                                   ss_mod, 
                                   element_vec_len, 
                                   ss1_iblt_copies_vec[i][copy_idx]);
        }
     }
}

static void gen_db_entries(size_t num_runs, size_t db_size, size_t db_entry_vec_len, uint8_t ss_mod, PRNG& prg,  vector<vector<AlignedUnVector<uint8_t>>>& db_entry_vecs) {
    db_entry_vecs.resize(num_runs);
    
    for (size_t i = 0; i < num_runs; i++) {
        db_entry_vecs[i].resize(db_size);
        std::set<vector<uint8_t>> seen_entries;
        
        for (size_t j = 0; j < db_size; j++) {
            vector<uint8_t> entry(db_entry_vec_len);
            
            // Generate unique entries
            do {
                prg.get<uint8_t>(entry.data(), entry.size());

                for (size_t k = 0; k < entry.size(); k++) {
                    entry[k] = entry[k] % ss_mod;
                }

            } while (seen_entries.count(entry) > 0);
            
            seen_entries.insert(entry);
            db_entry_vecs[i][j].resize(db_entry_vec_len);
            std::copy(entry.begin(), entry.end(), db_entry_vecs[i][j].data());
        }
    }

}

static void gen_sel_bin_ss(size_t num_runs, size_t db_size, size_t num_matching_shares, uint8_t ss_mod, PRNG& prg,
                            vector<AlignedUnVector<uint8_t>>& sel_bin_ss0_vec,
                            vector<AlignedUnVector<uint8_t>>& sel_bin_ss1_vec) {
    sel_bin_ss0_vec.resize(num_runs);
    sel_bin_ss1_vec.resize(num_runs);

    vector<vector<array<uint8_t, 2>>> sel_bin_ss_vec(num_runs);
    for (size_t i = 0; i < num_runs; i++) {
        sel_bin_ss_vec[i].resize(db_size);

        for (size_t j = 0; j < num_matching_shares; j++) {
            uint16_t sel_bin_ss_0 = prg.get<uint8_t>() % ss_mod;
            uint16_t sel_bin_ss_1 = ((ss_mod - sel_bin_ss_0) + 1) % ss_mod; 

            sel_bin_ss_vec[i][j][0] = sel_bin_ss_0;
            sel_bin_ss_vec[i][j][1] = sel_bin_ss_1;
        }

        for (size_t j = num_matching_shares; j < db_size; j++) {
            uint16_t sel_bin_ss_0 = prg.get<uint8_t>() % ss_mod;
            uint16_t sel_bin_ss_1 = ((ss_mod - sel_bin_ss_0)) % ss_mod;

            sel_bin_ss_vec[i][j][0] = sel_bin_ss_0;
            sel_bin_ss_vec[i][j][1] = sel_bin_ss_1;
        }

        std::shuffle(sel_bin_ss_vec[i].begin(), sel_bin_ss_vec[i].end(), std::mt19937(prg.get<uint64_t>()));

    }

    for (size_t i = 0; i < num_runs; i++) {
        sel_bin_ss0_vec[i].resize(db_size);
        sel_bin_ss1_vec[i].resize(db_size);
        for (size_t j = 0; j < db_size; j++) {
            sel_bin_ss0_vec[i][j] = sel_bin_ss_vec[i][j][0];
            sel_bin_ss1_vec[i][j] = sel_bin_ss_vec[i][j][1];
        }
    }

}

static void expected_db_matches(const vector<AlignedUnVector<uint8_t>>& db_entry_vecs, 
                                  const AlignedUnVector<uint8_t>& sel_bin_ss0,
                                  const AlignedUnVector<uint8_t>& sel_bin_ss1, 
                                  uint8_t ss_mod,
                                  vector<vector<uint8_t>>& expected_matching_entries_out) {
    for (size_t i = 0; i < sel_bin_ss0.size(); i++) {
        uint16_t sel_bin_ss_0 = sel_bin_ss0[i];
        uint16_t sel_bin_ss_1 = sel_bin_ss1[i];

        if ((sel_bin_ss_0 + sel_bin_ss_1) % static_cast<uint16_t>(ss_mod) == 1) {
            expected_matching_entries_out.push_back(vector<uint8_t>(db_entry_vecs[i].begin(), db_entry_vecs[i].end()));
        }
    }

}

static void expected_db_matches(const vector<AlignedUnVector<uint8_t>>& db_entry_vecs, 
                                  const AlignedUnVector<uint8_t>& sel_bin_ss0,
                                  const AlignedUnVector<uint8_t>& sel_bin_ss1, 
                                  uint8_t ss_mod,
                                  set<vector<uint8_t>>& expected_matching_entries_out) {
    for (size_t i = 0; i < sel_bin_ss0.size(); i++) {
        uint16_t sel_bin_ss_0 = sel_bin_ss0[i];
        uint16_t sel_bin_ss_1 = sel_bin_ss1[i];

        if ((sel_bin_ss_0 + sel_bin_ss_1) % static_cast<uint16_t>(ss_mod) == 1) {
            expected_matching_entries_out.insert(vector<uint8_t>(db_entry_vecs[i].begin(), db_entry_vecs[i].end()));
        }
    }

}

static bool is_same_elements(const vector<AlignedUnVector<uint8_t>>& list_out, const vector<vector<uint8_t>>& expected_matching_entries) {
    std::set<vector<uint8_t>> list_out_set;
    for (const auto& entry : list_out) {
        list_out_set.insert(vector<uint8_t>(entry.begin(), entry.end()));
    }

    REQUIRE(list_out_set.size() == expected_matching_entries.size());

    for (const auto& expected_entry : expected_matching_entries) {
        REQUIRE(list_out_set.count(expected_entry) > 0);
    }

    return true;
}

static void merge_list_out_into_set(const vector<AlignedUnVector<uint8_t>>& list_out, set<vector<uint8_t>>& set_out) {
    for (const auto& entry : list_out) {
        set_out.insert(vector<uint8_t>(entry.begin(), entry.end()));
    }
}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^10, db entry bitlen (n) = 16, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^10][db_entry_bitlen=16][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 10;
    const size_t db_entry_bitlen = 16;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^10, db entry bitlen (n) = 16, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^12, db entry bitlen (n) = 16, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^12][db_entry_bitlen=16][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 12;
    const size_t db_entry_bitlen = 16;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 16, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^14, db entry bitlen (n) = 16, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^14][db_entry_bitlen=16][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 16;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^14, db entry bitlen (n) = 16, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^10, db entry bitlen (n) = 16, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^10][db_entry_bitlen=16][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 10;
    const size_t db_entry_bitlen = 16;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^10, db entry bitlen (n) = 16, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^12, db entry bitlen (n) = 16, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^12][db_entry_bitlen=16][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 12;
    const size_t db_entry_bitlen = 16;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 16, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^14, db entry bitlen (n) = 16, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^14][db_entry_bitlen=16][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 16;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^14, db entry bitlen (n) = 16, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^10, db entry bitlen (n) = 32, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^10][db_entry_bitlen=32][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 10;
    const size_t db_entry_bitlen = 32;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^10, db entry bitlen (n) = 32, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^12, db entry bitlen (n) = 32, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^12][db_entry_bitlen=32][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 12;
    const size_t db_entry_bitlen = 32;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 32, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^14, db entry bitlen (n) = 32, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^14][db_entry_bitlen=32][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 32;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^14, db entry bitlen (n) = 32, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^10, db entry bitlen (n) = 32, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^10][db_entry_bitlen=32][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 10;
    const size_t db_entry_bitlen = 32;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^10, db entry bitlen (n) = 32, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^12, db entry bitlen (n) = 32, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^12][db_entry_bitlen=32][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 12;
    const size_t db_entry_bitlen = 32;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 32, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^14, db entry bitlen (n) = 32, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^14][db_entry_bitlen=32][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 32;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^14, db entry bitlen (n) = 32, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^10, db entry bitlen (n) = 64, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^10][db_entry_bitlen=64][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 10;
    const size_t db_entry_bitlen = 64;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^10, db entry bitlen (n) = 64, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^12, db entry bitlen (n) = 64, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^12][db_entry_bitlen=64][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 12;
    const size_t db_entry_bitlen = 64;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 64, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^14, db entry bitlen (n) = 64, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^14][db_entry_bitlen=64][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 64;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^14, db entry bitlen (n) = 64, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^10, db entry bitlen (n) = 64, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^10][db_entry_bitlen=64][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 10;
    const size_t db_entry_bitlen = 64;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^10, db entry bitlen (n) = 64, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^12, db entry bitlen (n) = 64, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^12][db_entry_bitlen=64][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 12;
    const size_t db_entry_bitlen = 64;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 64, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^14, db entry bitlen (n) = 64, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^14][db_entry_bitlen=64][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 64;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^14, db entry bitlen (n) = 64, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^10, db entry bitlen (n) = 128, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^10][db_entry_bitlen=128][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 10;
    const size_t db_entry_bitlen = 128;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^10, db entry bitlen (n) = 128, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^12, db entry bitlen (n) = 128, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^12][db_entry_bitlen=128][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 12;
    const size_t db_entry_bitlen = 128;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 128, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^14, db entry bitlen (n) = 128, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^14][db_entry_bitlen=128][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 128;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^14, db entry bitlen (n) = 128, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^10, db entry bitlen (n) = 128, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^10][db_entry_bitlen=128][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 10;
    const size_t db_entry_bitlen = 128;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^10, db entry bitlen (n) = 128, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^12, db entry bitlen (n) = 128, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^12][db_entry_bitlen=128][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 12;
    const size_t db_entry_bitlen = 128;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 128, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Computation: db size = 2^14, db entry bitlen (n) = 128, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[db_size=2^14][db_entry_bitlen=128][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 128;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db size = 2^14, db entry bitlen (n) = 128, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        });


        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);


               

            }
        }

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            bool all_decoded = false;
            
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                vector<vector<uint8_t>> expected_matching_entries;
                expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries);

                REQUIRE(resp_max_match_count == expected_matching_entries.size());

                all_decoded |= is_same_elements(list_out, expected_matching_entries);
            }
            
            REQUIRE(all_decoded);
        }

    };

}


// FPIR SS IBLT Response Decoding benchmarks ===============================================================================


TEST_CASE("FPIR SS IBLT Response Decoding: db entry bitlen (n) = 16, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[decoding][db_entry_bitlen=16][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 16;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 16, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);
        vector<set<vector<uint8_t>>> matching_entries_vec(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);
            }

            set<vector<uint8_t>>& matching_entries = matching_entries_vec[run_idx];

            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                merge_list_out_into_set(list_out, matching_entries);
            }
        });

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {

            set<vector<uint8_t>> expected_matching_entries_set;
            expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries_set);
            
            REQUIRE(resp_max_match_count == expected_matching_entries_set.size());

            REQUIRE(matching_entries_vec[run_idx] == expected_matching_entries_set);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Decoding: db entry bitlen (n) = 16, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[decoding][db_entry_bitlen=16][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 16;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 16, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);
        vector<set<vector<uint8_t>>> matching_entries_vec(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);
            }

            set<vector<uint8_t>>& matching_entries = matching_entries_vec[run_idx];

            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                merge_list_out_into_set(list_out, matching_entries);
            }
        });

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {

            set<vector<uint8_t>> expected_matching_entries_set;
            expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries_set);
            
            REQUIRE(resp_max_match_count == expected_matching_entries_set.size());

            REQUIRE(matching_entries_vec[run_idx] == expected_matching_entries_set);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Decoding: db entry bitlen (n) = 32, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[decoding][db_entry_bitlen=32][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 32;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 32, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);
        vector<set<vector<uint8_t>>> matching_entries_vec(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);
            }

            set<vector<uint8_t>>& matching_entries = matching_entries_vec[run_idx];

            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                merge_list_out_into_set(list_out, matching_entries);
            }
        });

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {

            set<vector<uint8_t>> expected_matching_entries_set;
            expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries_set);
            
            REQUIRE(resp_max_match_count == expected_matching_entries_set.size());

            REQUIRE(matching_entries_vec[run_idx] == expected_matching_entries_set);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Decoding: db entry bitlen (n) = 32, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[decoding][db_entry_bitlen=32][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 32;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 32, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);
        vector<set<vector<uint8_t>>> matching_entries_vec(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);
            }

            set<vector<uint8_t>>& matching_entries = matching_entries_vec[run_idx];

            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                merge_list_out_into_set(list_out, matching_entries);
            }
        });

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {

            set<vector<uint8_t>> expected_matching_entries_set;
            expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries_set);
            
            REQUIRE(resp_max_match_count == expected_matching_entries_set.size());

            REQUIRE(matching_entries_vec[run_idx] == expected_matching_entries_set);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Decoding: db entry bitlen (n) = 64, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[decoding][db_entry_bitlen=64][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 64;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 64, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);
        vector<set<vector<uint8_t>>> matching_entries_vec(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);
            }

            set<vector<uint8_t>>& matching_entries = matching_entries_vec[run_idx];

            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                merge_list_out_into_set(list_out, matching_entries);
            }
        });

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {

            set<vector<uint8_t>> expected_matching_entries_set;
            expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries_set);
            
            REQUIRE(resp_max_match_count == expected_matching_entries_set.size());

            REQUIRE(matching_entries_vec[run_idx] == expected_matching_entries_set);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Decoding: db entry bitlen (n) = 64, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[decoding][db_entry_bitlen=64][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 64;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 64, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);
        vector<set<vector<uint8_t>>> matching_entries_vec(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);
            }

            set<vector<uint8_t>>& matching_entries = matching_entries_vec[run_idx];

            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                merge_list_out_into_set(list_out, matching_entries);
            }
        });

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {

            set<vector<uint8_t>> expected_matching_entries_set;
            expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries_set);
            
            REQUIRE(resp_max_match_count == expected_matching_entries_set.size());

            REQUIRE(matching_entries_vec[run_idx] == expected_matching_entries_set);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Decoding: db entry bitlen (n) = 128, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[decoding][db_entry_bitlen=128][ss_mod=251][resp_max_match_count=64][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 128;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 64;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 128, ss_mod = 251, max response match count = 64, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);
        vector<set<vector<uint8_t>>> matching_entries_vec(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);
            }

            set<vector<uint8_t>>& matching_entries = matching_entries_vec[run_idx];

            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                merge_list_out_into_set(list_out, matching_entries);
            }
        });

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {

            set<vector<uint8_t>> expected_matching_entries_set;
            expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries_set);
            
            REQUIRE(resp_max_match_count == expected_matching_entries_set.size());

            REQUIRE(matching_entries_vec[run_idx] == expected_matching_entries_set);
        }

    };

}

TEST_CASE("FPIR SS IBLT Response Decoding: db entry bitlen (n) = 128, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2, IBLT space multiplication factor = 2.5", "[decoding][db_entry_bitlen=128][ss_mod=251][resp_max_match_count=128][num_iblt_hash_funcs=7][num_ss_iblt_copies=2][iblt_space_mult_fact=2.5]") {
    
    const size_t db_size = 1 << 14;
    const size_t db_entry_bitlen = 128;
    const uint8_t ss_mod = 251;
    const size_t resp_max_match_count = 128;
    const size_t num_iblt_hash_funcs = 7;
    constexpr size_t num_ss_iblt_copies = 2;
    const double iblt_space_mult_fact = 2.5;

    auto test_prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);
    
    BENCHMARK_ADVANCED("db entry bitlen (n) = 128, ss_mod = 251, max response match count = 128, number of hash functions (k) = 7, number of SS IBLT copies = 2")(Catch::Benchmark::Chronometer meter) {

        size_t num_runs = meter.runs();

        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss0_iblt_copies_vec;
        vector<array<u8_ss_iblt::table, num_ss_iblt_copies>> ss1_iblt_copies_vec;
        vector<vector<AlignedUnVector<uint8_t>>> db_entry_vecs(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss0(num_runs);
        vector<AlignedUnVector<uint8_t>> sel_bin_ss1(num_runs);
        vector<set<vector<uint8_t>>> matching_entries_vec(num_runs);

        init_ss_tables<num_ss_iblt_copies>(resp_max_match_count,
                       iblt_space_mult_fact,
                       num_iblt_hash_funcs,
                       ss_mod,
                       db_entry_vec_len,
                       num_runs,
                       test_prg,
                       ss0_iblt_copies_vec,
                       ss1_iblt_copies_vec);

        gen_db_entries(num_runs, db_size, db_entry_vec_len, ss_mod, test_prg, db_entry_vecs);
        gen_sel_bin_ss(num_runs, db_size, resp_max_match_count, ss_mod, test_prg, sel_bin_ss0, sel_bin_ss1);

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                for (size_t j = 0; j < db_size; j++) {
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss0[run_idx][j], ss0_iblt_copies_vec[run_idx][copy_idx]);
                    u8_ss_iblt::insert(db_entry_vecs[run_idx][j], sel_bin_ss1[run_idx][j], ss1_iblt_copies_vec[run_idx][copy_idx]);
                }
            }
        }

        meter.measure([&](int run_idx) {
            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                u8_ss_iblt::reconstruct(ss1_iblt_copies_vec[run_idx][copy_idx], ss0_iblt_copies_vec[run_idx][copy_idx]);
            }

            set<vector<uint8_t>>& matching_entries = matching_entries_vec[run_idx];

            for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
                vector<AlignedUnVector<uint8_t>> list_out;
                u8_ss_iblt::list(ss0_iblt_copies_vec[run_idx][copy_idx], list_out);

                merge_list_out_into_set(list_out, matching_entries);
            }
        });

        for (size_t run_idx = 0; run_idx < num_runs; run_idx++) {

            set<vector<uint8_t>> expected_matching_entries_set;
            expected_db_matches(db_entry_vecs[run_idx], sel_bin_ss0[run_idx], sel_bin_ss1[run_idx], ss_mod, expected_matching_entries_set);
            
            REQUIRE(resp_max_match_count == expected_matching_entries_set.size());

            REQUIRE(matching_entries_vec[run_idx] == expected_matching_entries_set);
        }

    };

}