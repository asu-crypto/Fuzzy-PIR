#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <array>
#include <vector>
#include "../pk_hd_fss.hpp"
#include "../ss_iblt.hpp"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <gmpxx.h>
#include <set>

using osuCrypto::PRNG;
using std::array;
using std::vector;
using osuCrypto::BitVector;
using osuCrypto::block;
using std::set;

TEST_CASE("init_ss_u32_iblt correctly initiates the data structures of the IBLT", "[ss_u32_iblt]") {

    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    ss_u32_iblt iblt;
    block iblt_hash_funcs_seed = prg.get<block>();
    init_ss_u32_iblt(10, 4, iblt_hash_funcs_seed, iblt);

    REQUIRE(iblt.subtable_bin_count == 10/4 + 1);
    REQUIRE(iblt.num_hash_funcs == 4);
    REQUIRE(iblt.hash_funcs.size() == 4);
    REQUIRE(iblt.cnt_bins.size() == 4);
    REQUIRE(iblt.sum_bins.size() == 4);
    for (size_t i = 0; i < iblt.num_hash_funcs; i++) {
        REQUIRE(iblt.cnt_bins[i].size() == iblt.subtable_bin_count);
        REQUIRE(iblt.sum_bins[i].size() == iblt.subtable_bin_count);
        for (size_t j = 0; j < iblt.subtable_bin_count; j++) {
            REQUIRE(iblt.cnt_bins[i][j] == 0);
            REQUIRE(iblt.sum_bins[i][j] == 0);
        }
    }

}

TEST_CASE("insert_ss_u32_iblt correctly updates the IBLT data structures", "[ss_u32_iblt]") {

    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    ss_u32_iblt iblt_ss0, iblt_ss1;
    ss_u32_iblt expected_reconstruction_iblt;

    block iblt_hash_funcs_seed = prg.get<block>();

    init_ss_u32_iblt(10, 4, iblt_hash_funcs_seed, iblt_ss0);
    init_ss_u32_iblt(10, 4, iblt_hash_funcs_seed, iblt_ss1);

    uint32_t e0_ss0 = prg.get<uint32_t>();
    uint32_t e1_ss0 = prg.get<uint32_t>();    
    uint32_t e2_ss0 = prg.get<uint32_t>();

    insert_ss_u32_iblt(13, e0_ss0, iblt_ss0);
    insert_ss_u32_iblt(1321, e1_ss0, iblt_ss0);
    insert_ss_u32_iblt(123456, e2_ss0, iblt_ss0);

    insert_ss_u32_iblt(13, (uint32_t) (((uint32_t) 1) - e0_ss0), iblt_ss1);
    insert_ss_u32_iblt(1321, (uint32_t) (((uint32_t) 0) - e1_ss0), iblt_ss1);
    insert_ss_u32_iblt(123456, (uint32_t) (((uint32_t) 1) - e2_ss0), iblt_ss1);

    reconstruct_u32_iblt(iblt_ss0, iblt_ss1);

    set<uint32_t> expected_set = {13, 123456};
    std::vector<uint32_t> reconstructed_list;
    list_u32_iblt(iblt_ss0, reconstructed_list);

    set<uint32_t> reconstructed_set(reconstructed_list.begin(), reconstructed_list.end());

    REQUIRE(reconstructed_set == expected_set);

}