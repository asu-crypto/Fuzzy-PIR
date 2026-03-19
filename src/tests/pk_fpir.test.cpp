#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <array>
#include <vector>
#include "../pk_hd_fss.hpp"
#include "../pk_fpir.hpp"
#include "../ss_iblt.hpp"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <gmpxx.h>

using osuCrypto::PRNG;
using std::array;
using std::vector;
using osuCrypto::BitVector;

TEST_CASE("The PK HD FPIR Scheme perfectly matches a single string in the DB where |DB| = 1", "[pk_fpir]") {
    // This test checks that the PK HD FPIR scheme correctly identifies a match when there is only one entry in the database and that entry matches the query.

    // Set up parameters for the test.
    const size_t n = 10; // Bit length of the database entries and query.
    const size_t inclusive_hd_threshold = 4; // Hamming distance threshold for a match.
    const size_t blum_int_bitlen = 1024; // Bit length of the Blum integer for Paillier key generation.
    const size_t miller_rabin_rounds_per_prime = 25; // Miller-Rabin rounds for primality testing during Paillier key generation.
    const size_t stat_sec_param = 40; // Statistical security parameter for key generation.
    const size_t eval_out_ss_prime_mod = 263; // Prime modulus for the output of the eval function.

    PRNG prg(osuCrypto::toBlock(123)); // Initialize a pseudorandom generator with a fixed seed for reproducibility.

    // Generate a one-time setup secret key for the FSS scheme.
    pk_hd_fss::one_time_setup_sk fss_setup_sk;
    pk_hd_fss::one_time_setup_opts setup_opts{blum_int_bitlen, miller_rabin_rounds_per_prime, stat_sec_param, eval_out_ss_prime_mod, n, inclusive_hd_threshold};
    pk_hd_fss::one_time_setup(setup_opts, prg, fss_setup_sk);

    // Create a query bit vector that will be used to generate the FSS keys. This will also be the entry in our database.
    BitVector query_bv(n);
    query_bv.randomize(prg); // Randomize the query bit vector.

    // Generate FSS keys for both parties using the same query bit vector (since we want a match).
    array<pk_hd_fss::key, 2> hd_query_fss_keys;
    pk_fpir::gen_hd_query(fss_setup_sk, query_bv, prg, hd_query_fss_keys);

    // Create a database with a single entry that matches the query bit vector.
    vector<BitVector> db(1);
    db[0] = query_bv; // The single entry in the database is exactly the same as the query.

    // Generate the response for the first party's FSS key.
    ss_u32_iblt hd_threshold_match_adss_iblt0, hd_threshold_match_adss_iblt1;

    pk_fpir::gen_hd_response(hd_query_fss_keys[0], n, db, osuCrypto::toBlock(456), 1, hd_threshold_match_adss_iblt0);
    pk_fpir::gen_hd_response(hd_query_fss_keys[1], n, db, osuCrypto::toBlock(456), 1, hd_threshold_match_adss_iblt1);

    reconstruct_u32_iblt(hd_threshold_match_adss_iblt0, hd_threshold_match_adss_iblt1);

    // Check that the final IBLT contains the expected match. Since there is only one entry in the database and it matches the query, we expect to find a match at index 0.
    vector<uint32_t> matching_elements;
    list_u32_iblt(hd_threshold_match_adss_iblt0, matching_elements);
    REQUIRE(matching_elements.size() == 1);
    REQUIRE(db[0].getSpan<uint32_t>()[0] == matching_elements[0]);

}
