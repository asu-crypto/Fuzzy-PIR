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

static void gen_rand_matching_input(PRNG& prng, BitVector& query_bv, size_t matching_threshold, vector<BitVector>& db_entry) {
    assert(query_bv.size() == 32 || query_bv.size() == 64);

    const size_t n = query_bv.size();

    BitVector q_copy(query_bv);

    size_t d = prng.get<size_t>() % (matching_threshold + 1);

    size_t num_flipped = 0;
    while (num_flipped < d) {
        size_t idx = prng.get<size_t>() % n;
        if (q_copy[idx] != query_bv[idx]) continue;
        q_copy[idx] = !q_copy[idx];
        num_flipped++;
    }

    db_entry.push_back(q_copy);

}

static void gen_rand_matching_inputs(size_t n, PRNG& prng, BitVector& query_bv, size_t matching_threshold, vector<BitVector>& db_entry) {

    for (size_t i = 0; i < n; i++) {
        gen_rand_matching_input(prng, query_bv, matching_threshold, db_entry);
    }


}

static void gen_rand_non_matching_input(PRNG& prng, BitVector& query_bv, size_t matching_threshold, vector<BitVector>& db_entry) {
    assert(query_bv.size() == 32 || query_bv.size() == 64);

    const size_t n = query_bv.size();

    BitVector q_copy(query_bv);

    size_t d = (prng.get<size_t>() % (n - matching_threshold - 1)) + (matching_threshold + 1);

    size_t num_flipped = 0;
    while (num_flipped < d) {
        size_t idx = prng.get<size_t>() % n;
        if (q_copy[idx] != query_bv[idx]) continue;
        q_copy[idx] = !q_copy[idx];
        num_flipped++;
    }

    db_entry.push_back(q_copy);


}

static void gen_rand_non_matching_inputs(size_t n, PRNG& prng, BitVector& query_bv, size_t matching_threshold, vector<BitVector>& db_entry) {
    for (size_t i = 0; i < n; i++) {
        gen_rand_non_matching_input(prng, query_bv, matching_threshold, db_entry);
    }
}

TEST_CASE("The PK HD FPIR Scheme perfectly matches a single string in the DB where |DB| = 10, n=64, and d = 6", "[pk_fpir][n=64][d=6][db_len=10]") {

    // Set up parameters for the test.
    const size_t n = 64; // Bit length of the database entries and query.
    const size_t inclusive_hd_threshold = 6; // Hamming distance threshold for a match.
    const size_t blum_int_bitlen = 1024; // Bit length of the Blum integer for Paillier key generation.
    const size_t miller_rabin_rounds_per_prime = 25; // Miller-Rabin rounds for primality testing during Paillier key generation.
    const size_t stat_sec_param = 40; // Statistical security parameter for key generation.
    const uint64_t eval_out_ss_prime_mod = 251; // Prime modulus for the output of the eval function.
    const size_t db_size = 10; // Number of entries in the database.
    const size_t num_matching_db_entries = 7; // Number of entries in the database that should match the query.

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
    vector<BitVector> db;
    db.reserve(db_size);
    gen_rand_matching_inputs(num_matching_db_entries, prg, query_bv, inclusive_hd_threshold, db);
    gen_rand_non_matching_inputs(db_size - num_matching_db_entries, prg, query_bv, inclusive_hd_threshold, db);
    std::shuffle(db.begin(), db.end(), prg);

    osuCrypto::AlignedUnVector<uint32_t> matches_ss0(db.size());
    osuCrypto::AlignedUnVector<uint32_t> matches_ss1(db.size());
    matches_ss0[0] = 0;
    matches_ss1[0] = 0;

    pk_fpir::gen_hd_response(hd_query_fss_keys[0], n, db, matches_ss0);
    pk_fpir::gen_hd_response(hd_query_fss_keys[1], n, db, matches_ss1);

    size_t num_matches = 0;
    for (size_t i = 0; i < db.size(); i++) {
        size_t hw = (db[i] ^ query_bv).hammingWeight();

        if (hw <= inclusive_hd_threshold) {
            REQUIRE((matches_ss0[i] + matches_ss1[i]) % eval_out_ss_prime_mod == 1);
        } else {
            REQUIRE((matches_ss0[i] + matches_ss1[i]) % eval_out_ss_prime_mod == 0);
        }
    }

}

TEST_CASE("The PK HD FPIR Scheme perfectly matches a single string in the DB where |DB| = 5, n=64, and d = 6", "[pk_fpir][n=64][d=6][db_len=5]") {

    // Set up parameters for the test.
    const size_t n = 64; // Bit length of the database entries and query.
    const size_t inclusive_hd_threshold = 6; // Hamming distance threshold for a match.
    const size_t blum_int_bitlen = 1024; // Bit length of the Blum integer for Paillier key generation.
    const size_t miller_rabin_rounds_per_prime = 25; // Miller-Rabin rounds for primality testing during Paillier key generation.
    const size_t stat_sec_param = 40; // Statistical security parameter for key generation.
    const uint64_t eval_out_ss_prime_mod = 251; // Prime modulus for the output of the eval function.
    const size_t db_size = 5; // Number of entries in the database.
    const size_t num_matching_db_entries = 2; // Number of entries in the database that should match the query.

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
    vector<BitVector> db;
    db.reserve(db_size);
    gen_rand_matching_inputs(num_matching_db_entries, prg, query_bv, inclusive_hd_threshold, db);
    gen_rand_non_matching_inputs(db_size - num_matching_db_entries, prg, query_bv, inclusive_hd_threshold, db);
    std::shuffle(db.begin(), db.end(), prg);

    osuCrypto::AlignedUnVector<uint32_t> matches_ss0(db.size());
    osuCrypto::AlignedUnVector<uint32_t> matches_ss1(db.size());
    matches_ss0[0] = 0;
    matches_ss1[0] = 0;

    pk_fpir::gen_hd_response(hd_query_fss_keys[0], n, db, matches_ss0);
    pk_fpir::gen_hd_response(hd_query_fss_keys[1], n, db, matches_ss1);

    size_t num_matches = 0;
    for (size_t i = 0; i < db.size(); i++) {
        size_t hw = (db[i] ^ query_bv).hammingWeight();

        if (hw <= inclusive_hd_threshold) {
            REQUIRE((matches_ss0[i] + matches_ss1[i]) % eval_out_ss_prime_mod == 1);
        } else {
            REQUIRE((matches_ss0[i] + matches_ss1[i]) % eval_out_ss_prime_mod == 0);
        }
    }

}

TEST_CASE("The PK HD FPIR Scheme perfectly matches a single string in the DB where |DB| = 10, n=32, and d = 5", "[pk_fpir][n=32][d=5][db_len=10]") {

    // Set up parameters for the test.
    const size_t n = 32; // Bit length of the database entries and query.
    const size_t inclusive_hd_threshold = 5; // Hamming distance threshold for a match.
    const size_t blum_int_bitlen = 1024; // Bit length of the Blum integer for Paillier key generation.
    const size_t miller_rabin_rounds_per_prime = 25; // Miller-Rabin rounds for primality testing during Paillier key generation.
    const size_t stat_sec_param = 40; // Statistical security parameter for key generation.
    const uint64_t eval_out_ss_prime_mod = 251; // Prime modulus for the output of the eval function.
    const size_t db_size = 10; // Number of entries in the database.
    const size_t num_matching_db_entries = 7; // Number of entries in the database that should match the query.

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
    vector<BitVector> db;
    db.reserve(db_size);
    gen_rand_matching_inputs(num_matching_db_entries, prg, query_bv, inclusive_hd_threshold, db);
    gen_rand_non_matching_inputs(db_size - num_matching_db_entries, prg, query_bv, inclusive_hd_threshold, db);
    std::shuffle(db.begin(), db.end(), prg);

    osuCrypto::AlignedUnVector<uint32_t> matches_ss0(db.size());
    osuCrypto::AlignedUnVector<uint32_t> matches_ss1(db.size());
    matches_ss0[0] = 0;
    matches_ss1[0] = 0;

    pk_fpir::gen_hd_response(hd_query_fss_keys[0], n, db, matches_ss0);
    pk_fpir::gen_hd_response(hd_query_fss_keys[1], n, db, matches_ss1);

    size_t num_matches = 0;
    for (size_t i = 0; i < db.size(); i++) {
        size_t hw = (db[i] ^ query_bv).hammingWeight();

        if (hw <= inclusive_hd_threshold) {
            REQUIRE((matches_ss0[i] + matches_ss1[i]) % eval_out_ss_prime_mod == 1);
        } else {
            REQUIRE((matches_ss0[i] + matches_ss1[i]) % eval_out_ss_prime_mod == 0);
        }
    }

}

TEST_CASE("The PK HD FPIR Scheme perfectly matches a single string in the DB where |DB| = 1, n=32, and d = 5", "[pk_fpir][n=32][d=5]") {

    // Set up parameters for the test.
    const size_t n = 32; // Bit length of the database entries and query.
    const size_t inclusive_hd_threshold = 5; // Hamming distance threshold for a match.
    const size_t blum_int_bitlen = 1024; // Bit length of the Blum integer for Paillier key generation.
    const size_t miller_rabin_rounds_per_prime = 25; // Miller-Rabin rounds for primality testing during Paillier key generation.
    const size_t stat_sec_param = 40; // Statistical security parameter for key generation.
    const uint64_t eval_out_ss_prime_mod = 251; // Prime modulus for the output of the eval function.
    const size_t db_size = 5; // Number of entries in the database.
    const size_t num_matching_db_entries = 2; // Number of entries in the database that should match the query.

    PRNG prg(osuCrypto::toBlock(123)); // Initialize a pseudorandom generator with a fixed seed for reproducibility.

    // Generate a one-time setup secret key for the FSS scheme.
    pk_hd_fss::one_time_setup_sk fss_setup_sk;
    pk_hd_fss::one_time_setup_opts setup_opts{blum_int_bitlen, miller_rabin_rounds_per_prime, stat_sec_param, eval_out_ss_prime_mod, n, inclusive_hd_threshold};
    pk_hd_fss::one_time_setup(setup_opts, prg, fss_setup_sk);

    // Create a query bit vector that will be used to generate the FSS keys. This will also be the entry in our database.
    BitVector query_bv(n);
    query_bv.randomize(prg); // Randomize the query bit vector.  
    
    std::cout << "Query BV: " << query_bv.getSpan<uint32_t>()[0] << std::endl;

    // Generate FSS keys for both parties using the same query bit vector (since we want a match).
    array<pk_hd_fss::key, 2> hd_query_fss_keys;
    pk_fpir::gen_hd_query(fss_setup_sk, query_bv, prg, hd_query_fss_keys);

    // Create a database with a single entry that matches the query bit vector.
    vector<BitVector> db;
    db.reserve(db_size);
    gen_rand_matching_inputs(num_matching_db_entries, prg, query_bv, inclusive_hd_threshold, db);
    gen_rand_non_matching_inputs(db_size - num_matching_db_entries, prg, query_bv, inclusive_hd_threshold, db);
    //db[0] = query_bv; // The single entry in the database is exactly the same as the query.

    std::cout << "DB Entry: " << db[0].getSpan<uint32_t>()[0] << std::endl;

    osuCrypto::AlignedUnVector<uint32_t> matches_ss0(db.size());
    osuCrypto::AlignedUnVector<uint32_t> matches_ss1(db.size());
    matches_ss0[0] = 0;
    matches_ss1[0] = 0;

    pk_fpir::gen_hd_response(hd_query_fss_keys[0], n, db, matches_ss0);
    pk_fpir::gen_hd_response(hd_query_fss_keys[1], n, db, matches_ss1);

    size_t num_matches = 0;
    for (size_t i = 0; i < db.size(); i++) {
        size_t hw = (db[i] ^ query_bv).hammingWeight();
        std::cout << "Hamming Weight between DB Entry " << i << " and Query: " << hw << std::endl;

        if (hw <= inclusive_hd_threshold) {
            REQUIRE((matches_ss0[i] + matches_ss1[i]) % eval_out_ss_prime_mod == 1);
        } else {
            REQUIRE((matches_ss0[i] + matches_ss1[i]) % eval_out_ss_prime_mod == 0);
        }
    }

}
/*
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
*/