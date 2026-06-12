#include "./pk_fpir.hpp"
#include <cmath>
#include <span>
#include <iostream>

using osuCrypto::PRNG;
using osuCrypto::BitVector;
using osuCrypto::block;
using osuCrypto::AlignedUnVector;
using std::vector;
using std::array;

static void log2Floor(size_t n, size_t& log2_floor_out) {
    
}

void pk_fpir::gen_hd_query(const pk_hd_fss::one_time_setup_sk& fss_setup_sk,
                            const osuCrypto::BitVector& bv,
                            osuCrypto::PRNG& prg,
                            std::array<pk_hd_fss::key, 2>& hd_query_fss_keys) {

    pk_hd_fss::key_gen(fss_setup_sk, bv, prg, hd_query_fss_keys[0], hd_query_fss_keys[1]);

}
/*
void pk_fpir::gen_hd_response(const pk_hd_fss::key& hd_query_fss_key,
                              size_t db_entries_bitlen,
                              const std::vector<osuCrypto::BitVector>& db,
                              osuCrypto::block iblt_hash_funcs_seed,
                              size_t resp_max_match_count,
                              u64_ss_iblt::table& hd_threshold_match_adss_iblt) {
    assert(db_entries_bitlen == 32);
    assert(db_entries_bitlen == hd_query_fss_key.n);

    size_t n = hd_query_fss_key.n;
    size_t inclusive_hd_threshold = hd_query_fss_key.inclusive_hd_threshold;

    // The IBLT parameters here are just temporary.
    const size_t iblt_size_mult_fact = 4.5;
    const size_t num_iblt_hash_funcs = 5;
    
    const size_t iblt_target_num_bins = static_cast<size_t>(std::ceil(((double) resp_max_match_count) * iblt_size_mult_fact));

    u64_ss_iblt::init(resp_max_match_count, num_iblt_hash_funcs, iblt_hash_funcs_seed, hd_threshold_match_adss_iblt);

    for (const auto& db_entry : db) {
        assert(db_entry.size() == n);

        auto db_entry_as_u32 = db_entry.getSpan<uint32_t>()[0]; 

        uint32_t hd_threshold_match_adss_out;
        
        pk_hd_fss::eval(hd_query_fss_key, db_entry, hd_threshold_match_adss_out);
        
        //std::cout << "DB Entry: " << db_entry_as_u32 << ", HD Threshold Match ADSS Out: " << hd_threshold_match_adss_out << std::endl;

        //insert_ss_u32_iblt(db_entry_as_u32, hd_threshold_match_adss_out, hd_threshold_match_adss_iblt);
    
    }

}

void pk_fpir::gen_hd_response(const pk_hd_fss::key& hd_query_fss_key,
                         size_t db_entries_bitlen,
                         const std::vector<osuCrypto::BitVector>& db,
                         osuCrypto::AlignedUnVector<uint32_t>& matches) {
    assert(db_entries_bitlen == 32 || db_entries_bitlen == 64);
    assert(db_entries_bitlen == hd_query_fss_key.n);
    assert(matches.size() == db.size());

    size_t n = hd_query_fss_key.n;
    size_t inclusive_hd_threshold = hd_query_fss_key.inclusive_hd_threshold;
    
    for (size_t i = 0; i < db.size(); i++) {
        const auto& db_entry = db[i];
        assert(db_entry.size() == n);

        uint32_t hd_threshold_match_adss_out;
        
        pk_hd_fss::eval(hd_query_fss_key, db_entry, hd_threshold_match_adss_out);
        
        matches[i] = hd_threshold_match_adss_out;
    
    }

}*/

static void valid_db_entries_assert(const std::vector<osuCrypto::BitVector>& db, size_t db_entries_bitlen, uint8_t ss_mod) {
    assert(db_entries_bitlen > 0);
    assert(db_entries_bitlen <= 128);

    for (const auto& db_entry : db) {
        assert(db_entry.size() == db_entries_bitlen);
    }

}

static void encode_db_entry_as_ss_mod_vec(uint8_t ss_mod, const osuCrypto::BitVector& db_entry, AlignedUnVector<uint8_t>& ss_mod_vec_out) {
    assert(ss_mod > 2);
    assert(db_entry.size() > 0); 

    size_t ss_mod_log2_floor = static_cast<size_t>(std::floor(std::log2(ss_mod)));
    size_t num_vec_entries = static_cast<size_t>(std::ceil(static_cast<double>(db_entry.size()) / static_cast<double>(ss_mod_log2_floor)));

    ss_mod_vec_out.resize(num_vec_entries);

    for (size_t i = 0; i < num_vec_entries; i++) {
        uint8_t ss_mod_vec_entry = 0;

        for (size_t j = 0; j < ss_mod_log2_floor; j++) {
            size_t db_entry_bit_idx = i * ss_mod_log2_floor + j;

            if (db_entry_bit_idx < db_entry.size()) {
                ss_mod_vec_entry |= (static_cast<uint8_t>(db_entry[db_entry_bit_idx]) << j);
            }
        }

        ss_mod_vec_out[i] = ss_mod_vec_entry;
    }

}

void pk_fpir::gen_hd_response(const pk_hd_fss::key& hd_query_fss_key,
                              block pub_prng_seed,
                              size_t db_entries_bitlen,
                              const std::vector<osuCrypto::BitVector>& db,
                              size_t resp_max_match_count,
                              u8_ss_iblt::table& res_ss_iblt) {
    valid_db_entries_assert(db, db_entries_bitlen, hd_query_fss_key.ss_mod);
    assert(db_entries_bitlen == hd_query_fss_key.n);

    const size_t db_entries_bytelen = (db_entries_bitlen + 7) / 8;
    
    const size_t n = hd_query_fss_key.n;
    const size_t inclusive_hd_threshold = hd_query_fss_key.inclusive_hd_threshold;
    
    PRNG pub_prng(pub_prng_seed);
    block iblt_hash_funcs_seed = pub_prng.get<block>();

    size_t ss_mod_log2_floor = static_cast<size_t>(std::floor(std::log2(hd_query_fss_key.ss_mod)));
    size_t num_vec_entries = static_cast<size_t>(std::ceil(static_cast<double>(db_entries_bitlen) / static_cast<double>(ss_mod_log2_floor)));

    u8_ss_iblt::init_table(resp_max_match_count, iblt_hash_funcs_seed, hd_query_fss_key.ss_mod, num_vec_entries, res_ss_iblt);

    AlignedUnVector<uint8_t> ss_mod_vec(num_vec_entries);

    for (size_t i = 0; i < db.size(); i++) {
        const auto& bv_db_entry = db[i];

        uint32_t hd_threshold_match_adss_out;
        
        pk_hd_fss::eval(hd_query_fss_key, bv_db_entry, hd_threshold_match_adss_out);

        encode_db_entry_as_ss_mod_vec(hd_query_fss_key.ss_mod, bv_db_entry, ss_mod_vec);
        u8_ss_iblt::insert(ss_mod_vec, static_cast<uint8_t>(hd_threshold_match_adss_out), res_ss_iblt);
        
    }

}

void pk_fpir::gen_hd_decode_response(size_t db_entries_bitlen,
                                     u8_ss_iblt::table& ss0_iblt, 
                                     u8_ss_iblt::table& ss1_iblt, 
                                     std::vector<osuCrypto::BitVector>& db_matches_out) {

    const size_t ss_mod = ss0_iblt.ss_mod;

    u8_ss_iblt::reconstruct(ss1_iblt, ss0_iblt);

    std::vector<AlignedUnVector<uint8_t>> ss_mod_vec_matches;

    u8_ss_iblt::list(ss0_iblt, ss_mod_vec_matches);
    db_matches_out.resize(ss_mod_vec_matches.size());

    size_t ss_mod_log2_floor = static_cast<size_t>(std::floor(std::log2(ss_mod)));

    for (size_t i = 0; i < ss_mod_vec_matches.size(); i++) {
        const auto& ss_mod_vec_match = ss_mod_vec_matches[i];

        osuCrypto::BitVector& db_entry_match = db_matches_out[i];
        db_entry_match.resize(db_entries_bitlen);

        for (size_t j = 0; j < ss_mod_vec_match.size(); j++) {
            uint8_t ss_mod_vec_entry = ss_mod_vec_match[j];

            for (size_t k = 0; k < ss_mod_log2_floor; k++) {
                size_t db_entry_bit_idx = j * ss_mod_log2_floor + k;

                if (db_entry_bit_idx < db_entries_bitlen) {
                    db_entry_match[db_entry_bit_idx] = (ss_mod_vec_entry >> k) & 1;
                }
            }
        }

    }

}