#include "./pk_fpir.hpp"
#include <cmath>
#include <span>

void pk_fpir::gen_hd_query(const pk_hd_fss::one_time_setup_sk& fss_setup_sk,
                            const osuCrypto::BitVector& bv,
                            osuCrypto::PRNG& prg,
                            std::array<pk_hd_fss::key, 2>& hd_query_fss_keys) {

    pk_hd_fss::key_gen(fss_setup_sk, bv, prg, hd_query_fss_keys[0], hd_query_fss_keys[1]);

}

void pk_fpir::gen_hd_response(const pk_hd_fss::key& hd_query_fss_key,
                              size_t db_entries_bitlen,
                              const std::vector<osuCrypto::BitVector>& db,
                              osuCrypto::block iblt_hash_funcs_seed,
                              size_t resp_max_match_count,
                              ss_u32_iblt& hd_threshold_match_adss_iblt) {
    assert(db_entries_bitlen <= 32);
    assert(db_entries_bitlen == hd_query_fss_key.n);

    size_t n = hd_query_fss_key.n;
    size_t inclusive_hd_threshold = hd_query_fss_key.inclusive_hd_threshold;

    // The IBLT users here a just temporary.
    const size_t iblt_size_mult_fact = 4.5;
    const size_t num_iblt_hash_funcs = 5;
    
    const size_t iblt_target_num_bins = static_cast<size_t>(std::ceil(((double) resp_max_match_count) * iblt_size_mult_fact));

    init_ss_u32_iblt(iblt_target_num_bins, num_iblt_hash_funcs, iblt_hash_funcs_seed, hd_threshold_match_adss_iblt);

    for (const auto& db_entry : db) {
        assert(db_entry.size() == n);

        auto db_entry_as_u32 = db_entry.getSpan<uint32_t>()[0]; 

        uint32_t hd_threshold_match_adss_out;
        
        pk_hd_fss::eval(hd_query_fss_key, db_entry, hd_threshold_match_adss_out);
        
        insert_ss_u32_iblt(db_entry_as_u32, hd_threshold_match_adss_out, hd_threshold_match_adss_iblt);
    
    }

}
