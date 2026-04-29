#pragma once
#include "./pk_hd_fss.hpp"
#include "./u64_ss_iblt.hpp"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/Aligned.h"
#include <cstdint>
#include <vector>
#include <array>

namespace pk_fpir {

    void gen_hd_query(const pk_hd_fss::one_time_setup_sk& fss_setup_sk,
                      const osuCrypto::BitVector& bv,
                      osuCrypto::PRNG& prg,
                      std::array<pk_hd_fss::key, 2>& hd_query_fss_keys);
    
    void gen_hd_response(const pk_hd_fss::key& hd_query_fss_key,
                         size_t db_entries_bitlen,
                         const std::vector<osuCrypto::BitVector>& db,
                         osuCrypto::block iblt_hash_funcs_seed,
                         size_t resp_max_match_count,
                         u64_ss_iblt::table& hd_threshold_match_adss_iblt);

    void gen_hd_response(const pk_hd_fss::key& hd_query_fss_key,
                         size_t db_entries_bitlen,
                         const std::vector<osuCrypto::BitVector>& db,
                         osuCrypto::AlignedUnVector<uint32_t>& matches_ss);

}