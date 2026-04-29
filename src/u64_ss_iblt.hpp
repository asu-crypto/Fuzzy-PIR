#pragma once

#include <cstdint>
#include <vector>
#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Aligned.h"

namespace u64_ss_iblt{

    constexpr uint64_t prime_mod = (1ULL << 31) - 1;

    struct table {
        size_t subtable_bin_count;
        size_t num_hash_funcs;
        osuCrypto::AlignedUnVector<osuCrypto::AES> hash_funcs;
        osuCrypto::AlignedUnVector<uint32_t> cnt_vec;
        osuCrypto::AlignedUnVector<uint32_t> sum_vec;
    };

    void init(size_t threshold, size_t num_hash_funcs, osuCrypto::block hash_funcs_seed, u64_ss_iblt::table& table);

    void insert(uint32_t input, uint64_t bin_match_adss_mod_p, u64_ss_iblt::table& table);

    // This functions reconstructs a u64 IBLT from two given IBLT tables.
    // The output in written over iblt_ss0.
    void reconstruct_u64_iblt(u64_ss_iblt::table& iblt_ss0, u64_ss_iblt::table& iblt_ss1);
    
    // This function erases all elements in the iblt datastructures.
    void list(u64_ss_iblt::table& iblt, std::vector<uint32_t>& list_out);

}
