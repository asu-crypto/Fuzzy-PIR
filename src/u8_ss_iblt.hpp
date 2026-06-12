#pragma once

#include <cstdint>
#include <vector>
#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Aligned.h"

namespace u8_ss_iblt {

    struct table {
        size_t subtable_bin_count;
        size_t num_hash_funcs;
        std::vector<osuCrypto::AES> aes_vec;
        uint8_t ss_mod;
        size_t element_byte_len;
        osuCrypto::AlignedUnVector<uint8_t> cnt_bins;
        osuCrypto::AlignedUnVector<uint8_t> sum_bins;
    };

    void init_table(size_t threshold, 
                    osuCrypto::block hash_funcs_seed,
                    uint8_t ss_mod,
                    size_t element_vec_len,
                    table& uninit_table_out);

    void init_table(size_t threshold, 
                    double space_mult_fac,
                    size_t num_hash_funcs,
                    osuCrypto::block hash_funcs_seed,
                    uint8_t ss_mod,
                    size_t element_vec_len,
                    table& uninit_table_out);

    void insert(const osuCrypto::AlignedUnVector<uint8_t>& element, uint8_t sel_bin_ss, table& table);

    void reconstruct(const table& table0_in, table& table1_in_out);

    // This function erases all elements in the iblt datastructures.
    void list(table& table_in, std::vector<osuCrypto::AlignedUnVector<uint8_t>>& list_out);

    size_t byte_size(const table& table);

}