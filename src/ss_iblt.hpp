#pragma once

#include <cstdint>
#include <vector>
#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/BitVector.h"

struct ss_u32_iblt {
    size_t subtable_bin_count;
    size_t num_hash_funcs;
    std::vector<osuCrypto::AES> hash_funcs;
    uint32_t prime_mod;
    size_t element_bitlen;
    std::vector<std::vector<uint8_t>> cnt_bins;
    std::vector<std::vector<osuCrypto::BitVector>> sum_bins;
};

void init_ss_u32_iblt(size_t target_num_bins, size_t num_hash_funcs, osuCrypto::block hash_funcs_seed, ss_u32_iblt& uninit_ss_u32_iblt_out);
// void hash_func_eval(const ss_u32_iblt& ss_u32_iblt_in, uint32_t input, std::vector<size_t>& hash_vals_out);
void insert_ss_u32_iblt(const osuCrypto::BitVector& input, uint32_t bin_match_u32addss, ss_u32_iblt& ss_u32_iblt_in_out);
void reconstruct_u32_iblt(ss_u32_iblt& ss_u32_iblt0_in_out, ss_u32_iblt& ss_u32_iblt1_in_out);

// This function erases all elements in the iblt datastructures.
void list_u32_iblt(ss_u32_iblt& ss_u32_iblt_in, std::vector<uint32_t>& list_out);
