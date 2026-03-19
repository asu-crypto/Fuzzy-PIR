#include "./ss_iblt.hpp"
#include <queue>
#include <array>
#include <cmath>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/block.h"

using osuCrypto::AES;
using osuCrypto::PRNG;
using osuCrypto::block;
using std::vector;
using std::queue;
using std::array;
using osuCrypto::BitVector;

size_t calc_element_slice_bitlen(uint32_t prime_mod) {
    return std::log2(prime_mod);
}

size_t calc_num_slices(size_t element_bitlen, uint32_t prime_mod) {
    size_t element_slice_bitlen = calc_element_slice_bitlen(prime_mod);
    return (element_bitlen / element_slice_bitlen) + ((element_bitlen % element_slice_bitlen) != 0);
}

void init_ss_u32_iblt(size_t target_num_bins, 
                      size_t num_hash_funcs, 
                      block hash_funcs_seed, 
                      size_t element_bitlen,
                      uint32_t prime_mod,
                      ss_u32_iblt& uninit_ss_u32_iblt_out) {
    assert(element_bitlen <= 128);

    uninit_ss_u32_iblt_out.subtable_bin_count = (target_num_bins / num_hash_funcs) + 1;
    uninit_ss_u32_iblt_out.num_hash_funcs = num_hash_funcs;
    uninit_ss_u32_iblt_out.hash_funcs.resize(num_hash_funcs);
    uninit_ss_u32_iblt_out.prime_mod = prime_mod;
    uninit_ss_u32_iblt_out.element_bitlen = element_bitlen;
    size_t num_slices = calc_num_slices(element_bitlen, prime_mod);
    size_t slice_bitlen = calc_element_slice_bitlen(prime_mod);
    
    PRNG prng(hash_funcs_seed);
    for (size_t i = 0; i < num_hash_funcs; i++) {
        uninit_ss_u32_iblt_out.hash_funcs[i].setKey(prng.get<block>());
    }

    uninit_ss_u32_iblt_out.cnt_bins.resize(num_hash_funcs);
    uninit_ss_u32_iblt_out.sum_bins.resize(num_hash_funcs);
    for (size_t i = 0; i < num_hash_funcs; i++) {
        assert(uninit_ss_u32_iblt_out.cnt_bins[i].empty());
        assert(uninit_ss_u32_iblt_out.sum_bins[i].empty());

        uninit_ss_u32_iblt_out.cnt_bins[i].resize(uninit_ss_u32_iblt_out.subtable_bin_count,0);
        uninit_ss_u32_iblt_out.sum_bins[i].resize(uninit_ss_u32_iblt_out.subtable_bin_count);

        for (size_t j = 0; j < uninit_ss_u32_iblt_out.subtable_bin_count; j++) {
            uninit_ss_u32_iblt_out.sum_bins[i][j].resize(slice_bitlen * num_slices);
        }
    }

}

/*
void hash_func_eval(const ss_u32_iblt& ss_u32_iblt_in, uint32_t input, vector<size_t>& hash_vals_out) {

    size_t num_hash_funcs = ss_u32_iblt_in.num_hash_funcs;
    size_t subtable_bin_count = ss_u32_iblt_in.subtable_bin_count;

    hash_vals_out.resize(num_hash_funcs);

    for (size_t i = 0; i < num_hash_funcs; i++) {
        hash_vals_out[i] = ss_u32_iblt_in.hash_funcs[i].hashBlock(block(0,input)).get<size_t>()[0] % subtable_bin_count;
    }

}*/

void insert_ss_u32_iblt(const BitVector& input, uint32_t bin_match_u32addss, ss_u32_iblt& ss_u32_iblt_in_out) {

    size_t subtable_bin_count = ss_u32_iblt_in_out.subtable_bin_count;
    size_t num_hash_funcs = ss_u32_iblt_in_out.num_hash_funcs;
    uint32_t prime_mod = ss_u32_iblt_in_out.prime_mod;
    size_t element_bitlen = ss_u32_iblt_in_out.element_bitlen;
    size_t num_slices = calc_num_slices(element_bitlen, prime_mod);

    for (size_t i = 0; i < num_hash_funcs; i++) {
        uint32_t hash_val = ss_u32_iblt_in_out.hash_funcs[i].hashBlock(input.blocks()[0]).get<size_t>()[0] % subtable_bin_count;
        
        ss_u32_iblt_in_out.cnt_bins[i][hash_val] = ((((uint32_t) ss_u32_iblt_in_out.cnt_bins[i][hash_val]) + bin_match_u32addss) % prime_mod);
        
        BitVector& sum_bin = ss_u32_iblt_in_out.sum_bins[i][hash_val];

        for (size_t slice_idx = 0; slice_idx < num_slices; slice_idx++) {
            size_t slice_start_bit = slice_idx * calc_element_slice_bitlen(prime_mod);
            size_t slice_end_bit = std::min(slice_start_bit + calc_element_slice_bitlen(prime_mod), element_bitlen);

            uint32_t input_slice_val = input.getBits(slice_start_bit, slice_end_bit).template get<uint32_t>();

            uint32_t sum_bin_slice_val = sum_bin.getBits(slice_start_bit, slice_end_bit).template get<uint32_t>();

            sum_bin.setBits(slice_start_bit, slice_end_bit, ((sum_bin_slice_val + input_slice_val) % prime_mod));
        }
    }

}

void reconstruct_u32_iblt(ss_u32_iblt& ss_u32_iblt0_in_out, ss_u32_iblt& ss_u32_iblt1_in_out) {
    assert(ss_u32_iblt0_in_out.subtable_bin_count == ss_u32_iblt1_in_out.subtable_bin_count);
    assert(ss_u32_iblt0_in_out.num_hash_funcs == ss_u32_iblt1_in_out.num_hash_funcs);
    
    size_t subtable_bin_count = ss_u32_iblt0_in_out.subtable_bin_count;
    size_t num_hash_funcs = ss_u32_iblt0_in_out.num_hash_funcs;

    for (size_t i = 0; i < num_hash_funcs; i++) {
        for (size_t j = 0; j < subtable_bin_count; j++) {
            ss_u32_iblt0_in_out.cnt_bins[i][j] += ss_u32_iblt1_in_out.cnt_bins[i][j];
            ss_u32_iblt0_in_out.sum_bins[i][j] += ss_u32_iblt1_in_out.sum_bins[i][j];
        }
    }
}


void list_u32_iblt(ss_u32_iblt& u32_iblt_in, vector<uint32_t>& list_out) {
    assert(list_out.empty());

    size_t subtable_bin_count = u32_iblt_in.subtable_bin_count;
    size_t num_hash_funcs = u32_iblt_in.num_hash_funcs;

    list_out.reserve(subtable_bin_count * num_hash_funcs);
    queue<array<size_t, 2>> candidate_bins;

    for (size_t i = 0; i < num_hash_funcs; i++) {
        for (size_t j = 0; j < subtable_bin_count; j++) {
            
            candidate_bins.push({i, j});

        }
    }

    while (!candidate_bins.empty()) {
        auto candidate_bin = candidate_bins.front();
        candidate_bins.pop();

        if (u32_iblt_in.cnt_bins[candidate_bin[0]][candidate_bin[1]] != 1) continue;

        uint32_t peeled_val = u32_iblt_in.sum_bins[candidate_bin[0]][candidate_bin[1]];
        list_out.push_back(peeled_val);

        for (size_t i = 0; i < num_hash_funcs; i++) {
            uint32_t hash_val = u32_iblt_in.hash_funcs[i].hashBlock(block(0,peeled_val)).get<size_t>()[0] % subtable_bin_count;
            
            u32_iblt_in.cnt_bins[i][hash_val] -= 1;
            u32_iblt_in.sum_bins[i][hash_val] -= peeled_val;

            if (i != candidate_bin[0]) candidate_bins.push({i, hash_val});
        }
    }
    
}