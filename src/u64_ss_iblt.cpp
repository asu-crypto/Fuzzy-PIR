#include "./u64_ss_iblt.hpp"
#include "cryptoTools/Crypto/PRNG.h"

using osuCrypto::AES;
using osuCrypto::block;
using osuCrypto::PRNG;
using osuCrypto::AlignedUnVector;
using std::vector;

static size_t calc_subtab_len(size_t threshold, size_t num_hash_funcs, double mult_fac) {
        return static_cast<size_t>(std::ceil(mult_fac * static_cast<double>(threshold) / static_cast<double>(num_hash_funcs)));
    }

// All the switch cases for small thresholds were creating for testing purposes only.
static size_t calc_subtab_len(size_t threshold,  size_t num_hash_funcs) {
    switch (threshold) {
        case 32:
            return  calc_subtab_len(threshold, num_hash_funcs, 1000.0);
        case 64:
            return  calc_subtab_len(threshold, num_hash_funcs, 1000.0);
        case 10:
            return  calc_subtab_len(threshold, num_hash_funcs, 1000.0);
        case 1 << 15:
            return  calc_subtab_len(threshold, num_hash_funcs, 4.5);
        case 1 << 17:
            return  calc_subtab_len(threshold, num_hash_funcs, 3.5);
        case 1 << 19:
            return  calc_subtab_len(threshold, num_hash_funcs, 2.0);
        case 1 << 20:
            return  calc_subtab_len(threshold, num_hash_funcs, 1.5);
        case 1 << 21:
            return  calc_subtab_len(threshold, num_hash_funcs, 1.5);
        default:
            throw std::invalid_argument("Unsupported threshold value for IBLT initialization.");
    }
}

// All the switch cases for small thresholds were creating for testing purposes only.
static size_t calc_tab_len(size_t threshold, size_t num_hash_funcs) {
    assert(threshold > 0);

    return num_hash_funcs * calc_subtab_len(threshold, num_hash_funcs);
}

static bool iblt_initiated(const u64_ss_iblt::table& t) {
    return t.subtable_bin_count > 0 && t.sum_vec.size() == t.num_hash_funcs * t.subtable_bin_count &&  t.sum_vec.size() == t.cnt_vec.size();
}

inline static void hash_key(size_t subtable_len, const AlignedUnVector<osuCrypto::AES>& hash_funcs, const block& key, AlignedUnVector<size_t>& idxs) {
    assert(hash_funcs.size() == idxs.size());

    const size_t NUM_HASH_FUNCS = hash_funcs.size();

    for (size_t i = 0; i < NUM_HASH_FUNCS; i++) {
        block aes_hash_out = hash_funcs[i].hashBlock(key);
        idxs[i] = aes_hash_out.get<uint64_t>()[0] % subtable_len;         
    }

}

inline static void iblt_del(u64_ss_iblt::table& table, uint32_t val) {

    AlignedUnVector<size_t> idxs(table.num_hash_funcs);

    block key_block(val, 0);
    hash_key(table.subtable_bin_count, table.hash_funcs, key_block, idxs);

    for (size_t i = 0; i < table.num_hash_funcs; i++) {
        table.cnt_vec[i * table.subtable_bin_count + idxs[i]]--;
        table.sum_vec[i * table.subtable_bin_count + idxs[i]] -= val;
    }

}

void u64_ss_iblt::init(size_t threshold, size_t num_hash_funcs, osuCrypto::block hash_funcs_seed, u64_ss_iblt::table& table) {

    table.subtable_bin_count = calc_subtab_len(threshold, num_hash_funcs);
    table.num_hash_funcs = num_hash_funcs;
    table.hash_funcs.resize(num_hash_funcs);
    table.cnt_vec.resize(calc_tab_len(threshold, num_hash_funcs));
    table.sum_vec.resize(calc_tab_len(threshold, num_hash_funcs));

    PRNG prng(hash_funcs_seed);

    for (size_t i = 0; i < num_hash_funcs; i++) {
        table.hash_funcs[i].setKey(prng.get<block>());
    }

    std::fill(table.cnt_vec.begin(), table.cnt_vec.end(), 0);
    std::fill(table.sum_vec.begin(), table.sum_vec.end(), 0);

}

void u64_ss_iblt::insert(uint32_t input, uint64_t bin_match_adss_mod_p, u64_ss_iblt::table& table) {
    assert(iblt_initiated(table));
    
    AlignedUnVector<size_t> idxs(table.num_hash_funcs);

    block key_block(input, 0);
    hash_key(table.subtable_bin_count, table.hash_funcs, key_block, idxs);

    uint64_t cnt_i, sum_i;

    for (size_t i = 0; i < table.num_hash_funcs; i++) {
        cnt_i = static_cast<uint64_t>(table.cnt_vec[i * table.subtable_bin_count + idxs[i]]);
        cnt_i += bin_match_adss_mod_p;
        cnt_i = (cnt_i >= u64_ss_iblt::prime_mod) ? cnt_i - u64_ss_iblt::prime_mod : cnt_i;
        table.cnt_vec[i * table.subtable_bin_count + idxs[i]] = static_cast<uint32_t>(cnt_i);

        sum_i = static_cast<uint64_t>(table.sum_vec[i * table.subtable_bin_count + idxs[i]]);
        sum_i += bin_match_adss_mod_p * input;
        sum_i = (sum_i >= u64_ss_iblt::prime_mod) ? sum_i - u64_ss_iblt::prime_mod : sum_i;
        table.sum_vec[i * table.subtable_bin_count + idxs[i]] = static_cast<uint32_t>(sum_i);
    }

}

void u64_ss_iblt::reconstruct_u64_iblt(u64_ss_iblt::table& iblt_ss0, u64_ss_iblt::table& iblt_ss1) {
    assert(iblt_initiated(iblt_ss0));
    assert(iblt_initiated(iblt_ss1));

    for (size_t i = 0; i < iblt_ss0.cnt_vec.size(); i++) {
        iblt_ss0.cnt_vec[i] += iblt_ss1.cnt_vec[i];
        iblt_ss0.cnt_vec[i] = (iblt_ss0.cnt_vec[i] >= u64_ss_iblt::prime_mod) ? iblt_ss0.cnt_vec[i] - u64_ss_iblt::prime_mod : iblt_ss0.cnt_vec[i];

        iblt_ss0.sum_vec[i] += iblt_ss1.sum_vec[i];
        iblt_ss0.sum_vec[i] = (iblt_ss0.sum_vec[i] >= u64_ss_iblt::prime_mod) ? iblt_ss0.sum_vec[i] - u64_ss_iblt::prime_mod : iblt_ss0.sum_vec[i];
    }

}

void u64_ss_iblt::list(u64_ss_iblt::table& iblt, vector<uint32_t>& list_out) {
    assert(iblt_initiated(iblt));

    const size_t ell = iblt.subtable_bin_count;
    const size_t k = iblt.num_hash_funcs;
    const size_t m = iblt.cnt_vec.size();

    size_t num_decoded_elements_last_round = 1;

    AlignedUnVector<uint32_t>& cnt_vec = iblt.cnt_vec;
    AlignedUnVector<uint32_t>& sum_vec = iblt.sum_vec;

    while (num_decoded_elements_last_round > 0) {
        num_decoded_elements_last_round = 0;
        
        for (size_t i = 0; i < m; i++) {

            if (cnt_vec[i] != 1) continue;

            uint32_t decoded_element = sum_vec[i];
            list_out.push_back(decoded_element);
            iblt_del(iblt, decoded_element);
            num_decoded_elements_last_round++;
        }

    }

}