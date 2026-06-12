#include "./u8_ss_iblt.hpp"

using std::vector;
using osuCrypto::BitVector;
using osuCrypto::AlignedUnVector;
using osuCrypto::block;
using osuCrypto::PRNG;

static constexpr size_t HASHES_PER_BLK = 4;

static size_t calc_subtab_len(size_t threshold, size_t num_hash_funcs, double mult_fac) {
    return static_cast<size_t>(std::ceil(mult_fac * static_cast<double>(threshold) / static_cast<double>(num_hash_funcs)));
}

// All the switch cases for small thresholds were creating for testing purposes only.
static void recommended_iblt_params(size_t threshold, double& space_mult_fac, size_t& num_hash_funcs_out) {
    
    num_hash_funcs_out = 5;

    switch(threshold) {
        case 32:
            
            space_mult_fac = 1000.0;
            break;
        case 64:
            space_mult_fac = 1000.0;
            break;
        case 10:
            space_mult_fac = 1000.0;
            break;
        case 1 << 15:
            space_mult_fac = 4.5;
            break;
        case 1 << 17:
            space_mult_fac = 3.5;
            break;
        case 1 << 19:
            space_mult_fac = 2.0;
            break;
        case 1 << 20:
            space_mult_fac = 1.5;
            break;
        case 1 << 21:
            space_mult_fac = 1.5;
            break;
        default:
            throw std::invalid_argument("No recommended IBLT parameters for the given threshold value " + std::to_string(threshold) + ".");
    }

}

static bool iblt_initiated(const u8_ss_iblt::table& t) {
    return t.subtable_bin_count > 0 && t.sum_bins.size() == t.num_hash_funcs * t.subtable_bin_count * t.element_byte_len &&  t.cnt_bins.size() == t.num_hash_funcs * t.subtable_bin_count;
}

void u8_ss_iblt::init_table(size_t threshold, 
                            double space_mult_fac,
                            size_t num_hash_funcs,
                            osuCrypto::block hash_funcs_seed, 
                            uint8_t ss_mod, 
                            size_t element_vec_len,
                            table& uninit_table_out) {
    assert(threshold > 0);
    assert(element_vec_len <= 16); // We can support up to 16 bytes since we are using AES as the hash function and it outputs 16 bytes.

    uninit_table_out.num_hash_funcs = num_hash_funcs;
    uninit_table_out.subtable_bin_count = calc_subtab_len(threshold, num_hash_funcs, space_mult_fac);

    const size_t aes_vec_len = static_cast<size_t>(std::ceil(static_cast<double>(num_hash_funcs) / static_cast<double>(HASHES_PER_BLK)));

    PRNG prng(hash_funcs_seed);
    uninit_table_out.aes_vec.resize(aes_vec_len);
    for (size_t i = 0; i < aes_vec_len; i++) {
        uninit_table_out.aes_vec[i].setKey(prng.get<osuCrypto::block>());
    }

    uninit_table_out.ss_mod = ss_mod;
    uninit_table_out.element_byte_len = element_vec_len;

    uninit_table_out.cnt_bins.resize(uninit_table_out.subtable_bin_count * uninit_table_out.num_hash_funcs);
    uninit_table_out.sum_bins.resize(uninit_table_out.subtable_bin_count * uninit_table_out.num_hash_funcs * uninit_table_out.element_byte_len);

    for (size_t i = 0; i < uninit_table_out.cnt_bins.size(); i++) {
        uninit_table_out.cnt_bins[i] = 0;
    }

    for (size_t i = 0; i < uninit_table_out.sum_bins.size(); i++) {
        uninit_table_out.sum_bins[i] = 0;
    }

}

void u8_ss_iblt::init_table(size_t threshold, 
                            osuCrypto::block hash_funcs_seed, 
                            uint8_t ss_mod, 
                            size_t element_vec_len,
                            table& uninit_table_out) {
    assert(threshold > 0);
    assert(element_vec_len <= 16); // We can support up to 16 bytes since we are using AES as the hash function and it outputs 16 bytes.

    size_t recommended_num_hash_funcs;
    double recommended_space_mult_fac;

    recommended_iblt_params(threshold, recommended_space_mult_fac, recommended_num_hash_funcs);

    init_table(threshold, recommended_space_mult_fac, recommended_num_hash_funcs, hash_funcs_seed, ss_mod, element_vec_len, uninit_table_out);

}

inline static void hash_key(size_t subtable_len, const std::vector<osuCrypto::AES>& aes_vec, const block& key, AlignedUnVector<size_t>& idxs) {
    constexpr size_t hashs_per_aes = 4;
    
    assert(aes_vec.size() > 0);
    assert(idxs.size() == aes_vec.size() * hashs_per_aes);

    const size_t NUM_HASH_FUNCS = idxs.size();
    const size_t AES_VEC_LEN = aes_vec.size();

    for (size_t i = 0;i < AES_VEC_LEN; i++) {
        block hash_out_block = aes_vec[i].hashBlock(key);
        
        for (size_t j = 0; j < hashs_per_aes; j++) {
            size_t hash_idx = i * hashs_per_aes + j;
            idxs[hash_idx] = hash_out_block.get<uint32_t>()[j] % subtable_len;
        }
    }

}

static block u8_vec_to_block(const osuCrypto::AlignedUnVector<uint8_t>& vec) {
    assert(vec.size() <= 16); // Block is 16 bytes, so we can only convert vectors of up to 16 bytes to a block.

    block block_out = block(0, 0);

    uint8_t* block_bytes = reinterpret_cast<uint8_t*>(block_out.data());
    for (size_t i = 0; i < vec.size(); i++) {
        block_bytes[i] = vec[i];
    }
    
    return block_out;
}

static bool valid_element(const osuCrypto::AlignedUnVector<uint8_t>& element, size_t element_byte_len, uint8_t ss_mod) {
    return element.size() == element_byte_len && std::all_of(element.begin(), element.end(), [ss_mod](uint8_t byte) { return byte < ss_mod; });
}

void u8_ss_iblt::insert(const osuCrypto::AlignedUnVector<uint8_t>& element, uint8_t sel_bin_ss, u8_ss_iblt::table& table) {
    
    constexpr size_t hashs_per_aes = 4;
    
    assert(iblt_initiated(table));
    assert(valid_element(element, table.element_byte_len, table.ss_mod));

    AlignedUnVector<size_t> idxs(table.aes_vec.size() * hashs_per_aes); // table.aes_vec.size() * hashs_per_aes >= table.num_hash_funcs.

    block key_block = u8_vec_to_block(element);
    hash_key(table.subtable_bin_count, table.aes_vec, key_block, idxs);
    
    const uint8_t ss_mod = table.ss_mod;

    for (size_t i = 0; i < table.num_hash_funcs; i++) {
        size_t cnt_idx = i * table.subtable_bin_count + idxs[i];
        size_t sum_idx = cnt_idx * table.element_byte_len;

        // Update count bin with modular addition.
        uint16_t cnt_i = table.cnt_bins[cnt_idx];
        cnt_i += sel_bin_ss;
        cnt_i = (cnt_i >= ss_mod) ? cnt_i - ss_mod : cnt_i;
        table.cnt_bins[cnt_idx] = cnt_i;

        // Update sum bin with modular addition.
        for (size_t byte_idx = 0; byte_idx < table.element_byte_len; byte_idx++) {
            uint16_t sum_byte_i = table.sum_bins[sum_idx + byte_idx];
            
            sum_byte_i += (((uint16_t) element[byte_idx]) * ((uint16_t) sel_bin_ss));
            sum_byte_i %= ss_mod;

            table.sum_bins[sum_idx + byte_idx] = sum_byte_i;
        }
    }

}

void u8_ss_iblt::reconstruct(const table& table0_in, table& table1_in_out) {
    
    assert(iblt_initiated(table0_in));
    assert(iblt_initiated(table1_in_out));
    assert(table0_in.subtable_bin_count == table1_in_out.subtable_bin_count);
    assert(table0_in.num_hash_funcs == table1_in_out.num_hash_funcs);
    assert(table0_in.ss_mod == table1_in_out.ss_mod);
    assert(table0_in.element_byte_len == table1_in_out.element_byte_len);

    const size_t subtable_bin_count = table0_in.subtable_bin_count;
    const size_t num_hash_funcs = table0_in.num_hash_funcs;
    const uint8_t ss_mod = table0_in.ss_mod;
    const size_t element_byte_len = table0_in.element_byte_len;

    for (size_t i = 0; i < num_hash_funcs; i++) {
        for (size_t j = 0; j < subtable_bin_count; j++) {
            size_t idx = i * subtable_bin_count + j;

            // Update count bins with modular addition.
            uint16_t cnt_sum = static_cast<uint16_t>(table0_in.cnt_bins[idx]) + static_cast<uint16_t>(table1_in_out.cnt_bins[idx]);
            cnt_sum = (cnt_sum >= ss_mod) ? cnt_sum - ss_mod : cnt_sum;
            table1_in_out.cnt_bins[idx] = cnt_sum;

            // Update sum bins with modular addition.
            size_t sum_idx = idx * element_byte_len;
            for (size_t byte_idx = 0; byte_idx < element_byte_len; byte_idx++) {
                uint16_t sum_byte_i = static_cast<uint16_t>(table0_in.sum_bins[sum_idx + byte_idx]) + static_cast<uint16_t>(table1_in_out.sum_bins[sum_idx + byte_idx]);
                sum_byte_i = (sum_byte_i >= ss_mod) ? sum_byte_i - ss_mod : sum_byte_i;
                table1_in_out.sum_bins[sum_idx + byte_idx] = sum_byte_i;
            }
        }
    }

}

inline static void iblt_del(u8_ss_iblt::table& table, const osuCrypto::AlignedUnVector<uint8_t>& element) {
    constexpr size_t hashs_per_aes = 4;
    
    assert(iblt_initiated(table));
    assert(valid_element(element, table.element_byte_len, table.ss_mod));

    AlignedUnVector<size_t> idxs(table.aes_vec.size() * hashs_per_aes); // table.aes_vec.size() * hashs_per_aes >= table.num_hash_funcs.

    block key_block = u8_vec_to_block(element);
    hash_key(table.subtable_bin_count, table.aes_vec, key_block, idxs);

    const uint8_t ss_mod = table.ss_mod;

    for (size_t i = 0; i < table.num_hash_funcs; i++) {
        size_t cnt_idx = i * table.subtable_bin_count + idxs[i];
        size_t sum_idx = cnt_idx * table.element_byte_len;

        table.cnt_bins[cnt_idx]--;

        // Update sum bin with modular subtraction.
        for (size_t byte_idx = 0; byte_idx < table.element_byte_len; byte_idx++) {
            uint16_t sum_byte_i = table.sum_bins[sum_idx + byte_idx];
            
            sum_byte_i += (ss_mod - (((uint16_t) element[byte_idx]))); // Subtracting the element byte is equivalent to adding (ss_mod - element byte) in modular arithmetic.
            sum_byte_i %= ss_mod;

            table.sum_bins[sum_idx + byte_idx] = sum_byte_i;
        }
    }
}

void u8_ss_iblt::list(table& table_in, vector<osuCrypto::AlignedUnVector<uint8_t>>& list_out) {
    assert(iblt_initiated(table_in));
    

    const size_t subtable_bin_count = table_in.subtable_bin_count;
    const size_t num_hash_funcs = table_in.num_hash_funcs;
    const uint8_t ss_mod = table_in.ss_mod;
    const size_t element_byte_len = table_in.element_byte_len;

    size_t num_elements_listed_out_last_it = 0;

    do {
        num_elements_listed_out_last_it = 0;

        for (size_t i = 0; i < num_hash_funcs; i++) {
            for (size_t j = 0; j < subtable_bin_count; j++) {
                size_t idx = i * subtable_bin_count + j;

                if (table_in.cnt_bins[idx] != 1) continue;

                osuCrypto::AlignedUnVector<uint8_t> decoded_element(element_byte_len);
                size_t sum_idx = idx * element_byte_len;

                for (size_t byte_idx = 0; byte_idx < element_byte_len; byte_idx++) {
                    decoded_element[byte_idx] = table_in.sum_bins[sum_idx + byte_idx];
                }

                list_out.push_back(decoded_element);
                iblt_del(table_in, decoded_element);
                num_elements_listed_out_last_it++;
            }
        }
        
    } while (num_elements_listed_out_last_it != 0);

}

size_t u8_ss_iblt::byte_size(const table& table) {

    assert(iblt_initiated(table));

    size_t size = 0;

    size += table.cnt_bins.size();
    size += table.sum_bins.size();

    return size;

}