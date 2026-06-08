#include "./fss.hpp"
#include <cassert>
#include <array>
#include <cmath>
#include <limits>
#include <utility>
#include "./utils.hpp"
#include "cryptoTools/Common/Aligned.h"

using osuCrypto::block;
using osuCrypto::BitVector;
using osuCrypto::PRNG;
using std::vector;
using std::array;
using osuCrypto::AllOneBlock;
using std::pair;
using osuCrypto::AlignedUnVector;

static constexpr size_t MAX_N = 128; // We can only support up to 128 bits for now, since we use a block to represent the input space.
static constexpr size_t left = 0, right = 1;

// FOR DEBUGGING PURPOSES ONLY
static constexpr bool block_lt(const block& a, const block& b) {
    const array<uint64_t,2> a_chunks = a.get<uint64_t>();
    const array<uint64_t,2> b_chunks = b.get<uint64_t>();

    if (a_chunks[1] < b_chunks[1]) {
        return true;
    } else if (a_chunks[1] > b_chunks[1]) {
        return false;
    } else {
        return a_chunks[0] < b_chunks[0];
    }
}

static constexpr bool block_in_domain(const block& x, size_t domain_bitlen) {
    assert(domain_bitlen > 0 && domain_bitlen <= MAX_N);

    if (domain_bitlen == MAX_N) {
        return true; // If the domain bit length is greater than or equal to the maximum supported bit length, then any block is in the domain.
    }

    block domain_size = domain_bitlen < 64 ? block(0, 1ULL << domain_bitlen) : block(1ULL << (domain_bitlen - 64), 0);
    
    return block_lt(x, domain_size);


}

static inline bool get_bit(const block& x, size_t idx) {
    assert(idx < MAX_N);

    uint64_t block_chunck = x.get<uint64_t>()[idx/64];

    return (block_chunck >> (idx % 64)) & 1;

}

static inline void set_bit(block& x, size_t idx, bool bit) {
    assert(idx < MAX_N);

    uint64_t block_chunck = x.get<uint64_t>()[idx/64];

    if (bit) {
        block_chunck |= (1ULL << (idx % 64));
    } else {
        block_chunck &= ~(1ULL << (idx % 64));
    }

    x.set<uint64_t>(idx/64, block_chunck);
}

static array<bool,MAX_N> block_to_bool(const block& x, array<bool,MAX_N>& bits) {
    
     uint64_t block_chunck = x.get<uint64_t>()[0];
     for (size_t i = 0;i < 64; i++) {
        bits[i] = (block_chunck >> i) & 1;
     }

    block_chunck = x.get<uint64_t>()[1];
    for (size_t i = 0;i < 64; i++) {
        bits[64 + i] = (block_chunck >> i) & 1;
     }

     return bits;

}

static size_t pow2(size_t exp) {
    assert(exp < 64);
    return 1ULL << exp;
}

void halve_bitvector(const osuCrypto::BitVector& bv, osuCrypto::BitVector& least_sig_half, osuCrypto::BitVector& most_sig_half) {
    assert(bv.size() > 0 && bv.size() <= MAX_N);

    size_t n = bv.size();
    size_t least_sig_vec_size = n / 2;
    size_t most_sig_vec_size = n - least_sig_vec_size;

    //std::cout << "bv size: " << bv.size() << std::endl;
    //std::cout << "least_sig_vec_size: " << least_sig_vec_size << std::endl;

    least_sig_half.append(bv, least_sig_vec_size, 0);
    most_sig_half.append(bv, most_sig_vec_size, least_sig_vec_size);

    least_sig_half.blocks()[0] &= (AllOneBlock ^ (AllOneBlock << least_sig_vec_size));
    most_sig_half.blocks()[0] &= (AllOneBlock ^ (AllOneBlock << most_sig_vec_size));
}

void old_dpf_gen_cws(PRNG& prg, size_t n, const block& p0_root_seed, const block& p1_root_seed, const block& alpha, const block& beta, dpf_cws& cws, osuCrypto::block& p0_beta_shares, osuCrypto::block& p1_beta_shares) {

    assert(n > 0);
    assert(n <= MAX_N); // We can only support up to 128 bits for now, since we use a block to represent the input space.
    assert(block_in_domain(alpha, n) && "Alpha must be contained in the input space defined by n.");

    cws.cw_seed_vec.resize(n);

    block p0_parent_seed = p0_root_seed;
    block p1_parent_seed = p1_root_seed;
    bool p0_parent_ctrl_bit = 0;
    bool p1_parent_ctrl_bit = 1;

    // OPTIMIZE: (1) We only need to convert the n first bits of alpha. (2) We may lazily convert the bits of alpha as we need them in the loop below, instead of converting them all at once here at the beginning.
    array<bool,MAX_N> alpha_bits;
    block_to_bool(alpha, alpha_bits);

    for (size_t i = 0; i < n; i++) {
        
        bool alpha_i = alpha_bits[i];

        PRNG p0_prg(p0_parent_seed);
        PRNG p1_prg(p1_parent_seed);

        const block p0_lvl_seeds[2] = {p0_prg.get<block>(), p0_prg.get<block>()};
        const bool p0_lvl_ctrl_bits[2] = {p0_prg.get<bool>(), p0_prg.get<bool>()};
        const block p1_lvl_seeds[2] = {p1_prg.get<block>(), p1_prg.get<block>()};
        const bool p1_lvl_ctrl_bits[2] = {p1_prg.get<bool>(), p1_prg.get<bool>()};

        const size_t keep = alpha_i;
        const size_t lose = !alpha_i;

        const block cw_seed = p0_lvl_seeds[lose] ^ p1_lvl_seeds[lose];
        bool cw_ctrl_bits[2] = {0,0};

        cw_ctrl_bits[left] = p0_lvl_ctrl_bits[left] ^ p1_lvl_ctrl_bits[left] ^ alpha_i ^ 1;
        cw_ctrl_bits[right] = p0_lvl_ctrl_bits[right] ^ p1_lvl_ctrl_bits[right] ^ alpha_i;

        cws.cw_seed_vec[i] = cw_seed;
        
        set_bit(cws.cw_left_ctrl_bit_vec, i, cw_ctrl_bits[left]);
        set_bit(cws.cw_right_ctrl_bit_vec, i, cw_ctrl_bits[right]);

        p0_parent_seed = p0_lvl_seeds[keep] ^ (p0_parent_ctrl_bit ? cw_seed : block());
        p1_parent_seed = p1_lvl_seeds[keep] ^ (p1_parent_ctrl_bit ? cw_seed : block());
        
        p0_parent_ctrl_bit = p0_lvl_ctrl_bits[keep] ^ (p0_parent_ctrl_bit & cw_ctrl_bits[keep]);
        p1_parent_ctrl_bit = p1_lvl_ctrl_bits[keep] ^ (p1_parent_ctrl_bit & cw_ctrl_bits[keep]);

    }

    cws.out_cw = p0_parent_seed ^ p1_parent_seed ^ beta;

    p0_beta_shares = p0_parent_seed ^ (p0_parent_ctrl_bit ? cws.out_cw : block());
    p1_beta_shares = p1_parent_seed ^ (p1_parent_ctrl_bit ? cws.out_cw : block());

}

void new_dpf_gen_cws(PRNG& prg, size_t n, const block& p0_root_seed, bool p0_root_ctrl_bit, const block& p1_root_seed, bool p1_root_ctrl_bit, const block& alpha, const block& beta, dpf_cws& cws, osuCrypto::block& p0_beta_shares, bool& p0_final_ctrl_bit, osuCrypto::block& p1_beta_shares, bool& p1_final_ctrl_bit) {

    assert(n > 0);
    assert(n <= MAX_N); // We can only support up to 128 bits for now, since we use a block to represent the input space.
    assert(block_in_domain(alpha, n) && "Alpha must be contained in the input space defined by n.");
    assert(p0_root_ctrl_bit ^ p1_root_ctrl_bit && "The root control bits must be a binary secret share of 1.");

    cws.cw_seed_vec.resize(n);

    block p0_parent_seed = p0_root_seed;
    block p1_parent_seed = p1_root_seed;
    bool p0_parent_ctrl_bit = p0_root_ctrl_bit;
    bool p1_parent_ctrl_bit = p1_root_ctrl_bit;

    // OPTIMIZE: (1) We only need to convert the n first bits of alpha. (2) We may lazily convert the bits of alpha as we need them in the loop below, instead of converting them all at once here at the beginning.
    array<bool,MAX_N> alpha_bits;
    block_to_bool(alpha, alpha_bits);

    for (size_t i = 0; i < n; i++) {
        
        bool alpha_i = alpha_bits[i];

        PRNG p0_prg(p0_parent_seed);
        PRNG p1_prg(p1_parent_seed);

        const block p0_lvl_seeds[2] = {p0_prg.get<block>(), p0_prg.get<block>()};
        const bool p0_lvl_ctrl_bits[2] = {p0_prg.get<bool>(), p0_prg.get<bool>()};
        const block p1_lvl_seeds[2] = {p1_prg.get<block>(), p1_prg.get<block>()};
        const bool p1_lvl_ctrl_bits[2] = {p1_prg.get<bool>(), p1_prg.get<bool>()};

        const size_t keep = alpha_i;
        const size_t lose = !alpha_i;

        const block cw_seed = p0_lvl_seeds[lose] ^ p1_lvl_seeds[lose];
        bool cw_ctrl_bits[2] = {0,0};

        cw_ctrl_bits[left] = p0_lvl_ctrl_bits[left] ^ p1_lvl_ctrl_bits[left] ^ alpha_i ^ 1;
        cw_ctrl_bits[right] = p0_lvl_ctrl_bits[right] ^ p1_lvl_ctrl_bits[right] ^ alpha_i;

        cws.cw_seed_vec[i] = cw_seed;
        
        set_bit(cws.cw_left_ctrl_bit_vec, i, cw_ctrl_bits[left]);
        set_bit(cws.cw_right_ctrl_bit_vec, i, cw_ctrl_bits[right]);

        p0_parent_seed = p0_lvl_seeds[keep] ^ (p0_parent_ctrl_bit ? cw_seed : block());
        p1_parent_seed = p1_lvl_seeds[keep] ^ (p1_parent_ctrl_bit ? cw_seed : block());
        
        p0_parent_ctrl_bit = p0_lvl_ctrl_bits[keep] ^ (p0_parent_ctrl_bit & cw_ctrl_bits[keep]);
        p1_parent_ctrl_bit = p1_lvl_ctrl_bits[keep] ^ (p1_parent_ctrl_bit & cw_ctrl_bits[keep]);

    }

    cws.out_cw = p0_parent_seed ^ p1_parent_seed ^ beta;

    p0_final_ctrl_bit = p0_parent_ctrl_bit;
    p1_final_ctrl_bit = p1_parent_ctrl_bit;
    p0_beta_shares = p0_parent_seed ^ (p0_parent_ctrl_bit ? cws.out_cw : block());
    p1_beta_shares = p1_parent_seed ^ (p1_parent_ctrl_bit ? cws.out_cw : block());

}

void new_dpf_gen_cws(PRNG& prg, size_t n, const block& p0_root_seed, bool p0_root_ctrl_bit, const block& p1_root_seed, bool p1_root_ctrl_bit, const block& alpha, const block& beta, dpf_cws& cws) {

    assert(n > 0);
    assert(n <= MAX_N); // We can only support up to 128 bits for now, since we use a block to represent the input space.
    assert(block_in_domain(alpha, n) && "Alpha must be contained in the input space defined by n.");
    assert(p0_root_ctrl_bit ^ p1_root_ctrl_bit && "The root control bits must be a binary secret share of 1.");

    cws.cw_seed_vec.resize(n);

    block p0_parent_seed = p0_root_seed;
    block p1_parent_seed = p1_root_seed;
    bool p0_parent_ctrl_bit = p0_root_ctrl_bit;
    bool p1_parent_ctrl_bit = p1_root_ctrl_bit;

    // OPTIMIZE: (1) We only need to convert the n first bits of alpha. (2) We may lazily convert the bits of alpha as we need them in the loop below, instead of converting them all at once here at the beginning.
    array<bool,MAX_N> alpha_bits;
    block_to_bool(alpha, alpha_bits);

    for (size_t i = 0; i < n; i++) {
        
        bool alpha_i = alpha_bits[i];

        PRNG p0_prg(p0_parent_seed);
        PRNG p1_prg(p1_parent_seed);

        const block p0_lvl_seeds[2] = {p0_prg.get<block>(), p0_prg.get<block>()};
        const bool p0_lvl_ctrl_bits[2] = {p0_prg.get<bool>(), p0_prg.get<bool>()};
        const block p1_lvl_seeds[2] = {p1_prg.get<block>(), p1_prg.get<block>()};
        const bool p1_lvl_ctrl_bits[2] = {p1_prg.get<bool>(), p1_prg.get<bool>()};

        const size_t keep = alpha_i;
        const size_t lose = !alpha_i;

        const block cw_seed = p0_lvl_seeds[lose] ^ p1_lvl_seeds[lose];
        bool cw_ctrl_bits[2] = {0,0};

        cw_ctrl_bits[left] = p0_lvl_ctrl_bits[left] ^ p1_lvl_ctrl_bits[left] ^ alpha_i ^ 1;
        cw_ctrl_bits[right] = p0_lvl_ctrl_bits[right] ^ p1_lvl_ctrl_bits[right] ^ alpha_i;

        cws.cw_seed_vec[i] = cw_seed;
        
        set_bit(cws.cw_left_ctrl_bit_vec, i, cw_ctrl_bits[left]);
        set_bit(cws.cw_right_ctrl_bit_vec, i, cw_ctrl_bits[right]);

        p0_parent_seed = p0_lvl_seeds[keep] ^ (p0_parent_ctrl_bit ? cw_seed : block());
        p1_parent_seed = p1_lvl_seeds[keep] ^ (p1_parent_ctrl_bit ? cw_seed : block());
        
        p0_parent_ctrl_bit = p0_lvl_ctrl_bits[keep] ^ (p0_parent_ctrl_bit & cw_ctrl_bits[keep]);
        p1_parent_ctrl_bit = p1_lvl_ctrl_bits[keep] ^ (p1_parent_ctrl_bit & cw_ctrl_bits[keep]);

    }

    cws.out_cw = p0_parent_seed ^ p1_parent_seed ^ beta;

}

void dpf_gen(PRNG& prg, size_t n, const block& alpha, const block& beta, std::array<dpf_key,2>& key_pair) {
    assert(n > 0);
    assert(n <= MAX_N); // We can only support up to 128 bits for now, since we use a block to represent the input space.
    assert(block_in_domain(alpha, n) && "Alpha must be contained in the input space defined by n.");

    dpf_cws* cws = new dpf_cws();
    key_pair[0].cws = cws;
    key_pair[1].cws = cws;

    key_pair[0].party_idx = 0;
    key_pair[1].party_idx = 1;
    key_pair[0].n = n;
    key_pair[1].n = n;

    key_pair[0].root_seed = prg.get<block>();
    key_pair[1].root_seed = prg.get<block>();
    key_pair[0].root_ctrl_bit = 0;
    key_pair[1].root_ctrl_bit = 1;

    block p0_beta_share, p1_beta_share;
    bool p0_final_ctrl_bit, p1_final_ctrl_bit;

    new_dpf_gen_cws(prg, n, key_pair[0].root_seed, key_pair[0].root_ctrl_bit, key_pair[1].root_seed, key_pair[1].root_ctrl_bit, alpha, beta, *cws);
    
}

block dpf_eval(size_t party_idx, size_t n, const block& root_seed, const dpf_cws& dpf_cws, const block& x) {
    assert(party_idx == 0 || party_idx == 1);
    assert(n > 0 && n <= MAX_N); // We can only support up to 128 bits for now, since we use a block to represent the input space.
    assert(dpf_cws.cw_seed_vec.size() == n); // The number of correction words must be equal to the bit length of the input space.
    assert(block_in_domain(x, n) && "The eval point x must be a member of the function input space");


    block parent_seed = root_seed;
    bool parent_ctrl_bit = party_idx;

    for (size_t i = 0; i < n; i++) {
        
        const block cw_seed = dpf_cws.cw_seed_vec[i];
        const bool cw_ctrl_bits[2] = {
            get_bit(dpf_cws.cw_left_ctrl_bit_vec, i),
            get_bit(dpf_cws.cw_right_ctrl_bit_vec, i)
        };

        PRNG prg(parent_seed);

        const block lvl_seeds[2] = {prg.get<block>(), prg.get<block>()};

        const bool lvl_ctrl_bits[2] = {prg.get<bool>(), prg.get<bool>()};

        const block corrected_seeds[2] = {
            lvl_seeds[left] ^ (parent_ctrl_bit ? cw_seed : block()),
            lvl_seeds[right] ^ (parent_ctrl_bit ? cw_seed : block())
        };

        const bool corrected_ctrl_bits[2] = {
            lvl_ctrl_bits[left] ^ (parent_ctrl_bit & cw_ctrl_bits[left]),
            lvl_ctrl_bits[right] ^ (parent_ctrl_bit & cw_ctrl_bits[right])
        };

        const bool x_i = get_bit(x, i);
        
        parent_seed = x_i == 0 ? corrected_seeds[left] : corrected_seeds[right];
        parent_ctrl_bit = x_i == 0 ? corrected_ctrl_bits[left] : corrected_ctrl_bits[right];

    }

    return parent_seed ^ (parent_ctrl_bit ? dpf_cws.out_cw : block());

}

pair<bool, osuCrypto::block> new_dpf_eval(size_t party_idx, size_t n, const block& root_seed, bool root_ctrl_bit, const dpf_cws& dpf_cws, const block& x) {
    assert(party_idx == 0 || party_idx == 1);
    assert(n > 0 && n <= MAX_N); // We can only support up to 128 bits for now, since we use a block to represent the input space.
    assert(dpf_cws.cw_seed_vec.size() == n); // The number of correction words must be equal to the bit length of the input space.
    assert(block_in_domain(x, n) && "The eval point x must be a member of the function input space");


    block parent_seed = root_seed;
    bool parent_ctrl_bit = root_ctrl_bit;

    for (size_t i = 0; i < n; i++) {
        
        const block cw_seed = dpf_cws.cw_seed_vec[i];
        const bool cw_ctrl_bits[2] = {
            get_bit(dpf_cws.cw_left_ctrl_bit_vec, i),
            get_bit(dpf_cws.cw_right_ctrl_bit_vec, i)
        };

        PRNG prg(parent_seed);

        const block lvl_seeds[2] = {prg.get<block>(), prg.get<block>()};

        const bool lvl_ctrl_bits[2] = {prg.get<bool>(), prg.get<bool>()};

        const block corrected_seeds[2] = {
            lvl_seeds[left] ^ (parent_ctrl_bit ? cw_seed : block()),
            lvl_seeds[right] ^ (parent_ctrl_bit ? cw_seed : block())
        };

        const bool corrected_ctrl_bits[2] = {
            lvl_ctrl_bits[left] ^ (parent_ctrl_bit & cw_ctrl_bits[left]),
            lvl_ctrl_bits[right] ^ (parent_ctrl_bit & cw_ctrl_bits[right])
        };

        const bool x_i = get_bit(x, i);
        
        parent_seed = x_i == 0 ? corrected_seeds[left] : corrected_seeds[right];
        parent_ctrl_bit = x_i == 0 ? corrected_ctrl_bits[left] : corrected_ctrl_bits[right];

    }

    return {parent_ctrl_bit, parent_seed ^ (parent_ctrl_bit ? dpf_cws.out_cw : block())};

}

block dpf_eval(const dpf_key& key, block x) {
    
    assert(key.party_idx == 0 || key.party_idx == 1);
    assert(key.n > 0 && key.n <= MAX_N); // We can only support up to 128 bits for now, since we use a block to represent the input space.
    assert(key.cws->cw_seed_vec.size() == key.n); // The number of correction words must be equal to the bit length of the input space.
    assert(block_in_domain(x, key.n) && "The eval point x must be a member of the function input space");

    return new_dpf_eval(key.party_idx, key.n, key.root_seed, key.root_ctrl_bit, *(key.cws), x).second;

}

void hw_fss_gen(PRNG& priv_dealer_prg, size_t n, const block& alpha, const block& beta, std::array<ddf_key,2>& key_pair) {
    assert(n > 0);
    assert((n & (n - 1)) == 0 && "n must be a power of two");
    assert(n <= MAX_N); // We can only support up to 128 bits for now, since we use a block to represent the input space.
    assert(block_in_domain(alpha, n) && "Alpha must be contained in the input space defined by n.");

    BitVector alpha_bv;
    alpha_bv.reset(); // Initialize the bit vector to all zeros.
    alpha_bv.assign(alpha);
    alpha_bv.resize(n); // We only care about the n least significant bits of alpha, since the input space is defined to be of bit length n.

    const size_t h = log2_ceil(n);
    const size_t tree_node_count = 2*n - 1;

    key_pair[0].party_idx = 0;
    key_pair[1].party_idx = 1;
    key_pair[0].n = n;
    key_pair[1].n = n;

    key_pair[0].root_seed0 = priv_dealer_prg.get<block>();
    key_pair[1].root_seed0 = priv_dealer_prg.get<block>();
    key_pair[0].root_seed1 = priv_dealer_prg.get<block>();
    key_pair[1].root_seed1 = priv_dealer_prg.get<block>();
    key_pair[0].root_seed2 = priv_dealer_prg.get<block>();
    key_pair[1].root_seed2 = priv_dealer_prg.get<block>();

    dpf_cws* cws = new dpf_cws[tree_node_count+1]; // The extra one is for the DPF used for the where x = alpha.
    key_pair[0].cws = cws;
    key_pair[1].cws = cws;

    block dummy_beta_share0, dummy_beta_share1;
    bool dummy_ctrl_bit0, dummy_ctrl_bit1;
    new_dpf_gen_cws(priv_dealer_prg, n, key_pair[0].root_seed0, 0, key_pair[1].root_seed0, 1, alpha, beta, cws[tree_node_count], dummy_beta_share0, dummy_ctrl_bit0, dummy_beta_share1, dummy_ctrl_bit1);

    vector<BitVector> alpha_slices_heap(tree_node_count); // POSSIBLE OPTIMIZATION POINT: Make sure this vector is optimally aligned.
    AlignedUnVector<block> r_heap(tree_node_count);
    AlignedUnVector<block> p0_seed_heap(tree_node_count);
    AlignedUnVector<bool> p0_ctrl_bit_heap(tree_node_count);
    AlignedUnVector<block> p1_seed_heap(tree_node_count);
    AlignedUnVector<bool> p1_ctrl_bit_heap(tree_node_count);

    halve_bitvector(alpha_bv, alpha_slices_heap[1], alpha_slices_heap[2]);

    //std::cout << alpha_bv.size() << std::endl;
    //std::cout << "alpha slices heap[1]: " << alpha_slices_heap[1].size() << std::endl;
    //std::cout << "alpha slices heap[2]: " << alpha_slices_heap[2].size() << std::endl;

    p0_seed_heap[1] = key_pair[0].root_seed1;
    p0_ctrl_bit_heap[1] = 0;
    p1_seed_heap[1] = key_pair[1].root_seed1;
    p1_ctrl_bit_heap[1] = 1;
    r_heap[1] = priv_dealer_prg.get<block>();
    
    p0_seed_heap[2] = key_pair[0].root_seed2;
    p0_ctrl_bit_heap[2] = 0;
    p1_seed_heap[2] = key_pair[1].root_seed2;
    p1_ctrl_bit_heap[2] = 1;
    r_heap[2] = priv_dealer_prg.get<block>();

    for (size_t i = 1; i < n-1; i++) {

        //std::cout << "Generating cws for node " << i << " / " << tree_node_count << std::endl;

        block p0_beta_share, p1_beta_share;
        bool p0_beta_ctrl_bit, p1_beta_ctrl_bit;

        //std::cout << alpha_slices_heap[i].size() << " : " << alpha_slices_heap[i].blocks()[0] << std::endl;

        new_dpf_gen_cws(priv_dealer_prg, alpha_slices_heap[i].size(), p0_seed_heap[i], p0_ctrl_bit_heap[i], p1_seed_heap[i], p1_ctrl_bit_heap[i], alpha_slices_heap[i].blocks()[0], beta, cws[i], p0_beta_share, p0_beta_ctrl_bit, p1_beta_share, p1_beta_ctrl_bit);

        //old_dpf_gen_cws(priv_dealer_prg, alpha_slices_heap[i].size(), p0_seed_heap[i], p1_seed_heap[i], alpha_slices_heap[i].blocks()[0], r_heap[i], cws[i], p0_beta_share, p1_beta_share);
        
        p0_ctrl_bit_heap[2*i+1] = p0_beta_ctrl_bit;
        p1_ctrl_bit_heap[2*i+1] = p1_beta_ctrl_bit;
        p0_ctrl_bit_heap[2*i+2] = p0_beta_ctrl_bit;
        p1_ctrl_bit_heap[2*i+2] = p1_beta_ctrl_bit;

        PRNG p0_prg(p0_beta_share);
        PRNG p1_prg(p1_beta_share);

        p0_seed_heap[2*i+1] = p0_prg.get<block>();
        p1_seed_heap[2*i+1] = p1_prg.get<block>();
        p0_seed_heap[2*i+2] = p0_prg.get<block>();
        p1_seed_heap[2*i+2] = p1_prg.get<block>();

        r_heap[2*i+1] = priv_dealer_prg.get<block>();
        r_heap[2*i+2] = priv_dealer_prg.get<block>();

        const size_t j = i + (((i-1)%2==0) ? 1 : -1);

        halve_bitvector(alpha_slices_heap[j], alpha_slices_heap[2*i+1], alpha_slices_heap[2*i+2]);
    }

    //std::cout << "Finished generating seeds and alpha slices for all nodes in the tree." << std::endl;

    for (size_t i = n-1; i < tree_node_count; i++) {
       //std::cout << "Generating cws for node " << i << " / " << tree_node_count << std::endl;

        block p0_beta_share, p1_beta_share;
        bool p0_beta_ctrl_bit, p1_beta_ctrl_bit;
        
        const size_t j = i + (((i-1)%2==0) ? 1 : -1);

        alpha_slices_heap[i].append(alpha_slices_heap[j], 1, 0);

        assert(alpha_slices_heap[i].size() == 2 && "The leaf DPFs should have a domain of bit-length 2.");

        alpha_slices_heap[i][1] = !alpha_slices_heap[i][1];

        //std::cout << alpha_slices_heap[i].size() << " : " << alpha_slices_heap[i].blocks()[0] << std::endl;

        new_dpf_gen_cws(priv_dealer_prg, alpha_slices_heap[i].size(), p0_seed_heap[i], p0_ctrl_bit_heap[i], p1_seed_heap[i], p1_ctrl_bit_heap[i], alpha_slices_heap[i].blocks()[0], beta, cws[i], p0_beta_share, p0_beta_ctrl_bit, p1_beta_share, p1_beta_ctrl_bit);
    }

}

size_t dpf_key_size(const dpf_key& key) {
    size_t size = 0;
    
    size += sizeof(key.root_seed);
        
    size += key.cws->cw_seed_vec.size() * sizeof(block);

    size += sizeof(block); // For the out_cw

    size += 2 * ((double) key.n / 8.0); // For the control bit correction, we can store them in a bit vector, so we only need n bits, which is n/8 bytes.
    
    return size;
}

size_t ddf_key_size(const ddf_key& key) {
    size_t size = 0;
    
    size += 3 * sizeof(key.root_seed0); // For the three root seeds.
        
    const size_t num_dpfs = 2*key.n;

    for (size_t i = 0; i < num_dpfs; i++) {
        
        const dpf_cws& cws = key.cws[i];

        size += cws.cw_seed_vec.size() * sizeof(block); // For the cw seeds.
        size += sizeof(block); // For the out_cw
        size += 2 * ((double) cws.cw_seed_vec.size() / 8.0); // For the control bit correction, we can store them in a bit vector, so we only need n bits, which is n/8 bytes.

    }

    return size;
}

block hw_fss_eval(const ddf_key& key, block x) {
    assert(key.party_idx == 0 || key.party_idx == 1);
    assert(key.n > 0 && key.n <= MAX_N); // We can only support up to 128 bits for now, since we use a block to represent the input space.
    assert((key.n & (key.n - 1)) == 0 && "key.n must be a power of two");
    assert(block_in_domain(x, key.n) && "The eval point x must be a member of the function input space");

    BitVector x_bv;
    x_bv.reset(); // Initialize the bit vector to all zeros.
    x_bv.assign(x);
    x_bv.resize(key.n); // We only care about the n least significant bits of x, since the input space is defined to be of bit length n.

    const size_t h = log2_ceil(key.n);
    const size_t tree_node_count = 2*key.n - 1;

    // POINTS OF OPTIMIZATION: (i) We can avoid storing all the slices of x in memory at the same time, since we only need them one at a time as we traverse down the tree. We can thus lazily compute the slices of x as we need them during the tree traversal, instead of computing and storing them all at the beginning here at the start of the function.
    //                         (ii) We don't need to keep the seeds and slices for all nodes, just the ones for the current and next level of the tree.
    //                         (iii) Make sure the vectors of BitVectors is optimially aligned
    vector<BitVector> x_slices_heap(tree_node_count);
    AlignedUnVector<block> seed_heap(tree_node_count);
    AlignedUnVector<bool> ctrl_bit_heap(tree_node_count);

    seed_heap[1] = key.root_seed1;
    seed_heap[2] = key.root_seed2;
    ctrl_bit_heap[1] = key.party_idx;
    ctrl_bit_heap[2] = key.party_idx;

    halve_bitvector(x_bv, x_slices_heap[1], x_slices_heap[2]);

    const size_t n = key.n;

    for (size_t i = 1; i < n-1; i++) {

        const dpf_cws& cws = key.cws[i];

        pair<bool, osuCrypto::block> dpf_eval_res = new_dpf_eval(key.party_idx, x_slices_heap[i].size(), seed_heap[i], ctrl_bit_heap[i], cws, x_slices_heap[i].blocks()[0]);

        //std::cout << "Party " << key.party_idx << " evaluated at node " << i <<  " dpf_eval(" << key.party_idx << ", " << x_slices_heap[i].size() << ", " << seed_heap[i] << ", cws, " << x_slices_heap[i].blocks()[0] << ") = " << dpf_eval_res.second << std::endl;

        PRNG prg(dpf_eval_res.second);
        seed_heap[2*i+1] = prg.get<block>();
        seed_heap[2*i+2] = prg.get<block>();
        ctrl_bit_heap[2*i+1] = dpf_eval_res.first;
        ctrl_bit_heap[2*i+2] = dpf_eval_res.first;

        const size_t j = i + (((i-1)%2==0) ? 1 : -1);

        halve_bitvector(x_slices_heap[j], x_slices_heap[2*i+1], x_slices_heap[2*i+2]);
    }

     block hd_eval = block(0,0);

    for (size_t i = n-1; i < tree_node_count; i++) {

        const dpf_cws& cws = key.cws[i];

        assert(x_slices_heap[i].size() == 1 && "At the leaf nodes of the tree, the alpha slices should be of size 1, since they correspond to single bits of the input space." );
        
        const size_t j = i + (((i-1)%2==0) ? 1 : -1);

        x_slices_heap[i].append(x_slices_heap[j], 1, 0);

        //if (i == 14) {
        //    std::cout << "Reached leaf node " << i << " with x slice: " << x_slices_heap[i].blocks()[0] << std::endl;
        //}

        std::pair<bool,osuCrypto::block> dpf_eval_res = new_dpf_eval(key.party_idx, x_slices_heap[i].size(), seed_heap[i], ctrl_bit_heap[i], cws, x_slices_heap[i].blocks()[0]);

        //std::cout << "Party " << key.party_idx << " Eval at node " << i <<  " for " << x_slices_heap[i].blocks()[0] << " : " << dpf_eval_res.second << std::endl;

        hd_eval ^= dpf_eval_res.second;

    }

    pair<bool, osuCrypto::block> dpf_eval_res = new_dpf_eval(key.party_idx, key.n, key.root_seed0, key.party_idx, key.cws[tree_node_count], x);

    return hd_eval ^ dpf_eval_res.second;

}
