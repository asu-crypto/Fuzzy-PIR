#pragma once

#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/BitVector.h"
#include <vector>
#include <array>
#include <cstdint>
#include <memory>
#include <utility>
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Crypto/PRNG.h"

struct dpf_cws {

    osuCrypto::AlignedUnVector<osuCrypto::block> cw_seed_vec;
    osuCrypto::block out_cw;
    osuCrypto::block cw_left_ctrl_bit_vec;
    osuCrypto::block cw_right_ctrl_bit_vec;

};

struct dpf_key {

    size_t party_idx;
    size_t n;
    
    osuCrypto::block root_seed;
    bool root_ctrl_bit;

    dpf_cws* cws;

};

struct ddf_key {

    size_t party_idx;
    size_t n;

    osuCrypto::block root_seed0;
    osuCrypto::block root_seed1;
    osuCrypto::block root_seed2;

    dpf_cws* cws;

};

void old_dpf_gen_cws(osuCrypto::PRNG& prg, size_t n, const osuCrypto::block& p0_root_seed, const osuCrypto::block& p1_root_seed, const osuCrypto::block& alpha, const osuCrypto::block& beta, dpf_cws& cws, osuCrypto::block& p0_beta_shares, osuCrypto::block& p1_beta_shares);
void new_dpf_gen_cws(osuCrypto::PRNG& prg, 
                 size_t n, 
                 const osuCrypto::block& p0_root_seed,
                 bool p0_root_ctrl_bit, 
                 const osuCrypto::block& p1_root_seed,
                 bool p1_root_ctrl_bit, 
                 const osuCrypto::block& alpha, 
                 const osuCrypto::block& beta, 
                 dpf_cws& cws, 
                 osuCrypto::block& p0_beta_shares, 
                 bool& p0_final_ctrl_bit,
                 osuCrypto::block& p1_beta_shares,
                 bool& p1_final_ctrl_bit);

void dpf_gen(osuCrypto::PRNG& prg, size_t n, const osuCrypto::block& alpha, const osuCrypto::block& beta, std::array<dpf_key,2>& key_pair);
osuCrypto::block dpf_eval(const dpf_key& key, osuCrypto::block x);
osuCrypto::block dpf_eval(size_t party_idx, size_t n, const osuCrypto::block& root_seed, const dpf_cws& dpf_cws, const osuCrypto::block& x);
std::pair<bool,osuCrypto::block> new_dpf_eval(size_t party_idx, size_t n, const osuCrypto::block& root_seed, bool root_ctrl_bit, const dpf_cws& dpf_cws, const osuCrypto::block& x);

void hw_fss_gen(osuCrypto::PRNG& prg, size_t n, const osuCrypto::block& alpha, const osuCrypto::block& beta, std::array<ddf_key,2>& key_pair);
osuCrypto::block hw_fss_eval(const ddf_key& key, osuCrypto::block x);