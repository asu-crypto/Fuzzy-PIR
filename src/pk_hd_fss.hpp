#pragma once

#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "./pal_hss.hpp"
#include <cstdint>
#include <vector>
#include <array>

namespace pk_hd_fss {

    struct key {
        size_t n;
        size_t inclusive_hd_threshold;
        uint8_t ss_mod;
        pal_hss::pk hss_pk;
        pal_hss::ek hss_ek;
        std::vector<pal_hss::input> enc_bv;
    };

    struct one_time_setup_opts {
        size_t blum_int_bitlen; // This is the bitlength of the Blum integer to generate during Paillier key generation. The resulting Paillier modulus N will be this many bits long.
        size_t miller_rabin_rounds_per_prime; // This is the number of Miller-Rabin rounds to perform when testing the primality of each prime during Paillier key generation.
        size_t stat_sec_param; // This is the statistical security parameter. It mainly determines the size of the integer shares.
        size_t eval_out_ss_prime_mod; // This is the prime modulus to use for the output of the eval function. It should be larger than n.
        size_t n;
        size_t inclusive_hd_threshold;
    };

    struct one_time_setup_sk {
        size_t n;
        size_t inclusive_hd_threshold;
        pal_hss::pk hss_pk;
        pal_hss::sk hss_sk;
    };

    void one_time_setup(const one_time_setup_opts& opts, 
                        osuCrypto::PRNG& prg,
                        one_time_setup_sk& secret_out);

    void key_gen(const one_time_setup_sk& setup_sk,
                 const osuCrypto::BitVector& bv, // bv's length must be greater than 2.
                 osuCrypto::PRNG& prg,
                 pk_hd_fss::key& k0,
                 pk_hd_fss::key& k1);

    size_t key_byte_size(const pk_hd_fss::key& k);

    void eval(const pk_hd_fss::key& k,
              const osuCrypto::BitVector& pub_bit_vector,
              uint32_t& hd_threshold_match_adss_out);

}