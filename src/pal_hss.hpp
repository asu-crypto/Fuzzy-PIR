#pragma once

#include <stdint.h>
#include <vector>
#include <array>
#include <gmpxx.h>
#include "./paillier.hpp"
#include "cryptoTools/Crypto/PRNG.h"

namespace pal_hss {

    struct pk {
        pal_pk pk;
        size_t value_base_bitlen;
        size_t d_slice_bitlen;
        size_t stat_sec_param;
        std::vector<mpz_class> D_slice_cts;
    };

    struct sk {
        pal_sk sk;
        std::vector<mpz_class> d_slices;
    };

    struct ek {
        size_t pidx;
        mpz_class d_intss;
        std::vector<mpz_class> d_slice_intss;
    };

    struct input {
        mpz_class x_ct;
        std::vector<mpz_class> xd_slices_cts;
    };

    struct mem {
        mpz_class x_intss;
        mpz_class xd_intss;
        std::vector<mpz_class> sliced_xd_intss;
    };

    struct setup_opts {
        size_t blum_int_bitlen; // This is the bitlength of the Blum integer to generate during Paillier key generation. The resulting Paillier modulus N will be this many bits long.
        size_t miller_rabin_rounds_per_prime; // This is the number of Miller-Rabin rounds to perform when testing the primality of each prime during Paillier key generation.
        size_t stat_sec_param; // This is the statistical security parameter. It mainly determines the size of the integer shares.
        size_t value_base_bitlen; 
    };

    void setup(const pal_hss::setup_opts& opts, 
               osuCrypto::PRNG& prg, 
               pal_hss::pk& pk_out, 
               std::array<pal_hss::ek, 2>& ek_out,
               pal_hss::sk& sk_out);

    // This function is the same as the above one, except it doesn't generate evaluation keys.
    void setup(const pal_hss::setup_opts& opts, 
               osuCrypto::PRNG& prg, 
               pal_hss::pk& pk_out, 
               pal_hss::sk& sk_out);

    void gen_eks(const pal_hss::sk& sk, 
                 const pal_hss::pk& pk, 
                 osuCrypto::PRNG& prg, 
                 std::array<pal_hss::ek, 2>& ek_out);

    void enc_input(const mpz_class& input, 
                   const pal_hss::pk& pk, 
                   const pal_hss::sk& sk, 
                   osuCrypto::PRNG& prg, 
                   pal_hss::input& input_out);

    void enc_bin_input(bool input, 
                       const pal_hss::pk& pk, 
                       const pal_hss::sk& sk, 
                       osuCrypto::PRNG& prg, 
                       pal_hss::input& input_out);
    
    // Assuming the encoded input is binary, the resulting input encode the negation of the original input.
    // No promises are made about the output if the input is not binary.
    void hom_neg_input(const pal_hss::input& input, const pal_hss::pk& pk, pal_hss::input& neg_input_out);
    
    void hom_add_inputs(const pal_hss::input& in0, const pal_hss::input& in1, const pal_hss::pk& pk, pal_hss::input& sum_input_out);

    // This function is an in-place version of the above function that stores the result in in0_and_out to save memory. in1 is not modified.
    void hom_add_inputs(pal_hss::input& in0_and_out, const pal_hss::input& in1, const pal_hss::pk& pk);
    
    void input_to_mem(const pal_hss::input& input, const pal_hss::pk& pk, const pal_hss::ek& ek, pal_hss::mem& mem_out);

    void hom_mult_mem_input(const pal_hss::mem& mem_in, const pal_hss::input& input, const pal_hss::pk& pk, const pal_hss::ek& ek, pal_hss::mem& mem_out);        

    // This function multiplies an input and a memory share, and stores the result in the memory share to save memory. The input is not modified.
    void hom_mult_mem_input(pal_hss::mem& mem_in_out, const pal_hss::input& input, const pal_hss::pk& pk, const pal_hss::ek& ek);

    void reconst_mem(const pal_hss::mem& mem0, const pal_hss::mem& mem1, const pal_hss::pk& pk, mpz_class& x_out, mpz_class& xd_out, std::vector<mpz_class>& xd_slices_out);

}