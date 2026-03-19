#pragma once

#include <stdint.h>
#include <vector>
#include <gmpxx.h>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "./pal_hss.hpp"

void hd_intss(const osuCrypto::BitVector& pub_bit_vector, 
              const std::vector<pal_hss::input>& enc_bv,
              const pal_hss::pk& pk, 
              const pal_hss::ek& ek,
              mpz_class& hd_intss_out);

void hd_threshold_match(const osuCrypto::BitVector& pub_bit_vector, 
                        const std::vector<pal_hss::input>& enc_bv,
                        const pal_hss::pk& pk, 
                        const pal_hss::ek& ek,
                        size_t inclusive_hd_threshold,
                        uint32_t& prime_mod,
                        uint32_t& hd_threshold_match_adss_out,
                        bool& hd_threshold_match_bss_out);
