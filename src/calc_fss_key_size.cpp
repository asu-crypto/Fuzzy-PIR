#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include "./fss.hpp"
#include "./pk_hd_fss.hpp"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/block.h"

using osuCrypto::block;
using osuCrypto::PRNG;
using osuCrypto::BitVector;
using std::vector;
using std::array;
using osuCrypto::AllOneBlock;

static constexpr size_t MAX_N = 128;

static size_t n_choose_k(size_t n, size_t k) {
    if (k > n) {
        return 0;
    }

    k = std::min(k, n - k);
    size_t result = 1;
    for (size_t i = 1; i <= k; i++) {
        result = (result * (n - k + i)) / i;
    }

    return result;
}

static size_t dpf_key_byte_size(size_t n) {
    assert(n > 0 && n <= MAX_N);

    PRNG prg(osuCrypto::toBlock(0, 0)); // The actual seed doesn't matter for computing the key size.
    array<dpf_key, 2> key_pair;
    block alpha(1,1), beta(1,1); // The actual alpha and beta values don't matter for computing the key size.
    dpf_gen(prg, n, alpha, beta, key_pair);

    return dpf_key_size(key_pair[0]);
    
}

static size_t naive_sk_hd_fss_key_byte_size(size_t n, size_t delta) {
    assert(n > 0 && n <= MAX_N);
    assert(delta > 0 && delta < n);

    size_t num_dpfs = 0;
    for (size_t i = 0; i <= delta; i++) {
        num_dpfs += n_choose_k(n, i);
    }

    return num_dpfs * dpf_key_byte_size(n);

}

static size_t sk_hd_fss_key_byte_size(size_t n) {
    assert(n > 0 && n <= MAX_N);

    PRNG prg(osuCrypto::toBlock(0, 0)); // The actual seed doesn't matter for computing the key size.
    array<ddf_key, 2> key_pair;
    block alpha(1,1), beta(1,1); // The actual alpha and beta values don't matter for computing the key size.

    hw_fss_gen(prg, n, alpha, beta, key_pair); // The actual parameters don't matter for computing the key size.
    return ddf_key_size(key_pair[0]);
}

static size_t pk_hd_fss_key_byte_size(size_t n, size_t inclusive_hd_threshold) {
    assert(n > 0 && n <= MAX_N);

    PRNG prg(osuCrypto::toBlock(0, 0)); // The actual seed doesn't matter for computing the key size.

    pk_hd_fss::one_time_setup_opts one_time_setup_opts;
    one_time_setup_opts.blum_int_bitlen = 2048;
    one_time_setup_opts.miller_rabin_rounds_per_prime = 25;
    one_time_setup_opts.stat_sec_param = 40;
    one_time_setup_opts.eval_out_ss_prime_mod = 251;
    one_time_setup_opts.n = n;
    one_time_setup_opts.inclusive_hd_threshold = inclusive_hd_threshold;

    pk_hd_fss::one_time_setup_sk one_time_setup_sk;
    pk_hd_fss::one_time_setup(one_time_setup_opts, prg, one_time_setup_sk);

    BitVector secret_bv(n);
    secret_bv.randomize(prg); // Only the sive of the bit vector matters for computing the key size, so we can just randomize it.

    pk_hd_fss::key k0, k1;
    pk_hd_fss::key_gen(one_time_setup_sk, secret_bv, prg, k0, k1); 

    return pk_hd_fss::key_byte_size(k0);
    
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <fss_type> <n> <delta>" << std::endl;
        return 1;
    }

    std::string fss_type = argv[1];
    size_t n = std::stoull(argv[2]);
    size_t delta = std::stoull(argv[3]);

    if (n == 0 || n > MAX_N) {
        std::cerr << "Error: n must be in the range [1, " << MAX_N << "]" << std::endl;
        return 1;
    }

    if (delta == 0 || delta >= n) {
        std::cerr << "Error: delta must be in the range [1, n-1]" << std::endl;
        return 1;
    }

    if (fss_type != "dpf" && fss_type != "naive_sk_hd_fss" && fss_type != "sk_hd_fss" && fss_type != "pk_hd_fss") {
        std::cerr << "Error: fss_type must be either 'dpf', 'naive_sk_hd_fss', 'sk_hd_fss', or 'pk_hd_fss'" << std::endl;
        return 1;
    }

    size_t key_size_bytes = 0;

    if (fss_type == "dpf") {
        key_size_bytes = dpf_key_byte_size(n);

        std::cout << "DPF key size for n = " << n << ": " << key_size_bytes << " bytes (" << (key_size_bytes / 1024.0) << " KB)" << std::endl;

    } else if (fss_type == "naive_sk_hd_fss") {
        key_size_bytes = naive_sk_hd_fss_key_byte_size(n, delta);

        std::cout << "Naive SK HD-FSS key size for n = " << n << " and delta = " << delta << ": " << key_size_bytes << " bytes (" << (key_size_bytes / 1024.0) << " KB)" << std::endl;

    } else if (fss_type == "sk_hd_fss") {
        key_size_bytes = sk_hd_fss_key_byte_size(n);

        std::cout << "SK HD-FSS key size for n = " << n << " and delta = 1: " << key_size_bytes << " bytes (" << (key_size_bytes / 1024.0) << " KB)" << std::endl;
    } else if (fss_type == "pk_hd_fss") {
        key_size_bytes = pk_hd_fss_key_byte_size(n, delta);

        std::cout << "PK HD-FSS key size for n = " << n << " and inclusive HD threshold = " << delta << ": " << key_size_bytes << " bytes (" << (key_size_bytes / 1024.0) << " KB)" << std::endl;
    }
    
    return 0;
}
