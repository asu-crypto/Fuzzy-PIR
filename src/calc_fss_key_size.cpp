#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include "./fss.hpp"
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

    if (fss_type != "dpf" && fss_type != "naive_sk_hd_fss" && fss_type != "sk_hd_fss") {
        std::cerr << "Error: fss_type must be either 'dpf', 'naive_sk_hd_fss', or 'sk_hd_fss'" << std::endl;
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
    }
    
    return 0;
}
