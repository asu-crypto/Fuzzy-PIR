#include <cstdint>
#include <array>
#include <vector>
#include "./pk_hd_fss.hpp"
#include "./pk_fpir.hpp"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Aligned.h"
#include <thread>
#include <gmpxx.h>
#include <algorithm>
#include <random>    
#include <set>
#include <unordered_set>

using osuCrypto::PRNG;
using std::array;
using std::vector;
using osuCrypto::BitVector;
using osuCrypto::block;
using osuCrypto::AlignedUnVector;
using std::unordered_set;
using std::set;

template<size_t num_ss_iblt_copies>
static void init_ss_tables(size_t threshold, 
                            double space_mult_fac,
                            size_t num_hash_funcs,
                            uint8_t ss_mod, 
                            size_t element_vec_len,
                            size_t num_runs,
                            PRNG& prg,
                            vector<array<u8_ss_iblt::table, num_ss_iblt_copies>>& ss0_iblt_copies_vec,
                            vector<array<u8_ss_iblt::table, num_ss_iblt_copies>>& ss1_iblt_copies_vec) {

    ss0_iblt_copies_vec.resize(num_runs);
    ss1_iblt_copies_vec.resize(num_runs);
    for (size_t i = 0; i < num_runs; i++) {
        for (size_t copy_idx = 0; copy_idx < num_ss_iblt_copies; copy_idx++) {
            block hash_funcs_seed = prg.get<block>();

            u8_ss_iblt::init_table(threshold, 
                                   space_mult_fac, 
                                   num_hash_funcs, 
                                   hash_funcs_seed, 
                                   ss_mod, 
                                   element_vec_len, 
                                   ss0_iblt_copies_vec[i][copy_idx]);
            u8_ss_iblt::init_table(threshold, 
                                   space_mult_fac, 
                                   num_hash_funcs, 
                                   hash_funcs_seed, 
                                   ss_mod, 
                                   element_vec_len, 
                                   ss1_iblt_copies_vec[i][copy_idx]);
        }
     }
}

static size_t db_entry_ss_mod_vec_len(size_t db_entry_bitlen, uint8_t ss_mod) {
    size_t ss_mod_log2_floor = static_cast<size_t>(std::floor(std::log2(ss_mod)));
    return static_cast<size_t>(std::ceil(static_cast<double>(db_entry_bitlen) / static_cast<double>(ss_mod_log2_floor)));
}


int main(int argc, char* argv[]) {
    
    const uint8_t ss_mod = 251;
    const size_t num_iblt_hash_funcs = 7;

    if (argc != 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <db_entry_bitlen> <resp_max_match_count> <iblt_space_mult_fac> <num_ss_iblt_copies>"
                  << std::endl;
        return 1;
    }

    size_t db_entry_bitlen = std::stoull(argv[1]);
    size_t resp_max_match_count = std::stoull(argv[2]);
    double iblt_space_mult_fac = std::stod(argv[3]);
    size_t num_ss_iblt_copies = std::stoull(argv[4]);

    if (num_ss_iblt_copies == 0) {
        std::cerr << "num_ss_iblt_copies must be > 0" << std::endl;
        return 1;
    }

    size_t db_entry_vec_len = db_entry_ss_mod_vec_len(db_entry_bitlen, ss_mod);

    auto prg = PRNG(osuCrypto::toBlock(10942234989902908197ULL, 4846269562746846116ULL));

    block hash_funcs_seed = prg.get<block>();

    u8_ss_iblt::table ss0_table;

    u8_ss_iblt::init_table(resp_max_match_count, 
                            iblt_space_mult_fac, 
                            num_iblt_hash_funcs, 
                            hash_funcs_seed, 
                            ss_mod, 
                            db_entry_vec_len, 
                            ss0_table);

    size_t ss0_iblt_byte_size = u8_ss_iblt::byte_size(ss0_table) * num_ss_iblt_copies;

    std::cout << "FPIR Single Server Response Size for ";
    std::cout << "db entry bitlen (n) = " << db_entry_bitlen << ", ";
    std::cout << "max response match count = " << resp_max_match_count << ", ";
    std::cout << "iblt space multiplication factor = " << iblt_space_mult_fac << ": ";
    std::cout << "num of iblt copies = " << num_ss_iblt_copies << ": ";
    std::cout << ss0_iblt_byte_size * num_ss_iblt_copies << " bytes (";
    std::cout << (ss0_iblt_byte_size * num_ss_iblt_copies / 1024.0) << " KB)" << std::endl;

}
