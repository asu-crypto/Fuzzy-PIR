#include <vector>
#include <cstdint>
#include <array>
#include "./fss.hpp"
#include "cryptoTools/Common/BitVector.h"
#include <iostream>
#include <map>
#include <chrono>
#include <random>
#include <fstream>

using osuCrypto::block;
using osuCrypto::PRNG;
using osuCrypto::BitVector;
using std::vector;
using std::array;

using namespace std;

static block random_block(PRNG& prg, size_t n) {
    BitVector bv(n);

    for (size_t i = 0; i < n; i++) {
        bv[i] = prg.get<bool>();
    }

    return bv.blocks()[0];
}


void domred_based_fss_evaluation_2() {

    auto global_prg = PRNG(osuCrypto::toBlock(5719839740904675739ULL));

    vector<int> u_set{2, 3, 4, 5, 6};
    vector<int> d_set{2};
    vector<int> delta_set{1, 2};
    vector<int> p_set{0, 1, 2}; 

    std::map<int, int> secret_centers;
    secret_centers[2] = 2;
    secret_centers[3] = 5;
    secret_centers[4] = 11;
    secret_centers[5] = 25;
    secret_centers[6] = 39;

    std::map<int, int> test_centers;
    test_centers[2] = 2;
    test_centers[3] = 6;
    test_centers[4] = 10;
    test_centers[5] = 22;
    test_centers[6] = 35;

    std::ofstream log_file("domred_results.log", std::ios_base::app);
    if (!log_file.is_open()) {
        std::cerr << "Error: Could not open log file.\n";
        return;
    }

    block res;
    int num_iters = 100;
    
    for(auto u : u_set){
        for(auto d : d_set){
            for(auto delta : delta_set){
                for(auto p : p_set){ 
                    int duration_keygen = 0;
                    int duration_eval = 0;
                    
                    for(int i = 0; i < num_iters; i++){
                        vector<int64_t> y(d, secret_centers[u]);
                        auto start = std::chrono::high_resolution_clock::now();
                        std::array<domainred_lpfss_key, 2> key_pair;
                        domainred_keygen(global_prg, u, d, p, delta, y, key_pair);
                        auto end_keygen = std::chrono::high_resolution_clock::now();

                        vector<int64_t> x(d, test_centers[u]);
                        block eval0 = domainred_eval(key_pair[0], x, delta, u, d, p);
                        auto end_eval = std::chrono::high_resolution_clock::now();

                        duration_keygen += std::chrono::duration_cast<std::chrono::microseconds>(end_keygen - start).count();
                        duration_eval += std::chrono::duration_cast<std::chrono::microseconds>(end_eval - end_keygen).count();

                        block eval1 = domainred_eval(key_pair[1], x, delta, u, d, p);

                        res = eval0 ^ eval1;

                        delete key_pair[0].filter_key.cws;
                    }

                    std::string result_str = "DOMRED: [u = " + std::to_string(u) + 
                                             ", d = " + std::to_string(d) + 
                                             ", delta = " + std::to_string(delta) + 
                                             ", p = " + std::to_string(p) + "]: " + 
                                             std::to_string(_mm_cvtsi128_si64(res.mData)) + 
                                             "; Keygen = " + std::to_string(duration_keygen/num_iters) + 
                                             " us; Eval = " + std::to_string(duration_eval/num_iters) + " us\n";

                    cout << result_str;
                    
                    log_file << result_str;
                }
            }
        }
    }
    
    log_file.close();

}

void enum_based_fss_evaluation() {

    auto global_prg = PRNG(osuCrypto::toBlock(5719839740904675739ULL));
    
    vector<int> u_set{2, 3, 4, 5, 6};
    vector<int> d_set{2, 3, 4};
    vector<int> delta_set{1}; // Replaces the hardcoded radius
    vector<int> p_set{0, 1, 2};    // Added p set to iterate through

    std::map<int, int> secret_centers;
    secret_centers[2] = 2;
    secret_centers[3] = 5;
    secret_centers[4] = 11;
    secret_centers[5] = 25;
    secret_centers[6] = 39;

    std::map<int, int> test_centers;
    test_centers[2] = 2;
    test_centers[3] = 6;
    test_centers[4] = 10;
    test_centers[5] = 22;
    test_centers[6] = 35;

    std::ofstream log_file("enum_results.log", std::ios_base::app);
    if (!log_file.is_open()) {
        std::cerr << "Error: Could not open log file.\n";
        return;
    }

    int num_iters = 100;

    for(auto u : u_set){
        for(auto d : d_set){
            for(auto delta : delta_set){
                for(auto p : p_set){
                    int duration_keygen = 0;
                    int duration_eval = 0;
                    block res;

                    for(int t = 0; t < num_iters; t++){
                        vector<int64_t> y_coords(d);               // secret point
                        vector<int64_t> x_coords(d);               // test point

                        for(int i = 0; i < d; i++){
                            y_coords[i] = secret_centers[u];
                            x_coords[i] = test_centers[u];
                        }

                        int64_t y = coords_to_block(y_coords, u, d);
                        block x(coords_to_block(x_coords, u, d));       

                        auto start = std::chrono::high_resolution_clock::now();
                        std::array<enum_based_lpfss_key, 2> key_pair;
                        enum_based_lpfss_keygen(global_prg, u, d, block(y), key_pair);
                        auto end_keygen = std::chrono::high_resolution_clock::now();
                        
                        // Using delta as the radius equivalent
                        block res0 = enum_based_lpfss_eval(key_pair[0], x, delta, u, d, p);
                        auto end_eval = std::chrono::high_resolution_clock::now();

                        block res1 = enum_based_lpfss_eval(key_pair[1], x, delta, u, d, p);

                        duration_keygen += std::chrono::duration_cast<std::chrono::microseconds>(end_keygen - start).count();
                        duration_eval += std::chrono::duration_cast<std::chrono::microseconds>(end_eval - end_keygen).count();

                        res = res0 ^ res1;

                        delete key_pair[0].key.cws;
                    }

                    std::string result_str = "ENUM: [u = " + std::to_string(u) + 
                                             ", d = " + std::to_string(d) + 
                                             ", delta = " + std::to_string(delta) + 
                                             ", p = " + std::to_string(p) + "]: " + 
                                             std::to_string(_mm_cvtsi128_si64(res.mData)) + 
                                             "; Keygen = " + std::to_string(duration_keygen/num_iters) + 
                                             " us; Eval = " + std::to_string(duration_eval/num_iters) + " us\n";

                    cout << result_str;
                    
                    log_file << result_str;
                }
            }
        }
    }
    
    log_file.close();
}


int main() {
    
    domred_based_fss_evaluation_2();
    enum_based_fss_evaluation();

    return 0;
}

