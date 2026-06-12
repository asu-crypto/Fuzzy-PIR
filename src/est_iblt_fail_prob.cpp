#include <iostream>
#include <cstdint>
#include <random>
#include <limits>
#include <chrono>
#include <utility>
#include <string.h>
#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include <atomic>

#ifndef MULT_FAC_DEF
#define MULT_FAC_DEF 2.5
#endif

using namespace osuCrypto;

using namespace std;
static constexpr size_t NUM_THREADS = 90;
static constexpr size_t NUM_EXPS = 1ULL << 35; // 2^35
//static constexpr size_t NUM_EXPS = 1073741824; // 2^30
//static constexpr size_t NUM_EXPS = 1048576; // 2^20
//static constexpr size_t NUM_EXPS = 16777216; // 2^24
//static constexpr size_t NUM_EXPS = 1 << 26; // 2^26

static constexpr double MULT_FAC = MULT_FAC_DEF;
static constexpr size_t NUM_KEYS = 1 << 6; // 2^6
static constexpr size_t MAX_QUEUE_LENGTH = 10*NUM_KEYS;
static constexpr size_t NUM_HASH_FUNCS = 7;
static_assert(NUM_HASH_FUNCS == 7, "NUM_HASH_FUNCS must be 7");

static constexpr size_t SUBTABLE_LENGTH = static_cast<size_t>(ceil((MULT_FAC * ((double) NUM_KEYS)) / ((double) NUM_HASH_FUNCS)));
static constexpr size_t TABLE_LENGTH = NUM_HASH_FUNCS * SUBTABLE_LENGTH;

inline void hash_item(AES& aes, size_t item, size_t* hash_out) {
    block in_blks[2];
    block out_blks[2];

    in_blks[0] = block(0, item);
    in_blks[1] = block(11400095595373522076ULL, item);

    aes.hashBlocks(in_blks, 2, out_blks);

    uint32_t* data0 = (uint32_t*) out_blks[0].data();
    uint32_t* data1 = (uint32_t*) out_blks[1].data();

    hash_out[0] = static_cast<size_t>(data0[0]);
    hash_out[1] = static_cast<size_t>(data0[1]);
    hash_out[2] = static_cast<size_t>(data0[2]);
    hash_out[3] = static_cast<size_t>(data0[3]);
    hash_out[4] = static_cast<size_t>(data1[0]);
    hash_out[5] = static_cast<size_t>(data1[1]);
    hash_out[6] = static_cast<size_t>(data1[2]);

}

inline void fill_table(uint64_t* sums, uint64_t* counters, AES& aes) {

    size_t hash_out[NUM_HASH_FUNCS];

    for (size_t i = 0; i < NUM_KEYS; i++) {
        
        hash_item(aes, i, hash_out);
        
        #pragma unroll
        for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
            size_t index = (hash_out[j] % SUBTABLE_LENGTH) + j * SUBTABLE_LENGTH;
            counters[index]++;
            sums[index] ^= i;
        }
    }

}

inline bool is_peelable(uint64_t* sums, uint64_t* counters, size_t* queue, AES& aes) {

    size_t num_peeled = 0;
    size_t queue_tail = 0;
    size_t queue_head = 0;

    size_t hash_out[NUM_HASH_FUNCS];

    for (size_t i = 0; i < TABLE_LENGTH; i++) {
        if (counters[i] == 1) {
            uint64_t val = sums[i];

            if (!(val >= 0 && val < NUM_KEYS)) {
                return false;
            }

            hash_item(aes, val, hash_out);
            num_peeled++;

            #pragma unroll
            for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
                size_t table_idx = (hash_out[j] % SUBTABLE_LENGTH) + j * SUBTABLE_LENGTH;

                sums[table_idx] ^= val;
                counters[table_idx]--;
                
                queue[queue_tail] = table_idx;

                queue_tail = (queue_tail + 1) % MAX_QUEUE_LENGTH;
                #ifdef DEBUG_MODE
                    if (queue_tail == queue_head) {
                        std::cout << "Queue overflow" << std::endl;
                    }
                #endif
            }
        }
    }

    while (queue_head != queue_tail) {
        size_t table_idx = queue[queue_head];
        queue_head = (queue_head + 1) % MAX_QUEUE_LENGTH;

        if (counters[table_idx] == 1) {
            num_peeled++;
            uint64_t val = sums[table_idx];

            if (!(val >= 0 && val < NUM_KEYS)) {
                return false;
            }

            hash_item(aes, val, hash_out);


            #pragma unroll
            for (size_t i = 0; i < NUM_HASH_FUNCS; i++) {
                size_t table_idx = (hash_out[i] % SUBTABLE_LENGTH) + i * SUBTABLE_LENGTH;

                sums[table_idx] ^= val;
                counters[table_idx]--;
                
                queue[queue_tail] = table_idx;
                queue_tail = (queue_tail + 1) % MAX_QUEUE_LENGTH;
                #ifdef DEBUG_MODE
                    if (queue_tail == queue_head) {
                        std::cout << "Queue overflow" << std::endl;
                    }
                #endif
            }
        }
    }

    return num_peeled == NUM_KEYS;

}

void run_experiments(size_t num_exps, std::atomic<uint64_t>& num_errors) {

    uint64_t* counters = new uint64_t[TABLE_LENGTH];
    uint64_t* sums = new uint64_t[TABLE_LENGTH];
    size_t* queue = new size_t[MAX_QUEUE_LENGTH];

    std::random_device rd;
    std::mt19937 gen(rd());

    uniform_int_distribution<uint64_t> hash_distrib;

    PRNG prng(block(hash_distrib(gen), hash_distrib(gen)));

    uint64_t local_num_errors = 0;

    AES aes;


    for (size_t i = 0; i < num_exps; i++) {
        block key = block(hash_distrib(gen), hash_distrib(gen));
        AES aes(key);

        memset(counters, 0, TABLE_LENGTH * sizeof(uint64_t));
        memset(sums, 0, TABLE_LENGTH * sizeof(uint64_t));

        fill_table(sums, counters, aes);

        if (!is_peelable(sums, counters, queue, aes)) {
            local_num_errors++;
        }

        //std::cout << rounds << std::endl;

    }

    num_errors += local_num_errors;

    delete[] counters;
    delete[] sums;
    delete[] queue;

}

int main(int argc, char* argv[]) {

    std::cout << "Number of threads: " << NUM_THREADS << std::endl;
    std::cout << "Number of experiments: " << NUM_EXPS << std::endl;
    std::cout << "Number of keys: " << NUM_KEYS << std::endl;
    std::cout << "Multiplication factor: " << MULT_FAC << std::endl;
    std::cout << "Table Length: " << TABLE_LENGTH << std::endl;

    const size_t NUM_EXPS_PER_THREAD = (size_t) ceil((double) NUM_EXPS / (double) NUM_THREADS);

    boost::asio::thread_pool pool(NUM_THREADS);
    
    std::atomic<uint64_t> num_errors(0);

    for (size_t i = 0; i < NUM_THREADS; i++) {
        boost::asio::post(pool, [&num_errors]() {
            run_experiments(NUM_EXPS_PER_THREAD, num_errors);
        });
    }
    pool.join();

    std::cout << "Number of errors: " << num_errors.load() << std::endl;
    std::cout << "Number of experiments: " << NUM_EXPS << std::endl;
    std::cout << "Failure rate: " << (double) num_errors.load() / (double) NUM_EXPS << std::endl;
    std::cout << "Failure rate (log2): " << log2((double) num_errors.load() / (double) NUM_EXPS) << std::endl;
   
    return 0;
}
