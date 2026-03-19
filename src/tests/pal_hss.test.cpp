#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <array>
#include <vector>
#include "../rand.hpp"
#include "../paillier.hpp"
#include "../pal_hss.hpp"
#include "../ss.hpp"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <gmpxx.h>

using osuCrypto::PRNG;
using std::array;
using std::vector;

void reconstuct_d_from_slices(const std::vector<mpz_class>& d_slices, size_t d_slice_bitlen, mpz_class& d_out) {
    d_out = 0;
    for (size_t i = 0; i < d_slices.size(); i++) {
        mpz_class shifted_d_slice;
        mpz_mul_2exp(shifted_d_slice.get_mpz_t(), d_slices[i].get_mpz_t(), i * d_slice_bitlen);
        d_out += shifted_d_slice;
    }
}

TEST_CASE("pal_hss::setup generates consistent keys and ciphertexts", "[pal_hss][setup]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pal_hss::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 25;
    opts.stat_sec_param = 40;
    opts.value_base_bitlen = 7; // log2(128)

    pal_hss::pk hss_pk;
    std::array<pal_hss::ek, 2> hss_ek;
    pal_hss::sk hss_sk;

    pal_hss::setup(opts, prg, hss_pk, hss_ek, hss_sk);

    REQUIRE(hss_pk.value_base_bitlen == opts.value_base_bitlen);

    REQUIRE(hss_pk.d_slice_bitlen > 0);
    REQUIRE(hss_pk.stat_sec_param == opts.stat_sec_param);
    REQUIRE(hss_pk.value_base_bitlen == opts.value_base_bitlen);
    REQUIRE(hss_pk.D_slice_cts.size() > 0);
    REQUIRE(hss_pk.D_slice_cts.size() == hss_sk.d_slices.size());
    REQUIRE(hss_pk.D_slice_cts.size() == hss_ek[0].d_slice_intss.size());
    REQUIRE(hss_pk.D_slice_cts.size() == hss_ek[1].d_slice_intss.size());
    REQUIRE(hss_ek[0].d_slice_intss.size() == hss_ek[1].d_slice_intss.size());
    REQUIRE(hss_ek[0].d_slice_intss.size() > 0);
    REQUIRE(hss_ek[0].pidx == 0);
    REQUIRE(hss_ek[1].pidx == 1);

    mpz_class int_ss_d_reconst;
    intss_reconst(hss_ek[0].d_intss, hss_ek[1].d_intss, int_ss_d_reconst);
    REQUIRE(int_ss_d_reconst == hss_sk.sk.d);

    mpz_class sum_d_slices;
    reconstuct_d_from_slices(hss_sk.d_slices, hss_pk.d_slice_bitlen, sum_d_slices);

    REQUIRE(sum_d_slices == hss_sk.sk.d);

    vector<mpz_class> reconstructed_d_slices_from_eks(hss_ek[0].d_slice_intss.size());
    vector<mpz_class> reconstructed_d_slices_from_ek1(hss_ek[1].d_slice_intss.size());
    batch_intss_reconst(hss_ek[0].d_slice_intss, hss_ek[1].d_slice_intss, reconstructed_d_slices_from_eks);

    reconstuct_d_from_slices(hss_sk.d_slices, hss_pk.d_slice_bitlen, sum_d_slices);
    REQUIRE(sum_d_slices == hss_sk.sk.d);

    vector<mpz_class> decrypted_d_slices(hss_pk.D_slice_cts.size());
    for (size_t i = 0; i < hss_pk.D_slice_cts.size(); i++) {
        pal_decrypt(hss_pk.D_slice_cts[i], hss_sk.sk, hss_pk.pk, decrypted_d_slices[i]);
    }

    reconstuct_d_from_slices(decrypted_d_slices, hss_pk.d_slice_bitlen, sum_d_slices);
    REQUIRE(sum_d_slices == hss_sk.sk.d);

}

TEST_CASE("pal_hss::setup with no evaluation key generation produces consistent keys and ciphertexts", "[pal_hss][setup_no_eks]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pal_hss::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 25;
    opts.stat_sec_param = 40;
    opts.value_base_bitlen = 7; // log2(128)

    pal_hss::pk hss_pk;
    pal_hss::sk hss_sk;

    pal_hss::setup(opts, prg, hss_pk, hss_sk);

    REQUIRE(hss_pk.value_base_bitlen == opts.value_base_bitlen);

    REQUIRE(hss_pk.d_slice_bitlen > 0);
    REQUIRE(hss_pk.stat_sec_param == opts.stat_sec_param);
    REQUIRE(hss_pk.value_base_bitlen == opts.value_base_bitlen);
    REQUIRE(hss_pk.D_slice_cts.size() > 0);
    REQUIRE(hss_pk.D_slice_cts.size() == hss_sk.d_slices.size());
    REQUIRE(hss_pk.d_slice_bitlen > 0);

    mpz_class sum_d_slices;
    reconstuct_d_from_slices(hss_sk.d_slices, hss_pk.d_slice_bitlen, sum_d_slices);
    REQUIRE(sum_d_slices == hss_sk.sk.d);

    vector<mpz_class> decrypted_d_slices(hss_pk.D_slice_cts.size());
    for (size_t i = 0; i < hss_pk.D_slice_cts.size(); i++) {
        pal_decrypt(hss_pk.D_slice_cts[i], hss_sk.sk, hss_pk.pk, decrypted_d_slices[i]);
    }

    reconstuct_d_from_slices(decrypted_d_slices, hss_pk.d_slice_bitlen, sum_d_slices);
    REQUIRE(sum_d_slices == hss_sk.sk.d);

}

TEST_CASE("pal_hss::gen_eks produces evaluation keys that reconstruct to the secret key and secret key slices", "[pal_hss][gen_eks]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pal_hss::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 25;
    opts.stat_sec_param = 40;
    opts.value_base_bitlen = 7; // log2(128)

    pal_hss::pk hss_pk;
    std::array<pal_hss::ek, 2> hss_ek;
    pal_hss::sk hss_sk;

    pal_hss::setup(opts, prg, hss_pk, hss_ek, hss_sk);

    std::array<pal_hss::ek, 2> gen_eks_out;
    pal_hss::gen_eks(hss_sk, hss_pk, prg, gen_eks_out);

    REQUIRE(gen_eks_out[0].d_slice_intss.size() == hss_sk.d_slices.size());
    REQUIRE(gen_eks_out[1].d_slice_intss.size() == hss_sk.d_slices.size());
    REQUIRE(gen_eks_out[0].pidx == 0);
    REQUIRE(gen_eks_out[1].pidx == 1);

    mpz_class int_ss_d_reconst;
    intss_reconst(gen_eks_out[0].d_intss, gen_eks_out[1].d_intss, int_ss_d_reconst);
    REQUIRE(int_ss_d_reconst == hss_sk.sk.d);

    vector<mpz_class> reconstructed_d_slices_from_gen_eks(hss_sk.d_slices.size());
    batch_intss_reconst(gen_eks_out[0].d_slice_intss, gen_eks_out[1].d_slice_intss, reconstructed_d_slices_from_gen_eks);

    for (size_t i = 0; i < hss_sk.d_slices.size(); i++) {
        REQUIRE(reconstructed_d_slices_from_gen_eks[i] == hss_sk.d_slices[i]);
    }
}

TEST_CASE("pal_hss::enc_input produces ciphertexts that decrypt to input * d_slices[i] and input itself", "[pal_hss][enc_input]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pal_hss::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 25;
    opts.stat_sec_param = 40;
    opts.value_base_bitlen = 7; // log2(128)

    pal_hss::pk hss_pk;
    std::array<pal_hss::ek, 2> hss_ek;
    pal_hss::sk hss_sk;

    pal_hss::setup(opts, prg, hss_pk, hss_ek, hss_sk);

    mpz_class input = 42;

    pal_hss::input enc_input_out;
    pal_hss::enc_input(input, hss_pk, hss_sk, prg, enc_input_out);

    REQUIRE(enc_input_out.xd_slices_cts.size() == hss_sk.d_slices.size());

    for (size_t i = 0; i < enc_input_out.xd_slices_cts.size(); i++) {
        mpz_class decrypted_input_times_d_slice;
        pal_decrypt(enc_input_out.xd_slices_cts[i], hss_sk.sk, hss_pk.pk, decrypted_input_times_d_slice);

        mpz_class expected_input_times_d_slice = input * hss_sk.d_slices[i];

        REQUIRE(decrypted_input_times_d_slice == expected_input_times_d_slice);
    }

    mpz_class decrypted_input;
    pal_decrypt(enc_input_out.x_ct, hss_sk.sk, hss_pk.pk, decrypted_input);
    REQUIRE(decrypted_input == input);
}

TEST_CASE("pal_hss::enc_bin_input produces ciphertexts that decrypt to input * d_slices[i] where input is binary", "[pal_hss][enc_bin_input]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pal_hss::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 25;
    opts.stat_sec_param = 40;
    opts.value_base_bitlen = 7; // log2(128)

    pal_hss::pk hss_pk;
    std::array<pal_hss::ek, 2> hss_ek;
    pal_hss::sk hss_sk;

    pal_hss::setup(opts, prg, hss_pk, hss_ek, hss_sk);

    bool t_input = true;
    bool f_input = false;

    pal_hss::input enc_t_input_out, enc_f_input_out;
    pal_hss::enc_bin_input(t_input, hss_pk, hss_sk, prg, enc_t_input_out);
    pal_hss::enc_bin_input(f_input, hss_pk, hss_sk, prg, enc_f_input_out);

    REQUIRE(enc_t_input_out.xd_slices_cts.size() == hss_sk.d_slices.size());
    REQUIRE(enc_f_input_out.xd_slices_cts.size() == hss_sk.d_slices.size());

    for (size_t i = 0; i < enc_t_input_out.xd_slices_cts.size(); i++) {
        mpz_class decrypted_input_times_d_slice;
        pal_decrypt(enc_t_input_out.xd_slices_cts[i], hss_sk.sk, hss_pk.pk, decrypted_input_times_d_slice);

        mpz_class expected_input_times_d_slice = (t_input ? 1 : 0) * hss_sk.d_slices[i];

        REQUIRE(decrypted_input_times_d_slice == expected_input_times_d_slice);
    }

    for (size_t i = 0; i < enc_f_input_out.xd_slices_cts.size(); i++) {
        mpz_class decrypted_input_times_d_slice;
        pal_decrypt(enc_f_input_out.xd_slices_cts[i], hss_sk.sk, hss_pk.pk, decrypted_input_times_d_slice);

        mpz_class expected_input_times_d_slice = (f_input ? 1 : 0) * hss_sk.d_slices[i];

        REQUIRE(decrypted_input_times_d_slice == expected_input_times_d_slice);
    }

    mpz_class decrypted_t_input;
    pal_decrypt(enc_t_input_out.x_ct, hss_sk.sk, hss_pk.pk, decrypted_t_input);
    REQUIRE(decrypted_t_input == (t_input ? 1 : 0));

    mpz_class decrypted_f_input;
    pal_decrypt(enc_f_input_out.x_ct, hss_sk.sk, hss_pk.pk, decrypted_f_input);
    REQUIRE(decrypted_f_input == (f_input ? 1 : 0));

}

TEST_CASE("pal_hss::hom_neg_input produces ciphertexts that decrypt to -input * d_slices[i] (assuming binary input)", "[pal_hss][hom_neg_input]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pal_hss::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 25;
    opts.stat_sec_param = 40;
    opts.value_base_bitlen = 7; // log2(128)

    pal_hss::pk hss_pk;
    std::array<pal_hss::ek, 2> hss_ek;
    pal_hss::sk hss_sk;

    pal_hss::setup(opts, prg, hss_pk, hss_ek, hss_sk);

    mpz_class in0 = 0;
    mpz_class in1 = 1;

    pal_hss::input enc_in0_out, enc_in1_out;
    pal_hss::enc_input(in0, hss_pk, hss_sk, prg, enc_in0_out);
    pal_hss::enc_input(in1, hss_pk, hss_sk, prg, enc_in1_out);

    pal_hss::input neg_enc_input0_out, neg_enc_input1_out;
    pal_hss::hom_neg_input(enc_in0_out, hss_pk, neg_enc_input0_out);
    pal_hss::hom_neg_input(enc_in1_out, hss_pk, neg_enc_input1_out);

    REQUIRE(neg_enc_input0_out.xd_slices_cts.size() == hss_sk.d_slices.size());
    REQUIRE(neg_enc_input1_out.xd_slices_cts.size() == hss_sk.d_slices.size());

    for (size_t i = 0; i < neg_enc_input0_out.xd_slices_cts.size(); i++) {
        mpz_class decrypted_neg_input_times_d_slice;
        pal_decrypt(neg_enc_input0_out.xd_slices_cts[i], hss_sk.sk, hss_pk.pk, decrypted_neg_input_times_d_slice);

        mpz_class expected_neg_input_times_d_slice = (1-in0) * hss_sk.d_slices[i];

        REQUIRE(decrypted_neg_input_times_d_slice == expected_neg_input_times_d_slice);
    }

    for (size_t i = 0; i < neg_enc_input1_out.xd_slices_cts.size(); i++) {
        mpz_class decrypted_neg_input_times_d_slice;
        pal_decrypt(neg_enc_input1_out.xd_slices_cts[i], hss_sk.sk, hss_pk.pk, decrypted_neg_input_times_d_slice);

        mpz_class expected_neg_input_times_d_slice = (1-in1) * hss_sk.d_slices[i];

        REQUIRE(decrypted_neg_input_times_d_slice == expected_neg_input_times_d_slice);
    }

    mpz_class decrypted_neg_input0;
    pal_decrypt(neg_enc_input0_out.x_ct, hss_sk.sk, hss_pk.pk, decrypted_neg_input0);
    REQUIRE(decrypted_neg_input0 == (1 - in0));

    mpz_class decrypted_neg_input1;
    pal_decrypt(neg_enc_input1_out.x_ct, hss_sk.sk, hss_pk.pk, decrypted_neg_input1);
    REQUIRE(decrypted_neg_input1 == (1 - in1));


}

TEST_CASE("pal_hss::hom_add_inputs produces ciphertexts that decrypt to the sum of the original inputs times d_slices[i]", "[pal_hss][hom_add_inputs]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pal_hss::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 25;
    opts.stat_sec_param = 40;
    opts.value_base_bitlen = 7; // log2(128)

    pal_hss::pk hss_pk;
    std::array<pal_hss::ek, 2> hss_ek;
    pal_hss::sk hss_sk;

    pal_hss::setup(opts, prg, hss_pk, hss_ek, hss_sk);

    mpz_class input0 = 42;
    mpz_class input1 = 17;

    pal_hss::input enc_input0, enc_input1;
    pal_hss::enc_input(input0, hss_pk, hss_sk, prg, enc_input0);
    pal_hss::enc_input(input1, hss_pk, hss_sk, prg, enc_input1);

    pal_hss::input sum_input;
    pal_hss::hom_add_inputs(enc_input0, enc_input1, hss_pk, sum_input);

    REQUIRE(sum_input.xd_slices_cts.size() == hss_sk.d_slices.size());

    for (size_t i = 0; i < sum_input.xd_slices_cts.size(); i++) {
        mpz_class decrypted_sum_times_d_slice;
        pal_decrypt(sum_input.xd_slices_cts[i], hss_sk.sk, hss_pk.pk, decrypted_sum_times_d_slice);

        mpz_class expected_sum_times_d_slice = (input0 + input1) * hss_sk.d_slices[i];

        REQUIRE(decrypted_sum_times_d_slice == expected_sum_times_d_slice);
    }

    mpz_class decrypted_sum;
    pal_decrypt(sum_input.x_ct, hss_sk.sk, hss_pk.pk, decrypted_sum);
    REQUIRE(decrypted_sum == (input0 + input1));

}

TEST_CASE("pal_hss::hom_add_inputs in-place version produces ciphertexts that decrypt to the sum of the original inputs times d_slices[i]", "[pal_hss][hom_add_inputs][in-place]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pal_hss::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 25;
    opts.stat_sec_param = 40;
    opts.value_base_bitlen = 7; // log2(128)

    pal_hss::pk hss_pk;
    std::array<pal_hss::ek, 2> hss_ek;
    pal_hss::sk hss_sk;

    pal_hss::setup(opts, prg, hss_pk, hss_ek, hss_sk);

    mpz_class input0 = 42;
    mpz_class input1 = 17;

    pal_hss::input enc_input0, enc_input1;
    pal_hss::enc_input(input0, hss_pk, hss_sk, prg, enc_input0);
    pal_hss::enc_input(input1, hss_pk, hss_sk, prg, enc_input1);

    pal_hss::hom_add_inputs(enc_input0, enc_input1, hss_pk); // in-place version

    REQUIRE(enc_input0.xd_slices_cts.size() == hss_sk.d_slices.size());

    for (size_t i = 0; i < enc_input0.xd_slices_cts.size(); i++) {
        mpz_class decrypted_sum_times_d_slice;
        pal_decrypt(enc_input0.xd_slices_cts[i], hss_sk.sk, hss_pk.pk, decrypted_sum_times_d_slice);

        mpz_class expected_sum_times_d_slice = (input0 + input1) * hss_sk.d_slices[i];

        REQUIRE(decrypted_sum_times_d_slice == expected_sum_times_d_slice);
    }

    mpz_class decrypted_sum;
    pal_decrypt(enc_input0.x_ct, hss_sk.sk, hss_pk.pk, decrypted_sum);
    REQUIRE(decrypted_sum == (input0 + input1));

}

TEST_CASE("pal_hss::input_to_mem produces memory shares that reconstruct to the original input * d_slices[i] and input * d", "[pal_hss][input_to_mem]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pal_hss::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 25;
    opts.stat_sec_param = 40;
    opts.value_base_bitlen = 7; // log2(128)

    pal_hss::pk hss_pk;
    std::array<pal_hss::ek, 2> hss_ek;
    pal_hss::sk hss_sk;

    pal_hss::setup(opts, prg, hss_pk, hss_ek, hss_sk);

    mpz_class input = 42;

    pal_hss::input enc_input_out;
    pal_hss::enc_input(input, hss_pk, hss_sk, prg, enc_input_out);

    pal_hss::mem mem_out_0, mem_out_1;
    pal_hss::input_to_mem(enc_input_out, hss_pk, hss_ek[0], mem_out_0);
    pal_hss::input_to_mem(enc_input_out, hss_pk, hss_ek[1], mem_out_1);

    REQUIRE(mem_out_0.sliced_xd_intss.size() == hss_sk.d_slices.size());

    mpz_class reconstruced_xd;

    intss_reconst(mem_out_0.xd_intss, mem_out_1.xd_intss, reconstruced_xd);

    mpz_class expected_xd = input * hss_sk.sk.d;

    REQUIRE(reconstruced_xd == expected_xd);

    vector<mpz_class> reconstructed_xd_slices_from_eks(mem_out_0.sliced_xd_intss.size());

    batch_intss_reconst(mem_out_0.sliced_xd_intss, mem_out_1.sliced_xd_intss, reconstructed_xd_slices_from_eks);

    for (size_t i = 0; i < mem_out_0.sliced_xd_intss.size(); i++) {
        mpz_class expected_xd_slice = input * hss_sk.d_slices[i];
        REQUIRE(reconstructed_xd_slices_from_eks[i] == expected_xd_slice);
    }

    mpz_class reconstructed_x;
    intss_reconst(mem_out_0.x_intss, mem_out_1.x_intss, reconstructed_x);
    REQUIRE(reconstructed_x == input);

}

TEST_CASE("pal_hss::hom_mult_mem_input produces memory shares that reconstruct to the product of the original input and memory shares", "[pal_hss][hom_mult_mem_input]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pal_hss::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 25;
    opts.stat_sec_param = 40;
    opts.value_base_bitlen = 7; // log2(128)

    pal_hss::pk hss_pk;
    std::array<pal_hss::ek, 2> hss_ek;
    pal_hss::sk hss_sk;

    pal_hss::setup(opts, prg, hss_pk, hss_ek, hss_sk);

    mpz_class in0 = 11;
    mpz_class in1 = 7;

    pal_hss::input enc_in0_out, enc_in1_out;
    pal_hss::enc_input(in0, hss_pk, hss_sk, prg, enc_in0_out);
    pal_hss::enc_input(in1, hss_pk, hss_sk, prg, enc_in1_out);

    pal_hss::mem in0_as_mem0, in0_as_mem1;
    pal_hss::input_to_mem(enc_in0_out, hss_pk, hss_ek[0], in0_as_mem0);
    pal_hss::input_to_mem(enc_in0_out, hss_pk, hss_ek[1], in0_as_mem1);

    pal_hss::mem mem_out0, mem_out1;
    pal_hss::hom_mult_mem_input(in0_as_mem0, enc_in1_out, hss_pk, hss_ek[0], mem_out0);
    pal_hss::hom_mult_mem_input(in0_as_mem1, enc_in1_out, hss_pk, hss_ek[1], mem_out1);

    mpz_class reconstruced_xd;

    intss_reconst(mem_out0.xd_intss, mem_out1.xd_intss, reconstruced_xd);

    mpz_class expected_xd = in0 * in1 * hss_sk.sk.d;

    REQUIRE(reconstruced_xd == expected_xd);

    vector<mpz_class> reconstructed_xd_slices_from_eks(mem_out0.sliced_xd_intss.size());

    batch_intss_reconst(mem_out0.sliced_xd_intss, mem_out1.sliced_xd_intss, reconstructed_xd_slices_from_eks);

    for (size_t i = 0; i < mem_out0.sliced_xd_intss.size(); i++) {
        mpz_class expected_xd_slice = in0 * in1 * hss_sk.d_slices[i];
        REQUIRE(reconstructed_xd_slices_from_eks[i] == expected_xd_slice);
    }

    mpz_class reconstructed_in0_times_in1;
    intss_reconst(mem_out0.x_intss, mem_out1.x_intss, reconstructed_in0_times_in1);
    REQUIRE(reconstructed_in0_times_in1 == in0 * in1);

}

TEST_CASE("pal_hss::hom_mult_mem_input produces memory shares that reconstruct to the product of the original input and memory shares (in-place version)", "[pal_hss][hom_mult_mem_input]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pal_hss::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 25;
    opts.stat_sec_param = 40;
    opts.value_base_bitlen = 7; // log2(128)

    pal_hss::pk hss_pk;
    std::array<pal_hss::ek, 2> hss_ek;
    pal_hss::sk hss_sk;

    pal_hss::setup(opts, prg, hss_pk, hss_ek, hss_sk);

    mpz_class in0 = 11;
    mpz_class in1 = 7;

    pal_hss::input enc_in0_out, enc_in1_out;
    pal_hss::enc_input(in0, hss_pk, hss_sk, prg, enc_in0_out);
    pal_hss::enc_input(in1, hss_pk, hss_sk, prg, enc_in1_out);

    pal_hss::mem mem_out0, mem_out1;
    pal_hss::input_to_mem(enc_in0_out, hss_pk, hss_ek[0], mem_out0);
    pal_hss::input_to_mem(enc_in0_out, hss_pk, hss_ek[1], mem_out1);

    pal_hss::hom_mult_mem_input(mem_out0, enc_in1_out, hss_pk, hss_ek[0]);
    pal_hss::hom_mult_mem_input(mem_out1, enc_in1_out, hss_pk, hss_ek[1]);

    mpz_class reconstruced_xd;

    intss_reconst(mem_out0.xd_intss, mem_out1.xd_intss, reconstruced_xd);

    mpz_class expected_xd = in0 * in1 * hss_sk.sk.d;

    REQUIRE(reconstruced_xd == expected_xd);

    vector<mpz_class> reconstructed_xd_slices_from_eks(mem_out0.sliced_xd_intss.size());

    batch_intss_reconst(mem_out0.sliced_xd_intss, mem_out1.sliced_xd_intss, reconstructed_xd_slices_from_eks);

    for (size_t i = 0; i < mem_out0.sliced_xd_intss.size(); i++) {
        mpz_class expected_xd_slice = in0 * in1 * hss_sk.d_slices[i];
        REQUIRE(reconstructed_xd_slices_from_eks[i] == expected_xd_slice);
    }

    mpz_class reconstructed_in0_times_in1;
    intss_reconst(mem_out0.x_intss, mem_out1.x_intss, reconstructed_in0_times_in1);
    REQUIRE(reconstructed_in0_times_in1 == in0 * in1);

}

TEST_CASE("pal_hss::reconst_mem correctly reconstructs the original input * d and input * d_slices[i]", "[pal_hss][reconst_mem]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    pal_hss::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 25;
    opts.stat_sec_param = 40;
    opts.value_base_bitlen = 7; // log2(128)

    pal_hss::pk hss_pk;
    std::array<pal_hss::ek, 2> hss_ek;
    pal_hss::sk hss_sk;

    pal_hss::setup(opts, prg, hss_pk, hss_ek, hss_sk);

    mpz_class input = 42;

    pal_hss::input enc_input_out;
    pal_hss::enc_input(input, hss_pk, hss_sk, prg, enc_input_out);

    pal_hss::mem mem0, mem1;
    pal_hss::input_to_mem(enc_input_out, hss_pk, hss_ek[0], mem0);
    pal_hss::input_to_mem(enc_input_out, hss_pk, hss_ek[1], mem1);

    mpz_class reconstruced_xd;
    vector<mpz_class> reconstructed_xd_slices;

    mpz_class reconstructed_x;
    pal_hss::reconst_mem(mem0, mem1, hss_pk, reconstructed_x, reconstruced_xd, reconstructed_xd_slices);

    REQUIRE(reconstructed_x == input);

    mpz_class expected_xd = input * hss_sk.sk.d;

    REQUIRE(reconstruced_xd == expected_xd);

    for (size_t i = 0; i < reconstructed_xd_slices.size(); i++) {
        mpz_class expected_xd_slice = input * hss_sk.d_slices[i];
        REQUIRE(reconstructed_xd_slices[i] == expected_xd_slice);
    }

    REQUIRE(reconstructed_xd_slices.size() == hss_sk.d_slices.size());

}