#include "./pal_hss.hpp"
#include "./ss.hpp"
#include "./paillier.hpp"

using std::array;
using std::vector;
using osuCrypto::PRNG;

static void ddlog(const mpz_class& N, const mpz_class& g, mpz_class& ddlog_out) {
    
    mpz_class h_prime;

    // Computes h (h=ddlog_out) and h' such that g = h'*N + h and 0 <= h < N.
    mpz_fdiv_qr(h_prime.get_mpz_t(), ddlog_out.get_mpz_t(), g.get_mpz_t(), N.get_mpz_t());

    // After the next line we have h = h^-1 mod N. (h = ddlog_g)
    mpz_invert(ddlog_out.get_mpz_t(), ddlog_out.get_mpz_t(), N.get_mpz_t());

    // After the next line we have ddlog_out = h * h' over the integers. (h = ddlog)
    mpz_mul(ddlog_out.get_mpz_t(), ddlog_out.get_mpz_t(), h_prime.get_mpz_t());

    // After the next line we have ddlog_out = h * h' mod N. (h = ddlog)
    mpz_mod(ddlog_out.get_mpz_t(), ddlog_out.get_mpz_t(), N.get_mpz_t());

}

void pal_hss::setup(const pal_hss::setup_opts& opts, PRNG& prg, pal_hss::pk& pk_out, array<pal_hss::ek, 2>& ek_out, pal_hss::sk& sk_out) {

    pal_sk psk;
    pal_pk ppk;
    pal_keygen(opts.blum_int_bitlen, opts.miller_rabin_rounds_per_prime, prg, psk, ppk);
    pk_out.pk = ppk;
    pk_out.stat_sec_param = opts.stat_sec_param;
    sk_out.sk = psk;
    pk_out.value_base_bitlen = opts.value_base_bitlen;

    size_t remaining_msg_bitlen = opts.blum_int_bitlen - (opts.value_base_bitlen + opts.stat_sec_param + 1);
    assert(remaining_msg_bitlen > 0);

    size_t d_slice_bitlen = remaining_msg_bitlen;
    pk_out.d_slice_bitlen = d_slice_bitlen;

    size_t d_bitlen = mpz_sizeinbase(psk.d.get_mpz_t(), 2);

    size_t num_slices = (d_bitlen + d_slice_bitlen - 1) / d_slice_bitlen;

    pk_out.D_slice_cts.resize(num_slices);
    sk_out.d_slices.resize(num_slices);
    ek_out[0].d_slice_intss.resize(num_slices);
    ek_out[1].d_slice_intss.resize(num_slices);
    ek_out[0].pidx = 0;
    ek_out[1].pidx = 1;

    samp_intss(psk.d, d_slice_bitlen + opts.value_base_bitlen, opts.stat_sec_param, prg, ek_out[0].d_intss, ek_out[1].d_intss);

    for (size_t i = 0; i < num_slices; i++) {
        size_t slice_start_bit = i * d_slice_bitlen;
        size_t slice_end_bit_exclusive = std::min(slice_start_bit + d_slice_bitlen, d_bitlen);
        size_t slice_bitlen = slice_end_bit_exclusive - slice_start_bit;

        mpz_fdiv_q_2exp(sk_out.d_slices[i].get_mpz_t(), psk.d.get_mpz_t(), slice_start_bit);
        mpz_mod_2exp(sk_out.d_slices[i].get_mpz_t(), sk_out.d_slices[i].get_mpz_t(), slice_bitlen);

        samp_intss(sk_out.d_slices[i], d_slice_bitlen + opts.value_base_bitlen, opts.stat_sec_param, prg, ek_out[0].d_slice_intss[i], ek_out[1].d_slice_intss[i]);
        pal_encrypt(sk_out.d_slices[i], pk_out.pk, prg, pk_out.D_slice_cts[i]);
    }
    
}

void pal_hss::setup(const pal_hss::setup_opts& opts, PRNG& prg, pal_hss::pk& pk_out, pal_hss::sk& sk_out) {
    
    pal_sk psk;
    pal_pk ppk;
    pal_keygen(opts.blum_int_bitlen, opts.miller_rabin_rounds_per_prime, prg, psk, ppk);
    pk_out.pk = ppk;
    pk_out.stat_sec_param = opts.stat_sec_param;
    sk_out.sk = psk;
    pk_out.value_base_bitlen = opts.value_base_bitlen;

    assert(opts.blum_int_bitlen > opts.value_base_bitlen + opts.stat_sec_param + 1);

    size_t remaining_msg_bitlen = opts.blum_int_bitlen - (opts.value_base_bitlen + opts.stat_sec_param + 1);
    
    size_t d_slice_bitlen = remaining_msg_bitlen;
    pk_out.d_slice_bitlen = d_slice_bitlen;

    size_t d_bitlen = mpz_sizeinbase(psk.d.get_mpz_t(), 2);

    size_t num_slices = (d_bitlen + d_slice_bitlen - 1) / d_slice_bitlen;

    pk_out.D_slice_cts.resize(num_slices);
    sk_out.d_slices.resize(num_slices);

    for (size_t i = 0; i < num_slices; i++) {
        size_t slice_start_bit = i * d_slice_bitlen;
        size_t slice_end_bit_exclusive = std::min(slice_start_bit + d_slice_bitlen, d_bitlen);
        size_t slice_bitlen = slice_end_bit_exclusive - slice_start_bit;

        mpz_fdiv_q_2exp(sk_out.d_slices[i].get_mpz_t(), psk.d.get_mpz_t(), slice_start_bit);
        mpz_mod_2exp(sk_out.d_slices[i].get_mpz_t(), sk_out.d_slices[i].get_mpz_t(), slice_bitlen);

        pal_encrypt(sk_out.d_slices[i], pk_out.pk, prg, pk_out.D_slice_cts[i]);
    }

}

void pal_hss::gen_eks(const pal_hss::sk& sk, const pal_hss::pk& pk, osuCrypto::PRNG& prg, array<pal_hss::ek, 2>& ek_out) {
    
    size_t value_base_bitlen = pk.value_base_bitlen;
    size_t d_slice_bitlen = pk.d_slice_bitlen;
    size_t num_slices = sk.d_slices.size();
    size_t stat_sec_param = pk.stat_sec_param;
    size_t d_bitlen = mpz_sizeinbase(sk.sk.d.get_mpz_t(), 2);

    ek_out[0].pidx = 0;
    ek_out[1].pidx = 1;
    ek_out[0].d_slice_intss.resize(num_slices);
    ek_out[1].d_slice_intss.resize(num_slices);

    samp_intss(sk.sk.d, d_bitlen + value_base_bitlen, stat_sec_param, prg, ek_out[0].d_intss, ek_out[1].d_intss);

    for (size_t i = 0; i < num_slices; i++) {

        samp_intss(sk.d_slices[i], d_slice_bitlen + value_base_bitlen, stat_sec_param, prg, ek_out[0].d_slice_intss[i], ek_out[1].d_slice_intss[i]);
            
    }

}

void pal_hss::enc_input(const mpz_class& input, const pal_hss::pk& pk, const pal_hss::sk& sk, PRNG& prg, pal_hss::input& input_out) {
    assert(mpz_sizeinbase(input.get_mpz_t(), 2) <= pk.value_base_bitlen);
    
    size_t num_d_slices = pk.D_slice_cts.size();
    input_out.xd_slices_cts.resize(num_d_slices);

    pal_encrypt(input, pk.pk, prg, input_out.x_ct);

    for (size_t i = 0; i < num_d_slices; i++) {
        mpz_class input_times_d_slice = input * sk.d_slices[i];
        pal_encrypt(input_times_d_slice, pk.pk, prg, input_out.xd_slices_cts[i]);        
    }

}

void pal_hss::enc_bin_input(bool input, const pal_hss::pk& pk, const pal_hss::sk& sk, PRNG& prg, pal_hss::input& input_out) {
    assert(1 <= pk.value_base_bitlen);
    
    const mpz_class ZERO = 0;

    size_t num_d_slices = pk.D_slice_cts.size();
    input_out.xd_slices_cts.resize(num_d_slices);

    mpz_class input_as_mpz = input ? 1 : 0;
    pal_encrypt(input_as_mpz, pk.pk, prg, input_out.x_ct);

    for (size_t i = 0; i < num_d_slices; i++) {
        const mpz_class& input_times_d_slice = (input ? sk.d_slices[i] : ZERO);
        
        pal_encrypt(input_times_d_slice, pk.pk, prg, input_out.xd_slices_cts[i]);        
    }

}

void pal_hss::hom_neg_input(const pal_hss::input& input, const pal_hss::pk& pk, pal_hss::input& neg_input_out) {
    assert(input.xd_slices_cts.size() == pk.D_slice_cts.size());

    size_t num_slices = input.xd_slices_cts.size();
    neg_input_out.xd_slices_cts.resize(num_slices);

    mpz_invert(neg_input_out.x_ct.get_mpz_t(), input.x_ct.get_mpz_t(), pk.pk.N_squared.get_mpz_t());
    mpz_mul(neg_input_out.x_ct.get_mpz_t(), neg_input_out.x_ct.get_mpz_t(), pk.pk.N_plus_1.get_mpz_t());
    mpz_mod(neg_input_out.x_ct.get_mpz_t(), neg_input_out.x_ct.get_mpz_t(), pk.pk.N_squared.get_mpz_t());

    for (size_t i = 0; i < num_slices; i++) {
        mpz_invert(neg_input_out.xd_slices_cts[i].get_mpz_t(), input.xd_slices_cts[i].get_mpz_t(), pk.pk.N_squared.get_mpz_t());
        mpz_mul(neg_input_out.xd_slices_cts[i].get_mpz_t(), neg_input_out.xd_slices_cts[i].get_mpz_t(), pk.D_slice_cts[i].get_mpz_t());
        mpz_mod(neg_input_out.xd_slices_cts[i].get_mpz_t(), neg_input_out.xd_slices_cts[i].get_mpz_t(), pk.pk.N_squared.get_mpz_t());
    }

}

void pal_hss::hom_add_inputs(const pal_hss::input& in0, const pal_hss::input& in1, const pal_hss::pk& pk, pal_hss::input& sum_input_out) {
    assert(in0.xd_slices_cts.size() == in1.xd_slices_cts.size());
    
    size_t num_slices = in0.xd_slices_cts.size();
    sum_input_out.xd_slices_cts.resize(num_slices);

    hom_ct_add(in0.x_ct, in1.x_ct, pk.pk, sum_input_out.x_ct);

    for (size_t i = 0; i < num_slices; i++) {
        hom_ct_add(in0.xd_slices_cts[i], in1.xd_slices_cts[i], pk.pk, sum_input_out.xd_slices_cts[i]);
    }

}

void pal_hss::hom_add_inputs(pal_hss::input& in0_and_out, const pal_hss::input& in1, const pal_hss::pk& pk) {
    assert(in0_and_out.xd_slices_cts.size() == in1.xd_slices_cts.size());

    size_t num_slices = in0_and_out.xd_slices_cts.size();

    hom_ct_add(in0_and_out.x_ct, in1.x_ct, pk.pk);

    for (size_t i = 0; i < num_slices; i++) {
        hom_ct_add(in0_and_out.xd_slices_cts[i], in1.xd_slices_cts[i], pk.pk);
    }
    
}

void pal_hss::hom_add_mem(const pal_hss::mem& mem0, const pal_hss::mem& mem1, const pal_hss::pk& pk, pal_hss::mem& sum_mem_out) {
    assert(mem0.sliced_xd_intss.size() == mem1.sliced_xd_intss.size());

    size_t num_slices = mem0.sliced_xd_intss.size();
    sum_mem_out.sliced_xd_intss.resize(num_slices);

    mpz_add(sum_mem_out.x_intss.get_mpz_t(), mem0.x_intss.get_mpz_t(), mem1.x_intss.get_mpz_t());
    mpz_add(sum_mem_out.xd_intss.get_mpz_t(), mem0.xd_intss.get_mpz_t(), mem1.xd_intss.get_mpz_t());

    for (size_t i = 0; i < num_slices; i++) {
        mpz_add(sum_mem_out.sliced_xd_intss[i].get_mpz_t(), mem0.sliced_xd_intss[i].get_mpz_t(), mem1.sliced_xd_intss[i].get_mpz_t());
    }
    
}

// THIS IS WHERE I STOPPED.
// I MAY NOT NEED SHARES OF THE SLICES.

void pal_hss::input_to_mem(const pal_hss::input& input, const pal_hss::pk& pk, const pal_hss::ek& ek, pal_hss::mem& mem_out) {
    assert(input.xd_slices_cts.size() == pk.D_slice_cts.size());

    size_t d_slice_bitlen = pk.d_slice_bitlen;
    size_t num_d_slices = input.xd_slices_cts.size();
    mem_out.sliced_xd_intss.resize(num_d_slices);
    mem_out.xd_intss = 0;

    for (size_t i = 0; i < num_d_slices; i++) {
        mpz_class shifted_xd_slice_ss;

        mpz_powm(mem_out.sliced_xd_intss[i].get_mpz_t(), input.xd_slices_cts[i].get_mpz_t(), ek.d_intss.get_mpz_t(), pk.pk.N_squared.get_mpz_t());
        
        ddlog(pk.pk.N, mem_out.sliced_xd_intss[i], mem_out.sliced_xd_intss[i]);

        mpz_mul_2exp(shifted_xd_slice_ss.get_mpz_t(), mem_out.sliced_xd_intss[i].get_mpz_t(), i * d_slice_bitlen);
        mpz_add(mem_out.xd_intss.get_mpz_t(), mem_out.xd_intss.get_mpz_t(), shifted_xd_slice_ss.get_mpz_t());
    }

    mpz_powm(mem_out.x_intss.get_mpz_t(), input.x_ct.get_mpz_t(), ek.d_intss.get_mpz_t(), pk.pk.N_squared.get_mpz_t());
    
    ddlog(pk.pk.N, mem_out.x_intss, mem_out.x_intss);

}

void pal_hss::pubconst_to_mem(const mpz_class& pubconst, const pal_hss::pk& pk, const pal_hss::ek& ek, size_t party_idx, pal_hss::mem& mem_out) {
    assert(party_idx == 0 || party_idx == 1);

    const size_t num_d_slices = ek.d_slice_intss.size();
    mem_out.sliced_xd_intss.resize(num_d_slices);

    mem_out.x_intss = (party_idx == 0) ? 0 : pubconst;

    mpz_mul(mem_out.xd_intss.get_mpz_t(), ek.d_intss.get_mpz_t(), pubconst.get_mpz_t());
    
    for (size_t i = 0; i < num_d_slices; i++) {
        mpz_mul(mem_out.sliced_xd_intss[i].get_mpz_t(), ek.d_slice_intss[i].get_mpz_t(), pubconst.get_mpz_t());
    }

}

void pal_hss::hom_mult_mem_input(const pal_hss::mem& mem_in, const pal_hss::input& input, const pal_hss::pk& pk, const pal_hss::ek& ek, pal_hss::mem& mem_out) {
    assert(input.xd_slices_cts.size() == pk.D_slice_cts.size());
    assert(mem_in.sliced_xd_intss.size() == pk.D_slice_cts.size());

    size_t d_slice_bitlen = pk.d_slice_bitlen;
    size_t num_d_slices = mem_in.sliced_xd_intss.size();
    mem_out.sliced_xd_intss.resize(num_d_slices);
    mem_out.xd_intss = 0;

    for (size_t i = 0; i < num_d_slices; i++) {
         mpz_class shifted_xd_slice_ss;

        mpz_powm(mem_out.sliced_xd_intss[i].get_mpz_t(), input.xd_slices_cts[i].get_mpz_t(), mem_in.xd_intss.get_mpz_t(), pk.pk.N_squared.get_mpz_t());
        ddlog(pk.pk.N, mem_out.sliced_xd_intss[i], mem_out.sliced_xd_intss[i]);

        mpz_mul_2exp(shifted_xd_slice_ss.get_mpz_t(), mem_out.sliced_xd_intss[i].get_mpz_t(), i * d_slice_bitlen);
        mpz_add(mem_out.xd_intss.get_mpz_t(), mem_out.xd_intss.get_mpz_t(), shifted_xd_slice_ss.get_mpz_t());
    }

    mpz_powm(mem_out.x_intss.get_mpz_t(), input.x_ct.get_mpz_t(), mem_in.xd_intss.get_mpz_t(), pk.pk.N_squared.get_mpz_t());
    ddlog(pk.pk.N, mem_out.x_intss, mem_out.x_intss);

}

void pal_hss::hom_mult_mem_palct(const pal_hss::mem& mem_in, const mpz_class& pal_ct, const pal_hss::pk& pk, const pal_hss::ek& ek, mpz_class& ss_out) {
    mpz_powm(ss_out.get_mpz_t(), pal_ct.get_mpz_t(), mem_in.xd_intss.get_mpz_t(), pk.pk.N_squared.get_mpz_t());
    ddlog(pk.pk.N, ss_out, ss_out);
}

void pal_hss::hom_mult_mem_pubconst(const pal_hss::mem& mem_in, const mpz_class& pubconst, const pal_hss::pk& pk, const pal_hss::ek& ek, pal_hss::mem& mem_out) {
    
    const size_t num_d_slices = mem_in.sliced_xd_intss.size();
    mem_out.sliced_xd_intss.resize(num_d_slices);

    mpz_mul(mem_out.x_intss.get_mpz_t(), mem_in.x_intss.get_mpz_t(), pubconst.get_mpz_t());
    
    mpz_mul(mem_out.xd_intss.get_mpz_t(), mem_in.xd_intss.get_mpz_t(), pubconst.get_mpz_t());
    
    for (size_t i = 0; i < num_d_slices; i++) {
        mpz_mul(mem_out.sliced_xd_intss[i].get_mpz_t(), mem_in.sliced_xd_intss[i].get_mpz_t(), pubconst.get_mpz_t());
    }

}

void pal_hss::hom_mult_mem_input(pal_hss::mem& mem_in_out, const pal_hss::input& input, const pal_hss::pk& pk, const pal_hss::ek& ek) {
    assert(input.xd_slices_cts.size() == pk.D_slice_cts.size());
    assert(mem_in_out.sliced_xd_intss.size() == pk.D_slice_cts.size());

    size_t d_slice_bitlen = pk.d_slice_bitlen;
    size_t num_d_slices = mem_in_out.sliced_xd_intss.size();
    mpz_class input_times_xd_intss = 0;

    for (size_t i = 0; i < num_d_slices; i++) {
         mpz_class shifted_xd_slice_ss;

        mpz_powm(mem_in_out.sliced_xd_intss[i].get_mpz_t(), input.xd_slices_cts[i].get_mpz_t(), mem_in_out.xd_intss.get_mpz_t(), pk.pk.N_squared.get_mpz_t());
        ddlog(pk.pk.N, mem_in_out.sliced_xd_intss[i], mem_in_out.sliced_xd_intss[i]);

        mpz_mul_2exp(shifted_xd_slice_ss.get_mpz_t(), mem_in_out.sliced_xd_intss[i].get_mpz_t(), i * d_slice_bitlen);
        mpz_add(input_times_xd_intss.get_mpz_t(), input_times_xd_intss.get_mpz_t(), shifted_xd_slice_ss.get_mpz_t());
    }

    mpz_powm(mem_in_out.x_intss.get_mpz_t(), input.x_ct.get_mpz_t(), mem_in_out.xd_intss.get_mpz_t(), pk.pk.N_squared.get_mpz_t());
    ddlog(pk.pk.N, mem_in_out.x_intss, mem_in_out.x_intss);

    mem_in_out.xd_intss = input_times_xd_intss;

}

void pal_hss::reconst_mem(const pal_hss::mem& mem0, 
                          const pal_hss::mem& mem1, 
                          const pal_hss::pk& pk,
                          mpz_class& x_out, 
                          mpz_class& xd_out, 
                          vector<mpz_class>& xd_slices_out) {
    assert(mem0.sliced_xd_intss.size() == mem1.sliced_xd_intss.size());

    size_t d_slice_bitlen = pk.d_slice_bitlen;
    size_t num_d_slices = mem0.sliced_xd_intss.size();
    xd_slices_out.resize(num_d_slices);
    xd_out = 0;

    for (size_t i = 0; i < num_d_slices; i++) {
        mpz_class xd_slice_ss_sum;
        mpz_sub(xd_slices_out[i].get_mpz_t(), mem1.sliced_xd_intss[i].get_mpz_t(), mem0.sliced_xd_intss[i].get_mpz_t());

        mpz_class shifted_xd_slice_ss;
        mpz_mul_2exp(shifted_xd_slice_ss.get_mpz_t(), xd_slices_out[i].get_mpz_t(), i * d_slice_bitlen);
        mpz_add(xd_out.get_mpz_t(), xd_out.get_mpz_t(), shifted_xd_slice_ss.get_mpz_t());
    }

    mpz_sub(x_out.get_mpz_t(), mem1.x_intss.get_mpz_t(), mem0.x_intss.get_mpz_t());
}